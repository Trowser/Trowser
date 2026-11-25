using System.Text.Json;
using Trowser.Automation;
using Trowser.Security;
using Trowser.Security.Workflow;

namespace Trowser.Repro;

/// <summary>
/// Generic k-run repro verification over <see cref="WorkflowVerifyService"/>.
/// Clears the session and optionally applies an identity between runs, then classifies
/// the outcome as reproducible / flaky / not-reproducible (plus a pass rate).
/// </summary>
public static class ReproVerifyService
{
    public static async Task<ReproVerifyResult> VerifyAsync(
        JsonElement workflow,
        WorkflowDependencies deps,
        IdentityStore identityStore,
        int runs,
        bool clearSession,
        string? identity,
        string? expect,
        string? startUrlAfterClear = null,
        string? workflowJsonForRebind = null,
        Func<int, Task>? beforeEachRun = null,
        bool classifyPreconditions = false)
    {
        runs = Math.Clamp(runs, 1, 20);
        var results = new List<ReproRunResult>();
        var service = new WorkflowVerifyService();
        var context = deps.Context;

        for (var i = 0; i < runs; i++)
        {
            deps.Cancellation.ThrowIfCancellationRequested();

            if (clearSession)
            {
                try { await context.ClearSession(); }
                catch (Exception ex)
                {
                    results.Add(PreRunFailure(i + 1, "clearSession", $"clearSession failed: {ex.Message}"));
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(startUrlAfterClear)
                    && Uri.TryCreate(startUrlAfterClear, UriKind.Absolute, out var startUri)
                    && (startUri.Scheme == Uri.UriSchemeHttp || startUri.Scheme == Uri.UriSchemeHttps))
                {
                    try { await context.Navigate(startUrlAfterClear); }
                    catch (Exception ex)
                    {
                        results.Add(PreRunFailure(i + 1, "navigate", $"navigate after clearSession failed: {ex.Message}"));
                        continue;
                    }
                }
            }

            if (beforeEachRun != null)
            {
                try { await beforeEachRun(i + 1); }
                catch (Exception ex)
                {
                    results.Add(PreRunFailure(i + 1, "beforeRun", ex.Message));
                    continue;
                }
            }

            if (!string.IsNullOrWhiteSpace(identity))
            {
                try { await identityStore.ApplyAsync(context, identity); }
                catch (Exception ex)
                {
                    results.Add(PreRunFailure(i + 1, "identity", $"identity apply failed: {ex.Message}"));
                    continue;
                }
            }

            JsonDocument? reboundDoc = null;
            try
            {
                var runWorkflow = workflow;
                if (clearSession && !string.IsNullOrWhiteSpace(workflowJsonForRebind))
                {
                    var enriched = ReproWorkflowStableSelectors.EnrichTriggerSteps(workflowJsonForRebind, context);
                    reboundDoc = JsonDocument.Parse(enriched);
                    runWorkflow = reboundDoc.RootElement;
                }

                var run = await service.RunAsync(runWorkflow, deps);
                var failure = run.Verified ? null : FirstFailure(run);
                results.Add(new ReproRunResult
                {
                    Run = i + 1,
                    Passed = run.Verified,
                    Workflow = run,
                    Error = failure?.Message ?? run.Error,
                    Failure = failure,
                    Precondition = failure != null && IsPreconditionFailure(failure)
                });
            }
            finally
            {
                reboundDoc?.Dispose();
            }
        }

        var passed = results.Count(r => r.Passed);
        var failed = results.Count - passed;
        var verdict = Classify(passed, results.Count);
        string? reason = null;
        if (classifyPreconditions && passed == 0 && results.Count > 0 && results.All(r => r.Precondition))
        {
            // Every run failed before the steps under test got going: the start state was wrong, not the app.
            verdict = ReproVerdict.Inconclusive;
            reason = "precondition-failed";
        }
        var expected = ParseExpect(expect);
        if (expected != null && expected != verdict)
        {
            verdict = ReproVerdict.Inconclusive;
            reason ??= "unexpected-verdict";
        }

        return new ReproVerifyResult
        {
            Verdict = verdict,
            Reason = reason,
            Rate = results.Count == 0 ? 0 : (double)passed / results.Count,
            Passed = passed,
            Failed = failed,
            Runs = results
        };
    }

    private static ReproRunResult PreRunFailure(int run, string phase, string message) => new()
    {
        Run = run,
        Passed = false,
        Error = message,
        Failure = new ReproRunFailure { Phase = phase, Message = message },
        Precondition = true
    };

    /// <summary>A failure in <c>setup</c> or at the first trigger step means the run never reached the steps under test.</summary>
    public static bool IsPreconditionFailure(ReproRunFailure failure) =>
        failure.Phase is "setup" or "clearSession" or "navigate" or "beforeRun" or "identity"
        || (failure.Phase == "trigger" && failure.StepIndex == 0);

    /// <summary>The first failed step (or the oracle) of a workflow run, as an object instead of a JSON string.</summary>
    public static ReproRunFailure? FirstFailure(WorkflowVerifyResult run)
    {
        foreach (var (phase, list) in new[] { ("setup", run.Setup), ("trigger", run.Trigger), ("cleanup", run.Cleanup) })
        {
            foreach (var step in list)
            {
                if (!step.TryGetValue("success", out var ok) || ok is not false) continue;
                return new ReproRunFailure
                {
                    Phase = phase,
                    StepIndex = step.TryGetValue("index", out var idx) && idx is int n ? n : null,
                    StepType = step.TryGetValue("type", out var t) ? t?.ToString() : null,
                    Message = step.TryGetValue("error", out var err) ? err?.ToString() ?? "" : ""
                };
            }
        }

        if (run.Oracle is { Passed: false } oracle)
            return new ReproRunFailure { Phase = "oracle", StepType = oracle.Type, Message = oracle.Error ?? "Oracle check failed." };

        return string.IsNullOrWhiteSpace(run.Error)
            ? null
            : new ReproRunFailure { Phase = run.FailurePhase ?? "workflow", Message = run.Error };
    }

    public static ReproVerdict Classify(int passed, int total)
    {
        if (total <= 0) return ReproVerdict.Inconclusive;
        if (passed == total) return ReproVerdict.Reproducible;
        if (passed == 0) return ReproVerdict.NotReproducible;
        return ReproVerdict.Flaky;
    }

    public static string ToApiString(ReproVerdict verdict) => verdict switch
    {
        ReproVerdict.Reproducible => "reproducible",
        ReproVerdict.NotReproducible => "not-reproducible",
        ReproVerdict.Flaky => "flaky",
        _ => "inconclusive"
    };

    private static ReproVerdict? ParseExpect(string? expect)
    {
        if (string.IsNullOrWhiteSpace(expect)) return null;
        return expect.Trim().ToLowerInvariant() switch
        {
            "reproducible" or "verified" => ReproVerdict.Reproducible,
            "not-reproducible" or "not_reproducible" or "notverified" or "not_verified" => ReproVerdict.NotReproducible,
            "flaky" => ReproVerdict.Flaky,
            "inconclusive" => ReproVerdict.Inconclusive,
            _ => null
        };
    }
}

public enum ReproVerdict
{
    Reproducible,
    Flaky,
    NotReproducible,
    Inconclusive
}

public sealed class ReproRunResult
{
    public int Run { get; init; }
    public bool Passed { get; init; }
    public WorkflowVerifyResult? Workflow { get; init; }
    /// <summary>Plain-text failure message (the step's error, not a serialized object).</summary>
    public string? Error { get; init; }
    public ReproRunFailure? Failure { get; init; }
    /// <summary>True when the run failed before the steps under test ran (setup, session prep, or the first step).</summary>
    public bool Precondition { get; init; }
}

public sealed class ReproRunFailure
{
    /// <summary><c>setup</c>, <c>trigger</c>, <c>cleanup</c>, <c>oracle</c>, or a pre-run phase (<c>clearSession</c>, <c>navigate</c>, <c>beforeRun</c>, <c>identity</c>).</summary>
    public string Phase { get; init; } = "";
    public int? StepIndex { get; init; }
    public string? StepType { get; init; }
    public string Message { get; init; } = "";
}

public sealed class ReproVerifyResult
{
    public ReproVerdict Verdict { get; init; }
    /// <summary>Why the verdict is inconclusive: <c>precondition-failed</c> or <c>unexpected-verdict</c>.</summary>
    public string? Reason { get; init; }
    public double Rate { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public List<ReproRunResult> Runs { get; init; } = [];
}
