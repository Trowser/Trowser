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
        string? expect)
    {
        runs = Math.Clamp(runs, 1, 20);
        var results = new List<ReproRunResult>();
        var service = new WorkflowVerifyService();

        for (var i = 0; i < runs; i++)
        {
            deps.Cancellation.ThrowIfCancellationRequested();

            if (clearSession)
            {
                try { await deps.Context.ClearSession(); }
                catch (Exception ex)
                {
                    results.Add(new ReproRunResult
                    {
                        Run = i + 1,
                        Passed = false,
                        Error = $"clearSession failed: {ex.Message}"
                    });
                    continue;
                }
            }

            if (!string.IsNullOrWhiteSpace(identity))
            {
                try { await identityStore.ApplyAsync(deps.Context, identity); }
                catch (Exception ex)
                {
                    results.Add(new ReproRunResult
                    {
                        Run = i + 1,
                        Passed = false,
                        Error = $"identity apply failed: {ex.Message}"
                    });
                    continue;
                }
            }

            var run = await service.RunAsync(workflow, deps);
            results.Add(new ReproRunResult
            {
                Run = i + 1,
                Passed = run.Verified,
                Workflow = run,
                Error = run.Error
            });
        }

        var passed = results.Count(r => r.Passed);
        var failed = results.Count - passed;
        var verdict = Classify(passed, results.Count);
        var expected = ParseExpect(expect);
        if (expected != null && expected != verdict)
            verdict = ReproVerdict.Inconclusive;

        return new ReproVerifyResult
        {
            Verdict = verdict,
            Rate = results.Count == 0 ? 0 : (double)passed / results.Count,
            Passed = passed,
            Failed = failed,
            Runs = results
        };
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
    public string? Error { get; init; }
}

public sealed class ReproVerifyResult
{
    public ReproVerdict Verdict { get; init; }
    public double Rate { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public List<ReproRunResult> Runs { get; init; } = [];
}
