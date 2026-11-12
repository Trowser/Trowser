using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace Trowser.Security.Workflow;

public sealed class WorkflowVerifyService
{
    private readonly WorkflowStepExecutor _steps = new();
    private readonly WorkflowOracleEvaluator _oracle = new();

    public async Task<WorkflowVerifyResult> RunAsync(JsonElement body, WorkflowDependencies deps)
    {
        var sw = Stopwatch.StartNew();
        var ctx = new WorkflowExecutionContext
        {
            WorkflowId = body.TryGetProperty("workflowId", out var wid) ? wid.GetString() : Guid.NewGuid().ToString("N")[..12],
            WorkflowName = body.TryGetProperty("name", out var n) ? n.GetString() : null
        };

        if (body.TryGetProperty("markers", out var markersEl) && markersEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in markersEl.EnumerateObject())
                ctx.Markers[p.Name] = WorkflowVarSubstitution.Substitute(p.Value.GetString(), ctx.Vars);
        }

        var exportEvidence = body.TryGetProperty("exportEvidence", out var ee) && ee.ValueKind == JsonValueKind.True;

        // setup
        var setupOk = await RunPhaseAsync(body, "setup", ctx, deps);
        if (!setupOk)
        {
            sw.Stop();
            return FailResult(ctx, sw.ElapsedMilliseconds, "setup");
        }

        // trigger prep
        ctx.NetworkMarkerIndex = deps.Context.GetNetworkLog().Count;
        ctx.RefGenerationBeforeTrigger = deps.Context.RefGeneration;
        // Watermark runtime sensor events for sinkReached / messageDelivered oracles.
        deps.Context.ActiveTab.RuntimeEvents.Mark();

        var triggerOk = await RunPhaseAsync(body, "trigger", ctx, deps);
        if (!triggerOk)
        {
            sw.Stop();
            return FailResult(ctx, sw.ElapsedMilliseconds, "trigger");
        }

        if (body.TryGetProperty("oracle", out var oraclePrep) && oraclePrep.ValueKind == JsonValueKind.Object)
        {
            var waitMs = body.TryGetProperty("waitAfterTriggerMs", out var wEl) && wEl.ValueKind == JsonValueKind.Number
                ? Math.Clamp(wEl.GetInt32(), 0, 30_000) : 0;
            if (waitMs > 0)
                await Task.Delay(waitMs, deps.Cancellation);
            else if (OracleUsesEffectCheck(oraclePrep))
            {
                var idleTimeout = body.TryGetProperty("waitForIdleTimeoutMs", out var idleEl) && idleEl.ValueKind == JsonValueKind.Number
                    ? idleEl.GetInt32() : 10_000;
                await deps.Context.WaitForIdle(timeoutMs: idleTimeout);
            }
        }

        OracleCheckResult? oracleResult = null;
        if (body.TryGetProperty("oracle", out var oracleEl) && oracleEl.ValueKind == JsonValueKind.Object)
            oracleResult = await _oracle.EvaluateAsync(oracleEl, ctx, deps);
        else
            oracleResult = new OracleCheckResult { Type = "none", Passed = false, Error = "Missing oracle." };

        var cleanupOk = true;
        if (body.TryGetProperty("cleanup", out var cleanupEl) && cleanupEl.ValueKind == JsonValueKind.Array)
            cleanupOk = await RunPhaseAsync(body, "cleanup", ctx, deps);

        sw.Stop();
        var verified = setupOk && triggerOk && oracleResult.Passed && cleanupOk;

        string? failurePhase = null;
        if (!verified)
        {
            if (!setupOk) failurePhase = "setup";
            else if (!triggerOk) failurePhase = "trigger";
            else if (!oracleResult.Passed) failurePhase = "oracle";
            else if (!cleanupOk) failurePhase = "cleanup";
        }

        var result = new WorkflowVerifyResult
        {
            Name = ctx.WorkflowName,
            WorkflowId = ctx.WorkflowId,
            Verified = verified,
            SetupOk = setupOk,
            TriggerOk = triggerOk,
            OraclePassed = oracleResult.Passed,
            CleanupOk = cleanupOk,
            FailurePhase = failurePhase,
            Oracle = oracleResult,
            Setup = ctx.SetupResults,
            Trigger = ctx.TriggerResults,
            Cleanup = ctx.CleanupResults,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            EvidenceBundlePath = exportEvidence ? EvidenceExportService.ExportBundle(body, verified, oracleResult, ctx, deps) : null,
            CapturedVars = ctx.Vars.Count > 0 ? new Dictionary<string, string>(ctx.Vars) : null,
            StepErrors = CollectStepErrors(ctx, oracleResult, verified)
        };

        return result;
    }

    private static bool OracleUsesEffectCheck(JsonElement oracle)
    {
        if (oracle.TryGetProperty("type", out var typeEl))
        {
            var type = typeEl.GetString()?.ToLowerInvariant();
            if (type is "effectcheck" or "effect-check" or "expression")
                return oracle.TryGetProperty("effectCheck", out _);
            if (type is "and" or "or")
            {
                if (oracle.TryGetProperty("checks", out var checks) && checks.ValueKind == JsonValueKind.Array)
                {
                    foreach (var check in checks.EnumerateArray())
                    {
                        if (OracleUsesEffectCheck(check)) return true;
                    }
                }
                return false;
            }
        }

        return oracle.TryGetProperty("effectCheck", out _);
    }

    /// <summary>Compile legacy single-shot verify into a minimal verify-workflow.</summary>
    public static JsonElement CompileLegacyVerify(JsonElement legacyBody)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("safetyMode", "active");
            writer.WritePropertyName("trigger");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteString("type", "inject");
            foreach (var prop in legacyBody.EnumerateObject())
            {
                if (prop.NameEquals("confirmBackend") || prop.NameEquals("safetyMode")) continue;
                writer.WritePropertyName(prop.Name);
                prop.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WritePropertyName("oracle");
            writer.WriteStartObject();
            writer.WriteString("type", "effectCheck");
            if (legacyBody.TryGetProperty("effectCheck", out var ec))
            {
                writer.WritePropertyName("effectCheck");
                ec.WriteTo(writer);
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        using var doc = JsonDocument.Parse(stream.ToArray());
        return doc.RootElement.Clone();
    }

    private async Task<bool> RunPhaseAsync(JsonElement body, string phase, WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        if (!body.TryGetProperty(phase, out var stepsEl) || stepsEl.ValueKind != JsonValueKind.Array)
            return true;

        var list = phase switch
        {
            "setup" => ctx.SetupResults,
            "trigger" => ctx.TriggerResults,
            "cleanup" => ctx.CleanupResults,
            _ => ctx.SetupResults
        };

        var i = 0;
        foreach (var step in stepsEl.EnumerateArray())
        {
            var result = await _steps.ExecuteAsync(step, i, phase, ctx, deps);
            list.Add(result);
            if (result.TryGetValue("success", out var ok) && ok is false)
                return false;
            i++;
        }
        return true;
    }

    private static WorkflowVerifyResult FailResult(WorkflowExecutionContext ctx, long elapsedMs, string phase)
    {
        var stepErrors = CollectStepErrors(ctx, null, false);
        var firstError = stepErrors.FirstOrDefault();
        string? detail = null;
        if (firstError != null)
        {
            try { detail = JsonSerializer.Serialize(firstError); }
            catch { /* ignore */ }
        }

        return new WorkflowVerifyResult
        {
            Name = ctx.WorkflowName,
            WorkflowId = ctx.WorkflowId,
            Verified = false,
            FailurePhase = phase,
            Error = detail ?? $"{phase} phase failed.",
            Setup = ctx.SetupResults,
            Trigger = ctx.TriggerResults,
            Cleanup = ctx.CleanupResults,
            ElapsedMs = (int)elapsedMs,
            CapturedVars = ctx.Vars.Count > 0 ? new Dictionary<string, string>(ctx.Vars) : null,
            StepErrors = stepErrors
        };
    }

    private static List<object> CollectStepErrors(WorkflowExecutionContext ctx, OracleCheckResult? oracle, bool verified)
    {
        var errors = new List<object>();
        foreach (var (phase, list) in new[] { ("setup", ctx.SetupResults), ("trigger", ctx.TriggerResults), ("cleanup", ctx.CleanupResults) })
        {
            foreach (var step in list)
            {
                if (step.TryGetValue("success", out var ok) && ok is false)
                    errors.Add(new { phase, step });
            }
        }
        if (!verified && oracle != null && !oracle.Passed)
            errors.Add(new { phase = "oracle", type = oracle.Type, error = oracle.Error, evidence = oracle.Evidence });
        return errors;
    }
}
