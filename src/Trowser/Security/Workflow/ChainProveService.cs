using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Workflow;

public sealed class ChainProveService
{
    private static readonly JsonSerializerOptions EvidenceJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly WorkflowVerifyService _workflow = new();

    public async Task<ChainProofResult> ProveAsync(
        string patternId,
        IReadOnlyList<ChainableFinding> findings,
        WorkflowDependencies deps,
        bool exportEvidence = false,
        ChainPattern? pattern = null,
        IReadOnlyDictionary<string, string>? substitutionOverrides = null)
    {
        var sw = Stopwatch.StartNew();
        var templateId = pattern != null
            ? ChainProvabilityHelper.ResolveTemplateId(pattern)
            : ProofTemplateCatalog.HasTemplate(patternId) ? patternId : null;

        if (templateId == null && !string.IsNullOrEmpty(pattern?.ProofTemplateId))
            templateId = ProofTemplateCatalog.HasTemplate(pattern.ProofTemplateId) ? pattern.ProofTemplateId : null;

        var template = templateId != null ? ProofTemplateCatalog.GetTemplate(templateId) : null;
        if (template == null)
        {
            var msg = $"No proof template for pattern '{patternId}'.";
            return new ChainProofResult
            {
                PatternId = patternId,
                Proven = false,
                FailureSummary = msg,
                FailureReason = msg,
                FailurePhase = "template",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        if (pattern != null)
        {
            var missing = ChainProvabilityHelper.GetMissingIdentities(pattern, deps.IdentityStore);
            if (missing.Count > 0)
            {
                var msg =
                    $"Missing identity snapshots: {string.Join(", ", missing)}. Capture via POST /api/identity/capture or handoff.";
                return new ChainProofResult
                {
                    PatternId = patternId,
                    Proven = false,
                    FailureSummary = msg,
                    FailureReason = msg,
                    FailurePhase = "identities",
                    TemplateExpanded = template.Value.GetRawText(),
                    ElapsedMs = (int)sw.ElapsedMilliseconds
                };
            }
        }

        var currentUrl = await deps.Context.GetCurrentUrl();
        var substitutions = ProofTemplateCatalog.BuildSubstitutionVars(findings, currentUrl);

        if (templateId is "jwt-algorithm-confusion" or "jwt-alg-none-acceptance" or "jwt-alg-variant-acceptance")
        {
            var jwtExtra = await JwtAlgorithmConfusionHelper.EnrichSubstitutionsAsync(
                deps.Context, findings, substitutions);
            foreach (var kv in jwtExtra)
            {
                if (!string.IsNullOrWhiteSpace(kv.Value))
                    substitutions[kv.Key] = kv.Value;
            }
        }
        if (substitutionOverrides != null)
        {
            foreach (var kv in substitutionOverrides)
            {
                if (string.IsNullOrWhiteSpace(kv.Value)) continue;
                substitutions[kv.Key] = kv.Value;
                if (kv.Key.Equals("endpoint", StringComparison.OrdinalIgnoreCase))
                    substitutions["endpoint"] = kv.Value;
                if (kv.Key.Equals("sensitiveEndpoint", StringComparison.OrdinalIgnoreCase))
                {
                    substitutions["sensitiveEndpoint"] = kv.Value;
                    substitutions["endpoint1"] = kv.Value;
                }
                if (kv.Key.Equals("corsEndpoint", StringComparison.OrdinalIgnoreCase))
                    substitutions["endpoint1"] = kv.Value;
            }
        }

        if (!substitutions.TryGetValue("endpoint", out var endpoint) || string.IsNullOrWhiteSpace(endpoint))
        {
            var templateRaw = template.Value.GetRawText();
            var requiresEndpoint = templateRaw.Contains("{{endpoint}}", StringComparison.OrdinalIgnoreCase);
            if (requiresEndpoint)
            {
                const string msg =
                    "Cannot prove chain: no {{endpoint}} available from matched findings or current page URL.";
                return new ChainProofResult
                {
                    PatternId = patternId,
                    Proven = false,
                    FailureSummary = msg,
                    FailureReason = msg,
                    FailurePhase = "substitution",
                    AttemptedSubstitutions = substitutions,
                    TemplateExpanded = templateRaw,
                    ElapsedMs = (int)sw.ElapsedMilliseconds
                };
            }
        }

        var unresolved = WorkflowVarSubstitution.FindUnresolvedStaticPlaceholders(template.Value.GetRawText(), substitutions);
        if (unresolved.Count > 0)
        {
            var msg = $"Template substitution incomplete for: {string.Join(", ", unresolved)}";
            return new ChainProofResult
            {
                PatternId = patternId,
                Proven = false,
                FailureSummary = msg,
                FailureReason = msg,
                FailurePhase = "substitution",
                AttemptedSubstitutions = substitutions,
                TemplateExpanded = template.Value.GetRawText(),
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var workflow = ProofTemplateCatalog.SubstituteTemplate(template.Value, substitutions);
        var templateExpanded = workflow.GetRawText();

        if (exportEvidence && workflow.ValueKind == JsonValueKind.Object)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in workflow.EnumerateObject())
                {
                    if (prop.NameEquals("exportEvidence")) continue;
                    writer.WritePropertyName(prop.Name);
                    prop.Value.WriteTo(writer);
                }
                writer.WriteBoolean("exportEvidence", true);
                writer.WriteEndObject();
            }
            using var doc = JsonDocument.Parse(stream.ToArray());
            workflow = doc.RootElement.Clone();
            templateExpanded = workflow.GetRawText();
        }

        var result = await _workflow.RunAsync(workflow, deps);
        sw.Stop();

        var stepErrors = CollectStepErrors(result);
        var steps = BuildStepResults(result);
        var failureDetail = BuildFailureDetail(result, stepErrors);

        if (exportEvidence && !string.IsNullOrEmpty(result.EvidenceBundlePath) && pattern != null)
        {
            EvidenceExportService.EnrichBundleWithChainContext(
                result.EvidenceBundlePath,
                pattern,
                findings,
                result.Verified);
        }

        var failureSummary = result.Verified
            ? null
            : BuildFailureSummary(result, stepErrors);

        return new ChainProofResult
        {
            PatternId = patternId,
            Proven = result.Verified,
            Steps = steps,
            FailureSummary = failureSummary,
            FailureReason = result.Verified
                ? null
                : failureDetail ?? result.Error ?? result.Oracle?.Error ?? "Proof failed",
            FailurePhase = result.FailurePhase ?? (result.Verified ? null : result.OraclePassed ? "workflow" : "oracle"),
            FailureDetail = failureDetail,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            WorkflowId = result.WorkflowId,
            EvidenceBundlePath = result.EvidenceBundlePath,
            OracleType = result.Oracle?.Type,
            OracleEvidence = result.Oracle?.Evidence,
            TemplateExpanded = templateExpanded,
            AttemptedSubstitutions = substitutions,
            StepErrors = stepErrors
        };
    }

    /// <summary>Short one-liner for agents — never the full serialized stepErrors blob.</summary>
    private static string BuildFailureSummary(WorkflowVerifyResult result, List<object> stepErrors)
    {
        if (!string.IsNullOrWhiteSpace(result.Oracle?.Error))
            return $"Oracle ({result.Oracle.Type}) failed: {result.Oracle.Error}";
        if (!string.IsNullOrWhiteSpace(result.Error))
            return result.Error!;
        if (stepErrors.Count > 0)
        {
            // Prefer first oracle/step error string if present on the anonymous object.
            foreach (var err in stepErrors)
            {
                try
                {
                    var json = JsonSerializer.Serialize(err);
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("error", out var e)
                        && e.ValueKind == JsonValueKind.String
                        && !string.IsNullOrWhiteSpace(e.GetString()))
                    {
                        var phase = doc.RootElement.TryGetProperty("phase", out var p)
                            ? p.GetString()
                            : "step";
                        return $"{phase}: {e.GetString()}";
                    }
                }
                catch
                {
                    /* fall through */
                }
            }
            return $"{stepErrors.Count} step error(s) — see stepErrors / failureReason for detail.";
        }

        return "Proof failed";
    }

    public static bool IsProvable(ChainPattern pattern, IdentityStore identityStore) =>
        ChainProvabilityHelper.IsProvable(pattern, identityStore);

    public static bool IsProvable(string patternId, IdentityStore identityStore, IEnumerable<string>? requiredIdentities = null)
    {
        if (!ProofTemplateCatalog.HasTemplate(patternId)) return false;
        if (requiredIdentities == null) return true;
        foreach (var name in requiredIdentities)
        {
            if (!IdentityStore.IsValidName(name)) continue;
            if (identityStore.Load(name) == null) return false;
        }
        return true;
    }

    private static List<ChainStepResult> BuildStepResults(WorkflowVerifyResult result)
    {
        var steps = new List<ChainStepResult>();
        var idx = 0;
        foreach (var s in result.Setup)
            steps.Add(ToStepResult(idx++, "setup", s));
        foreach (var s in result.Trigger)
            steps.Add(ToStepResult(idx++, "trigger", s));
        steps.Add(new ChainStepResult
        {
            StepIndex = idx++,
            Description = "oracle",
            Succeeded = result.OraclePassed,
            Evidence = SerializeEvidence(result.Oracle?.Evidence),
            Error = result.Oracle?.Error
        });
        foreach (var s in result.Cleanup)
            steps.Add(ToStepResult(idx++, "cleanup", s));
        return steps;
    }

    private static List<object> CollectStepErrors(WorkflowVerifyResult result)
    {
        var errors = new List<object>();
        foreach (var (phase, list) in new[] { ("setup", result.Setup), ("trigger", result.Trigger), ("cleanup", result.Cleanup) })
        {
            foreach (var step in list)
            {
                if (step.TryGetValue("success", out var ok) && ok is false)
                {
                    errors.Add(new
                    {
                        phase,
                        index = step.GetValueOrDefault("index"),
                        type = step.GetValueOrDefault("type"),
                        error = step.GetValueOrDefault("error"),
                        renderUrl = step.GetValueOrDefault("renderUrl"),
                        resolvedRenderUrl = step.GetValueOrDefault("resolvedRenderUrl"),
                        step
                    });
                }
            }
        }
        if (!result.OraclePassed && result.Oracle != null)
            errors.Add(new { phase = "oracle", type = result.Oracle.Type, error = result.Oracle.Error, evidence = result.Oracle.Evidence });
        return errors;
    }

    private static string? BuildFailureDetail(WorkflowVerifyResult result, List<object> stepErrors)
    {
        if (result.Verified) return null;
        if (stepErrors.Count == 0)
            return result.Error ?? result.Oracle?.Error;

        try
        {
            return JsonSerializer.Serialize(stepErrors, new JsonSerializerOptions { WriteIndented = false });
        }
        catch
        {
            return result.Error;
        }
    }

    private static string? SerializeEvidence(object? evidence)
    {
        if (evidence == null) return null;
        try
        {
            return JsonSerializer.Serialize(evidence, EvidenceJson);
        }
        catch
        {
            return JsonSerializer.Serialize(new { error = "Evidence serialization failed" }, EvidenceJson);
        }
    }

    private static ChainStepResult ToStepResult(int index, string phase, Dictionary<string, object?> step) =>
        new()
        {
            StepIndex = index,
            Description = $"{phase}:{step.GetValueOrDefault("type")}",
            Succeeded = step.TryGetValue("success", out var ok) && ok is true,
            Error = step.TryGetValue("error", out var err) ? err?.ToString() : null,
            Evidence = step.TryGetValue("resolvedRenderUrl", out var url) ? url?.ToString()
                : step.TryGetValue("error", out var e) ? e?.ToString() : null,
            Step = step
        };
}
