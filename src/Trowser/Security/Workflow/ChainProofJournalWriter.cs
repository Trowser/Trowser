using Trowser.Security.ChainEngine;
using Trowser.SessionLog;

namespace Trowser.Security.Workflow;

/// <summary>
/// Writes chain proof outcomes into the session journal for the discover → prove → export loop.
/// </summary>
public static class ChainProofJournalWriter
{
    public static void RecordChainProof(SessionLogger? logger, ChainProofResult result, string? patternName = null)
    {
        if (logger == null) return;

        var label = patternName ?? result.PatternId;
        var shortReason = Truncate(result.FailureReason, 180);
        var summary = result.Proven
            ? $"Chain proof VERIFIED: {label}"
            : shortReason != null
                ? $"Chain proof failed: {label} — {shortReason}"
                : $"Chain proof failed: {label} — oracle did not pass";

        var fields = new Dictionary<string, string>
        {
            ["patternId"] = result.PatternId,
            ["proven"] = result.Proven.ToString(),
            ["workflowId"] = result.WorkflowId ?? "",
            ["elapsedMs"] = result.ElapsedMs.ToString(),
            ["category"] = MapPatternCategory(result.PatternId),
            ["outcome"] = result.Proven ? "verified" : "not-verified"
        };
        if (!string.IsNullOrEmpty(result.EvidenceBundlePath))
            fields["bundlePath"] = result.EvidenceBundlePath;
        if (!string.IsNullOrEmpty(result.FailureReason))
            fields["failureReason"] = Truncate(result.FailureReason, 2000) ?? result.FailureReason;
        if (!string.IsNullOrEmpty(result.OracleType))
            fields["oracleType"] = result.OracleType;

        var tags = new List<string>
        {
            "chain-prove",
            result.Proven ? "verified" : "not-verified",
            result.PatternId
        };
        if (!string.IsNullOrEmpty(result.EvidenceBundlePath))
            tags.Add("evidence-export");

        logger.LogLlmNote(
            summary,
            result.Proven ? "info" : "high",
            NoteKinds.Observation,
            fields,
            tags);
    }

    private static string MapPatternCategory(string patternId) => patternId.ToLowerInvariant() switch
    {
        "jwt-algorithm-confusion" => "jwt-acceptance",
        "jwt-alg-none-acceptance" or "jwt-alg-variant-acceptance" => "jwt-acceptance",
        _ when patternId.StartsWith("jwt-", StringComparison.OrdinalIgnoreCase) => "jwt-acceptance",
        _ => "other"
    };

    private static string? Truncate(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return null;
        return text.Length <= maxLength ? text : text[..maxLength] + "…";
    }

    public static void RecordEvidenceExport(SessionLogger? logger, string bundlePath, bool verified, string? patternId = null)
    {
        if (logger == null) return;

        var summary = verified
            ? $"Evidence bundle exported (VERIFIED): {bundlePath}"
            : $"Evidence bundle exported (NOT_VERIFIED): {bundlePath}";

        var fields = new Dictionary<string, string> { ["bundlePath"] = bundlePath, ["verdict"] = verified ? "VERIFIED" : "NOT_VERIFIED" };
        if (!string.IsNullOrEmpty(patternId))
            fields["patternId"] = patternId;

        var tags = new List<string> { "evidence-export", verified ? "verified" : "not-verified" };
        if (!string.IsNullOrEmpty(patternId))
            tags.Add(patternId);

        logger.LogLlmNote(summary, "info", NoteKinds.Observation, fields, tags);
    }
}
