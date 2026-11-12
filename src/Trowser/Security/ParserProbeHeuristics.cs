using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Differential response heuristics for parser-probe content-type and body-shape tests.
/// </summary>
public static class ParserProbeHeuristics
{
    private static readonly string[] StackTraceIndicators =
    [
        "at java.", "at org.", "at com.", "at sun.", "at javax.",
        "Exception in thread", "Stack trace:", "Traceback (most recent call last)",
        "System.NullReferenceException", "System.InvalidOperationException",
        "org.springframework", "org.apache", "Caused by:", "PHP Fatal error",
        "PHP Warning", "Uncaught Error", "SyntaxError:", "JsonParseException",
        "com.fasterxml.jackson", "Unexpected token", "Cannot deserialize"
    ];

    private static readonly string[] PrivilegedFieldPatterns =
    [
        "\"isAdmin\"", "\"is_admin\"", "\"role\"", "\"roles\"", "\"permissions\"",
        "\"privilege\"", "\"admin\"", "\"superuser\"", "\"accessLevel\"", "\"access_level\"",
        "\"isSuperUser\"", "\"is_superuser\"", "\"authority\"", "\"authorities\""
    ];

    public sealed class HeuristicMatch
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Signal { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public static HeuristicMatch? Evaluate(
        int baselineStatus,
        string baselineBody,
        int probeStatus,
        string probeBody,
        string probeKind,
        string? contentType = null,
        string? bodyVariant = null)
    {
        var baseBody = baselineBody ?? "";
        var probeText = probeBody ?? "";

        if (baselineStatus == 415 && probeStatus is >= 200 and < 300 or >= 500)
        {
            return new HeuristicMatch
            {
                Category = "content-type-confusion",
                Severity = "low",
                Signal = "415-bypass",
                Detail = BuildDetail(probeKind, contentType, bodyVariant,
                    $"Baseline rejected with 415; alternate parser returned HTTP {probeStatus}.")
            };
        }

        if (probeStatus is >= 200 and < 300 && HasPrivilegedField(probeText) && !HasPrivilegedField(baseBody))
        {
            return new HeuristicMatch
            {
                Category = "deserialization-suspected",
                Severity = "high",
                Signal = "privileged-field-in-response",
                Detail = BuildDetail(probeKind, contentType, bodyVariant,
                    "Alternate parser response contains privileged-looking fields not present in baseline.")
            };
        }

        // Anonymous 401/403 vs 400 validation errors are not parser differentials.
        if (baselineStatus is 401 or 403 && probeStatus is not (>= 200 and < 300))
            return null;

        if (HasStackTrace(probeText) && !HasStackTrace(baseBody))
        {
            return new HeuristicMatch
            {
                Category = probeKind.Contains("content-type", StringComparison.OrdinalIgnoreCase)
                    ? "content-type-confusion" : "parser-differential",
                // Info-leak / parser behavior — keep below medium so chains do not over-promote.
                Severity = "low",
                Signal = "stack-trace-on-alternate-parser",
                Detail = BuildDetail(probeKind, contentType, bodyVariant,
                    $"HTTP {probeStatus} with stack trace; baseline HTTP {baselineStatus} had none.")
            };
        }

        if (probeStatus == baselineStatus && BodyDiffSignificant(baseBody, probeText))
        {
            return new HeuristicMatch
            {
                Category = "parser-differential",
                Severity = "low",
                Signal = "body-diff-same-status",
                Detail = BuildDetail(probeKind, contentType, bodyVariant,
                    $"Same HTTP {probeStatus} but response body differs significantly from baseline.")
            };
        }

        if (probeStatus >= 500 && baselineStatus < 500)
        {
            return new HeuristicMatch
            {
                Category = probeKind.Contains("content-type", StringComparison.OrdinalIgnoreCase)
                    ? "content-type-confusion" : "parser-differential",
                Severity = "low",
                Signal = "server-error-on-alternate-parser",
                Detail = BuildDetail(probeKind, contentType, bodyVariant,
                    $"Alternate parser triggered HTTP {probeStatus}; baseline was HTTP {baselineStatus}.")
            };
        }

        return null;
    }

    public static bool HasStackTrace(string text) =>
        StackTraceHeuristics.HasStackTrace(text)
        || StackTraceIndicators.Any(sig => text.Contains(sig, StringComparison.OrdinalIgnoreCase));

    public static bool HasPrivilegedField(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return PrivilegedFieldPatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    public static bool BodyDiffSignificant(string baseline, string probe, int minDelta = 80)
    {
        if (string.IsNullOrEmpty(baseline) && string.IsNullOrEmpty(probe)) return false;
        if (string.IsNullOrEmpty(baseline) || string.IsNullOrEmpty(probe)) return true;
        if (Math.Abs(baseline.Length - probe.Length) >= minDelta) return true;

        var normBase = NormalizeForDiff(baseline);
        var normProbe = NormalizeForDiff(probe);
        if (normBase == normProbe) return false;

        var maxLen = Math.Max(normBase.Length, normProbe.Length);
        if (maxLen == 0) return false;
        var common = 0;
        var limit = Math.Min(normBase.Length, normProbe.Length);
        for (var i = 0; i < limit; i++)
        {
            if (normBase[i] == normProbe[i]) common++;
        }
        var similarity = (double)common / maxLen;
        return similarity < 0.85;
    }

    private static string NormalizeForDiff(string text) =>
        Regex.Replace(text.Replace("\r", "").Replace("\n", " ").Trim(), @"\s+", " ");

    private static string BuildDetail(string probeKind, string? contentType, string? bodyVariant, string message)
    {
        var parts = new List<string> { message };
        if (!string.IsNullOrEmpty(contentType)) parts.Add($"Content-Type: {contentType}");
        if (!string.IsNullOrEmpty(bodyVariant)) parts.Add($"Body variant: {bodyVariant}");
        parts.Add($"Probe: {probeKind}");
        return string.Join(" ", parts);
    }
}
