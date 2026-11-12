using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>Regex patterns for secrets in streaming payloads (WebSocket frames, SSE event data).</summary>
public static class StreamSensitiveDataPatterns
{
    public static readonly (string Name, string Pattern, string Severity)[] Patterns =
    [
        ("Email address", @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "medium"),
        ("JWT token", @"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.", "high"),
        ("API key pattern", @"(?:api[_-]?key|apikey|api_secret)[""'\s:=]+[A-Za-z0-9_\-]{16,}", "high"),
        ("Password field", @"""(?:password|passwd|pwd|secret|credential)"":\s*""[^""]+""", "critical"),
        ("Bearer token", @"Bearer\s+[A-Za-z0-9_\-\.]{20,}", "high"),
        ("Credit card pattern", @"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "critical"),
        ("SSN pattern", @"\b\d{3}-\d{2}-\d{4}\b", "critical"),
        ("Internal IP", @"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "low"),
    ];

    public static string MaskSensitive(string value)
    {
        if (value.Length <= 8) return "***";
        return value[..4] + "…" + value[^4..];
    }

    public static IEnumerable<(string Name, string Severity, string Match)> ScanSample(string text, int maxMatchesPerPattern = 1)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (var (name, pattern, severity) in Patterns)
        {
            var count = 0;
            foreach (Match m in Regex.Matches(text, pattern, RegexOptions.IgnoreCase))
            {
                yield return (name, severity, m.Value);
                if (++count >= maxMatchesPerPattern) break;
            }
        }
    }
}
