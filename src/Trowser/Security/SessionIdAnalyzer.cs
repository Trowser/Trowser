using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Analyzes session identifier cookies for weak entropy, predictable patterns,
/// and common weak generation schemes (sequential, timestamp, MD5-of-counter).
/// </summary>
public class SessionIdAnalyzer
{
    public SessionIdAnalysisResult Analyze(
        string url,
        IReadOnlyList<Dictionary<string, object>> cookies,
        IReadOnlyList<string> historicalValues,
        int minSamplesForPattern = 2,
        string? targetCookieName = null,
        IReadOnlyDictionary<string, IReadOnlyList<string>>? historicalByCookieName = null,
        IReadOnlyList<string>? knownDisplayValues = null)
    {
        var sessionCookies = cookies
            .Where(c =>
            {
                var name = GetStr(c, "name");
                if (!string.IsNullOrWhiteSpace(targetCookieName))
                    return name.Equals(targetCookieName, StringComparison.OrdinalIgnoreCase);
                return SessionCookieDetector.IsSessionCookieName(name);
            })
            .ToList();

        if (sessionCookies.Count == 0 && !string.IsNullOrWhiteSpace(targetCookieName) && historicalValues.Count > 0)
        {
            sessionCookies.Add(new Dictionary<string, object>
            {
                ["name"] = targetCookieName,
                ["value"] = historicalValues[0]
            });
        }

        var findings = new List<SessionIdFinding>();
        var analyzed = new List<SessionIdSample>();

        foreach (var cookie in sessionCookies)
        {
            var name = GetStr(cookie, "name");
            var current = GetStr(cookie, "value");
            var samples = new List<string>();
            if (!string.IsNullOrEmpty(current))
                samples.Add(current);

            IReadOnlyList<string> cookieHistorical;
            if (historicalByCookieName != null
                && historicalByCookieName.TryGetValue(name, out var perCookie))
            {
                cookieHistorical = perCookie;
            }
            else if (!string.IsNullOrWhiteSpace(targetCookieName)
                     && name.Equals(targetCookieName, StringComparison.OrdinalIgnoreCase))
            {
                cookieHistorical = historicalValues;
            }
            else
            {
                cookieHistorical = [];
            }

            samples.AddRange(cookieHistorical.Where(v => !string.IsNullOrEmpty(v)));
            samples = samples.Distinct(StringComparer.Ordinal).ToList();

            var sampleAnalysis = AnalyzeSamples(samples, minSamplesForPattern, knownDisplayValues);
            analyzed.Add(new SessionIdSample
            {
                CookieName = name,
                CurrentValue = MaskValue(current),
                SampleCount = samples.Count,
                EntropyBitsPerChar = sampleAnalysis.EntropyBitsPerChar,
                EntropyAssessment = sampleAnalysis.EntropyAssessment,
                Patterns = sampleAnalysis.Patterns.Select(p => p.Category).Distinct().ToList()
            });

            foreach (var pattern in sampleAnalysis.Patterns)
            {
                findings.Add(new SessionIdFinding
                {
                    CookieName = name,
                    Severity = pattern.Severity,
                    Category = pattern.Category,
                    Description = pattern.Description,
                    Recommendation = pattern.Recommendation
                });
            }

            if (samples.Count < minSamplesForPattern && samples.Count > 0)
            {
                findings.Add(new SessionIdFinding
                {
                    CookieName = name,
                    Severity = Severity.Low,
                    Category = "InsufficientSamples",
                    Description = $"Only {samples.Count} distinct session value(s) available. Collect more samples (e.g. logout/login cycles) for reliable predictability analysis.",
                    Recommendation = samples.Count == 1 && cookieHistorical.Count == 0
                        ? "Jar holds a current value but no Set-Cookie history — collect samples via repeated login/logout or pass samples[] in the API."
                        : "Re-run after capturing multiple Set-Cookie values in the network log, or pass additional values via the API."
                });
            }
        }

        if (sessionCookies.Count == 0)
        {
            findings.Add(new SessionIdFinding
            {
                CookieName = targetCookieName ?? "",
                Severity = Severity.Low,
                Category = "NoSessionCookie",
                Description = string.IsNullOrWhiteSpace(targetCookieName)
                    ? "No session-like cookie detected on the current page."
                    : $"Cookie '{targetCookieName}' not found in the jar and no samples were provided.",
                Recommendation = "Browse through login first, or specify cookieName in the request body."
            });
        }

        return new SessionIdAnalysisResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Samples = analyzed,
            Findings = findings
        };
    }

    /// <summary>Collect distinct session cookie values from Set-Cookie headers in the network log.</summary>
    public static List<string> CollectHistoricalValuesFromNetwork(
        IEnumerable<Automation.NetworkEntry> entries,
        string cookieName)
    {
        var values = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in entries)
        {
            if (entry.ResponseHeaders == null)
                continue;

            foreach (var h in entry.ResponseHeaders.Where(h =>
                         h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)))
            {
                foreach (var parsed in SetCookieHeaderParser.ParseHeaderValue(h.Value))
                {
                    var n = parsed["name"]?.ToString() ?? "";
                    if (!n.Equals(cookieName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    var v = parsed["value"]?.ToString();
                    if (!string.IsNullOrEmpty(v))
                        values.Add(v);
                }
            }
        }

        return values.ToList();
    }

    private static SampleAnalysis AnalyzeSamples(
        List<string> samples,
        int minSamples,
        IReadOnlyList<string>? knownDisplayValues)
    {
        var patterns = new List<DetectedPattern>();
        if (samples.Count == 0)
            return new SampleAnalysis(0, "unknown", patterns);

        if (samples.All(s => IsDisplayIdentifier(s, knownDisplayValues)))
        {
            patterns.Add(new DetectedPattern
            {
                Category = "display-identifier",
                Severity = Severity.Info,
                Description = "Cookie value matches a display/login identifier (username), not an opaque server-issued secret.",
                Recommendation = "No session entropy check needed for display-only identifiers."
            });
            return new SampleAnalysis(0, "n/a-display", patterns);
        }

        var opaqueSamples = samples.Where(s => !IsDisplayIdentifier(s, knownDisplayValues)).ToList();
        if (opaqueSamples.Count == 0)
            opaqueSamples = samples;

        var entropy = EstimateEntropy(opaqueSamples);
        var assessment = entropy switch
        {
            >= 4.0 => "strong",
            >= 3.0 => "moderate",
            >= 2.0 => "weak",
            _ => "very-weak"
        };

        if (entropy < 3.0)
        {
            patterns.Add(new DetectedPattern
            {
                Category = "LowEntropy",
                Severity = entropy < 2.0 ? Severity.High : Severity.Medium,
                Description = $"Session ID entropy is low (~{entropy:F2} bits/char). Values may be guessable.",
                Recommendation = "Use a CSPRNG (e.g. 128+ bits of randomness) for session identifiers."
            });
        }

        if (opaqueSamples.Count >= minSamples)
        {
            if (TryDetectSequential(opaqueSamples, out var seqDetail))
            {
                patterns.Add(new DetectedPattern
                {
                    Category = "Sequential",
                    Severity = Severity.Critical,
                    Description = $"Session IDs appear sequential: {seqDetail}",
                    Recommendation = "Replace sequential generators with cryptographically secure random tokens."
                });
            }

            if (TryDetectTimestamp(opaqueSamples, out var tsDetail))
            {
                patterns.Add(new DetectedPattern
                {
                    Category = "TimestampBased",
                    Severity = Severity.High,
                    Description = $"Session ID may embed a timestamp: {tsDetail}",
                    Recommendation = "Do not derive session IDs from timestamps; use opaque random tokens."
                });
            }

            if (TryDetectMd5Sequential(opaqueSamples, out var md5Detail))
            {
                patterns.Add(new DetectedPattern
                {
                    Category = "Md5Sequential",
                    Severity = Severity.High,
                    Description = $"Session ID matches MD5 hash of sequential input: {md5Detail}",
                    Recommendation = "Avoid MD5/SHA1 of counters or timestamps for session IDs."
                });
            }
        }

        foreach (var s in opaqueSamples)
        {
            if (IsDisplayIdentifier(s, knownDisplayValues))
                continue;
            if (!LooksLikeOpaqueToken(s))
                continue;
            if (s.Length < 16 && !Regex.IsMatch(s, @"^[0-9a-f]{32,}$", RegexOptions.IgnoreCase))
            {
                patterns.Add(new DetectedPattern
                {
                    Category = "ShortSessionId",
                    Severity = Severity.Medium,
                    Description = $"Short opaque session token ({s.Length} chars): '{MaskValue(s)}' — small search space.",
                    Recommendation = "Use at least 128 bits of entropy (16+ random bytes, or 22+ base64url chars)."
                });
                break;
            }
        }

        return new SampleAnalysis(entropy, assessment, patterns);
    }

    private static bool IsDisplayIdentifier(string value, IReadOnlyList<string>? knownDisplayValues)
    {
        if (string.IsNullOrEmpty(value)) return false;
        if (knownDisplayValues != null && knownDisplayValues.Any(v =>
                !string.IsNullOrEmpty(v) && value.Equals(v, StringComparison.OrdinalIgnoreCase)))
            return true;
        if (value.Contains(' ') || value.Contains('@'))
            return true;
        return value.Length is >= 3 and <= 64
               && value.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.')
               && value.Any(char.IsLetter)
               && !LooksLikeOpaqueToken(value);
    }

    private static bool LooksLikeOpaqueToken(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        if (Regex.IsMatch(value, @"^[0-9a-f]{32,}$", RegexOptions.IgnoreCase))
            return true;
        if (value.Length >= 20 && value.Any(char.IsDigit) && value.Any(char.IsUpper))
            return true;
        return value.Length >= 22 && value.Count(char.IsLetterOrDigit) >= (int)(value.Length * 0.85);
    }

    private static double EstimateEntropy(IReadOnlyList<string> samples)
    {
        var chars = samples.SelectMany(s => s).ToList();
        if (chars.Count == 0)
            return 0;

        var freq = chars.GroupBy(c => c).ToDictionary(g => g.Key, g => (double)g.Count() / chars.Count);
        return freq.Values.Sum(p => p > 0 ? -p * Math.Log2(p) : 0);
    }

    private static bool TryDetectSequential(List<string> samples, out string detail)
    {
        detail = "";
        var numeric = samples
            .Select(s => Regex.IsMatch(s, @"^\d+$") ? long.TryParse(s, out var n) ? (long?)n : null : null)
            .Where(n => n.HasValue)
            .Select(n => n!.Value)
            .Distinct()
            .OrderBy(n => n)
            .ToList();

        if (numeric.Count >= 2)
        {
            var diffs = numeric.Zip(numeric.Skip(1), (a, b) => b - a).Distinct().ToList();
            if (diffs.Count == 1)
            {
                detail = $"numeric values {numeric.First()}..{numeric.Last()} (step {diffs[0]})";
                return true;
            }
        }

        if (samples.All(s => Regex.IsMatch(s, @"^[0-9a-f]{8,}$", RegexOptions.IgnoreCase)))
        {
            try
            {
                var hex = samples.Select(s => Convert.ToInt64(s, 16)).OrderBy(n => n).ToList();
                if (hex.Count >= 2)
                {
                    var diffs = hex.Zip(hex.Skip(1), (a, b) => b - a).Distinct().ToList();
                    if (diffs.Count == 1)
                    {
                        detail = $"hex values with constant increment {diffs[0]}";
                        return true;
                    }
                }
            }
            catch { /* not hex */ }
        }

        return false;
    }

    private static bool TryDetectTimestamp(List<string> samples, out string detail)
    {
        detail = "";

        foreach (var s in samples)
        {
            if (long.TryParse(s, out var n))
            {
                if (n is >= 1_000_000_000 and <= 2_000_000_000)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds(n);
                    detail = $"value {n} parses as Unix time {dt:u}";
                    return true;
                }
            }

            if (Regex.IsMatch(s, @"^\d{10,13}$") && long.TryParse(s[..10], out var sec) && sec is >= 1_000_000_000 and <= 2_000_000_000)
            {
                detail = $"embedded 10-digit Unix seconds in '{MaskValue(s)}'";
                return true;
            }
        }

        return false;
    }

    private static bool TryDetectMd5Sequential(List<string> samples, out string detail)
    {
        detail = "";
        if (samples.Count < 2)
            return false;

        var lower = samples.Select(s => s.ToLowerInvariant()).ToList();
        for (var i = 0; i <= 10000; i++)
        {
            var md5 = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(i.ToString()))).ToLowerInvariant();
            if (lower.Contains(md5))
            {
                if (i + 1 <= 10000)
                {
                    var md5Next = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes((i + 1).ToString()))).ToLowerInvariant();
                    if (lower.Contains(md5Next))
                    {
                        detail = $"matches MD5('{i}') and MD5('{i + 1}')";
                        return true;
                    }
                }
                detail = $"matches MD5('{i}')";
                return true;
            }
        }

        return false;
    }

    internal static string MaskValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        if (value.Length <= 8)
            return new string('*', value.Length);
        return value[..4] + "…" + value[^4..];
    }

    private static string GetStr(Dictionary<string, object> d, string key) =>
        d.TryGetValue(key, out var v) ? v?.ToString() ?? "" : "";

    private sealed class SampleAnalysis
    {
        public double EntropyBitsPerChar { get; }
        public string EntropyAssessment { get; }
        public List<DetectedPattern> Patterns { get; }

        public SampleAnalysis(double entropy, string assessment, List<DetectedPattern> patterns)
        {
            EntropyBitsPerChar = entropy;
            EntropyAssessment = assessment;
            Patterns = patterns;
        }
    }

    private sealed class DetectedPattern
    {
        public string Category { get; init; } = "";
        public Severity Severity { get; init; }
        public string Description { get; init; } = "";
        public string Recommendation { get; init; } = "";
    }
}

public class SessionIdFinding
{
    public string CookieName { get; init; } = "";
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Description { get; init; } = "";
    public string Recommendation { get; init; } = "";
}

public class SessionIdSample
{
    public string CookieName { get; init; } = "";
    public string CurrentValue { get; init; } = "";
    public int SampleCount { get; init; }
    public double EntropyBitsPerChar { get; init; }
    public string EntropyAssessment { get; init; } = "";
    public List<string> Patterns { get; init; } = new();
}

public class SessionIdAnalysisResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public List<SessionIdSample> Samples { get; init; } = new();
    public List<SessionIdFinding> Findings { get; init; } = new();
    public bool IsClean => Findings.All(f => f.Severity < Severity.Medium);
}
