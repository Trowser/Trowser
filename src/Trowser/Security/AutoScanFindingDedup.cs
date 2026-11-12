namespace Trowser.Security;

/// <summary>Merge duplicate auto-scan findings for triage-friendly output.</summary>
public static class AutoScanFindingDedup
{
    public static List<AutoScanPipeline.AutoScanFinding> Summarize(
        IReadOnlyList<AutoScanPipeline.AutoScanFinding> findings,
        List<AutoScanPipeline.AutoScanFinding>? suppressedOut = null)
    {
        if (findings.Count <= 1) return findings.ToList();

        var groups = new Dictionary<string, AutoScanPipeline.AutoScanFinding>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var f in findings)
        {
            var key = DedupKey(f);
            if (groups.TryGetValue(key, out var existing))
            {
                existing.Occurrences++;
                if (!string.IsNullOrEmpty(f.Evidence) && (existing.Evidence?.Contains(f.Evidence, StringComparison.Ordinal) != true))
                {
                    existing.Evidence = string.IsNullOrEmpty(existing.Evidence)
                        ? f.Evidence
                        : $"{existing.Evidence}; {f.Evidence}";
                    if (existing.Evidence.Length > 1200)
                        existing.Evidence = existing.Evidence[..1200] + "…";
                }

                // Prefer higher severity when merging payload variants of the same sink.
                if (SeverityRank(f.Severity) > SeverityRank(existing.Severity))
                {
                    // Keep the higher-severity title/detail as the visible representative.
                    suppressedOut?.Add(CloneFinding(existing));
                    existing.Severity = f.Severity;
                    existing.Title = NormalizeTitle(f.Title);
                    existing.Detail = f.Detail;
                    existing.Scanner = f.Scanner;
                }
                else if (SeverityRank(f.Severity) < SeverityRank(existing.Severity))
                {
                    suppressedOut?.Add(CloneFinding(f));
                }
            }
            else
            {
                order.Add(key);
                groups[key] = new AutoScanPipeline.AutoScanFinding
                {
                    Scanner = f.Scanner,
                    Severity = f.Severity,
                    Endpoint = NormalizeEndpoint(f.Endpoint),
                    Method = f.Method,
                    Title = NormalizeTitle(f.Title),
                    Detail = f.Detail,
                    Evidence = f.Evidence,
                    Occurrences = 1,
                    NextActions = f.NextActions?.Count > 0 ? [.. f.NextActions] : []
                };
            }
        }

        var merged = order.Select(k => groups[k]).ToList();
        return ApplyClassArbitration(merged, suppressedOut);
    }

    /// <summary>
    /// When multiple injection classes fire on the same endpoint+param, keep the stronger class:
    /// command-injection/RCE &gt; XSS (confirmed reflection) &gt; SQLi &gt; SSTI (same parameter).
    /// Echo-only SQLi differentials on search sinks that already have XSS must not survive.
    /// Also prefer confirmed reflected XSS over DOM XSS on the same sink.
    /// </summary>
    internal static List<AutoScanPipeline.AutoScanFinding> ApplyClassArbitration(
        List<AutoScanPipeline.AutoScanFinding> findings,
        List<AutoScanPipeline.AutoScanFinding>? suppressedOut = null)
    {
        if (findings.Count <= 1) return findings;

        var cmdKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var xssKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var reflectedXssKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            if (IsCommandInjectionFinding(f))
                cmdKeys.Add(EndpointParamKey(f));
            if (IsXssFinding(f))
            {
                xssKeys.Add(EndpointParamKey(f));
                if (IsReflectedXssFinding(f))
                    reflectedXssKeys.Add(EndpointParamKey(f));
            }
        }

        return findings
            .Where(f =>
            {
                var key = EndpointParamKey(f);
                if (IsSqliFinding(f) && cmdKeys.Contains(key))
                {
                    suppressedOut?.Add(CloneFinding(f));
                    return false;
                }
                // Drop weak/echo SQLi when the same sink already has XSS (search-term reflection).
                if (IsWeakEchoSqliFinding(f) && xssKeys.Contains(key))
                {
                    suppressedOut?.Add(CloneFinding(f));
                    return false;
                }
                // Prefer reflected/stored XSS over DOM-only duplicate on the same sink.
                if (IsDomXssFinding(f) && reflectedXssKeys.Contains(key))
                {
                    suppressedOut?.Add(CloneFinding(f));
                    return false;
                }
                return true;
            })
            .ToList();
    }

    private static bool IsReflectedXssFinding(AutoScanPipeline.AutoScanFinding f) =>
        IsXssFinding(f)
        && (f.Scanner.Contains("stored", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("Reflected XSS", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("Stored XSS", StringComparison.OrdinalIgnoreCase));

    private static bool IsDomXssFinding(AutoScanPipeline.AutoScanFinding f) =>
        IsXssFinding(f)
        && (f.Scanner.Contains("dom", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("DOM XSS", StringComparison.OrdinalIgnoreCase)
            || f.Detail?.Contains("not active in DOM", StringComparison.OrdinalIgnoreCase) == true
            || f.Detail?.Contains("not rendered as active", StringComparison.OrdinalIgnoreCase) == true);

    private static AutoScanPipeline.AutoScanFinding CloneFinding(AutoScanPipeline.AutoScanFinding f) => new()
    {
        Scanner = f.Scanner,
        Severity = f.Severity,
        Endpoint = f.Endpoint,
        Method = f.Method,
        Title = f.Title,
        Detail = f.Detail,
        Evidence = f.Evidence,
        Occurrences = f.Occurrences,
        NextActions = f.NextActions?.Count > 0 ? [.. f.NextActions] : []
    };

    private static bool IsCommandInjectionFinding(AutoScanPipeline.AutoScanFinding f) =>
        f.Scanner.Contains("cmd", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("command injection", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("command-injection", StringComparison.OrdinalIgnoreCase)
        || f.Detail?.Contains("command-injection", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsSqliFinding(AutoScanPipeline.AutoScanFinding f) =>
        f.Scanner.Contains("sqli", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("SQL injection", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("sqli", StringComparison.OrdinalIgnoreCase);

    private static bool IsXssFinding(AutoScanPipeline.AutoScanFinding f) =>
        f.Scanner.Contains("xss", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("XSS", StringComparison.OrdinalIgnoreCase)
        || f.Title.Contains("Cross-site", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Boolean-suspected / echo-shaped SQLi without error oracle — typical FP on reflected search terms.
    /// </summary>
    private static bool IsWeakEchoSqliFinding(AutoScanPipeline.AutoScanFinding f)
    {
        if (!IsSqliFinding(f)) return false;
        var title = f.Title ?? "";
        var detail = f.Detail ?? "";
        var evidence = f.Evidence ?? "";
        if (title.Contains("error-based", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("error-based", StringComparison.OrdinalIgnoreCase)
            || title.Contains("union-based", StringComparison.OrdinalIgnoreCase)
            || title.Contains("auth bypass", StringComparison.OrdinalIgnoreCase)
            || title.Contains("blind-boolean-confirmed", StringComparison.OrdinalIgnoreCase))
            return false;
        return title.Contains("blind-boolean-suspected", StringComparison.OrdinalIgnoreCase)
               || title.Contains("Suspected", StringComparison.OrdinalIgnoreCase)
               || evidence.Contains("identical after framework-noise strip", StringComparison.OrdinalIgnoreCase);
    }

    private static string EndpointParamKey(AutoScanPipeline.AutoScanFinding f)
    {
        var endpoint = NormalizeEndpoint(f.Endpoint);
        var param = ExtractParamHint(f);
        return $"{f.Method}|{endpoint}|{param}";
    }

    private static string NormalizeEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return "";
        // Prefer string split over Uri — brace templates must stay {id}, not %7Bid%7D.
        var decoded = AttackSurfaceMapper.DecodeTemplateBraces(endpoint);
        var q = decoded.IndexOf('?', StringComparison.Ordinal);
        var path = q >= 0 ? decoded[..q] : decoded;
        if (LooksAbsoluteUrl(path))
        {
            var schemeSep = path.IndexOf("://", StringComparison.Ordinal);
            var pathStart = path.IndexOf('/', schemeSep + 3);
            return pathStart >= 0 ? path[pathStart..] : path;
        }

        return path;
    }

    private static bool LooksAbsoluteUrl(string value) =>
        value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    private static string ExtractParamHint(AutoScanPipeline.AutoScanFinding f)
    {
        // Titles/details often look like: "SQLi on command" / "Parameter 'command'"
        foreach (var text in new[] { f.Title, f.Detail, f.Evidence })
        {
            if (string.IsNullOrEmpty(text)) continue;
            var m = System.Text.RegularExpressions.Regex.Match(
                text, @"via\s+'(?<p>[^']+)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["p"].Value;
            m = System.Text.RegularExpressions.Regex.Match(
                text, @"param(?:eter)?\s*['\""]?(\w+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;
            m = System.Text.RegularExpressions.Regex.Match(
                text, @"\b(command|cmd|exec|execute|shell|run)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;
        }

        return "";
    }

    /// <summary>
    /// Collapse by sink identity (scanner class + path + method + param + title class),
    /// not by payload-bearing URLs.
    /// </summary>
    private static string DedupKey(AutoScanPipeline.AutoScanFinding f)
    {
        var endpoint = NormalizeEndpoint(f.Endpoint);
        var param = ExtractParamHint(f);
        var title = NormalizeTitle(f.Title);
        var scannerClass = NormalizeScannerClass(f.Scanner);
        return $"{scannerClass}|{f.Method}|{endpoint}|{param}|{title}";
    }

    private static string NormalizeScannerClass(string scanner)
    {
        if (string.IsNullOrWhiteSpace(scanner)) return "";
        var s = scanner.Trim().ToLowerInvariant();
        if (s.Contains("sqli")) return "sqli";
        if (s.Contains("xss")) return "xss";
        if (s.Contains("ssti")) return "ssti";
        if (s.Contains("cmd")) return "cmd";
        if (s.Contains("ssrf")) return "ssrf";
        if (s.Contains("csrf")) return "csrf";
        if (s.Contains("path")) return "path";
        return s;
    }

    private static string NormalizeTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title)) return "";
        // Strip trailing payload snippets that used to prevent dedup.
        var t = title.Trim();
        var withPayload = t.IndexOf(" with payload", StringComparison.OrdinalIgnoreCase);
        if (withPayload > 0) t = t[..withPayload].Trim();
        var contextSuffix = t.LastIndexOf(" (", StringComparison.Ordinal);
        if (contextSuffix > 0 && t.EndsWith(')'))
            t = t[..contextSuffix].Trim();
        return t;
    }

    private static int SeverityRank(string? s) => (s ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0
    };
}
