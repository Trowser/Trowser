using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Reporting policy for cache-map indication findings (not live-key pollution proofs).
/// </summary>
public static class CacheMapPresentation
{
    public const string IndicationRemediation =
        "Cache-map is an indication only. Confirm with POST /api/security/cache-pollution-scan (active) on the live URL. " +
        "Do not cache error responses; include all response-affecting inputs in the cache key; use Cache-Control: no-store on errors.";

    public const string IndicationReference =
        "https://portswigger.net/web-security/web-cache-poisoning";

    /// <summary>
    /// Severity shown in orchestration summaries, markdown, and histograms for unconfirmed cache-map probes.
    /// </summary>
    public static string ReportingSeverity(string indicator, string confidence, string scannerSeverity)
    {
        var conf = SecurityConfidence.Normalize(confidence);
        var raw = (scannerSeverity ?? "medium").Trim().ToLowerInvariant();

        if (conf == SecurityConfidence.Confirmed)
            return raw is "critical" or "high" or "medium" or "low" or "info" ? raw : "medium";

        return indicator switch
        {
            "cacheable-error" => "info",
            "key-explosion-possible" => "info",
            "normalization-discrepancy" => "low",
            "unkeyed-query" => "low",
            "unkeyed-reflected" => conf == SecurityConfidence.Tentative ? "low" : "medium",
            _ => raw is "high" or "critical" ? "low" : raw
        };
    }

    public static string? ClaimedSeverity(string indicator, string confidence, string scannerSeverity)
    {
        var reporting = ReportingSeverity(indicator, confidence, scannerSeverity);
        var raw = (scannerSeverity ?? "").Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(raw) || raw == reporting)
            return null;
        return raw is "critical" or "high" or "medium" or "low" or "info" ? raw : null;
    }

    /// <summary>
    /// Merge duplicate cacheable-error rows (path normalization probes) into one finding per origin path.
    /// </summary>
    public static List<CacheMapFinding> CollapseCacheableErrors(IReadOnlyList<CacheMapFinding> findings)
    {
        if (findings.Count == 0)
            return [];

        var kept = new List<CacheMapFinding>();
        var errors = findings.Where(f =>
            f.Indicator.Equals("cacheable-error", StringComparison.OrdinalIgnoreCase)).ToList();
        var other = findings.Where(f =>
            !f.Indicator.Equals("cacheable-error", StringComparison.OrdinalIgnoreCase)).ToList();

        foreach (var group in errors.GroupBy(f => NormalizeOriginPath(f.Url), StringComparer.OrdinalIgnoreCase))
        {
            var list = group.ToList();
            if (list.Count == 1)
            {
                kept.Add(list[0]);
                continue;
            }

            var probes = list
                .Select(f => ProbeLabelFromTitle(f.Title))
                .Where(p => !string.IsNullOrEmpty(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var first = list[0];
            var detail = first.Detail;
            if (probes.Count > 0)
            {
                detail = $"{first.Detail} Probes ({probes.Count}): {string.Join(", ", probes)}.";
            }

            kept.Add(new CacheMapFinding
            {
                Url = first.Url,
                Indicator = first.Indicator,
                Severity = first.Severity,
                Confidence = first.Confidence,
                Title = "Cacheable error response (multiple normalization probes)",
                Detail = detail,
                HeaderName = first.HeaderName
            });
        }

        kept.AddRange(other);
        return kept;
    }

    public static ChainableFinding ToChainableFinding(
        CacheMapFinding f,
        string id,
        string source,
        string categoryOverride = "cache-map")
    {
        var reporting = ReportingSeverity(f.Indicator, f.Confidence, f.Severity);
        return new ChainableFinding
        {
            Id = id,
            Source = source,
            Category = categoryOverride,
            Severity = reporting,
            Title = f.Title,
            Endpoint = f.Url,
            Method = "GET",
            Detail = $"{f.Indicator} ({f.Confidence}). {f.Detail}",
            Evidence = f.HeaderName,
            Remediation = IndicationRemediation,
            Reference = IndicationReference,
            Tags = ["cache-indication", f.Indicator]
        };
    }

    public static ChainableFinding FromAutoScanCacheMap(AutoScanPipeline.AutoScanFinding f, string id, string source)
    {
        var indicator = ExtractIndicator(f.Detail);
        var confidence = ExtractConfidence(f.Detail);
        var reporting = ReportingSeverity(indicator, confidence, f.Severity);
        return new ChainableFinding
        {
            Id = id,
            Source = source,
            Category = "cache-map",
            Severity = reporting,
            Title = f.Title,
            Endpoint = f.Endpoint,
            Method = f.Method,
            Detail = f.Detail,
            Evidence = f.Evidence,
            Remediation = IndicationRemediation,
            Reference = IndicationReference,
            Tags = ["cache-indication", indicator]
        };
    }

    private static string NormalizeOriginPath(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Split('?')[0];

        return uri.GetLeftPart(UriPartial.Path);
    }

    private static string ProbeLabelFromTitle(string title)
    {
        const string via = " via ";
        var idx = title.LastIndexOf(via, StringComparison.OrdinalIgnoreCase);
        return idx >= 0 ? title[(idx + via.Length)..].Trim() : title;
    }

    private static string ExtractIndicator(string? detail)
    {
        if (string.IsNullOrEmpty(detail))
            return "cache-map";
        var paren = detail.IndexOf('(');
        if (paren <= 0)
            return "cache-map";
        return detail[..paren].Trim();
    }

    private static string ExtractConfidence(string? detail)
    {
        if (string.IsNullOrEmpty(detail))
            return SecurityConfidence.Likely;
        var start = detail.IndexOf('(');
        var end = detail.IndexOf(')', start + 1);
        if (start < 0 || end <= start)
            return SecurityConfidence.Likely;
        return detail[(start + 1)..end].Trim();
    }
}
