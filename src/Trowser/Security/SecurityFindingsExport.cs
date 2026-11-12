using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.SessionLog;

namespace Trowser.Security;

/// <summary>
/// Unified export of shadow, orchestrate, auto-scan, and manual chain findings for LLM triage.
/// </summary>
public static class SecurityFindingsExport
{
    public sealed class ExportOptions
    {
        public string? Host { get; set; }
        public string? Category { get; set; }
        public string? MinSeverity { get; set; }
        public string? MinConfidence { get; set; }
        public bool IncludeHygiene { get; set; }
        public bool IncludeShadow { get; set; } = true;
        public bool IncludeChain { get; set; } = true;
    }

    public static object BuildExport(
        AutomationContext context,
        SessionLogger? sessionLogger,
        ExportOptions options)
    {
        var unified = new List<UnifiedSecurityFinding>();
        var host = options.Host;

        if (options.IncludeChain)
        {
            var chain = ChainAnalysisService.CollectFindings(context, sessionLogger);
            if (!string.IsNullOrWhiteSpace(options.Category))
                chain = chain.Where(f =>
                    f.Category.Contains(options.Category, StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var f in chain)
            {
                if (!HostMatches(f.Endpoint, host)) continue;
                var tier = InferTier(f.Category, f.Severity);
                unified.Add(UnifiedSecurityFinding.Create(
                    category: f.Category,
                    title: f.Title,
                    severity: f.Severity,
                    confidence: SecurityConfidence.Likely,
                    endpoint: f.Endpoint,
                    method: f.Method,
                    param: f.Parameter,
                    evidence: f.Evidence ?? f.Detail,
                    proofHint: f.Detail,
                    tier: tier,
                    nextActions: [SecurityNextActions.ChainProve],
                    id: f.Id,
                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["source"] = f.Source
                    }));
            }
        }

        if (options.IncludeShadow && context.SecurityShadow is { Enabled: true } shadow)
        {
            foreach (var f in shadow.GetFindings())
            {
                if (!HostMatches(f.Url, host)) continue;
                var category = MapShadowAuditToCategory(f.Audit, f.Title);
                if (!string.IsNullOrWhiteSpace(options.Category)
                    && !category.Contains(options.Category, StringComparison.OrdinalIgnoreCase))
                    continue;

                unified.Add(UnifiedSecurityFinding.Create(
                    category: category,
                    title: f.Title,
                    severity: f.Severity.ToString().ToLowerInvariant(),
                    confidence: SecurityConfidence.Likely,
                    endpoint: f.Url,
                    evidence: f.Description,
                    proofHint: f.Recommendation,
                    tier: SecurityFindingTier.Hygiene,
                    id: $"shadow-{f.Id}",
                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["source"] = "shadow",
                        ["audit"] = f.Audit,
                        ["occurrences"] = f.Occurrences
                    }));
            }
        }

        if (!options.IncludeHygiene)
            unified = unified.Where(f => f.Tier == SecurityFindingTier.Exploitable).ToList();

        if (!string.IsNullOrWhiteSpace(options.MinConfidence))
            unified = unified.Where(f => SecurityConfidence.MeetsMinimum(f.Confidence, options.MinConfidence)).ToList();

        if (!string.IsNullOrWhiteSpace(options.MinSeverity))
        {
            var minRank = SeverityRank(options.MinSeverity);
            unified = unified.Where(f => SeverityRank(f.Severity) >= minRank).ToList();
        }

        unified = unified
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ThenByDescending(f => SecurityConfidence.Rank(f.Confidence))
            .ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var byCategory = unified.GroupBy(f => f.Category)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        return new
        {
            hostFilter = host,
            categoryFilter = options.Category,
            minSeverity = options.MinSeverity,
            minConfidence = options.MinConfidence,
            includeHygiene = options.IncludeHygiene,
            count = unified.Count,
            byCategory,
            findings = unified.Select(SecurityScanResult.ToApiFinding).ToList()
        };
    }

    private static string InferTier(string category, string severity)
    {
        if (category.Contains("header", StringComparison.OrdinalIgnoreCase)
            || category.Contains("cookie", StringComparison.OrdinalIgnoreCase)
            || category.Contains("csp", StringComparison.OrdinalIgnoreCase)
            || category.Contains("hsts", StringComparison.OrdinalIgnoreCase)
            || category.Contains("missing-", StringComparison.OrdinalIgnoreCase)
            || category.Contains("weak-", StringComparison.OrdinalIgnoreCase))
            return SecurityFindingTier.Hygiene;

        if (severity.Equals("info", StringComparison.OrdinalIgnoreCase)
            || severity.Equals("informational", StringComparison.OrdinalIgnoreCase))
            return SecurityFindingTier.Informational;

        return SecurityFindingTier.Exploitable;
    }

    private static bool HostMatches(string? endpoint, string? hostFilter)
    {
        if (string.IsNullOrWhiteSpace(hostFilter)) return true;
        if (string.IsNullOrWhiteSpace(endpoint)) return false;
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
            return endpoint.Contains(hostFilter, StringComparison.OrdinalIgnoreCase);
        return SecurityHostScope.Matches(uri.Host, hostFilter);
    }

    private static string MapShadowAuditToCategory(string audit, string title)
    {
        if (title.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase)) return "missing-httponly";
        if (title.Contains("Secure", StringComparison.OrdinalIgnoreCase) && title.Contains("Cookie", StringComparison.OrdinalIgnoreCase))
            return "missing-secure-flag";
        if (title.Contains("Content-Security-Policy", StringComparison.OrdinalIgnoreCase)) return "missing-csp";
        if (title.Contains("SQL", StringComparison.OrdinalIgnoreCase)) return "sqli";
        if (title.Contains("XSS", StringComparison.OrdinalIgnoreCase) || audit.Equals("xss", StringComparison.OrdinalIgnoreCase))
            return "xss";
        return audit switch
        {
            "security-headers" => "weak-headers",
            "cookies" => "weak-cookies",
            "network" => "info-leak",
            _ => "other"
        };
    }

    private static int SeverityRank(string? s) => (s ?? "").ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
