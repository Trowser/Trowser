using System.Text.RegularExpressions;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Shared deduplication keys for chain findings — source-agnostic so orchestration
/// and auto-scan feeds collapse identical hits.
/// </summary>
public static class ChainFindingDedup
{
    private static readonly Regex ViaParamRegex = new(
        @"via\s+'(?<p>[^']+)'",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CstiSourceSuffixRegex = new(
        @"\s*\((dom|query|hash|fragment|url)\)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Stable key for cross-source deduplication.</summary>
    public static string Key(ChainableFinding f)
    {
        var category = CanonicalCategory(f.Category);
        var endpoint = SecurityHostScope.LogicalEndpointKey(f.Method ?? "GET", f.Endpoint ?? "");
        var parameter = f.Parameter ?? ExtractParameter(f.Title, f.Detail, f.Evidence);
        var titlePart = TitleFragmentForDedup(f, category, parameter);
        return $"{category}|{endpoint}|{parameter ?? ""}|{titlePart}".ToLowerInvariant();
    }

    /// <summary>Map related scanner categories to a canonical bucket for dedup.</summary>
    public static string CanonicalCategory(string category)
    {
        var c = category.ToLowerInvariant();
        return c switch
        {
            "ssti-confirmed" or "ssti-polyglot" or "ssti-stored" or "ssti" => "ssti",
            "csti-confirmed" or "csti" => "csti",
            "sqli-indicator" or "sqli-login-bypass" => "sqli",
            "nosql-injection" => "nosql-injection",
            "xss-reflected" or "xss-dom" or "xss-stored" => "xss",
            _ => c
        };
    }

    private static string TitleFragmentForDedup(ChainableFinding f, string canonicalCategory, string? parameter)
    {
        if (IsHeaderCookieCategory(canonicalCategory))
            return "";

        // Injection findings with an extracted parameter dedupe on param, not full title.
        if (!string.IsNullOrEmpty(parameter) && canonicalCategory is "ssti" or "csti" or "sqli" or "nosql-injection" or "xss")
            return parameter;

        return NormalizeTitle(f.Title ?? "");
    }

    /// <summary>Best-effort parameter name from scanner titles/details (e.g. <c>via 'productId'</c>).</summary>
    public static string? ExtractParameter(string? title, string? detail, string? evidence = null)
    {
        foreach (var text in new[] { title, detail, evidence })
        {
            var p = ExtractParameterFromTitle(text);
            if (!string.IsNullOrEmpty(p))
                return p;
        }

        return null;
    }

    private static string NormalizeTitle(string title)
    {
        if (string.IsNullOrWhiteSpace(title)) return "";
        var t = CstiSourceSuffixRegex.Replace(title.Trim(), "");
        return t;
    }

    private static string? ExtractParameterFromTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title)) return null;
        var m = ViaParamRegex.Match(title);
        if (m.Success) return m.Groups["p"].Value;
        m = System.Text.RegularExpressions.Regex.Match(
            title, @"via\s+'(?<p>[^']+)'", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["p"].Value : null;
    }

    private static bool IsHeaderCookieCategory(string category) =>
        category.ToLowerInvariant() switch
        {
            "missing-csp" or "missing-hsts" or "missing-xframe" or "missing-content-type-options"
                or "missing-referrer-policy" or "missing-permissions-policy" or "weak-headers"
                or "missing-httponly" or "missing-secure-flag" or "missing-samesite" or "weak-cookies" => true,
            _ => false
        };
}
