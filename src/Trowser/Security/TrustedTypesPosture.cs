using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Parses Trusted Types directives from Content-Security-Policy (document posture, not a bypass scanner).</summary>
public sealed class TrustedTypesPosture
{
    public bool CspPresent { get; init; }
    public bool RequireTrustedTypesForScript { get; init; }
    public bool RequireTrustedTypesForHtml { get; init; }
    public List<string> TrustedTypePolicyNames { get; init; } = [];
    public string? RawCsp { get; init; }

    public static TrustedTypesPosture ParseCsp(string? csp)
    {
        if (string.IsNullOrWhiteSpace(csp))
            return new TrustedTypesPosture();

        var lower = csp.ToLowerInvariant();
        var requireScript = lower.Contains("require-trusted-types-for 'script'");
        var requireHtml = lower.Contains("require-trusted-types-for 'html'");
        var policies = ExtractTrustedTypeNames(csp);

        return new TrustedTypesPosture
        {
            CspPresent = true,
            RequireTrustedTypesForScript = requireScript,
            RequireTrustedTypesForHtml = requireHtml,
            TrustedTypePolicyNames = policies,
            RawCsp = csp.Length > 500 ? csp[..500] + "…" : csp
        };
    }

    public static async Task<TrustedTypesPosture> FromDocumentHeadersAsync(AutomationContext ctx)
    {
        var url = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(url))
            return new TrustedTypesPosture();

        var entry = HeadersChecker.FindNavigationDocumentEntry(ctx.ActiveTab.Network.PageEntries, url);
        if (entry?.ResponseHeaders == null
            || !entry.ResponseHeaders.TryGetValue("content-security-policy", out var csp)
            || string.IsNullOrWhiteSpace(csp))
        {
            return new TrustedTypesPosture();
        }

        return ParseCsp(csp);
    }

    public object ToApiObject() => new
    {
        cspPresent = CspPresent,
        requireTrustedTypesForScript = RequireTrustedTypesForScript,
        requireTrustedTypesForHtml = RequireTrustedTypesForHtml,
        trustedTypePolicyNames = TrustedTypePolicyNames,
        rawCspSnippet = RawCsp
    };

    private static List<string> ExtractTrustedTypeNames(string csp)
    {
        var list = new List<string>();
        var match = Regex.Match(
            csp,
            @"trusted-types\s+([^;]+)",
            RegexOptions.IgnoreCase);
        if (!match.Success)
            return list;

        var segment = match.Groups[1].Value;
        foreach (var token in segment.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            var t = token.Trim().Trim('\'', '"');
            if (t.Length == 0 || t is "*" or "'none'" or "none" or "'allow-duplicates'" or "allow-duplicates")
                continue;
            if (!list.Contains(t, StringComparer.OrdinalIgnoreCase))
                list.Add(t);
        }

        return list;
    }
}
