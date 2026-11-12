using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Cookie prefix bypass: replay stripped/forged <c>__Host-</c> / <c>__Secure-</c> cookies vs real session and cookieless baselines.
/// Hit when forged variant behaves like the real prefixed session while cookieless does not (RFC 6265bis semantics).
/// Inspired by RFC 6265bis cookie prefixes; also influenced by pentest-ai <c>web.cookie_prefix_bypass</c>.
/// </summary>
public static class CookiePrefixBypassChecker
{
    public sealed class BypassOptions
    {
        public string? PageUrl { get; set; }
        public int TimeoutMs { get; set; } = 12_000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class BypassFinding
    {
        public string Url { get; init; } = "";
        public string CookieName { get; init; } = "";
        public string Variant { get; init; } = "";
        public string ManipulatedName { get; init; } = "";
        public int BaselineLength { get; init; }
        public int VariantLength { get; init; }
        public int ControlLength { get; init; }
        public string Severity { get; init; } = "high";
        public string Category { get; init; } = "cookie-prefix-bypass";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public sealed class BypassResult
    {
        public List<BypassFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> PrefixedCookiesFound { get; init; } = [];
        public bool IsClean => Findings.Count == 0;
    }

    private static readonly string[] Prefixes = ["__Host-", "__Secure-"];

    private static readonly (string Variant, string Separator)[] WhitespaceVariants =
    [
        ("en_quad", "\u2000"),
        ("zero_width_space", "\u200b"),
        ("no_break_space", "\u00a0"),
        ("tab", "\t"),
    ];

    private static readonly (string Variant, string Leading)[] LeadingVariants =
    [
        ("leading_space", " "),
        ("leading_tab", "\t"),
    ];

    public static async Task<BypassResult> RunAsync(
        AutomationContext ctx,
        BypassOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = options.PageUrl ?? await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(pageUrl) || !Uri.TryCreate(pageUrl, UriKind.Absolute, out _))
            throw new InvalidOperationException("Navigate to a page before running cookie prefix bypass probe.");

        var prefixed = CollectPrefixedCookies(ctx, pageUrl);
        if (prefixed.Count == 0)
        {
            return new BypassResult
            {
                Summary = ["No __Host- or __Secure- cookies found in network Set-Cookie for this page."],
                PrefixedCookiesFound = []
            };
        }

        // Anonymous / cookieless shape — used as the negative control.
        var cookieless = await SecurityProbeHttp.FetchAsync(ctx, pageUrl, "GET", null, null, options.TimeoutMs,
            includeBrowserCookies: false, ct);
        var cookielessLen = cookieless.Body?.Length ?? 0;

        var findings = new List<BypassFinding>();

        foreach (var (name, value) in prefixed)
        {
            ct.ThrowIfCancellationRequested();

            // Real prefixed cookie = authenticated / session shape baseline.
            var sessionHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Cookie"] = $"{name}={value}"
            };
            var sessionResp = await SecurityProbeHttp.FetchAsync(ctx, pageUrl, "GET", sessionHeaders, null,
                options.TimeoutMs, includeBrowserCookies: false, ct);
            var sessionLen = sessionResp.Body?.Length ?? 0;

            // No auth differential to detect if session ≈ cookieless.
            if (ShapeClose(sessionLen, cookielessLen))
                continue;

            foreach (var variant in BuildManipulatedNames(name))
            {
                var variantHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Cookie"] = $"{variant.ManipulatedName}={value}"
                };

                var variantResp = await SecurityProbeHttp.FetchAsync(ctx, pageUrl, "GET", variantHeaders, null,
                    options.TimeoutMs, includeBrowserCookies: false, ct);

                var vLen = variantResp.Body?.Length ?? 0;

                // Hit: forged/stripped name behaves like the real prefixed session, not like anonymous.
                if (ShapeClose(sessionLen, vLen) && !ShapeClose(cookielessLen, vLen))
                {
                    findings.Add(new BypassFinding
                    {
                        Url = pageUrl,
                        CookieName = name,
                        Variant = variant.VariantName,
                        ManipulatedName = variant.ManipulatedName,
                        BaselineLength = sessionLen,
                        VariantLength = vLen,
                        ControlLength = cookielessLen,
                        Severity = "high",
                        Title = $"Cookie prefix bypass via {variant.VariantName} on {name}",
                        Detail =
                            $"Manipulated cookie name '{variant.ManipulatedName}' matched real prefixed session shape " +
                            $"({sessionLen} vs {vLen} bytes) while cookieless did not ({cookielessLen} bytes)."
                    });
                }
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindings(ctx, findings);

        var summary = findings.Count == 0
            ? new List<string> { $"Tested {prefixed.Count} prefixed cookie(s); no parser normalization bypass detected." }
            : new List<string> { $"{findings.Count} cookie prefix bypass finding(s)." };

        return new BypassResult
        {
            Findings = findings,
            Summary = summary,
            PrefixedCookiesFound = prefixed.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static List<(string Name, string Value)> CollectPrefixedCookies(AutomationContext ctx, string pageUrl)
    {
        var results = new List<(string, string)>();
        var fromNetwork = SetCookieHeaderParser.ExtractFromNetworkEntries(ctx.Network.Entries, pageUrl, pageScopeOnly: true);
        foreach (var row in fromNetwork)
        {
            var name = row.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            var value = row.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value)) continue;
            if (Prefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
                results.Add((name, value));
        }

        if (results.Count == 0)
        {
            foreach (var entry in ctx.Network.PageEntries)
            {
                if (entry.ResponseHeaders == null) continue;
                foreach (var h in entry.ResponseHeaders.Where(h =>
                             h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)))
                {
                    foreach (var parsed in SetCookieHeaderParser.ParseHeaderValue(h.Value))
                    {
                        var name = parsed.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                        var value = parsed.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
                        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(value)) continue;
                        if (Prefixes.Any(p => name.StartsWith(p, StringComparison.Ordinal)))
                            results.Add((name, value));
                    }
                }
            }
        }

        return results;
    }

    private static IEnumerable<(string VariantName, string ManipulatedName)> BuildManipulatedNames(string original)
    {
        foreach (var prefix in Prefixes)
        {
            if (!original.StartsWith(prefix, StringComparison.Ordinal)) continue;
            var rest = original[prefix.Length..];
            foreach (var (variant, sep) in WhitespaceVariants)
                yield return (variant, $"{prefix}{sep}{rest}");
            foreach (var (variant, lead) in LeadingVariants)
                yield return (variant, $"{lead}{original}");
            break;
        }
    }

    private static bool ShapeClose(int a, int b, double tolerance = 0.1)
    {
        if (a == 0 && b == 0) return true;
        var larger = Math.Max(a, b);
        if (larger == 0) return false;
        return Math.Abs(a - b) / (double)larger <= tolerance;
    }

    private static void RegisterFindings(AutomationContext ctx, List<BypassFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"cookie-prefix-{Math.Abs((f.CookieName + f.Variant).GetHashCode(StringComparison.Ordinal))}",
                Category = f.Category,
                Severity = f.Severity,
                Endpoint = f.Url,
                Method = "GET",
                Source = "cookie-prefix-bypass",
                Title = f.Title,
                Detail = f.Detail
            });
        }
    }
}
