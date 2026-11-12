using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Trusted reverse-proxy header spoofing (X-Forwarded-*, X-Original-URL, …) for auth bypass.
/// Requires anon gate (401/403) then 200 with non-shell, body differing from baseline.
/// Inspired by OWASP WSTG access-control / IP spoofing patterns; also influenced by pentest-ai <c>web.trusted_header_bypass</c>.
/// </summary>
public static class TrustedHeaderBypassChecker
{
    public sealed class BypassOptions
    {
        public IReadOnlyList<string>? Paths { get; set; }
        public IReadOnlyList<string>? Urls { get; set; }
        public IReadOnlyList<string>? Headers { get; set; }
        public IReadOnlyList<IReadOnlyDictionary<string, string>>? HeaderSets { get; set; }
        public bool DiscoverFromAttackSurface { get; set; } = true;
        public bool DiscoverFromDiscoverResults { get; set; } = true;
        public int MaxTargets { get; set; } = 20;
        public int TimeoutMs { get; set; } = 12_000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class BypassFinding
    {
        public string Url { get; init; } = "";
        public string Path { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int BypassStatus { get; init; }
        public string Severity { get; init; } = "high";
        public string Category { get; init; } = "auth-bypass-header-spoof";
        public string HeaderSet { get; init; } = "";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public string? BodySnippet { get; init; }
    }

    public sealed class BypassResult
    {
        public List<BypassFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> HeadersTested { get; init; } = [];
        public int TargetsAttempted { get; init; }
        public int TargetsTested { get; init; }
        public int TargetsSkipped { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    private static readonly string[] DefaultTargets =
    [
        "/admin", "/admin/", "/admin/users", "/admin/dashboard",
        "/internal", "/internal/", "/internal/whoami", "/internal/db-stats",
        "/_admin", "/_internal",
        "/api/admin", "/api/internal", "/api/secrets", "/api/users",
        "/actuator/env", "/actuator/heapdump",
        "/console", "/_console",
    ];

    private static readonly string[] IpVariants =
    [
        "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "0.0.0.0", "localhost"
    ];

    private static readonly string[] HighRiskPrefixes =
    [
        "/admin", "/_admin", "/internal", "/_internal", "/api/admin",
        "/api/internal", "/api/secrets", "/actuator",
    ];

    public static async Task<BypassResult> RunAsync(
        AutomationContext ctx,
        BypassOptions options,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running trusted-header bypass scan.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var shell = await SpaShellGuard.CaptureOriginShellAsync(ctx, origin, options.TimeoutMs);
        var paths = ResolvePaths(ctx, options, origin);
        var headerSets = BuildHeaderSets(options);
        var headersTested = headerSets
            .Select(h => string.Join(", ", h.Select(kv => $"{kv.Key}={kv.Value}")))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var findings = new List<BypassFinding>();
        var attempted = 0;
        var tested = 0;
        var skipped = 0;

        foreach (var path in paths.Take(Math.Clamp(options.MaxTargets, 1, 40)))
        {
            ct.ThrowIfCancellationRequested();
            var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? path
                : origin + (path.StartsWith('/') ? path : "/" + path);

            attempted++;

            var baseline = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET", null, null, options.TimeoutMs,
                includeBrowserCookies: false, ct);

            if (baseline.Status is not (401 or 403))
            {
                skipped++;
                continue;
            }

            tested++;

            foreach (var headerSet in headerSets)
            {
                ct.ThrowIfCancellationRequested();
                var probe = await SecurityProbeHttp.FetchAsync(
                    ctx, url, "GET", headerSet, null, options.TimeoutMs,
                    includeBrowserCookies: false, ct);

                if (probe.Status != 200)
                    continue;

                var probeBody = probe.Body ?? "";
                if (IsRejectedShellOrEmpty(probeBody, probe.Status, shell))
                    continue;

                // Prefer body differential — status-only 200 vs 401/403 error pages that echo the shell are weak.
                if (!BodyDiffersFromBaseline(baseline.Body, probeBody))
                    continue;

                var hdrStr = string.Join(", ", headerSet.Select(kv => $"{kv.Key}={kv.Value}"));
                var severity = IsHighRisk(path) ? "critical" : "high";
                findings.Add(new BypassFinding
                {
                    Url = url,
                    Path = path,
                    BaselineStatus = baseline.Status,
                    BypassStatus = probe.Status,
                    Severity = severity,
                    HeaderSet = hdrStr,
                    Title = $"Trusted-header bypass on {path} via {hdrStr}",
                    Detail =
                        $"Anonymous GET {url} -> {baseline.Status}. With {hdrStr} -> 200 with non-shell body differing from baseline.",
                    BodySnippet = Truncate(probeBody.Replace('\r', ' ').Replace('\n', ' '), 160)
                });
                break;
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindingsForChain(ctx, findings);

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add($"No trusted-header bypass on {tested} gated path(s) (401/403 baseline). {skipped} target(s) skipped (not gated).");
        else
            summary.Add($"{findings.Count} trusted-header bypass finding(s) — strip or validate proxy headers at the edge.");

        return new BypassResult
        {
            Findings = findings,
            Summary = summary,
            HeadersTested = headersTested,
            TargetsAttempted = attempted,
            TargetsTested = tested,
            TargetsSkipped = skipped
        };
    }

    private static void RegisterFindingsForChain(AutomationContext ctx, List<BypassFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"trusted-header-{Math.Abs((f.Url + f.HeaderSet).GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Title,
                Endpoint = f.Url,
                Method = "GET",
                Detail = f.Detail
            });
        }
    }

    private static List<IReadOnlyDictionary<string, string>> BuildHeaderSets(BypassOptions options)
    {
        if (options.HeaderSets is { Count: > 0 })
            return options.HeaderSets.ToList();

        var sets = new List<IReadOnlyDictionary<string, string>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddSet(Dictionary<string, string> dict)
        {
            var key = string.Join("|", dict.OrderBy(kv => kv.Key).Select(kv => $"{kv.Key}={kv.Value}"));
            if (seen.Add(key))
                sets.Add(dict);
        }

        if (options.Headers is { Count: > 0 })
        {
            foreach (var headerName in options.Headers)
            {
                foreach (var value in DefaultValuesForHeader(headerName))
                    AddSet(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [headerName] = value });
            }
            return sets;
        }

        AddSet(new Dictionary<string, string> { ["X-Forwarded-User"] = "admin" });
        AddSet(new Dictionary<string, string> { ["X-Forwarded-User"] = "root" });
        AddSet(new Dictionary<string, string> { ["X-Original-User"] = "admin" });
        AddSet(new Dictionary<string, string> { ["X-Remote-User"] = "admin" });
        AddSet(new Dictionary<string, string> { ["X-Forwarded-Host"] = "localhost" });
        AddSet(new Dictionary<string, string> { ["X-Authenticated-User"] = "admin" });
        AddSet(new Dictionary<string, string> { ["X-Original-URL"] = "/admin" });
        AddSet(new Dictionary<string, string> { ["X-Rewrite-URL"] = "/admin" });

        foreach (var ip in IpVariants)
        {
            AddSet(new Dictionary<string, string> { ["X-Forwarded-For"] = ip });
            AddSet(new Dictionary<string, string> { ["X-Real-IP"] = ip });
        }

        return sets;
    }

    private static IEnumerable<string> DefaultValuesForHeader(string headerName)
    {
        if (headerName.Equals("X-Forwarded-For", StringComparison.OrdinalIgnoreCase)
            || headerName.Equals("X-Real-IP", StringComparison.OrdinalIgnoreCase))
            return IpVariants;

        if (headerName.Contains("URL", StringComparison.OrdinalIgnoreCase)
            || headerName.Contains("Uri", StringComparison.OrdinalIgnoreCase))
            return ["/admin", "/internal"];

        if (headerName.Contains("Host", StringComparison.OrdinalIgnoreCase))
            return ["localhost", "127.0.0.1"];

        if (headerName.Contains("User", StringComparison.OrdinalIgnoreCase))
            return ["admin", "root"];

        return ["admin", "127.0.0.1", "localhost"];
    }

    private static List<string> ResolvePaths(AutomationContext ctx, BypassOptions options, string origin)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new List<string>();

        void Add(string? p)
        {
            if (string.IsNullOrWhiteSpace(p)) return;
            var path = p;
            if (Uri.TryCreate(p, UriKind.Absolute, out var abs))
                path = abs.PathAndQuery;
            if (!path.StartsWith('/')) path = "/" + path;
            if (seen.Add(path))
                paths.Add(path);
        }

        var explicitTargets = new List<string>();
        if (options.Urls is { Count: > 0 })
            explicitTargets.AddRange(options.Urls);
        if (options.Paths is { Count: > 0 })
            explicitTargets.AddRange(options.Paths);

        if (explicitTargets.Count > 0)
        {
            foreach (var p in explicitTargets)
                Add(p);
            return paths;
        }

        foreach (var t in DefaultTargets)
            Add(t);

        if (options.DiscoverFromAttackSurface)
        {
            var mapper = new AttackSurfaceMapper();
            var surface = mapper.Analyze(ctx.Network.Entries, includeAuth: true);
            foreach (var ep in surface.Endpoints)
            {
                if (ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase)
                    || ep.UrlTemplate.Contains("internal", StringComparison.OrdinalIgnoreCase)
                    || ep.UrlTemplate.Contains("actuator", StringComparison.OrdinalIgnoreCase))
                    Add(ep.UrlTemplate);
            }
        }

        return paths;
    }

    private static bool IsHighRisk(string path)
    {
        var p = path.StartsWith("http", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(path, UriKind.Absolute, out var u)
            ? u.AbsolutePath
            : path;
        return HighRiskPrefixes.Any(prefix =>
            p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRejectedShellOrEmpty(
        string body, int status, SpaShellGuard.ShellFingerprint? shell)
    {
        if (string.IsNullOrWhiteSpace(body)) return true;
        if (SpaShellGuard.IsApiLikeResponse(body)) return false;
        if (SpaShellGuard.LooksLikeSpaShellDuplicate(body, status, shell)) return true;
        if (SpaShellGuard.IsSpaHtmlShell(body)) return true;
        // Larger shell check: any sizable HTML document without API markers.
        var stripped = body.TrimStart();
        if (stripped.StartsWith('<') && body.Length <= 4000
            && (stripped.Contains("<html", StringComparison.OrdinalIgnoreCase)
                || stripped.Contains("<!doctype", StringComparison.OrdinalIgnoreCase)
                || stripped.Contains("<body", StringComparison.OrdinalIgnoreCase)))
            return true;
        return false;
    }

    private static bool BodyDiffersFromBaseline(string? baselineBody, string probeBody)
    {
        var baseline = baselineBody ?? "";
        if (string.IsNullOrWhiteSpace(baseline)) return !string.IsNullOrWhiteSpace(probeBody);
        if (string.Equals(baseline, probeBody, StringComparison.Ordinal)) return false;

        var a = baseline.Length;
        var b = probeBody.Length;
        var larger = Math.Max(a, b);
        if (larger == 0) return false;
        // Require a meaningful length delta or different hash-ish prefix.
        if (Math.Abs(a - b) > Math.Max(40, larger / 20)) return true;
        return !string.Equals(
            baseline.Length > 64 ? baseline[..64] : baseline,
            probeBody.Length > 64 ? probeBody[..64] : probeBody,
            StringComparison.Ordinal);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
