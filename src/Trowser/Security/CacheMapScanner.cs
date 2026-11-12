using System.Diagnostics;
using System.Text;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Safe cache-key indication pass: identify the cache, then map query/path/header membership
/// with unique busting query params. Does not poison the live URL slot.
/// Inspired by PortSwigger web cache poisoning methodology (key construction), not Param Miner.
/// </summary>
public sealed class CacheMapScanner
{
    public const string BusterParam = "trowser_cb";
    public const string ExtraParam = "trowser_x";

    private static readonly (string Header, string Value)[] HeaderProbes =
    [
        ("X-Forwarded-Host", "cache-map-probe.trowser.test"),
        ("X-Original-URL", "/cache-map-probe"),
        ("X-Forwarded-Scheme", "http"),
        ("X-Forwarded-Proto", "http"),
        ("X-Forwarded-Prefix", "/cache-map-probe"),
        ("X-Forwarded-Port", "8080"),
        ("X-Original-Host", "cache-map-probe.trowser.test"),
        ("X-Rewrite-URL", "/cache-map-probe"),
        ("X-Host", "cache-map-probe.trowser.test"),
        ("Forwarded", "host=cache-map-probe.trowser.test"),
        ("X-Amz-Website-Redirect-Location", "https://cache-map-probe.trowser.test/"),
        ("X-Middleware-Subrequest", "1"),
        ("X-Invoke-Path", "/cache-map-probe"),
        ("True-Client-IP", "1.2.3.4"),
        ("X-Real-IP", "1.2.3.4"),
    ];

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CacheMapScanner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<CacheMapResult> RunAsync(CacheMapOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running cache-map.");

        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var includeCookies = options.IncludeBrowserCookies;
        var maxTargets = options.MaxTargets > 0 ? options.MaxTargets : 2;
        var targets = ResolveTargets(options, currentUri, maxTargets);
        var comparisons = new List<CacheMapComparison>();
        var findings = new List<CacheMapFinding>();
        var headerInfluencers = new List<string>();
        var probesRun = 0;
        CacheIdentifySummary? identify = null;
        CacheOracleSummary? oracle = null;
        var queryKeyed = "unknown";
        var pathNorm = "unknown";
        var cookieKeyed = false;

        _log($"CacheMap: {targets.Count} target(s), cookies={includeCookies}, headers={options.IncludeHeaderProbes}", "#888888");

        foreach (var targetUrl in targets)
        {
            ct.ThrowIfCancellationRequested();

            var baseline = await TryFetch(_ctx, targetUrl, null, null, timeout, includeCookies, ct);
            probesRun++;
            if (baseline == null)
                continue;

            var id = CacheHeaderAnalyzer.Analyze(baseline.ResponseHeaders);
            identify ??= id;

            if (id.Vary.Any(v => v.Equals("Cookie", StringComparison.OrdinalIgnoreCase)))
                cookieKeyed = true;

            MaybeCacheableError(findings, targetUrl, baseline, "baseline");

            var buster = NewBuster();
            var busted = WithQuery(targetUrl, BusterParam, buster);

            var first = await TryFetch(_ctx, busted, null, null, timeout, includeCookies, ct);
            probesRun++;
            if (first == null)
                continue;

            await Task.Delay(150, ct);
            var second = await TryFetch(_ctx, busted, null, null, timeout, includeCookies, ct);
            probesRun++;
            if (second == null)
                continue;

            var firstId = CacheHeaderAnalyzer.Analyze(first.ResponseHeaders);
            var secondId = CacheHeaderAnalyzer.Analyze(second.ResponseHeaders);
            var bodyStable = CacheHeaderAnalyzer.BodyHash(first.Body) == CacheHeaderAnalyzer.BodyHash(second.Body);
            var secondHit = CacheHeaderAnalyzer.LooksLikeHit(second.ResponseHeaders);
            var usableOracle = bodyStable && (secondHit || firstId.Cacheable || secondId.Cacheable);
            var cacheInPlay = id.Detected || firstId.Detected || secondId.Detected || usableOracle;
            oracle ??= new CacheOracleSummary
            {
                Usable = usableOracle,
                BodyStable = bodyStable,
                FirstStatus = firstId.DocumentStatus,
                SecondStatus = secondId.DocumentStatus,
                Detail = usableOracle
                    ? "Two identical bustered GETs produced a stable body with cache headers — usable key-mapping oracle."
                    : "Bustered replay did not look like a cache HIT. Key-mapping results are weaker."
            };

            AddComparison(comparisons, targetUrl, "oracle-first", busted, first, firstId);
            AddComparison(comparisons, targetUrl, "oracle-replay", busted, second, secondId, "baseline",
                secondHit ? "hit-on-replay" : "miss-on-replay");

            // Extra random query param vs replay of the same param.
            var extraVal = NewBuster();
            var extraUrl = WithQuery(busted, ExtraParam, extraVal);
            var extra = await TryFetch(_ctx, extraUrl, null, null, timeout, includeCookies, ct);
            probesRun++;
            if (extra != null)
            {
                await Task.Delay(150, ct);
                var extraReplay = await TryFetch(_ctx, extraUrl, null, null, timeout, includeCookies, ct);
                probesRun++;
                var extraId = CacheHeaderAnalyzer.Analyze(extra.ResponseHeaders);
                var extraHash = CacheHeaderAnalyzer.BodyHash(extra.Body);
                var firstHash = CacheHeaderAnalyzer.BodyHash(first.Body);
                var extraSameAsFirst = extraHash == firstHash;
                var extraHit = CacheHeaderAnalyzer.LooksLikeHit(extra.ResponseHeaders);
                var extraReplayHit = extraReplay != null && CacheHeaderAnalyzer.LooksLikeHit(extraReplay.ResponseHeaders);

                string qVerdict;
                if (cacheInPlay && extraSameAsFirst && extraHit)
                {
                    qVerdict = "unkeyed-and-shared";
                    queryKeyed = queryKeyed is "keyed" or "mixed" ? "mixed" : "unkeyed";
                    findings.Add(Finding(targetUrl, "unkeyed-query", "medium", "likely",
                        "Query string appears unkeyed",
                        $"Extra param {ExtraParam} was served as a HIT of the prior bustered object."));
                }
                else if (cacheInPlay && !extraSameAsFirst && extraReplayHit)
                {
                    qVerdict = "keyed";
                    queryKeyed = queryKeyed is "unkeyed" or "mixed" ? "mixed" : "keyed";
                }
                else if (!cacheInPlay)
                {
                    // Same body on an extra query param is normal origin behavior when no cache is in play.
                    qVerdict = extraSameAsFirst ? "same-origin-body" : "distinct-origin-body";
                }
                else
                {
                    qVerdict = extraSameAsFirst ? "unkeyed" : "unknown";
                    if (extraSameAsFirst)
                        queryKeyed = queryKeyed is "keyed" or "mixed" ? "mixed" : "unkeyed";
                }

                AddComparison(comparisons, targetUrl, "query-extra", extraUrl, extra, extraId, "oracle-first", qVerdict);
                if (extraReplay != null)
                    AddComparison(comparisons, targetUrl, "query-extra-replay", extraUrl, extraReplay,
                        CacheHeaderAnalyzer.Analyze(extraReplay.ResponseHeaders), "query-extra", extraReplayHit ? "hit-on-replay" : "miss-on-replay");

                if (cacheInPlay && !extraSameAsFirst && CacheHeaderAnalyzer.LooksLikeMiss(extra.ResponseHeaders))
                {
                    findings.Add(Finding(targetUrl, "key-explosion-possible", "info", "likely",
                        "Cache-key explosion possible",
                        "Unique query values appear to create distinct cache objects (informational; not flooded)."));
                }

                MaybeCacheableError(findings, extraUrl, extra, "query-extra");
            }

            // Flip one captured query value (excluding our buster).
            if (Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri)
                && !string.IsNullOrEmpty(targetUri.Query))
            {
                var flipped = FlipOneQuery(targetUri, buster);
                if (flipped != null)
                {
                    var flipResp = await TryFetch(_ctx, flipped, null, null, timeout, includeCookies, ct);
                    probesRun++;
                    if (flipResp != null)
                    {
                        var flipId = CacheHeaderAnalyzer.Analyze(flipResp.ResponseHeaders);
                        var same = CacheHeaderAnalyzer.BodyHash(flipResp.Body) == CacheHeaderAnalyzer.BodyHash(first.Body)
                                   && CacheHeaderAnalyzer.LooksLikeHit(flipResp.ResponseHeaders);
                        var verdict = same ? "param-unkeyed" : "param-keyed-or-origin";
                        AddComparison(comparisons, targetUrl, "query-flip", flipped, flipResp, flipId, "oracle-first", verdict);
                        if (same)
                        {
                            queryKeyed = queryKeyed is "keyed" or "mixed" ? "mixed" : "unkeyed";
                            findings.Add(Finding(targetUrl, "unkeyed-query", "medium", "likely",
                                "Existing query parameter appears unkeyed",
                                "Flipping a captured query value still hit the prior cached object."));
                        }
                    }
                }
            }

            // Path normalization variants (same buster query).
            foreach (var (label, variant) in PathVariants(targetUrl, buster))
            {
                ct.ThrowIfCancellationRequested();
                var resp = await TryFetch(_ctx, variant, null, null, timeout, includeCookies, ct);
                probesRun++;
                if (resp == null) continue;
                var vid = CacheHeaderAnalyzer.Analyze(resp.ResponseHeaders);
                var sameBody = CacheHeaderAnalyzer.BodyHash(resp.Body) == CacheHeaderAnalyzer.BodyHash(first.Body);
                var hit = CacheHeaderAnalyzer.LooksLikeHit(resp.ResponseHeaders);
                var verdict = sameBody && hit ? "same-cache-object" : sameBody ? "same-body" : "distinct";
                AddComparison(comparisons, targetUrl, "path-" + label, variant, resp, vid, "oracle-first", verdict);
                if (verdict == "same-cache-object")
                {
                    pathNorm = "collapses";
                    findings.Add(Finding(targetUrl, "normalization-discrepancy", "medium", "likely",
                        $"Path normalization collapses via {label}",
                        $"{variant} was served as a HIT of {busted}."));
                }
                else if (pathNorm == "unknown")
                    pathNorm = "distinct";
                MaybeCacheableError(findings, variant, resp, "path-" + label);
            }

            // Param cloaking: duplicate keys / encoded &.
            var cloakDup = WithQuery(busted, ExtraParam, "a") + "&" + ExtraParam + "=b";
            var cloakEnc = busted + (busted.Contains('?') ? "&" : "?") + ExtraParam + "=a%26" + ExtraParam + "=b";
            foreach (var (label, url) in new[] { ("duplicate-param", cloakDup), ("encoded-amp", cloakEnc) })
            {
                var resp = await TryFetch(_ctx, url, null, null, timeout, includeCookies, ct);
                probesRun++;
                if (resp == null) continue;
                var cid = CacheHeaderAnalyzer.Analyze(resp.ResponseHeaders);
                var sameBody = CacheHeaderAnalyzer.BodyHash(resp.Body) == CacheHeaderAnalyzer.BodyHash(first.Body);
                var verdict = sameBody && CacheHeaderAnalyzer.LooksLikeHit(resp.ResponseHeaders)
                    ? "cache-origin-disagree-candidate"
                    : "distinct-or-origin";
                AddComparison(comparisons, targetUrl, "cloak-" + label, url, resp, cid, "oracle-first", verdict);
                if (verdict == "cache-origin-disagree-candidate")
                {
                    findings.Add(Finding(targetUrl, "normalization-discrepancy", "medium", "tentative",
                        $"Param cloaking ({label}) may disagree between cache and origin",
                        "Duplicate/encoded query was served from the prior cache object."));
                }
            }

            if (options.IncludeFatGet)
            {
                var fat = await TryFetch(_ctx, busted, null, "{\"trowser\":1}", timeout, includeCookies, ct);
                probesRun++;
                if (fat != null)
                {
                    var fatId = CacheHeaderAnalyzer.Analyze(fat.ResponseHeaders);
                    var changed = fat.Status != first.Status
                                  || CacheHeaderAnalyzer.BodyHash(fat.Body) != CacheHeaderAnalyzer.BodyHash(first.Body);
                    AddComparison(comparisons, targetUrl, "fat-get", busted, fat, fatId, "oracle-first",
                        changed ? "origin-reads-body" : "body-ignored");
                    if (changed)
                    {
                        findings.Add(Finding(targetUrl, "unkeyed-reflected", "medium", "likely",
                            "Fat GET: origin reads the body while the cache keys the URL",
                            $"GET body changed status {first.Status}→{fat.Status} on the busted URL."));
                    }
                }
            }

            if (options.IncludeHeaderProbes)
            {
                var names = options.HeaderNames is { Count: > 0 }
                    ? HeaderProbes.Where(h => options.HeaderNames.Any(n => n.Equals(h.Header, StringComparison.OrdinalIgnoreCase)))
                    : HeaderProbes.AsEnumerable();

                foreach (var (header, value) in names)
                {
                    ct.ThrowIfCancellationRequested();
                    var hdrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [header] = value };
                    var resp = await TryFetch(_ctx, busted, hdrs, null, timeout, includeCookies, ct);
                    probesRun++;
                    if (resp == null) continue;
                    var hid = CacheHeaderAnalyzer.Analyze(resp.ResponseHeaders);
                    var bodyChanged = CacheHeaderAnalyzer.BodyHash(resp.Body) != CacheHeaderAnalyzer.BodyHash(first.Body);
                    var statusChanged = resp.Status != first.Status;
                    var locChanged = HeaderValue(resp, "Location") != HeaderValue(first, "Location");
                    var reflected = resp.Body.Contains(value, StringComparison.OrdinalIgnoreCase)
                                    || HeaderContains(resp, value);
                    var influenced = bodyChanged || statusChanged || locChanged || reflected;
                    var verdict = influenced ? "header-influences-origin" : "no-effect";
                    AddComparison(comparisons, targetUrl, "header-" + header, busted, resp, hid, "oracle-first", verdict,
                        canaryInProbe: reflected);
                    if (influenced)
                    {
                        headerInfluencers.Add(header);
                        findings.Add(Finding(targetUrl, reflected ? "unkeyed-reflected" : "unkeyed-reflected",
                            "medium", reflected ? "likely" : "tentative",
                            $"Header {header} influences origin on the busted URL",
                            $"Candidate for live-key poison — not proof. status {first.Status}→{resp.Status}.",
                            header));
                    }
                    MaybeCacheableError(findings, busted, resp, header);
                }
            }
        }

        identify ??= new CacheIdentifySummary { Detected = false, DocumentStatus = CacheHeaderAnalyzer.DocumentStatusUnknown };
        oracle ??= new CacheOracleSummary { Usable = false, Detail = "No successful oracle pair." };

        var collapsed = CacheMapPresentation.CollapseCacheableErrors(findings);
        var interesting = collapsed
            .GroupBy(f => $"{f.Url}|{f.Indicator}|{f.HeaderName}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Confidence == "confirmed").First())
            .Select(NormalizeReportingSeverity)
            .ToList();

        var next = new List<string>();
        var dynamicOnly = identify.DocumentStatus.Equals("dynamic", StringComparison.OrdinalIgnoreCase);
        if (identify.Detected)
        {
            if (dynamicOnly && interesting.Count == 0)
            {
                next.Add("Monitor only — dynamic responses with no cache-map findings; cache-pollution probes unlikely to apply.");
            }
            else
            {
                next.Add("POST /api/security/cache-pollution-scan on this URL (live-key error store; requires safetyMode active).");
                if (headerInfluencers.Count > 0)
                    next.Add("POST /api/security/cache-poison-scan with headers: " + string.Join(", ", headerInfluencers.Distinct()));
                next.Add("POST /api/security/cache-deception-scan if the session is authenticated.");
            }
        }

        sw.Stop();
        var message = identify.Detected
            ? interesting.Count == 0
                ? $"Cache detected ({identify.DocumentStatus}); no unkeyed/discrepancy findings ({probesRun} probe(s))."
                : $"Cache detected; {interesting.Count} interesting indication(s) across {probesRun} probe(s)."
            : $"No cache identified ({probesRun} probe(s)).";

        return new CacheMapResult
        {
            Message = message,
            ProbesRun = probesRun,
            ElapsedMs = sw.ElapsedMilliseconds,
            Identify = identify,
            Oracle = oracle,
            KeyComponents = new CacheKeyComponents
            {
                QueryParams = queryKeyed,
                Headers = headerInfluencers.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                CookieKeyed = cookieKeyed,
                PathNormalization = pathNorm
            },
            Comparisons = comparisons,
            Findings = interesting,
            NextActions = next
        };
    }

    private List<string> ResolveTargets(CacheMapOptions options, Uri currentUri, int maxTargets)
    {
        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var list = new List<string>();

        if (options.Urls is { Count: > 0 })
        {
            foreach (var u in options.Urls)
            {
                if (Uri.TryCreate(u, UriKind.Absolute, out _))
                    list.Add(u);
                else if (Uri.TryCreate(origin + (u.StartsWith('/') ? u : "/" + u), UriKind.Absolute, out var abs))
                    list.Add(abs.ToString());
            }
        }
        else
        {
            list.Add(currentUri.GetLeftPart(UriPartial.Path) + currentUri.Query);
            foreach (var asset in CacheableAssets(origin, currentUri))
            {
                if (list.Count >= maxTargets) break;
                list.Add(asset);
            }
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(maxTargets).ToList();
    }

    private IEnumerable<string> CacheableAssets(string origin, Uri currentUri)
    {
        var pageHost = currentUri.Host;
        return _ctx.Network.Entries
            .Where(e => !e.IsTrowserGenerated && e.StatusCode is >= 200 and < 400)
            .Where(e => e.ResourceType is "Script" or "script" or "Stylesheet" or "stylesheet" or "Document" or "document")
            .Where(e => Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                        && u.Host.Equals(pageHost, StringComparison.OrdinalIgnoreCase))
            .Where(e => CacheHeaderAnalyzer.HasCacheabilitySignal(e.ResponseHeaders))
            .Select(e => e.Url.Split('#')[0])
            .Where(u => !u.Equals(currentUri.GetLeftPart(UriPartial.Path), StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<(string Label, string Url)> PathVariants(string targetUrl, string buster)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
            yield break;
        var path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path) || path == "/")
            yield break;

        var trimmed = path.TrimEnd('/');
        string Build(string p) => new UriBuilder(uri) { Path = p, Query = BusterParam + "=" + buster }.Uri.AbsoluteUri;

        yield return ("trailing-slash", Build(trimmed + "/"));
        var slash = trimmed.LastIndexOf('/');
        var doubled = slash >= 0 ? trimmed[..slash] + "//" + trimmed[(slash + 1)..] : "//" + trimmed.TrimStart('/');
        yield return ("double-slash", Build(doubled));
        yield return ("dot-segment", Build(trimmed + "/./"));
        yield return ("encoded-slash", uri.GetLeftPart(UriPartial.Authority) + trimmed + "%2f?trowser_cb=" + buster);
        yield return ("semicolon", uri.GetLeftPart(UriPartial.Authority) + trimmed + ";?trowser_cb=" + buster);
        yield return ("css-suffix", uri.GetLeftPart(UriPartial.Authority) + trimmed + "?.css?trowser_cb=" + buster);
    }

    private static string? FlipOneQuery(Uri uri, string buster)
    {
        var qb = HttpUtility.ParseQueryString(uri.Query);
        string? chosen = null;
        foreach (string? key in qb.AllKeys)
        {
            if (key == null || key.Equals(BusterParam, StringComparison.OrdinalIgnoreCase))
                continue;
            chosen = key;
            break;
        }

        if (chosen == null)
            return null;

        qb[chosen] = (qb[chosen] ?? "1") + "x";
        qb[BusterParam] = buster;
        return new UriBuilder(uri) { Query = qb.ToString() ?? "" }.Uri.AbsoluteUri;
    }

    private static void MaybeCacheableError(
        List<CacheMapFinding> findings, string url, SecurityProbeHttp.FetchResult resp, string via)
    {
        if (resp.Status < 400) return;
        if (!CacheHeaderAnalyzer.HasCacheabilitySignal(resp.ResponseHeaders)) return;
        findings.Add(Finding(url, "cacheable-error", "medium", "likely",
            $"Cacheable {resp.Status} via {via}",
            "Error response still looks storeable (not no-store). Confirm with cache-pollution-scan on the live URL."));
    }

    private static CacheMapFinding NormalizeReportingSeverity(CacheMapFinding f) =>
        new()
        {
            Url = f.Url,
            Indicator = f.Indicator,
            Severity = CacheMapPresentation.ReportingSeverity(f.Indicator, f.Confidence, f.Severity),
            Confidence = f.Confidence,
            Title = f.Title,
            Detail = f.Detail,
            HeaderName = f.HeaderName
        };

    private static CacheMapFinding Finding(
        string url, string indicator, string severity, string confidence,
        string title, string detail, string? header = null) =>
        new()
        {
            Url = url,
            Indicator = indicator,
            Severity = severity,
            Confidence = confidence,
            Title = title,
            Detail = detail,
            HeaderName = header
        };

    private static void AddComparison(
        List<CacheMapComparison> list,
        string url,
        string probe,
        string requestUrl,
        SecurityProbeHttp.FetchResult resp,
        CacheIdentifySummary id,
        string? vs = null,
        string? verdict = null,
        bool canaryInProbe = false)
    {
        list.Add(new CacheMapComparison
        {
            Url = url,
            Probe = probe,
            RequestUrl = requestUrl,
            Status = resp.Status,
            BodyHash = CacheHeaderAnalyzer.BodyHash(resp.Body),
            CacheStatus = id.DocumentStatus,
            CanaryInProbe = canaryInProbe,
            Versus = vs,
            Verdict = verdict ?? ""
        });
    }

    private static async Task<SecurityProbeHttp.FetchResult?> TryFetch(
        AutomationContext ctx, string url, IReadOnlyDictionary<string, string>? headers, string? body,
        int timeout, bool cookies, CancellationToken ct)
    {
        try
        {
            return await SecurityProbeHttp.FetchAsync(ctx, url, "GET", headers, body, timeout, cookies, ct);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string WithQuery(string url, string name, string value)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var sep = url.Contains('?') ? '&' : '?';
            return $"{url}{sep}{name}={Uri.EscapeDataString(value)}";
        }

        var qb = HttpUtility.ParseQueryString(uri.Query);
        qb[name] = value;
        return new UriBuilder(uri) { Query = qb.ToString() ?? "" }.Uri.AbsoluteUri;
    }

    private static string NewBuster() => Guid.NewGuid().ToString("N")[..12];

    private static string HeaderValue(SecurityProbeHttp.FetchResult resp, string name) =>
        CacheHeaderAnalyzer.TryGet(resp.ResponseHeaders, name, out var v) ? v : "";

    private static bool HeaderContains(SecurityProbeHttp.FetchResult resp, string needle) =>
        resp.ResponseHeaders.Values.Any(v => v.Contains(needle, StringComparison.OrdinalIgnoreCase));
}

public sealed class CacheMapOptions
{
    public List<string>? Urls { get; init; }
    public int MaxTargets { get; init; } = 2;
    public int TimeoutMs { get; init; } = 15000;
    public bool IncludeBrowserCookies { get; init; } = true;
    public bool IncludeHeaderProbes { get; init; }
    public bool IncludeFatGet { get; init; }
    public List<string>? HeaderNames { get; init; }
}

public sealed class CacheMapResult
{
    public string Message { get; init; } = "";
    public int ProbesRun { get; init; }
    public long ElapsedMs { get; init; }
    public CacheIdentifySummary Identify { get; init; } = new();
    public CacheOracleSummary Oracle { get; init; } = new();
    public CacheKeyComponents KeyComponents { get; init; } = new();
    public List<CacheMapComparison> Comparisons { get; init; } = [];
    public List<CacheMapFinding> Findings { get; init; } = [];
    public List<string> NextActions { get; init; } = [];

    public bool HasConfirmedIssue =>
        Findings.Any(f => f.Confidence == "confirmed"
                          && f.Indicator is "unkeyed-reflected" or "cacheable-error");

    public string Format(bool includeDetails = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Cache Map (indication) ===");
        sb.AppendLine(Message);
        sb.AppendLine($"Identify: detected={Identify.Detected} status={Identify.DocumentStatus} cacheable={Identify.Cacheable}");
        if (Identify.Vendors.Count > 0)
            sb.AppendLine($"Vendors: {string.Join(", ", Identify.Vendors)}");
        if (Identify.Evidence.Count > 0)
            sb.AppendLine($"Evidence: {CacheHeaderAnalyzer.FormatEvidence(Identify)}");
        sb.AppendLine($"Oracle usable: {Oracle.Usable} ({Oracle.Detail})");
        sb.AppendLine($"Key: query={KeyComponents.QueryParams} pathNorm={KeyComponents.PathNormalization} cookieKeyed={KeyComponents.CookieKeyed}");
        if (KeyComponents.Headers.Count > 0)
            sb.AppendLine($"Header candidates: {string.Join(", ", KeyComponents.Headers)}");
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

        if (includeDetails && Comparisons.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("COMPARISONS:");
            foreach (var c in Comparisons.Take(24))
                sb.AppendLine($"  {c.Probe}: HTTP {c.Status} {c.CacheStatus} hash={c.BodyHash} verdict={c.Verdict}");
        }

        if (NextActions.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("NEXT:");
            foreach (var n in NextActions)
                sb.AppendLine($"  {n}");
        }

        sb.AppendLine("==============================");
        return sb.ToString();
    }
}

public sealed class CacheOracleSummary
{
    public bool Usable { get; init; }
    public bool BodyStable { get; init; }
    public string FirstStatus { get; init; } = "";
    public string SecondStatus { get; init; } = "";
    public string Detail { get; init; } = "";
}

public sealed class CacheKeyComponents
{
    public string QueryParams { get; init; } = "unknown";
    public List<string> Headers { get; init; } = [];
    public bool CookieKeyed { get; init; }
    public string PathNormalization { get; init; } = "unknown";
}

public sealed class CacheMapComparison
{
    public string Url { get; init; } = "";
    public string Probe { get; init; } = "";
    public string RequestUrl { get; init; } = "";
    public int Status { get; init; }
    public string BodyHash { get; init; } = "";
    public string CacheStatus { get; init; } = "";
    public bool CanaryInProbe { get; init; }
    public bool CanaryInClean { get; init; }
    public string? Versus { get; init; }
    public string Verdict { get; init; } = "";
}

public sealed class CacheMapFinding
{
    public string Severity { get; init; } = "info";
    public string Confidence { get; init; } = "likely";
    public string Url { get; init; } = "";
    public string Indicator { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string? HeaderName { get; init; }
}
