using System.Diagnostics;
using Trowser.Automation;
using Trowser.Robustness;

namespace Trowser.Security;

/// <summary>
/// Classic web cache poisoning: inject canary values via unkeyed request headers,
/// then replay a clean request to detect cached poison persistence.
/// </summary>
public sealed class CachePoisonScanner
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public const string DefaultCanaryHost = "cache-poison-probe.trowser.test";

    private static readonly (string Header, string Description)[] UnkeyedHeaders =
    [
        ("X-Forwarded-Host", "Forwarded host override"),
        ("X-Original-URL", "Original URL override"),
        ("X-Forwarded-Scheme", "Scheme override (http/https)"),
        ("X-Amz-Website-Redirect-Location", "AWS redirect location"),
        ("X-Forwarded-Prefix", "Path prefix injection"),
        ("X-Rewrite-URL", "IIS rewrite URL"),
        ("X-Forwarded-Port", "Port override"),
        ("X-Original-Host", "Original host override"),
    ];

    public CachePoisonScanner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<CachePoisonResult> RunAsync(CachePoisonOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running cache poison tests.");

        var targets = ResolveTargets(options, currentUri);
        if (targets.Count == 0)
        {
            return new CachePoisonResult
            {
                Message = "No cache-poison targets. Pass explicit \"urls\" or navigate to a cacheable page.",
                ProbesRun = 0
            };
        }

        var canaryHost = string.IsNullOrWhiteSpace(options.CanaryHost)
            ? DefaultCanaryHost
            : options.CanaryHost.Trim();
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var includeCookies = options.IncludeBrowserCookies;
        var findings = new List<CachePoisonFinding>();
        var probesRun = 0;
        var probeId = 0;
        var skipped = 0;

        _log($"CachePoison: {targets.Count} target(s), canary={canaryHost}, queryBuster={options.UseQueryBuster}", "#888888");

        foreach (var targetUrl in targets)
        {
            ct.ThrowIfCancellationRequested();

            var baseline = await SecurityProbeHttp.FetchAsync(
                _ctx, targetUrl, "GET", null, null, timeout, includeCookies, ct);
            probesRun++;

            var identify = CacheHeaderAnalyzer.Analyze(baseline.ResponseHeaders);
            if (!identify.Cacheable && identify.DocumentStatus == CacheHeaderAnalyzer.DocumentStatusNotCached)
            {
                skipped++;
                _log($"  skip {targetUrl}: no-store / not an oracle ({CacheHeaderAnalyzer.FormatEvidence(identify)})", "#888888");
                continue;
            }

            var requestUrl = options.UseQueryBuster
                ? AppendBuster(targetUrl, Guid.NewGuid().ToString("N")[..10])
                : targetUrl;

            foreach (var (headerName, description) in UnkeyedHeaders)
            {
                if (options.Headers is { Count: > 0 }
                    && !options.Headers.Any(h => h.Equals(headerName, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ct.ThrowIfCancellationRequested();
                probeId++;
                var canary = $"{canaryHost}/wcp-{probeId}";

                var poisonHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [headerName] = canary
                };
                ApplyBypass(poisonHeaders, options);

                var poison = await SecurityProbeHttp.FetchAsync(
                    _ctx, requestUrl, "GET", poisonHeaders, null, timeout, includeCookies, ct);
                probesRun++;

                var reflectedInPoison = FindCanary(poison.Body, poison.ResponseHeaders, canary, canaryHost);
                if (reflectedInPoison.Count == 0)
                    continue;

                await Task.Delay(options.CacheReplayDelayMs > 0 ? options.CacheReplayDelayMs : 300, ct);

                var clean = await SecurityProbeHttp.FetchAsync(
                    _ctx, requestUrl, "GET", null, null, timeout, includeCookies, ct);
                probesRun++;

                var persisted = FindCanary(clean.Body, clean.ResponseHeaders, canary, canaryHost);
                var cached = persisted.Count > 0 && CacheHeaderAnalyzer.LooksLikeHit(clean.ResponseHeaders);
                var confirmed = persisted.Count > 0;
                var severity = cached ? "high" : "medium";
                var confidence = cached ? "confirmed" : confirmed ? "likely" : "likely";
                var indicator = cached ? "cached-persistence" : "reflected-not-cached";

                _log($"  FLAG cache-poison ({indicator}): {headerName} on {requestUrl}", "#F44747");
                findings.Add(new CachePoisonFinding
                {
                    Severity = severity,
                    Confidence = confidence,
                    Url = requestUrl,
                    HeaderName = headerName,
                    HeaderDescription = description,
                    CanaryValue = canary,
                    PoisonStatus = poison.Status,
                    CleanStatus = clean.Status,
                    ReflectedInPoison = reflectedInPoison,
                    PersistedInClean = persisted,
                    CacheHeaders = CacheHeaderAnalyzer.FormatCacheHeadersPair(
                        poison.ResponseHeaders, clean.ResponseHeaders, "poison", "clean"),
                    Indicator = indicator
                });
            }

            if (options.IncludeHeaderInjectionFuzz)
            {
                foreach (var payload in (FuzzerPayloads.Resolve("header-injection") ?? []).Take(options.MaxFuzzPayloads))
                {
                    ct.ThrowIfCancellationRequested();
                    var header = "X-Forwarded-Host";
                    var value = $"{canaryHost}{payload}";
                    var fuzzHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [header] = value
                    };
                    ApplyBypass(fuzzHeaders, options);
                    var fuzz = await SecurityProbeHttp.FetchAsync(
                        _ctx, requestUrl, "GET", fuzzHeaders, null, timeout, includeCookies, ct);
                    probesRun++;

                    if (!fuzz.Body.Contains(canaryHost, StringComparison.OrdinalIgnoreCase)
                        && !HeaderContains(fuzz.ResponseHeaders, canaryHost))
                        continue;

                    var clean = await SecurityProbeHttp.FetchAsync(
                        _ctx, requestUrl, "GET", null, null, timeout, includeCookies, ct);
                    probesRun++;

                    var persisted = FindCanary(clean.Body, clean.ResponseHeaders, canaryHost, canaryHost);
                    var cached = persisted.Count > 0 && CacheHeaderAnalyzer.LooksLikeHit(clean.ResponseHeaders);
                    findings.Add(new CachePoisonFinding
                    {
                        Severity = cached ? "high" : "medium",
                        Confidence = cached ? "confirmed" : "likely",
                        Url = requestUrl,
                        HeaderName = header,
                        HeaderDescription = "Header injection fuzz via X-Forwarded-Host",
                        CanaryValue = value,
                        PoisonStatus = fuzz.Status,
                        CleanStatus = clean.Status,
                        ReflectedInPoison = ["body-or-header"],
                        PersistedInClean = persisted,
                        CacheHeaders = CacheHeaderAnalyzer.FormatCacheHeadersPair(
                            fuzz.ResponseHeaders, clean.ResponseHeaders, "poison", "clean"),
                        Indicator = cached ? "cached-persistence" : "reflected-not-cached",
                        FuzzPayload = payload
                    });
                }
            }
        }

        sw.Stop();
        return BuildResult(findings, probesRun, sw.ElapsedMilliseconds, skipped);
    }

    private static List<string> ResolveTargets(CachePoisonOptions options, Uri currentUri)
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
            list.Add(currentUri.GetLeftPart(UriPartial.Path));
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(options.MaxTargets).ToList();
    }

    private static List<string> FindCanary(
        string body,
        IReadOnlyDictionary<string, string> headers,
        string canary,
        string canaryHost)
    {
        var hits = new List<string>();
        if (body.Contains(canary, StringComparison.OrdinalIgnoreCase))
            hits.Add("body");
        else if (body.Contains(canaryHost, StringComparison.OrdinalIgnoreCase))
            hits.Add("body-host");

        foreach (var (key, value) in headers)
        {
            if (value.Contains(canary, StringComparison.OrdinalIgnoreCase)
                || value.Contains(canaryHost, StringComparison.OrdinalIgnoreCase))
                hits.Add($"header:{key}");
        }
        return hits.Distinct().ToList();
    }

    private static bool HeaderContains(IReadOnlyDictionary<string, string> headers, string needle) =>
        headers.Values.Any(v => v.Contains(needle, StringComparison.OrdinalIgnoreCase));

    private static void ApplyBypass(Dictionary<string, string> headers, CachePoisonOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.BypassHeader))
            return;
        var value = string.IsNullOrWhiteSpace(options.BypassHeaderValue)
            ? DefaultBypassValue(options.BypassHeader)
            : options.BypassHeaderValue;
        headers[options.BypassHeader.Trim()] = value;
    }

    private static string DefaultBypassValue(string header) =>
        header.Equals("Cache-Control", StringComparison.OrdinalIgnoreCase) ? "no-cache"
        : header.Equals("Fastly-Force-Miss", StringComparison.OrdinalIgnoreCase) ? "1"
        : header.Equals("X-Refresh", StringComparison.OrdinalIgnoreCase) ? "1"
        : "no-cache";

    private static string AppendBuster(string url, string buster)
    {
        var sep = url.Contains('?') ? '&' : '?';
        return $"{url}{sep}{CacheMapScanner.BusterParam}={Uri.EscapeDataString(buster)}";
    }

    private static CachePoisonResult BuildResult(List<CachePoisonFinding> findings, int probesRun, long elapsedMs, int skipped)
    {
        var deduped = findings
            .GroupBy(f => $"{f.Url}|{f.HeaderName}|{f.CanaryValue}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Confidence == "confirmed").First())
            .ToList();

        var skippedNote = skipped > 0 ? $" Skipped {skipped} no-store target(s)." : "";
        var message = deduped.Count == 0
            ? $"No cache poisoning detected ({probesRun} probe(s)).{skippedNote}"
            : $"Found {deduped.Count} cache poison indicator(s) across {probesRun} probe(s).{skippedNote}";

        return new CachePoisonResult
        {
            Message = message,
            ProbesRun = probesRun,
            Findings = deduped,
            ElapsedMs = elapsedMs
        };
    }
}

public sealed class CachePoisonOptions
{
    public List<string>? Urls { get; init; }
    public List<string>? Headers { get; init; }
    public string? CanaryHost { get; init; }
    public int MaxTargets { get; init; } = 3;
    public int TimeoutMs { get; init; } = 15000;
    public int CacheReplayDelayMs { get; init; } = 300;
    public bool IncludeBrowserCookies { get; init; }
    public bool IncludeHeaderInjectionFuzz { get; init; }
    public int MaxFuzzPayloads { get; init; } = 6;
    /// <summary>Miss-forcing header from pollution identify step (live-key). Omitted from the clean replay.</summary>
    public string? BypassHeader { get; init; }
    public string? BypassHeaderValue { get; init; }
    /// <summary>Opt-in private-slot mapping via ?trowser_cb= — weaker than live-key proof.</summary>
    public bool UseQueryBuster { get; init; }
}

public sealed class CachePoisonResult
{
    public string Message { get; init; } = "";
    public int ProbesRun { get; init; }
    public long ElapsedMs { get; init; }
    public List<CachePoisonFinding> Findings { get; init; } = [];
}

public sealed class CachePoisonFinding
{
    public string Severity { get; init; } = "medium";
    public string Confidence { get; init; } = "likely";
    public string Url { get; init; } = "";
    public string HeaderName { get; init; } = "";
    public string HeaderDescription { get; init; } = "";
    public string CanaryValue { get; init; } = "";
    public int PoisonStatus { get; init; }
    public int CleanStatus { get; init; }
    public List<string> ReflectedInPoison { get; init; } = [];
    public List<string> PersistedInClean { get; init; } = [];
    public string CacheHeaders { get; init; } = "";
    public string Indicator { get; init; } = "";
    public string? FuzzPayload { get; init; }
}
