using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;
using Trowser.EndpointProbe;

namespace Trowser.Api;

public partial class TrowserApiServer
{
private Task HandlePostSecurity(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityOverviewAsync);

private Task HandlePostSecurityJsLibraries(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJsLibrariesAsync);

internal Task<object> BuildSecurityJsLibrariesAsync(JsonBody body) => BuildSecurityAuditPayloadAsync();

internal async Task<object> BuildSecurityOverviewAsync(JsonBody body)
{
    var sw = Stopwatch.StartNew();
    var includeDiscover = body.GetBool("includeDiscover", true);
    var includeMethods = body.GetBool("includeMethods", true);

    var techStack = await BuildTechStackPayloadAsync();
    var jsLibraries = await BuildSecurityAuditPayloadAsync();
    var headers = await BuildSecurityHeadersAuditPayloadAsync(body);
    var cors = await BuildSecurityCorsAsync(body);
    var xss = await BuildSecurityXssPayloadAsync();
    var mixedContent = await BuildMixedContentPayloadAsync();
    var cookies = await BuildCookieAuditPayloadAsync();
    var sourceMaps = await BuildSourceMapPayloadAsync();
    var storage = await BuildStorageAuditPayloadAsync();

    object? methods = null;
    if (includeMethods)
        methods = await BuildSecurityMethodsAsync(body);

    object? discover = null;
    if (includeDiscover)
        discover = await BuildSecurityDiscoverAsync(body);

    sw.Stop();

    bool methodsClean = methods == null || GetAnonymousBool(methods, "isClean");
    bool discoverClean = discover == null || GetAnonymousBool(discover, "isClean");

    bool isClean = GetAnonymousBool(jsLibraries, "isClean")
        && GetAnonymousBool(headers, "isClean")
        && GetAnonymousBool(cors, "isClean")
        && GetAnonymousBool(xss, "isClean")
        && GetAnonymousBool(mixedContent, "isClean")
        && GetAnonymousBool(cookies, "isClean")
        && GetAnonymousBool(sourceMaps, "isClean")
        && GetAnonymousBool(storage, "isClean")
        && methodsClean
        && discoverClean;

    return new
    {
        isClean,
        elapsedMs = sw.ElapsedMilliseconds,
        note = "Passive security overview (same modules as Quicktests → Security → 1 Security Scan). Retire.js only: POST /api/security/js-libraries.",
        techStack,
        jsLibraries,
        headers,
        cors,
        xss,
        mixedContent,
        cookies,
        sourceMaps,
        storage,
        methods,
        discover
    };
}

private Task HandlePostSecurityHeaders(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityHeadersAuditAsync);

internal async Task<object> BuildSecurityHeadersAuditAsync(JsonBody body) =>
    await BuildSecurityHeadersAuditPayloadAsync(body);

private Task HandlePostSecurityCors(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCorsAsync);

internal async Task<object> BuildSecurityCorsAsync(JsonBody body)
    {
        var urlList = body.GetStringArray("urls");
        var includeSweep = body.GetBool("includeAttackSurfaceUrls", false)
            || body.GetBool("sweep", false)
            || urlList is { Count: > 0 };

        if (includeSweep)
        {
            var corsBudget = body.HasProperty("budget") ? new JsonBody(body.GetObject("budget")) : null;
            var sweepOptions = new Security.CorsSweep.SweepOptions
            {
                IncludeAttackSurfaceUrls = body.GetBool("includeAttackSurfaceUrls", true),
                IncludeDefaultCandidates = body.GetBool("includeDefaultCandidates", true),
                MaxUrls = body.GetInt("maxUrls", 14),
                TimeoutMs = body.GetInt("timeoutMs", 12_000),
                IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
                IncludeCredentialsProbe = body.GetBool("includeCredentialsProbe", true),
                Urls = urlList,
                MaxSeconds = corsBudget?.GetInt("maxSeconds", 0) ?? 0
            };

            var sweep = await _context.CheckCorsSweep(sweepOptions);
            return new
            {
                isClean = sweep.IsClean,
                issueCount = sweep.IssueCount,
                documentUrl = sweep.DocumentUrl,
                urlsSwept = sweep.UrlsSwept,
                sweepResults = sweep.SweepResults,
                divergences = sweep.Divergences.Select(d => new
                {
                    d.Url,
                    d.Description,
                    documentSeverity = d.DocumentSeverity,
                    endpointSeverity = d.EndpointSeverity
                }).ToList(),
                endpoints = sweep.Endpoints.Select(ep => new
                {
                    url = ep.Url,
                    isDocumentBaseline = ep.IsDocumentBaseline,
                    isClean = ep.IsClean,
                    issueCount = ep.Issues.Count,
                    findings = ep.Issues.Select(f => new
                    {
                        origin = f.Origin,
                        reflected = f.Reflected,
                        wildcard = f.Wildcard,
                        allowOrigin = f.AllowOrigin,
                        allowCredentials = f.AllowCredentials,
                        severity = f.Severity?.ToString().ToLower(),
                        description = f.Description
                    }).ToList()
                }).ToList(),
                groupedIssues = sweep.GroupedIssues.Select(g => new
                {
                    g.RootCause,
                    g.IssueType,
                    allowOrigin = g.AllowOrigin,
                    allowCredentials = g.AllowCredentials,
                    severity = g.Severity,
                    affectedCount = g.AffectedCount,
                    affectedUrls = g.AffectedUrls
                }).ToList(),
                sources = sweep.Sources,
                networkUrlsIncluded = sweep.NetworkUrlsIncluded,
                crossOriginNetworkUrlsIncluded = sweep.CrossOriginNetworkUrlsIncluded,
                scaffoldUrlsIncluded = sweep.ScaffoldUrlsIncluded,
                skippedDueToMaxUrls = sweep.SkippedDueToMaxUrls > 0 ? (int?)sweep.SkippedDueToMaxUrls : null,
                warnings = sweep.Warnings.Count > 0 ? sweep.Warnings : null,
                budgetExhausted = sweep.BudgetExhausted ? (bool?)true : null,
                summary = sweep.IsClean
                    ? sweep.NetworkUrlsIncluded == 0 && includeSweep && body.GetBool("includeAttackSurfaceUrls", true)
                        ? "No CORS issues on document baseline; no network-derived API URLs were swept (browse API traffic or pass urls[])."
                        : "No CORS misconfigurations found across document and probed endpoints."
                    : $"{sweep.IssueCount} CORS issue(s) across {sweep.Endpoints.Count} endpoint(s)."
                        + (sweep.BudgetExhausted ? " (budget.maxSeconds exhausted — partial sweep.)" : "")
            };
        }

        var result = await _context.CheckCors();

        return new
        {
            isClean = result.IsClean,
            issueCount = result.IssueCount,
            findings = result.Issues.Select(f => new
            {
                origin = f.Origin,
                reflected = f.Reflected,
                wildcard = f.Wildcard,
                allowOrigin = f.AllowOrigin,
                allowCredentials = f.AllowCredentials,
                allowMethods = f.AllowMethods,
                allowHeaders = f.AllowHeaders,
                severity = f.Severity?.ToString().ToLower(),
                description = f.Description
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

private Task HandlePostSecurityForcedErrorScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityForcedErrorScanAsync);

internal async Task<object> BuildSecurityForcedErrorScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Forced-error scan sends malformed JSON to API endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.ForcedErrorScanner.ScanOptions
        {
            MaxEndpoints = body.GetInt("maxEndpoints", 12),
            TimeoutMs = body.GetInt("timeoutMs", 12_000),
            IncludeNetworkDiscovery = body.GetBool("includeNetworkDiscovery", true),
            Urls = body.GetStringArray("urls"),
            Payloads = body.GetStringList("payloads") ?? body.GetStringArray("payloads")
        };

        var result = await Security.ForcedErrorScanner.RunAsync(_context, options);
        return new
        {
            isClean = result.IsClean,
            findingCount = result.Findings.Count,
            endpointsProbed = result.EndpointsProbed,
            endpointsSkipped = result.EndpointsSkipped,
            payloadsUsed = result.PayloadsUsed,
            findings = result.Findings,
            summary = result.Summary
        };
    }

private Task HandlePostSecurityDiscover(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityDiscoverAsync);

internal async Task<object> BuildSecurityDiscoverAsync(JsonBody body)
    {
        var wordlist = body.GetString("wordlist") ?? "common";
        var basePath = body.GetString("basePath") ?? "/";
        var delayMs = body.GetInt("delayMs", 0);
        var spaMode = ResolveDiscoverSpaMode(body);
        var spaProbePath = body.GetString("spaProbePath");

        var scanner = new Security.EndpointScanner(_context);
        var result = await scanner.RunAsync(wordlist, basePath, delayMs, spaMode, spaProbePath);

        var accessibleCount = result.Discovered.Count(d => d.StatusCode is >= 200 and < 300);

        return new
        {
            isClean = accessibleCount == 0,
            accessibleCount,
            scannedCount = result.ScannedCount,
            probeCount = result.ProbeCount,
            discoveredCount = result.DiscoveredCount,
            spaMode = result.SpaMode,
            spaFilteredCount = result.SpaFilteredCount,
            authRedirectFilteredCount = result.AuthRedirectFilteredCount,
            apiEchoCount = result.ApiEchoCount > 0 ? result.ApiEchoCount : (int?)null,
            baselineNote = result.BaselineNote,
            zeroResultReason = result.ZeroResultReason,
            spaBaseline = result.SpaBaseline == null
                ? null
                : new
                {
                    probePath = result.SpaBaseline.ProbePath,
                    statusCode = result.SpaBaseline.StatusCode,
                    contentType = result.SpaBaseline.ContentType,
                    title = result.SpaBaseline.Title,
                    bodyLength = result.SpaBaseline.BodyLength,
                    redirectLocation = result.SpaBaseline.RedirectLocation
                },
            discovered = result.Discovered.Select(d => new
            {
                d.Url,
                d.Path,
                d.Method,
                d.StatusCode,
                d.ContentType,
                responseHeaders = d.ResponseHeaders,
                d.Title,
                d.RedirectLocation,
                d.BodySnippet,
                contentLength = d.ContentLength
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    /// <summary>
    /// Shell filtering is on unless the caller explicitly sets spaMode or baselineFilter to false.
    /// An omitted flag does not override an explicit false on the other alias.
    /// </summary>
    private static bool ResolveDiscoverSpaMode(JsonBody body)
    {
        var hasSpa = body.HasProperty("spaMode");
        var hasAlias = body.HasProperty("baselineFilter");
        if (!hasSpa && !hasAlias)
            return true;
        var spa = hasSpa && body.GetBool("spaMode");
        var alias = hasAlias && body.GetBool("baselineFilter");
        return spa || alias;
    }

private Task HandlePostSecurityAttackSurface(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityAttackSurfaceAsync);

internal async Task<object> BuildSecurityAttackSurfaceAsync(JsonBody body)
    {
        var includeParameters = body.GetBool("includeParameters", true);
        var includeAuth = body.GetBool("includeAuth", true);
        var includeResponsePatterns = body.GetBool("includeResponsePatterns", true);
        var hostFilter = body.GetString("host");
        var includeDataUrls = body.GetBool("includeDataUrls", false);
        var spaMode = body.GetBool("spaMode", false);
        var checkSecurityTxt = body.GetBool("checkSecurityTxt", true);

        var entries = _context.Network.Entries;
        if (entries.Count == 0 && !spaMode)
            throw new ApiCommandException(400,
                "No network traffic captured. Browse the target application first to populate the network log, or set \"spaMode\": true to map inputs/links from the live page (like GET /api/state) without network data.");

        var mapper = new Security.AttackSurfaceMapper();
        var result = mapper.Analyze(
            entries.Count == 0 ? new List<NetworkEntry>() : entries,
            includeParameters, includeAuth, includeResponsePatterns, hostFilter, includeDataUrls);

        var networkLogEmpty = entries.Count == 0;
        result.NetworkLogEmpty = networkLogEmpty;
        if (spaMode)
        {
            var interactive = await _context.GetInteractiveElements();
            var formCount = await _context.GetHtmlFormCountAsync();
            var pageUrl = await _context.GetCurrentUrl();
            var pageTitle = await _context.GetTitle();
            result.SpaRuntime = Security.AttackSurfaceMapper.BuildSpaRuntimeSurface(
                interactive, formCount, pageUrl, pageTitle);
            result.Source = networkLogEmpty ? "dom-only" : "network-log+dom";
        }
        else
        {
            result.Source = "network-log";
        }

        var navUrl = await _context.GetCurrentUrl();

        if (body.GetBool("includeApiEnrichment", true))
        {
            await Security.AttackSurfaceEnrichment.RunAsync(
                result,
                _context,
                entries.Count == 0 ? new List<NetworkEntry>() : entries,
                navUrl,
                new Security.AttackSurfaceEnrichment.Options(
                    IncludeOpenApiFromNetwork: body.GetBool("includeOpenApiFromNetwork", true),
                    IncludeOpenApiProbes: body.GetBool("includeOpenApiProbes", true),
                    IncludeJsBundleHints: body.GetBool("includeJsBundleHints", true),
                    IncludeDevArtifactProbes: body.GetBool("includeDevArtifactProbes", true),
                    MaxProbeOrigins: Math.Clamp(body.GetInt("maxProbeOrigins", 6), 1, 20),
                    MaxScripts: Math.Clamp(body.GetInt("maxJsScripts", 24), 1, 80),
                    MaxBytesPerScript: Math.Clamp(body.GetInt("maxJsBundleBytesPerFile", 524_288), 8192,
                        2_000_000),
                    MaxJsHintPaths: Math.Clamp(body.GetInt("maxJsHintPaths", 200), 16, 2000),
                    HttpTimeoutMs: Math.Clamp(body.GetInt("enrichmentHttpTimeoutMs", 12_000), 3_000, 60_000),
                    MaxWordPressRestRoutes: Math.Clamp(body.GetInt("maxWordPressRestRoutes", 8000), 64, 50_000)),
                _context.OperationCancellation);

            if (result.Enrichment is { Enabled: true })
                result.Source += "+api-discovery";
        }

        if (checkSecurityTxt)
            result.SecurityTxt = await SecurityTxtProbe.CheckCurrentDocumentHostAsync(
                entries.Count == 0 ? new List<NetworkEntry>() : entries,
                navUrl);

        string securityTxtAdvice;
        if (!checkSecurityTxt)
            securityTxtAdvice = "RFC 9116 security.txt probing was skipped (checkSecurityTxt: false).";
        else if (result.SecurityTxt.Count == 0)
        {
            securityTxtAdvice = string.IsNullOrWhiteSpace(navUrl) ||
                                 !Uri.TryCreate(navUrl.Trim(), UriKind.Absolute, out var pu) ||
                                 !pu.Scheme.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? "RFC 9116 probe skipped — no navigated HTTP(S) page URL."
                : "";
        }
        else
        {
            var ok = result.SecurityTxt.Count(static r => r.Found);
            securityTxtAdvice = result.SecurityTxt.Count == 1
                ? ok == 1
                    ? "Current host publishes security.txt — follow published channels before intrusive testing."
                    : "Current host did not expose a valid security.txt — exercise extra caution and responsible disclosure."
                : ok == result.SecurityTxt.Count
                    ? "Every probed host published security.txt — follow published channels before intrusive testing."
                    : ok > 0
                        ? $"{ok}/{result.SecurityTxt.Count} hosts publish security.txt — prefer coordinated disclosure on hosts without a file."
                        : "No valid security.txt on probed origins — exercise extra caution and responsible disclosure.";
        }

        object? apiInventory = null;
        if (body.GetBool("includeApiInventory", true))
        {
            try
            {
                var inventory = await Security.ApiInventoryAnalyzer.AnalyzeAsync(
                    result,
                    _context,
                    new Security.ApiInventoryAnalyzer.AnalyzeOptions
                    {
                        IncludeAuthDeltaProbes = body.GetBool("includeAuthDeltaProbes", false) &&
                                                 SafetyGate.Resolve(body).AllowsWriteVerbs(),
                        MaxAuthDeltaProbes = Math.Clamp(body.GetInt("maxAuthDeltaProbes", 16), 1, 40),
                        AuthDeltaTimeoutMs = Math.Clamp(body.GetInt("authDeltaTimeoutMs", 12_000), 3_000, 60_000)
                    },
                    _context.OperationCancellation);

                if (body.GetBool("registerChainFindings", true))
                {
                    foreach (var finding in Security.ApiInventoryPayload.ToChainFindings(inventory, navUrl))
                        _context.AddManualChainFinding(finding);
                }

                apiInventory = Security.ApiInventoryPayload.Serialize(inventory);
            }
            catch (Exception ex)
            {
                apiInventory = new { isClean = (bool?)null, error = ex.Message };
            }
        }

        return new
        {
            source = result.Source,
            networkLogEmpty = result.NetworkLogEmpty,
            spa = result.SpaRuntime,
            endpoints = result.Endpoints.Select(ep => new
            {
                url = ep.Url,
                displayUrl = Security.AttackSurfaceMapper.FormatDisplayUrl(ep),
                urlTemplate = ep.UrlTemplate,
                methods = ep.Methods.OrderBy(m => m).ToList(),
                parameters = new
                {
                    query = ep.Parameters.Query,
                    body = ep.Parameters.Body,
                    headers = ep.Parameters.Headers,
                    path = ep.Parameters.Path,
                    requestContentType = ep.Parameters.RequestContentType,
                    requestBodySample = ep.Parameters.RequestBodySample
                },
                auth = new
                {
                    required = ep.Auth.Required,
                    type = ep.Auth.Type
                },
                responsePatterns = ep.ResponsePatterns.ToDictionary(
                    kv => kv.Key,
                    kv => new
                    {
                        description = kv.Value.Description,
                        bodySnippet = kv.Value.BodySnippet,
                        bodyHash = kv.Value.BodyHash,
                        bodyLength = kv.Value.BodyLength,
                        count = kv.Value.Count
                    } as object),
                discoveredVia = ep.DiscoveredVia.ToList(),
                testPriority = ep.TestPriority,
                requestCount = ep.RequestCount
            }).ToList(),
            enrichment = result.Enrichment == null
                ? null
                : new
                {
                    enabled = result.Enrichment.Enabled,
                    networkBodiesExamined = result.Enrichment.NetworkLogSpecBodiesExamined,
                    openapiSpecsFromTraffic = result.Enrichment.OpenApiSpecsFromNetworkLog,
                    openapiProbeAttempts = result.Enrichment.OpenApiProbesAttempted,
                    devArtifactProbeAttempts = result.Enrichment.DevArtifactProbesAttempted,
                    devArtifactHits = result.Enrichment.DevArtifactHits,
                    openapiSpecsParsed = result.Enrichment.OpenApiSpecsParsed,
                    wordpressRestIndexesParsed = result.Enrichment.WordPressRestIndexesParsed,
                    openapiSpecSources = result.Enrichment.OpenApiSpecSources,
                    openapiErrors = result.Enrichment.OpenApiErrors,
                    jsScriptsFetched = result.Enrichment.JsScriptsFetched,
                    jsHintEndpoints = result.Enrichment.JsHintUrlsExtracted,
                    jsErrors = result.Enrichment.JsErrors,
                    candidatesMerged = result.Enrichment.EndpointsAddedBeforeMerge
                },
            summary = new
            {
                totalEndpoints = result.Summary.TotalEndpoints,
                authenticated = result.Summary.Authenticated,
                unauthenticated = result.Summary.Unauthenticated,
                highPriority = result.Summary.HighPriority,
                mediumPriority = result.Summary.MediumPriority,
                lowPriority = result.Summary.LowPriority,
                methodDistribution = result.Summary.MethodDistribution,
                hosts = result.Summary.Hosts
            },
            securityTxt = result.SecurityTxt.Select(st => new
            {
                host = st.Host,
                found = st.Found,
                url = st.Url,
                pathKind = st.PathKind,
                originAttempted = st.OriginAttempted,
                statusCode = st.StatusCode,
                error = st.Error
            }).ToList(),
            securityTxtAdvice = securityTxtAdvice,
            apiInventory,
            securityPreflight = BuildSecurityPreflightPayload(entries),
            recommendedNext = BuildAttackSurfaceRecommendedNext(result)
        };
    }

    private static IReadOnlyList<object>? BuildAttackSurfaceRecommendedNext(Security.AttackSurfaceResult result)
    {
        if (result.Summary.TotalEndpoints >= 3)
            return null;

        var steps = new List<object>
        {
            new { summary = "Browse login, search, and API-heavy flows so network log fills", mcp = "browser_navigate", rest = "POST /api/navigate" },
            new { summary = "Re-run with spaMode:true if the app is a thin SPA", mcp = "browser_attack_surface", args = new { spaMode = true, includeApiEnrichment = true } },
            new { summary = "Probe discovered APIs with server-side fetch", mcp = "browser_fetch", rest = "POST /api/fetch" },
            new { summary = "Targeted injection scan on a known URL", mcp = "browser_security_sqli_scan", rest = "POST /api/security/sqli-scan" }
        };
        return steps;
    }

private Task HandlePostSecurityApiInventory(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityApiInventoryAsync);

internal async Task<object> BuildSecurityApiInventoryAsync(JsonBody body)
    {
        try
        {
            var surfaceOptions = await ResolveAttackSurfaceOptionsAsync(body);
            if (!surfaceOptions.SpaMode && _context.Network.Entries.Count == 0)
                throw new ApiCommandException(400,
                    "No network traffic captured. Browse first, set spaMode: true, or run crawl-light.");

            surfaceOptions.SpaMode = surfaceOptions.SpaMode || _context.Network.Entries.Count == 0;

            var inventory = await Security.ApiInventoryPayload.RunForSessionAsync(
                _context,
                surfaceOptions,
                new Security.ApiInventoryAnalyzer.AnalyzeOptions
                {
                    IncludeAuthDeltaProbes = body.GetBool("includeAuthDeltaProbes", false) &&
                                             SafetyGate.Resolve(body).AllowsWriteVerbs(),
                    MaxAuthDeltaProbes = Math.Clamp(body.GetInt("maxAuthDeltaProbes", 16), 1, 40),
                    AuthDeltaTimeoutMs = Math.Clamp(body.GetInt("authDeltaTimeoutMs", 12_000), 3_000, 60_000)
                },
                _context.OperationCancellation);

            if (body.GetBool("registerChainFindings", true))
            {
                var navUrl = await _context.GetCurrentUrl();
                foreach (var finding in Security.ApiInventoryPayload.ToChainFindings(inventory, navUrl))
                    _context.AddManualChainFinding(finding);
            }

            return Security.ApiInventoryPayload.Serialize(inventory);
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"API inventory failed: {ex.Message}");
        }
    }

private Task HandlePostSecurityClickjackTest(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityClickjackTestAsync);

internal async Task<object> BuildSecurityClickjackTestAsync(JsonBody body)
    {
        var safety = SafetyGate.Resolve(body);
        var includeActive = body.GetBool("includeActiveTest", false) ||
                            safety.AllowsWriteVerbs();
        if (includeActive && !safety.AllowsWriteVerbs())
            throw new ApiCommandException(400,
                "Active clickjacking tests inject cross-origin iframes. Set safetyMode: \"active\".");

        var includeSweep = body.GetBool("includeAttackSurfaceUrls", false)
                           || body.GetBool("sweep", false);

        var sweepOptions = new Security.ClickjackSweep.SweepOptions
        {
            Urls = body.GetStringList("urls"),
            IncludeAttackSurfaceUrls = body.GetBool("includeAttackSurfaceUrls", true),
            IncludeDefaultCandidates = body.GetBool("includeDefaultCandidates", true),
            MaxUrls = Math.Clamp(body.GetInt("maxUrls", 12), 1, 30),
            IncludeActiveTest = includeActive,
            IncludeSensitiveOverlayTest = body.GetBool("includeSensitiveOverlayTest", includeActive),
            SensitiveRef = body.HasProperty("sensitiveRef") ? body.GetInt("sensitiveRef") : null,
            TimeoutMs = Math.Clamp(body.GetInt("timeoutMs", 8000), 3000, 30000)
        };

        try
        {
            Security.ClickjackSweep.SweepResult result;
            if (includeSweep)
            {
                result = await Security.ClickjackSweep.RunAsync(_context, sweepOptions);
            }
            else
            {
                var single = await Security.ClickjackTester.RunAsync(
                    _context,
                    new Security.ClickjackTester.TestOptions
                    {
                        IncludeActiveTest = includeActive,
                        IncludeSensitiveOverlayTest = sweepOptions.IncludeSensitiveOverlayTest,
                        SensitiveRef = sweepOptions.SensitiveRef,
                        TimeoutMs = sweepOptions.TimeoutMs
                    });
                result = new Security.ClickjackSweep.SweepResult
                {
                    DocumentUrl = single.DocumentUrl,
                    Document = single.Document,
                    Endpoints = [single.Document]
                };
            }

            if (body.GetBool("registerChainFindings", true))
            {
                foreach (var row in result.Endpoints.Where(e => e.IsVulnerable))
                {
                    _context.AddManualChainFinding(new Security.ChainEngine.ChainableFinding
                    {
                        Id = $"clickjack-{row.Url.GetHashCode():x8}",
                        Source = "clickjack-test",
                        Category = "clickjack-vulnerable",
                        Severity = row.IsSensitivePage ? "high" : "medium",
                        Title = row.IsSensitivePage
                            ? $"Clickjacking on sensitive page: {row.Url}"
                            : $"Missing frame protection: {row.Url}",
                        Detail = row.Active?.Detail ?? row.PassiveFindings.FirstOrDefault()?.Description,
                        Endpoint = row.Url
                    });
                }
            }

            return Security.ClickjackPayload.Serialize(result, includeSweep);
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"Clickjack test failed: {ex.Message}");
        }
    }

private Task HandlePostSecurityCrawlLight(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCrawlLightAsync);

/// <summary>Default SPA-aware crawl unless the caller explicitly sets spaMode.</summary>
private static bool ResolveCrawlLightSpaMode(JsonBody body) =>
    body.HasProperty("spaMode") ? body.GetBool("spaMode") : true;

internal async Task<object> BuildSecurityCrawlLightAsync(JsonBody body)
    {
        var options = new Security.LightSiteCrawler.CrawlOptions
        {
            AllowedHost = body.GetString("host"),
            MaxDepth = Math.Clamp(body.GetInt("maxDepth", 2), 0, 5),
            MaxPages = Math.Clamp(body.GetInt("maxPages", 30), 1, 100),
            FollowLinks = body.GetBool("followLinks", true),
            EnumerateForms = body.GetBool("enumerateForms", true),
            VisitFormActions = body.GetBool("visitFormActions", true),
            DelayMs = Math.Max(0, body.GetInt("delayMs", 200)),
            SpaMode = ResolveCrawlLightSpaMode(body),
            MaxInteractionsPerPage = Math.Clamp(body.GetInt("maxInteractionsPerPage", 20), 1, 50),
            WaitAfterInteractionMs = Math.Max(0, body.GetInt("waitAfterInteractionMs", 400)),
            IncludePaths = body.GetStringList("includePaths") ?? [],
            ExcludePaths = body.GetStringList("excludePaths") ?? [],
            ExcludeUrlPatterns = body.GetStringList("excludeUrlPatterns") ?? [],
            ExcludeLogout = body.GetBool("excludeLogout", true)
        };

        try
        {
            var entriesBefore = _context.Network.Entries.Count;
            var result = await Security.LightSiteCrawler.RunAsync(_context, options);
            return new
            {
                pagesVisited = result.PagesVisited,
                linksDiscovered = result.LinksDiscovered,
                formActionsDiscovered = result.FormActionsDiscovered,
                interactionsPerformed = result.InteractionsPerformed,
                spaMode = options.SpaMode,
                networkEntriesBefore = entriesBefore,
                networkEntriesAfter = result.NetworkEntriesAfter,
                visitedUrls = result.VisitedUrls,
                skippedUrls = result.SkippedUrls,
                skippedCount = result.SkippedUrls.Count,
                excludeLogout = result.ExcludeLogout,
                errors = result.Errors,
                elapsedMs = result.ElapsedMs,
                securityPreflight = BuildSecurityPreflightPayload(_context.Network.Entries)
            };
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"Light crawl failed: {ex.Message}");
        }
    }

private Task HandlePostSecurityMethods(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityMethodsAsync);

internal async Task<object> BuildSecurityMethodsAsync(JsonBody body)
    {
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            var currentUrl = await _context.GetCurrentUrl();
            url = currentUrl;
        }

        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
            throw new ApiCommandException(400, "Missing or invalid URL. Provide a 'url' field or navigate to a page first.");

        var probeResult = await Security.HttpMethodsSecurityProbe.RunAsync(url);

        var results = probeResult.Results.Select(r => new
        {
            method = r.Method,
            status = r.Status,
            statusText = r.StatusText,
            allowed = r.Allowed,
            security = r.Security,
            allowHeader = r.AllowHeader,
            error = r.Error,
        }).ToList();

        return new
        {
            url = probeResult.Url,
            isClean = probeResult.SecurityIssueCount == 0,
            allowedMethods = probeResult.AllowedMethods,
            securityIssueCount = probeResult.SecurityIssueCount,
            securityIssues = probeResult.SecurityIssues,
            results,
        };
    }

private Task HandlePostSecurityNextJsRscScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityNextJsRscScanAsync);

internal async Task<object> BuildSecurityNextJsRscScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Next.js RSC scan sends Flight deserialization payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.NextJsRscScanProbe.NextJsRscScanOptions
        {
            TimeoutMs = body.GetInt("timeoutMs", 6000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RequireNextJsFingerprint = body.GetBool("requireNextJsFingerprint", true)
        };

        try
        {
            var result = await _context.RunNextJsRscScan(options);
            return FormatNextJsRscScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityRaceConditionScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityRaceConditionScanAsync);

internal async Task<object> BuildSecurityRaceConditionScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Race-condition scan fires concurrent POST bursts that may create duplicate resources");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.RaceConditionScanProbe.RaceConditionScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            BurstSize = body.GetInt("burstSize", 15),
            TimeoutMs = body.GetInt("timeoutMs", 8000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            IncludeRedeemCodeBursts = body.GetBool("includeRedeemCodeBursts", true),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunRaceConditionScan(options);
            return FormatRaceConditionScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityRateLimitAudit(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityRateLimitAuditAsync);

internal async Task<object> BuildSecurityRateLimitAuditAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Rate-limit audit sends sequential and concurrent requests to measure throttling");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.RateLimitAuditProbe.RateLimitAuditOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            SequentialAttempts = body.GetInt("sequentialAttempts", 5),
            BurstSize = body.GetInt("burstSize", 8),
            DelayMs = body.GetInt("delayMs", 200),
            TimeoutMs = body.GetInt("timeoutMs", 8000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RespectRateLimits = body.GetBool("respectRateLimits", true),
            IncludeOtpTemplates = body.GetBool("includeOtpTemplates", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunRateLimitAudit(options);
            return FormatRateLimitAuditResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityReDoSScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityReDoSScanAsync);

internal async Task<object> BuildSecurityReDoSScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "ReDoS scan sends regex-heavy payloads to injectable parameters");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.ReDoSScanProbe.ReDoSScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            MaxPayloadsPerCandidate = body.GetInt("maxPayloadsPerCandidate", 3),
            SlowThresholdSeconds = body.GetDouble("slowThresholdSeconds", 3.0),
            TimeoutMs = body.GetInt("timeoutMs", 8000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RespectRateLimits = body.GetBool("respectRateLimits", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunReDoSScan(options);
            return FormatReDoSScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityBodySizeLimitScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityBodySizeLimitScanAsync);

private Task HandlePostSecurityCostlyOperations(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCostlyOperationsAsync);

private Task HandlePostSecuritySwaggering(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySwaggeringAsync);

internal async Task<object> BuildSecuritySwaggeringAsync(JsonBody body)
    {
        var safetyMode = body.HasProperty("safetyMode")
            ? SafetyModeExtensions.Parse(body.GetString("safetyMode"))
            : SafetyMode.Active;
        safetyMode = Trowser.Security.Orchestration.SecurityPreflight.EffectiveMode(safetyMode, null);

        if (safetyMode != SafetyMode.Passive)
        {
            var gateError = SafetyGate.RequireActive(body,
                safetyMode.AllowsWriteVerbs()
                    ? "Swaggering sends HTTP requests to documented API operations"
                    : "Swaggering sends GET probes to documented operations");
            if (gateError != null)
                throw new ApiCommandException(400, gateError.Value);
        }

        var options = new SwaggeringOrchestrator.SwaggeringOptions
        {
            SafetyMode = safetyMode,
            Depth = body.GetString("depth") ?? SwaggeringDepthProfile.Thorough,
            MaxStepSeconds = body.GetInt("maxStepSeconds", 0) is var s && s > 0 ? s : null,
            SpecUrls = body.GetStringArray("specUrls"),
            IncludeSpecsFromNetwork = body.GetBool("includeSpecsFromNetwork", true),
            IncludeOpenApiProbes = body.GetBool("includeOpenApiProbes", true),
            PathPrefix = body.GetString("pathPrefix"),
            IncludeDeprecated = body.GetBool("includeDeprecated", false),
            IncludeDeleteMethods = body.GetBool("includeDeleteMethods", false),
            TimeoutMs = body.GetInt("timeoutMs", 12_000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            IncludeCostlySpecLimits = body.GetBool("includeCostlySpecLimits", true)
        };

        try
        {
            var result = await _context.RunSwaggering(options);
            return FormatSwaggeringResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

    private static bool IsKnownCostlySafetyMode(string? value) =>
        value?.Trim().ToLowerInvariant() is "passive" or "safe" or "active" or "aggressive";

internal async Task<object> BuildSecurityCostlyOperationsAsync(JsonBody body)
    {
        if (body.HasProperty("safetyMode") && !IsKnownCostlySafetyMode(body.GetString("safetyMode")))
            throw new ApiCommandException(400, "safetyMode must be passive, safe, active, or aggressive.");

        var safetyMode = body.HasProperty("safetyMode")
            ? SafetyModeExtensions.Parse(body.GetString("safetyMode"))
            : SafetyMode.Passive;
        safetyMode = Trowser.Security.Orchestration.SecurityPreflight.EffectiveMode(safetyMode, null);

        var checks = body.GetStringArray("checks");
        if (checks is { Count: > 0 })
        {
            var known = new HashSet<string>(
                CostlyOperationsProbe.PassiveCheckIds.Concat(CostlyOperationsProbe.ConfirmCheckIds),
                StringComparer.OrdinalIgnoreCase);
            var unknown = checks
                .Where(c => !string.IsNullOrWhiteSpace(c) && !known.Contains(c.Trim()))
                .Select(c => c.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (unknown.Count > 0)
            {
                throw new ApiCommandException(400,
                    "Unknown checks: " + string.Join(", ", unknown) +
                    ". Valid checks: " + string.Join(", ", known.OrderBy(c => c, StringComparer.OrdinalIgnoreCase)) + ".");
            }
        }

        if (checks is { Count: > 0 }
            && checks.Any(c => CostlyOperationsProbe.ConfirmCheckIds.Contains(c.Trim(), StringComparer.OrdinalIgnoreCase))
            && !safetyMode.AllowsProbes())
        {
            throw new ApiCommandException(400,
                "Bounded confirms require safetyMode 'safe' or higher. Passive mode runs traffic/DOM analysis only.");
        }

        var options = new CostlyOperationsProbe.CostlyOperationsOptions
        {
            SafetyMode = safetyMode,
            Checks = checks,
            MaxCandidates = body.GetInt("maxCandidates", 24),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            MaxResponseBytes = body.GetInt("maxResponseBytes", 2_097_152),
            SlowThresholdMs = body.GetInt("slowThresholdMs", 3000),
            IncludeSpaDom = body.GetBool("includeSpaDom", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RespectRateLimits = body.GetBool("respectRateLimits", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            Urls = body.GetStringArray("urls"),
            IncludeSpecsFromNetwork = body.GetBool("includeSpecsFromNetwork", true),
            SpecUrls = body.GetStringArray("specUrls")
        };

        try
        {
            var result = await _context.RunCostlyOperations(options);
            return FormatCostlyOperationsResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

internal async Task<object> BuildSecurityBodySizeLimitScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Body-size scan sends escalating large payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.BodySizeLimitProbe.BodySizeLimitOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 6),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            RespectRateLimits = body.GetBool("respectRateLimits", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunBodySizeLimitScan(options);
            return FormatBodySizeLimitResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityCaptchaReplayScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCaptchaReplayScanAsync);

internal async Task<object> BuildSecurityCaptchaReplayScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Captcha replay scan submits duplicate feedback/comment rows");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.CaptchaReplayScanProbe.CaptchaReplayScanOptions
        {
            MaxSubmitCandidates = body.GetInt("maxSubmitCandidates", 6),
            TimeoutMs = body.GetInt("timeoutMs", 8000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true)
        };

        try
        {
            var result = await _context.RunCaptchaReplayScan(options);
            return FormatCaptchaReplayScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityWorkflowSkipScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityWorkflowSkipScanAsync);

internal async Task<object> BuildSecurityWorkflowSkipScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Workflow-skip scan POSTs directly to late-stage endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.WorkflowSkipScanProbe.WorkflowSkipScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            TimeoutMs = body.GetInt("timeoutMs", 10000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            TryMinimalBody = body.GetBool("tryMinimalBody", true),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunWorkflowSkipScan(options);
            return FormatWorkflowSkipScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityFailOpenScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityFailOpenScanAsync);

internal async Task<object> BuildSecurityFailOpenScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Fail-open scan replays endpoints without auth and after simulated errors");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            var result = await _context.RunFailOpenScan(new Security.FailOpenScanProbe.ScanOptions
            {
                Urls = body.GetStringArray("urls"),
                MaxEndpoints = body.GetInt("maxEndpoints", 10),
                TimeoutMs = body.GetInt("timeoutMs", 12000),
                IncludeUnauthenticated = body.GetBool("includeUnauthenticated", true),
                IncludeInvalidToken = body.GetBool("includeInvalidToken", true),
                IncludeAfterError = body.GetBool("includeAfterError", true),
                SkipStaticAssets = body.GetBool("skipStaticAssets", true),
                SkipAuthSurfaces = body.GetBool("skipAuthSurfaces", true),
                SkipPublicEndpoints = body.GetBool("skipPublicEndpoints", true),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityAuthControlIdentifier(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityAuthControlIdentifierAsync);

internal async Task<object> BuildSecurityAuthControlIdentifierAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "Auth Control Identifier replays captured requests while omitting/tampering auth cookies, headers, and token fields");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            var endpoints = ParseAuthControlEndpoints(body);
            if (endpoints.Count == 0)
                throw new ApiCommandException(400,
                    "Provide endpoints[] (or a single url/method/headers/body), or ensure the network log has matching traffic.");

            var result = await _context.RunAuthControlIdentifier(new Security.AuthControlIdentifier.ProbeOptions
            {
                Endpoints = endpoints,
                AllHeaders = body.GetBool("allHeaders", false),
                IncludeBodyFields = body.GetBool("includeBodyFields", true),
                IncludeQueryFields = body.GetBool("includeQueryFields", true),
                TimeoutMs = body.GetInt("timeoutMs", 12000)
            });

            return new
            {
                endpointsProbed = result.EndpointsProbed,
                candidatesTested = result.CandidatesTested,
                requestsSent = result.RequestsSent,
                endpointSummaries = result.EndpointSummaries.Select(e => new
                {
                    method = e.Method,
                    url = e.Url,
                    candidatesTested = e.CandidatesTested,
                    inconclusive = e.Inconclusive,
                    warning = e.Warning
                }).ToList(),
                summary = result.Summary,
                consistency = result.Consistency.Select(c => new
                {
                    kind = c.Kind,
                    name = c.Name,
                    verdict = c.Verdict,
                    endpointCount = c.EndpointCount,
                    matchingCount = c.MatchingCount,
                    summary = c.Summary
                }).ToList(),
                candidates = result.Candidates.Select(c => new
                {
                    method = c.Method,
                    url = c.Url,
                    kind = c.Candidate.Kind.ToString().ToLowerInvariant(),
                    name = c.Candidate.Name,
                    originalValue = TruncateAuthValue(c.Candidate.OriginalValue),
                    verdict = Security.AuthControlIdentifier.ToVerdictLabel(c.Verdict),
                    cookieFlagWarning = c.CookieFlagWarning,
                    omit = c.Omit == null ? null : new
                    {
                        status = c.Omit.Status,
                        bodiesMatchBaseline = c.Omit.BodiesMatchBaseline,
                        responseChanged = c.Omit.ResponseChanged
                    },
                    tamper = c.Tamper == null ? null : new
                    {
                        status = c.Tamper.Status,
                        bodiesMatchBaseline = c.Tamper.BodiesMatchBaseline,
                        responseChanged = c.Tamper.ResponseChanged,
                        tamperedValue = TruncateAuthValue(c.Tamper.TamperedValue)
                    }
                }).ToList(),
                rows = result.Rows.Select(r => new
                {
                    method = r.Method,
                    url = r.Url,
                    kind = r.Kind,
                    name = r.Name,
                    mutation = r.Mutation,
                    baselineStatus = r.BaselineStatus,
                    probeStatus = r.ProbeStatus,
                    bodiesMatch = r.BodiesMatch,
                    responseChanged = r.ResponseChanged,
                    verdict = r.Verdict,
                    originalValue = r.OriginalValue,
                    mutatedValue = r.MutatedValue,
                    cookieFlagWarning = r.CookieFlagWarning
                }).ToList()
            };
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private List<EndpointProbeItem> ParseAuthControlEndpoints(JsonBody body)
{
    var endpoints = new List<EndpointProbeItem>();

    if (body.RootElement.ValueKind == JsonValueKind.Object
        && body.RootElement.TryGetProperty("endpoints", out var arr)
        && arr.ValueKind == JsonValueKind.Array)
    {
        foreach (var ep in arr.EnumerateArray())
        {
            var item = ParseAuthControlEndpointElement(ep);
            if (item != null)
                endpoints.Add(item);
        }
    }

    // Single-request shorthand
    var singleUrl = body.GetString("url");
    if (!string.IsNullOrWhiteSpace(singleUrl))
    {
        Dictionary<string, string>? headers = null;
        if (body.RootElement.ValueKind == JsonValueKind.Object
            && body.RootElement.TryGetProperty("headers", out var h))
            headers = ParseHeadersFromJson(h);

        endpoints.Add(new EndpointProbeItem
        {
            Method = body.GetString("method") ?? "GET",
            Url = singleUrl,
            RequestHeaders = headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            RequestBody = body.GetString("body")
        });
    }

    if (endpoints.Count > 0)
    {
        return endpoints.Select(e => EnrichAuthControlEndpointFromNetworkLog(e, _context.Network.Entries)).ToList();
    }

    // Fall back to recent same-origin API-like traffic from the network log
    var maxFromLog = body.GetInt("maxEndpoints", 5);
    var fromLog = EndpointProbeDiscovery.FromNetworkLog(_context.Network.Entries)
        .Take(Math.Clamp(maxFromLog, 1, 25))
        .ToList();
    return fromLog;
}

private static EndpointProbeItem EnrichAuthControlEndpointFromNetworkLog(
    EndpointProbeItem item,
    IReadOnlyList<Automation.NetworkEntry> entries)
{
    var match = entries
        .Where(e => e.Method.Equals(item.Method, StringComparison.OrdinalIgnoreCase)
                    && e.Url.Equals(item.Url, StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(e => e.Timestamp)
        .FirstOrDefault();
    if (match == null)
        return item;

    var headers = item.RequestHeaders.Count > 0
        ? new Dictionary<string, string>(item.RequestHeaders, StringComparer.OrdinalIgnoreCase)
        : new Dictionary<string, string>(match.RequestHeaders, StringComparer.OrdinalIgnoreCase);

    return new EndpointProbeItem
    {
        Method = item.Method,
        Url = item.Url,
        RequestHeaders = headers,
        RequestBody = item.RequestBody ?? match.RequestBody,
        Priority = item.Priority,
        StatusCode = item.StatusCode,
        ResourceType = item.ResourceType
    };
}

private static EndpointProbeItem? ParseAuthControlEndpointElement(JsonElement ep)
{
    if (ep.ValueKind == JsonValueKind.String)
    {
        var url = ep.GetString();
        if (string.IsNullOrWhiteSpace(url)) return null;
        return new EndpointProbeItem
        {
            Method = "GET",
            Url = url,
            RequestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };
    }

    if (ep.ValueKind != JsonValueKind.Object) return null;
    var u = ep.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null;
    if (string.IsNullOrWhiteSpace(u)) return null;

    Dictionary<string, string>? headers = null;
    if (ep.TryGetProperty("headers", out var h))
        headers = ParseHeadersFromJson(h);

    string? fetchBody = null;
    if (ep.TryGetProperty("body", out var b))
        fetchBody = b.ValueKind == JsonValueKind.String ? b.GetString() : b.GetRawText();
    else if (ep.TryGetProperty("json", out var j))
    {
        fetchBody = j.GetRawText();
        headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        headers.TryAdd("Content-Type", "application/json");
    }

    return new EndpointProbeItem
    {
        Method = ep.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
        Url = u,
        RequestHeaders = headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        RequestBody = fetchBody
    };
}

private static string? TruncateAuthValue(string? value)
{
    if (string.IsNullOrEmpty(value)) return value;
    return value.Length <= 64 ? value : value[..61] + "...";
}

private Task HandlePostSecurityMissingParameterScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityMissingParameterScanAsync);

internal async Task<object> BuildSecurityMissingParameterScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Missing-parameter scan omits JSON fields on captured POST bodies");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            var result = await _context.RunMissingParameterScan(new Security.MissingParameterScanProbe.ScanOptions
            {
                Urls = body.GetStringArray("urls"),
                MaxEndpoints = body.GetInt("maxEndpoints", 8),
                MaxFieldsPerEndpoint = body.GetInt("maxFieldsPerEndpoint", 8),
                TimeoutMs = body.GetInt("timeoutMs", 12000),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityAuthBypassPivot(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityAuthBypassPivotAsync);

internal async Task<object> BuildSecurityAuthBypassPivotAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Auth bypass pivot may attempt SQLi login bypass");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        return await Security.AuthenticatedPivotService.RunAsync(_context, new Security.AuthenticatedPivotService.PivotOptions
        {
            Host = body.GetString("host"),
            Token = body.GetString("token"),
            MaxEndpoints = body.GetInt("maxEndpoints", 20),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            TrySqliLoginBypass = body.GetBool("trySqliLoginBypass", true),
            LoginUrl = body.GetString("loginUrl"),
            AuthMode = body.GetString("authMode"),
            CookieName = body.GetString("cookieName")
        });
    }

private Task HandlePostSecurityRestScaffold(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityRestScaffoldAsync);

internal async Task<object> BuildSecurityRestScaffoldAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "REST scaffold probes send unauthenticated requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            var result = await Security.RestScaffoldProbes.RunAsync(_context, new Security.RestScaffoldProbes.ScaffoldOptions
            {
                BaseUrl = body.GetString("baseUrl"),
                TimeoutMs = body.GetInt("timeoutMs", 12000),
                MaxPaths = body.GetInt("maxPaths", 24),
                Paths = body.GetStringList("paths") ?? body.GetStringArray("paths")?.ToList(),
                IncludeHead = body.GetBool("includeHead", true)
            });
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityPathFilterBypass(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityPathFilterBypassAsync);

internal async Task<object> BuildSecurityPathFilterBypassAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Path-filter bypass probes fetch directory paths");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        try
        {
            var pathBases = body.GetStringList("pathBases")
                            ?? body.GetStringList("bases")
                            ?? body.GetStringArray("pathBases")?.ToList()
                            ?? body.GetStringArray("bases")?.ToList();
            var result = await Security.PathFilterBypassChecker.RunAsync(_context, new Security.PathFilterBypassChecker.BypassOptions
            {
                BasePath = body.GetString("basePath"),
                PathBases = pathBases,
                Bases = pathBases,
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                MaxBases = body.GetInt("maxBases", 8)
            });
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, ex.Message);
        }
    }

private Task HandlePostSecurityHarvestIds(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityHarvestIdsAsync);

internal async Task<object> BuildSecurityHarvestIdsAsync(JsonBody body)
    {
        return await Security.ObjectIdHarvester.RunAsync(_context, new Security.ObjectIdHarvester.HarvestOptions
        {
            Host = body.GetString("host"),
            MaxIdsPerKind = body.GetInt("maxIdsPerKind", 12),
            IncludeDom = body.GetBool("includeDom", true)
        });
    }

private Task HandlePostSecurityBruteForce(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityBruteForceAsync);

internal async Task<object> BuildSecurityBruteForceAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Brute-force probe sends repeated login attempts");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var loginUrl = body.GetString("loginUrl") ?? body.GetString("url");
        if (string.IsNullOrWhiteSpace(loginUrl))
            throw new ApiCommandException(400, "loginUrl (or url) is required.");

        var method = body.GetString("method") ?? "POST";
        var headers = body.GetStringDictionary("headers");
        var bodyTemplate = body.GetString("body");
        if (string.IsNullOrEmpty(bodyTemplate) && body.HasProperty("json"))
        {
            var je = body.GetJsonElement("json");
            if (je != null) bodyTemplate = je.Value.GetRawText();
        }

        var passMarker = body.GetString("passwordPlaceholder") ?? "{{PASSWORD}}";
        var userMarker = body.GetString("usernamePlaceholder") ?? "{{USERNAME}}";
        var wrongPassword = body.GetString("wrongPassword") ?? "TrowserWrongPass-" + Guid.NewGuid().ToString("N")[..12];
        var attempts = body.GetInt("attempts", 6);
        var delayMs = body.GetInt("delayMs", 75);
        var timeoutMs = body.GetInt("timeoutMs", 15000);
        var usernames = body.GetStringArray("usernames");
        var passwords = body.GetStringArray("passwords");

        Security.HttpSecurityProbes.BruteForceResult result;
        if (usernames is { Count: > 0 })
        {
            delayMs = Math.Clamp(delayMs, 50, 2000);
            if (usernames.Count > 25)
                throw new ApiCommandException(400, "Password spray supports at most 25 usernames per request.");

            result = await Security.HttpSecurityProbes.RunPasswordSprayAsync(
                _context, loginUrl, method, headers, bodyTemplate, userMarker, passMarker,
                usernames, passwords ?? [], delayMs, timeoutMs);
        }
        else
        {
            result = await Security.HttpSecurityProbes.RunBruteForceAsync(
                _context, loginUrl, method, headers, bodyTemplate, passMarker, wrongPassword, attempts, delayMs, timeoutMs);
        }

        return new
        {
            result.LockoutOrRateLimitSuspected,
            result.SprayMode,
            result.PerUserLockoutSuspected,
            result.SuccessCount,
            observations = result.Observations,
            attempts = result.Attempts.Select(a => new { a.Index, a.Status, a.BodyLength, a.DurationMs, a.BodySnippet }),
            sprayRows = result.SprayRows.Select(r => new { r.Username, r.Status, r.BodyLength, r.DurationMs, r.SuccessSuspected, r.BodySnippet })
        };
    }

private Task HandlePostSecurityIdorScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityIdorScanAsync);

internal async Task<object> BuildSecurityIdorScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "IDOR scan requests multiple resource IDs");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var reqObj = body.GetObject("request");
        if (reqObj == null)
            throw new ApiCommandException(400, "Missing 'request' with url and optional method, headers, body (exactly one §id§ or {{id}} marker).");

        var req = new JsonBody(reqObj);
        var url = req.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
            throw new ApiCommandException(400, "request.url is required.");

        var method = req.GetString("method") ?? "GET";
        var headers = req.GetStringDictionary("headers");
        string? bodyTemplate = null;
        if (req.HasProperty("body"))
            bodyTemplate = req.GetString("body");
        else if (req.HasProperty("json"))
        {
            var je = req.GetJsonElement("json");
            if (je != null) bodyTemplate = je.Value.GetRawText();
        }

        var ids = body.GetStringArray("ids");
        if (ids == null || ids.Count == 0)
            ids = ["1", "2", "999999", "0"];
        var timeoutMs = body.GetInt("timeoutMs", 15000);
        var methodsList = body.GetStringList("methods") ?? body.GetStringArray("methods");
        var inferMethods = body.HasProperty("inferMethodsFromNetwork") ? body.GetBool("inferMethodsFromNetwork") : true;
        var dryRun = body.GetBool("dryRun", false);
        var safeDefaults = body.GetBool("safeDefaults", false);

        var eff = SecurityProbeSafety.ResolveIdor(
            body.HasProperty("includeMutatingProbes"),
            body.GetBool("includeMutatingProbes"),
            body.HasProperty("readOnlyProbes"),
            body.GetBool("readOnlyProbes"),
            safeDefaults,
            dryRun);

        try
        {
            var result = await Security.HttpSecurityProbes.RunIdorScanAsync(
                _context, url, method, headers, bodyTemplate, ids, timeoutMs,
                methodsList, inferMethods, eff.IncludeMutatingProbes, eff.ReadOnlyProbes, eff.DryRun);
            return new
            {
                warnings = eff.Warnings.Count > 0 ? eff.Warnings : null,
                dryRun = result.DryRun,
                plannedRequests = result.DryRun ? result.PlannedRequests : null,
                summary = result.Summary,
                rows = result.Rows.Select(r => new { r.Id, r.Method, r.Url, r.Status, r.BodyLength, r.Fingerprint, r.StrippedEvidenceHash, bodySample = r.BodySample })
            };
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityMassAssignmentScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityMassAssignmentScanAsync);

internal async Task<object> BuildSecurityMassAssignmentScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Mass assignment scan sends crafted JSON or form fields to your API");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var reqObj = body.GetObject("request");
        if (reqObj == null)
            throw new ApiCommandException(400, "Missing 'request' with url, method, headers?, and body or json (JSON object or application/x-www-form-urlencoded).");

        var req = new JsonBody(reqObj);
        var url = req.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
            throw new ApiCommandException(400, "request.url is required.");

        var method = req.GetString("method") ?? "POST";
        var headers = req.GetStringDictionary("headers");
        string? jsonBody = null;
        if (req.HasProperty("body"))
            jsonBody = req.GetString("body");
        else if (req.HasProperty("json"))
            jsonBody = req.GetRawJson("json");
        if (string.IsNullOrWhiteSpace(jsonBody))
            throw new ApiCommandException(400, "request.json or request.body is required (JSON object or application/x-www-form-urlencoded).");

        var privileged = body.GetStringList("privilegedFields") ?? body.GetStringArray("privilegedFields");
        var timeoutMs = body.GetInt("timeoutMs", 15000);
        var verifyPersistence = body.GetBool("verifyPersistence", false);
        var verifyFetchUrl = body.GetString("verifyFetchUrl");
        var verifyFetchMethod = body.GetString("verifyFetchMethod") ?? "GET";

        try
        {
            var result = await Security.MassAssignmentProbes.RunAsync(
                _context, url, method, headers, jsonBody, privileged, timeoutMs,
                verifyPersistence, verifyFetchUrl, verifyFetchMethod);
            return new
            {
                baselineStatus = result.BaselineStatus,
                baselineBodySample = result.BaselineBodySample,
                bodyKind = result.BodyKind,
                fieldsTested = result.FieldsTested,
                summary = result.Summary,
                probes = result.Probes.Select(p => new
                {
                    p.Field,
                    p.InjectedValue,
                    p.Status,
                    p.ValueReflected,
                    p.ValuePersisted,
                    p.Evidence,
                    p.VerifyFetchUrl,
                    p.BodySnippet
                })
            };
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityMassAssignmentPatch(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityMassAssignmentPatchAsync);

internal async Task<object> BuildSecurityMassAssignmentPatchAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "PATCH/PUT self-promote probe mutates profile data");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        return await Security.MassAssignmentExtendedProbes.RunPrivilegeEscalationPatchAsync(
            _context, new Security.MassAssignmentExtendedProbes.PatchProbeOptions
            {
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                MaxFields = body.GetInt("maxFields", 8)
            });
    }

private Task HandlePostSecurityMassAssignmentRegister(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityMassAssignmentRegisterAsync);

internal async Task<object> BuildSecurityMassAssignmentRegisterAsync(JsonBody body)
    {
        if (SafetyGate.RequireActive(body, "Registration scaffold creates user accounts") is { } regGate)
            throw new ApiCommandException(400, regGate);
        if (!body.GetBool("confirmDestructive", false))
            throw new ApiCommandException(400,
                "Registration scaffold creates user accounts. Set safetyMode: \"active\" and confirmDestructive: true.");

        return await Security.MassAssignmentExtendedProbes.RunRegistrationScaffoldAsync(
            _context, new Security.MassAssignmentExtendedProbes.RegisterScaffoldOptions
            {
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                MaxPaths = body.GetInt("maxPaths", 6),
                Paths = body.GetStringArray("paths")
            });
    }

private Task HandlePostSecurityBflaProbe(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityBflaProbeAsync);

internal async Task<object> BuildSecurityBflaProbeAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "BFLA probe sends POST/PUT to admin endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        List<Security.AttackSurfaceEndpoint>? endpoints = null;
        if (body.GetBool("discoverFromAttackSurface", true))
        {
            var surface = _context.CheckAttackSurface(hostFilter: body.GetString("host"));
            endpoints = surface.Endpoints;
        }

        return await Security.BflaAdminProbe.RunAsync(_context, new Security.BflaAdminProbe.ProbeOptions
        {
            BaseUrl = body.GetString("baseUrl"),
            TimeoutMs = body.GetInt("timeoutMs", 12000),
            MaxEndpoints = body.GetInt("maxEndpoints", 12),
            AdminPaths = body.GetStringArray("adminPaths"),
            Endpoints = endpoints,
            DiscoverFromAttackSurface = body.GetBool("discoverFromAttackSurface", true)
        });
    }

private Task HandlePostSecurityResponseFieldDiff(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityResponseFieldDiffAsync);

internal async Task<object> BuildSecurityResponseFieldDiffAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Response field diff probe fetches endpoints as two identities");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var low = body.GetString("lowPrivilegeIdentity") ?? body.GetString("userIdentity");
        var high = body.GetString("highPrivilegeIdentity") ?? body.GetString("adminIdentity");
        if (string.IsNullOrWhiteSpace(low) || string.IsNullOrWhiteSpace(high))
            throw new ApiCommandException(400, "lowPrivilegeIdentity and highPrivilegeIdentity are required (captured identity names).");

        List<Security.AttackSurfaceEndpoint>? surface = null;
        if (body.GetBool("discoverFromAttackSurface", true))
        {
            var map = _context.CheckAttackSurface(hostFilter: body.GetString("host"));
            surface = map.Endpoints;
        }

        return await Security.ResponseFieldDiffProbe.RunAsync(_context, _identityStore,
            new Security.ResponseFieldDiffProbe.DiffOptions
            {
                LowPrivilegeIdentity = low!,
                HighPrivilegeIdentity = high!,
                Endpoints = body.GetStringArray("endpoints"),
                AttackSurface = surface,
                MaxEndpoints = body.GetInt("maxEndpoints", 10),
                TimeoutMs = body.GetInt("timeoutMs", 15000)
            });
    }

private Task HandlePostSecurityAutoScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityAutoScanAsync);

internal async Task<object> BuildSecurityAutoScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Auto-scan runs active security probes against discovered endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var safeDefaults = body.GetBool("safeDefaults", false);
        var cliSafeProbes = App.Api.SafeSecurityProbesOnly;
        var mcpBudgetCap = body.GetBool("mcpBudgetCap", false);

        bool includeJwtSweep;
        if (body.HasProperty("includeJwtAcceptanceSweep"))
        {
            includeJwtSweep = body.GetBool("includeJwtAcceptanceSweep", false);
        }
        else
        {
            var mapper = new Security.AttackSurfaceMapper();
            var surface = mapper.Analyze(_context.Network.Entries, includeAuth: true, hostFilter: body.GetString("host"));
            includeJwtSweep = surface.Endpoints.Any(e => e.Auth.Required);
        }

        var options = new Security.AutoScanPipeline.AutoScanOptions
        {
            Host = body.GetString("host"),
            ExcludeThirdParty = body.GetBool("excludeThirdParty", true),
            MaxEndpointsPerScanner = body.GetInt("maxEndpointsPerScanner", 5),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeSqli = body.GetBool("includeSqli", true),
            IncludeIdor = body.GetBool("includeIdor", true),
            IncludeCsrf = body.GetBool("includeCsrf", true),
            IncludePathTraversal = body.GetBool("includePathTraversal", true),
            IncludeSsrf = body.GetBool("includeSsrf", true),
            IncludeOpenRedirect = body.GetBool("includeOpenRedirect", true),
            IncludeCacheDeception = body.GetBool("includeCacheDeception", true),
            IncludeCacheMap = body.GetBool("includeCacheMap", true),
            IncludeSsti = body.GetBool("includeSsti", true),
            IncludeXss = body.GetBool("includeXss", true),
            IncludeXssDom = body.GetBool("includeXssDom", true),
            IncludeXssStored = body.GetBool("includeXssStored", true),
            IncludeCsti = body.HasProperty("includeCsti") ? body.GetBool("includeCsti") : null,
            IncludeParserProbe = body.HasProperty("includeParserProbe")
                ? body.GetBool("includeParserProbe")
                : null,
            ConfirmBackend = true,
            IncludeDeserializationScan = body.GetBool("includeDeserializationScan", true),
            IncludeFileUploadScan = body.GetBool("includeFileUploadScan", true),
            IncludeNextJsRscScan = body.HasProperty("includeNextJsRscScan")
                ? body.GetBool("includeNextJsRscScan")
                : null,
            IncludeCmdCanary = body.GetBool("includeCmdCanary", true),
            IncludeNosql = body.GetBool("includeNosql", true),
            IncludeLdap = body.GetBool("includeLdap", true),
            IncludeSstiPolyglot = body.GetBool("includeSstiPolyglot", true),
            IncludeSstiStored = body.GetBool("includeSstiStored", true),
            IncludePrototypePollution = body.GetBool("includePrototypePollution", true),
            IncludeSqliLoginSweep = body.GetBool("includeSqliLoginSweep", true),
            ScanDepth = body.GetString("scanDepth")
                ?? (mcpBudgetCap ? AutoScanDepthProfile.Quick : AutoScanDepthProfile.Standard),
            PayloadProfile = PayloadProfileExtensions.Parse(body.GetString("payloadProfile")),
            // 0 → depth profile default (quick=120s, standard=300s, thorough=900s). Explicit value overrides.
            MaxStepSeconds = body.GetInt("maxStepSeconds", 0),
            SparseInjectionThreshold = body.GetInt("sparseInjectionThreshold", InjectionScaffold.DefaultSparseThreshold),
            IncludeApiEnrichment = body.GetBool("includeApiEnrichment", true),
            IncludeMassAssignment = body.GetBool("includeMassAssignment", true),
            MinPriority = body.GetString("minPriority"),
            IncludeJsonApiProbing = body.GetBool("includeJsonApiProbing", true),
            IncludeCsrfCorrelations = body.GetBool("includeCsrfCorrelations", true),
            IncludeChainAnalysis = body.GetBool("includeChainAnalysis", false),
            MinChainedSeverity = body.GetString("minChainedSeverity"),
            IncludePartialChains = body.GetBool("includePartial", true),
            IncludeIdorMutatingProbes = body.HasProperty("includeIdorMutatingProbes")
                ? body.GetBool("includeIdorMutatingProbes")
                : App.Api.DangerousSecurityProbesOk,
            IdorReadOnlyProbes = body.HasProperty("idorReadOnlyProbes") && body.GetBool("idorReadOnlyProbes"),
            FindingsMode = body.GetString("findingsMode") ?? "append",
            SummarizeFindings = body.GetBool("summarizeFindings", true),
            IncludeJwtAcceptanceSweep = includeJwtSweep,
            IncludeRestScaffold = body.GetBool("includeRestScaffold", false),
            RestScaffoldSparseThreshold = body.GetInt("restScaffoldSparseThreshold", 3),
            IncludePathFilterBypass = body.GetBool("includePathFilterBypass", false),
            IncludeAuthBypassPivot = body.GetBool("includeAuthBypassPivot", false),
            MassAssignmentVerifyPersistence = body.GetBool("massAssignmentVerifyPersistence", false),
            IncludeMassAssignmentPatch = body.GetBool("includeMassAssignmentPatch", false),
            IncludeMassAssignmentRegister = body.GetBool("includeMassAssignmentRegister", false),
            IncludeBflaAdminProbe = body.GetBool("includeBflaAdminProbe", true)
        };

        var safetyWarnings = new List<string>();
        if (cliSafeProbes)
            safetyWarnings.Add(
                "Instance started with --safe-probes-only: IDOR mutating probes disabled, IDOR limited to GET/HEAD/OPTIONS, mass-assignment scanner skipped (CLI overrides JSON).");

        if (safeDefaults && !cliSafeProbes)
            safetyWarnings.Add(
                "safeDefaults: IDOR mutating probes disabled, IDOR limited to read-only HTTP verbs, mass-assignment scanner skipped.");

        if (cliSafeProbes || safeDefaults)
        {
            options.IncludeIdorMutatingProbes = false;
            options.IdorReadOnlyProbes = true;
            options.IncludeMassAssignment = false;
            options.IncludeMassAssignmentRegister = false;
            options.IncludeMassAssignmentPatch = false;
            options.IncludeBflaAdminProbe = false;
        }

        var customProbesEl = body.GetJsonElement("customProbes");
        if (customProbesEl is { } cpEl && cpEl.ValueKind == JsonValueKind.Array)
        {
            options.CustomProbes = new List<Security.AutoScanPipeline.CustomProbe>();
            foreach (var p in cpEl.EnumerateArray())
            {
                var probe = new Security.AutoScanPipeline.CustomProbe
                {
                    Name = p.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                    Url = p.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                    Method = p.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
                    Body = p.TryGetProperty("body", out var b2) ? b2.GetString() : null,
                    Severity = p.TryGetProperty("severity", out var sv) ? sv.GetString() ?? "medium" : "medium"
                };
                if (p.TryGetProperty("headers", out var hdr) && hdr.ValueKind == JsonValueKind.Object)
                {
                    probe.Headers = new Dictionary<string, string>();
                    foreach (var kv in hdr.EnumerateObject()) probe.Headers[kv.Name] = kv.Value.GetString() ?? "";
                }
                if (p.TryGetProperty("expectStatus", out var es) && es.ValueKind == JsonValueKind.Number)
                    probe.ExpectStatus = es.GetInt32();
                if (p.TryGetProperty("failIfBodyContains", out var fc))
                    probe.FailIfBodyContains = fc.GetString();
                if (p.TryGetProperty("failIfBodyMissing", out var fm))
                    probe.FailIfBodyMissing = fm.GetString();
                if (p.TryGetProperty("failIfStatusRange", out var fr))
                    probe.FailIfStatusRange = fr.GetString();
                options.CustomProbes.Add(probe);
            }
        }

        ApplyAutoScanDepthApiPresets(options, body);

        if (Security.AutoScanDepthProfile.Normalize(options.ScanDepth) == Security.AutoScanDepthProfile.Quick
            && options.MaxStepSeconds > 120)
        {
            safetyWarnings.Add(
                $"scanDepth=quick with maxStepSeconds={options.MaxStepSeconds} may outlast typical REST client timeouts (~120–150s); prefer <=120 for agent-driven calls (response includes budgetExhausted when the step budget fires).");
        }

        if (mcpBudgetCap)
        {
            const int mcpDefaultCap = 75;
            if (!body.HasProperty("maxStepSeconds") || options.MaxStepSeconds <= 0 || options.MaxStepSeconds > mcpDefaultCap)
            {
                options.MaxStepSeconds = mcpDefaultCap;
                safetyWarnings.Add(
                    $"MCP auto-scan budget: maxStepSeconds capped at {mcpDefaultCap}s to reduce client timeout (-32001). " +
                    "Pass maxStepSeconds explicitly or use REST for long standard/thorough scans.");
            }

            if (!body.HasProperty("scanDepth"))
            {
                safetyWarnings.Add(
                    "MCP auto-scan defaults to scanDepth=quick (injection + access-control first). Pass scanDepth=standard or thorough for full coverage.");
            }
        }

        try
        {
            var result = await Security.AutoScanPipeline.RunAsync(
                _context, options, ct: _context.OperationCancellation, chainCatalog: _chainCatalog);
            object? cryptographicFailures = null;
            if (body.GetBool("includeCryptographicFailures", false))
            {
                cryptographicFailures = await SafeRunAuditAsync(
                    () => BuildCryptographicFailuresAuditPayloadAsync(body),
                    "Cryptographic failures");
            }

            return new
            {
                warnings = safetyWarnings.Count > 0 ? safetyWarnings : null,
                scanDepth = result.ScanDepth,
                payloadProfile = options.PayloadProfile.ToLabel(),
                // Lets operators tell whether payloadProfile=big actually loaded external corpora or
                // silently fell back to the built-in ("small") catalogs because corpora were absent.
                corporaAvailable = Security.PayloadCatalog.CorporaAvailable,
                maxStepSeconds = options.MaxStepSeconds,
                budgetExhausted = result.BudgetExhausted,
                partial = result.Partial || result.BudgetExhausted,
                timestamp = result.Timestamp,
                endpointsDiscovered = result.EndpointsDiscovered,
                endpointsScanned = result.EndpointsScanned,
                scannersRun = result.ScannersRun,
                scannersSkipped = result.ScannersSkipped,
                findingsCount = result.Findings.Count,
                findings = result.Findings.Select(f => new
                {
                    f.Scanner,
                    f.Severity,
                    url = f.Endpoint,
                    description = f.Detail,
                    f.Endpoint,
                    f.Method,
                    f.Title,
                    evidence = string.IsNullOrEmpty(f.Evidence) ? null : f.Evidence,
                    detail = f.Detail,
                    occurrences = f.Occurrences > 1 ? f.Occurrences : (int?)null,
                    nextActions = f.NextActions.Count > 0 ? f.NextActions : null
                }).ToList(),
                skippedEndpoints = result.SkippedEndpoints.Select(s => new
                {
                    s.Endpoint,
                    s.Scanner,
                    s.Reason
                }).ToList(),
                attackSurfaceSummary = result.AttackSurfaceSummary == null ? null : new
                {
                    totalEndpoints = result.AttackSurfaceSummary.TotalEndpoints,
                    authenticated = result.AttackSurfaceSummary.Authenticated,
                    unauthenticated = result.AttackSurfaceSummary.Unauthenticated,
                    highPriority = result.AttackSurfaceSummary.HighPriority,
                    mediumPriority = result.AttackSurfaceSummary.MediumPriority,
                    lowPriority = result.AttackSurfaceSummary.LowPriority,
                    methodDistribution = result.AttackSurfaceSummary.MethodDistribution,
                    hosts = result.AttackSurfaceSummary.Hosts
                },
                errors = result.Errors,
                agentNotes = result.AgentNotes.Count > 0 ? result.AgentNotes : null,
                sparseInjectionScaffold = result.SparseInjectionScaffold ? true : (bool?)null,
                elapsedMs = result.ElapsedMs,
                correlations = result.Correlations.Select(c => new
                {
                    id = c.Id,
                    severity = c.Severity,
                    title = c.Title,
                    description = c.Description,
                    relatedTools = c.RelatedTools,
                    fieldName = c.FieldName,
                    url = c.Url,
                }).ToList(),
                chainAnalysis = result.ChainAnalysis == null
                    ? null
                    : ChainAnalysisService.BuildAnalyzePayload(result.ChainAnalysis),
                cryptographicFailures
            };
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"Auto-scan failed: {ex.Message}");
        }
    }

    private static void ApplyAutoScanDepthApiPresets(Security.AutoScanPipeline.AutoScanOptions options, JsonBody body)
    {
        if (AutoScanDepthProfile.Normalize(options.ScanDepth) == AutoScanDepthProfile.Thorough)
            return;

        if (!body.HasProperty("includeCacheDeception"))
            options.IncludeCacheDeception = false;
        if (!body.HasProperty("includeDeserializationScan"))
            options.IncludeDeserializationScan = false;
        if (!body.HasProperty("includeFileUploadScan"))
            options.IncludeFileUploadScan = false;

        if (AutoScanDepthProfile.Normalize(options.ScanDepth) == AutoScanDepthProfile.Quick
            && !body.HasProperty("includeCsrfCorrelations"))
            options.IncludeCsrfCorrelations = false;
    }

private Task HandlePostSecuritySecretsHarvest(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySecretsHarvestAsync);

internal async Task<object> BuildSecuritySecretsHarvestAsync(JsonBody body)
    {
        // Purely passive sources (cookies/storage, captured network log, page text/HTML comments) run under
        // safe mode. Fetching *additional* JS bundles and source maps makes new outbound requests, so those
        // are gated behind active/aggressive (matching the audit-all pipeline).
        var safety = SafetyGate.Resolve(body);
        if (!safety.AllowsProbes())
        {
            var gateError = SafetyGate.RequireAtLeast(safety, SafetyMode.Safe,
                "Secrets harvest reads cookies, storage, network log, and page text (passive); active also fetches JS bundles and source maps");
            if (gateError != null)
                throw new ApiCommandException(400, gateError.Value);
        }

        var allowActiveFetch = safety.AllowsWriteVerbs();
        var options = new Security.SecretsHarvestPipeline.HarvestOptions
        {
            IncludeJsBundles = allowActiveFetch && body.GetBool("includeJsBundles", true),
            IncludeCookiesAndStorage = body.GetBool("includeCookiesAndStorage", true),
            IncludeNetworkResponses = body.GetBool("includeNetworkResponses", true),
            IncludePageText = body.GetBool("includePageText", true),
            IncludeSourceMaps = allowActiveFetch && body.GetBool("includeSourceMaps", true),
            MaxJsScripts = body.GetInt("maxJsScripts", 20),
            MaxNetworkResponses = body.GetInt("maxNetworkResponses", 100),
            MaxBytesPerFile = Math.Clamp(body.GetInt("maxBytesPerFile", 1_048_576), 8_192, 2_000_000),
            IncludeHtmlComments = body.GetBool("includeHtmlComments", true),
            TimeoutMs = body.GetInt("timeoutMs", 30000)
        };

        try
        {
            var result = await Security.SecretsHarvestPipeline.RunAsync(_context, options);
            return new
            {
                timestamp = result.Timestamp,
                url = result.Url,
                totalFindings = result.TotalFindings,
                filteredNoise = result.FilteredNoise,
                warnings = result.Warnings,
                findings = result.Findings.Select(f => new
                {
                    f.Source,
                    f.Category,
                    f.Severity,
                    f.Location,
                    f.Description,
                    f.Snippet
                }).ToList(),
                summary = new
                {
                    result.Summary.Critical,
                    result.Summary.High,
                    result.Summary.Medium,
                    result.Summary.Low,
                    result.Summary.Info,
                    bySource = result.Summary.BySource,
                    byCategory = result.Summary.ByCategory
                },
                sourcesScanned = result.SourcesScanned,
                passiveOnly = !allowActiveFetch,
                errors = result.Errors,
                elapsedMs = result.ElapsedMs
            };
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"Secrets harvest failed: {ex.Message}");
        }
    }

private Task HandlePostSecurityGraphqlAnalyze(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityGraphqlAnalyzeAsync);

internal async Task<object> BuildSecurityGraphqlAnalyzeAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "GraphQL analysis sends multiple probing queries to the target endpoint");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.GraphqlAnalyzer.GraphqlOptions
        {
            Url = body.GetString("url"),
            AutoDetect = body.GetBool("autoDetect", true),
            TimeoutMs = body.GetInt("timeoutMs", 30000),
            SkipIntrospection = body.GetBool("skipIntrospection"),
            SkipBatching = body.GetBool("skipBatching"),
            SkipAmplification = body.GetBool("skipAmplification"),
            SkipDepthProbe = body.GetBool("skipDepthProbe"),
            SkipLimitProbe = body.GetBool("skipLimitProbe"),
            SkipFieldSuggestion = body.GetBool("skipFieldSuggestion"),
            SkipDraftAccess = body.GetBool("skipDraftAccess")
        };

        var headersDict = body.GetStringDictionary("headers");
        if (headersDict != null)
            options.Headers = headersDict;

        try
        {
            var result = await Security.GraphqlAnalyzer.RunAsync(_context, options);
            return new
            {
                timestamp = result.Timestamp,
                url = result.Url,
                totalFindings = result.Findings.Count,
                findings = result.Findings.Select(f => new
                {
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Description,
                    f.Details
                }),
                schema = new
                {
                    result.Schema.TotalTypes,
                    result.Schema.QueryTypes,
                    result.Schema.MutationTypes,
                    result.Schema.SubscriptionTypes,
                    result.Schema.HasMutations,
                    result.Schema.HasSubscriptions,
                    result.Schema.SensitiveTypes,
                    result.Schema.RateLimit
                },
                errors = result.Errors,
                elapsedMs = result.ElapsedMs
            };
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, $"GraphQL analysis failed: {ex.Message}");
        }
    }

private Task HandlePostSecurityVerify(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityVerifyAsync);

internal async Task<object> BuildSecurityVerifyAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Exploit verification sends real payloads and navigates your app");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        if (!body.TryGetRoot(out var root))
            throw new ApiCommandException(400, "Invalid JSON body.");

        var compiled = WorkflowVerifyService.CompileLegacyVerify(root);
        var service = new WorkflowVerifyService();
        var result = await service.RunAsync(compiled, BuildWorkflowDependencies());
        return FormatWorkflowVerifyResponse(result);
    }

private Task HandlePostSecurityVerifyBatch(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityVerifyBatchAsync);

internal async Task<object> BuildSecurityVerifyBatchAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Exploit verification sends real payloads and navigates your app");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var items = body.GetArray("items");
        if (items == null || items.Count == 0)
            throw new ApiCommandException(400,
                "Provide a non-empty 'items' array (each entry uses the same shape as POST /api/security/verify).");

        var resultRows = new List<object>();
        for (var i = 0; i < items.Count; i++)
        {
            var itemBody = new JsonBody(items[i]);
            if (!ExploitVerifyRequestParser.TryParse(itemBody, out var opt, out var markers, out var parseError))
            {
                resultRows.Add(new { index = i, ok = false, parseError });
                continue;
            }

            var r = await Security.ExploitVerifier.VerifyAsync(_context, markers, opt);
            resultRows.Add(new
            {
                index = i,
                ok = true,
                r.Verified,
                effectObserved = r.EffectObserved,
                effectValue = r.EffectValue,
                evidence = r.Evidence,
                cleanedUp = r.CleanedUp,
                error = r.Error,
                elapsedMs = r.ElapsedMs
            });
        }

        return new { count = items.Count, results = resultRows };
    }

private Task HandlePostSecurityVerifyWorkflow(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityVerifyWorkflowAsync);

internal async Task<object> BuildSecurityVerifyWorkflowAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Workflow verification may send real payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        if (!body.TryGetRoot(out var root))
            throw new ApiCommandException(400, "Invalid JSON body.");

        if (!root.TryGetProperty("oracle", out var oracle) || oracle.ValueKind != JsonValueKind.Object)
            throw new ApiCommandException(400, "verify-workflow requires phases.oracle object.");

        var service = new WorkflowVerifyService();
        var result = await service.RunAsync(root, BuildWorkflowDependencies());
        VpxExportService.RecordSessionProof(_context, root, result);
        return FormatWorkflowVerifyResponse(result);
    }

private Task HandlePostSecurityChainProve(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityChainProveAsync);

internal async Task<object> BuildSecurityChainProveAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "chain-prove executes proof workflows");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var patternId = body.GetString("patternId");
        if (string.IsNullOrWhiteSpace(patternId))
            throw new ApiCommandException(400, "Missing required field: patternId.");

        var pattern = ResolveChainPattern(patternId);
        var templateId = pattern != null
            ? ChainProvabilityHelper.ResolveTemplateId(pattern)
            : ProofTemplateCatalog.HasTemplate(patternId) ? patternId : null;

        if (templateId == null)
            throw new ApiCommandException(404, $"No proof template for pattern '{patternId}'.");

        var findings = CollectChainableFindingsForSession();
        var thirdParty = await _context.CheckThirdParty();
        var analyzeOptions = await BuildChainAnalyzeOptionsWithThirdPartyAsync(new JsonBody(null), thirdParty);
        var analyze = ChainAnalysisService.Analyze(_chainCatalog, findings, analyzeOptions);
        var chain = analyze.Chains.FirstOrDefault(c => c.PatternId == patternId);
        var matched = chain?.MatchedFindings ?? [];
        if (matched.Count == 0)
        {
            var partial = analyze.PartialChains.FirstOrDefault(p => p.PatternId == patternId);
            if (partial != null)
                matched = partial.PresentFindings;
        }
        if (body.TryGetRoot(out var root) && root.TryGetProperty("findings", out var fEl) && fEl.ValueKind == JsonValueKind.Array)
        {
            matched = [];
            foreach (var el in fEl.EnumerateArray())
            {
                matched.Add(new ChainableFinding
                {
                    Category = el.TryGetProperty("category", out var c) ? c.GetString() ?? "" : "",
                    Endpoint = el.TryGetProperty("endpoint", out var e) ? e.GetString() : null,
                    Parameter = el.TryGetProperty("parameter", out var p) ? p.GetString() : null,
                    Method = el.TryGetProperty("method", out var m) ? m.GetString() : null
                });
            }
        }

        var exportEvidence = body.GetBool("exportEvidence");
        var exportTrwPath = body.GetString("exportTrwPath");
        if (!string.IsNullOrWhiteSpace(exportTrwPath))
        {
            if (!ExportPathGuard.TryResolve(exportTrwPath, SafeMode, out var trwFull, out var trwError))
                throw new ApiCommandException(400, trwError ?? "Export path rejected.");
            exportTrwPath = trwFull;
        }
        var substitutionOverrides = BuildChainProveSubstitutionOverrides(body);
        var prove = new ChainProveService();
        var result = await prove.ProveAsync(patternId, matched, BuildWorkflowDependencies(), exportEvidence, pattern, substitutionOverrides);
        if (matched.Count > 0)
        {
            var syntheticWorkflow = JsonSerializer.SerializeToElement(new
            {
                vpxFindingId = VpxExportService.NormalizeFindingId(matched[0].Id)
            });
            VpxExportService.RecordSessionProofFromChain(_context, syntheticWorkflow, result, patternId);
        }

        ChainProofJournalWriter.RecordChainProof(SessionLogger, result, pattern?.Name);
        if (!string.IsNullOrEmpty(result.EvidenceBundlePath))
            ChainProofJournalWriter.RecordEvidenceExport(SessionLogger, result.EvidenceBundlePath, result.Proven, patternId);

        if (!string.IsNullOrWhiteSpace(exportTrwPath) && !string.IsNullOrEmpty(result.EvidenceBundlePath))
        {
            var trwSrc = Path.Combine(result.EvidenceBundlePath, "scenario.trw");
            if (File.Exists(trwSrc))
                File.Copy(trwSrc, exportTrwPath, overwrite: true);
        }

        // Agent-facing envelope: put failureSummary / templateExpanded first so thin MCP
        // summaries still surface oracle failures without digging through stepErrors JSON.
        return new Dictionary<string, object?>
        {
            ["patternId"] = result.PatternId,
            ["proven"] = result.Proven,
            ["failureSummary"] = result.FailureSummary,
            ["failureReason"] = result.FailureReason,
            ["failurePhase"] = result.FailurePhase,
            ["failureDetail"] = result.FailureDetail,
            ["oracleType"] = result.OracleType,
            ["oracleEvidence"] = result.OracleEvidence,
            ["templateExpanded"] = result.TemplateExpanded,
            ["attemptedSubstitutions"] = result.AttemptedSubstitutions,
            ["stepErrors"] = result.StepErrors,
            ["steps"] = result.Steps,
            ["workflowId"] = result.WorkflowId,
            ["evidenceBundlePath"] = result.EvidenceBundlePath,
            ["elapsedMs"] = result.ElapsedMs,
            ["screenshot"] = result.Screenshot
        };
    }

private Task HandlePostSecurityEvidenceExport(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityEvidenceExportAsync);

internal async Task<object> BuildSecurityEvidenceExportAsync(JsonBody body)
    {
        if (!body.TryGetRoot(out var root))
            throw new ApiCommandException(400, "Invalid JSON body.");

        var existingBundle = body.GetString("bundlePath");
        if (!string.IsNullOrWhiteSpace(existingBundle))
        {
            if (!ExportPathGuard.TryResolveRead(existingBundle, out _, out var bundleError))
                throw new ApiCommandException(400, bundleError ?? "Bundle path rejected.");
            var redact = body.GetBool("redact", true);
            var exported = EvidenceExportService.ExportExistingBundle(existingBundle, redact);
            if (exported == null)
                throw new ApiCommandException(404, $"Evidence bundle not found: {existingBundle}");
            return new { bundlePath = exported, exportedFrom = existingBundle, redact };
        }

        var runWorkflow = body.HasProperty("workflow") || body.HasProperty("setup") || body.HasProperty("trigger")
                          || body.HasProperty("oracle") || root.TryGetProperty("workflow", out _);
        if (runWorkflow)
        {
            if (SafetyGate.RequireActive(body, "Running a workflow to generate evidence") is { } gateError)
            {
                throw new ApiCommandException(400, gateError with
                {
                    Message = gateError.Message +
                              " To export an existing bundle without re-running, pass bundlePath."
                });
            }
        }

        root = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("workflow", out var wf) ? wf : root;
        var service = new WorkflowVerifyService();
        var run = await service.RunAsync(root, BuildWorkflowDependencies());
        var bundlePath = run.EvidenceBundlePath;
        if (string.IsNullOrEmpty(bundlePath) && run.Oracle != null)
        {
            var ctx = new WorkflowExecutionContext { WorkflowId = run.WorkflowId, WorkflowName = run.Name };
            foreach (var kv in run.CapturedVars ?? [])
                ctx.Vars[kv.Key] = kv.Value;
            bundlePath = EvidenceExportService.ExportBundle(root, run.Verified, run.Oracle, ctx, BuildWorkflowDependencies());
        }

        return new { bundlePath, verdict = run.Verified ? "VERIFIED" : "NOT_VERIFIED", workflow = FormatWorkflowVerifyResponse(run) };
    }

private Task HandlePostSecurityEvidenceRerun(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityEvidenceRerunAsync);

internal async Task<object> BuildSecurityEvidenceRerunAsync(JsonBody body)
    {
        var bundlePath = body.GetString("bundlePath");
        var expect = body.GetString("expect");
        if (string.IsNullOrWhiteSpace(bundlePath))
            throw new ApiCommandException(400, "Missing required field: bundlePath.");
        if (!ExportPathGuard.TryResolveRead(bundlePath, out _, out var rerunPathError))
            throw new ApiCommandException(400, rerunPathError ?? "Bundle path rejected.");

        var rerun = await EvidenceExportService.RerunAsync(bundlePath, expect, BuildWorkflowDependencies());
        return new
        {
            verdict = rerun.Verdict.ToString().ToUpperInvariant(),
            bundlePath = rerun.BundlePath,
            workflow = rerun.Workflow != null ? FormatWorkflowVerifyResponse(rerun.Workflow) : null,
            error = rerun.Error
        };
    }
}
