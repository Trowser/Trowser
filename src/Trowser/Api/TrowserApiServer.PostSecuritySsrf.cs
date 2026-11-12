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

namespace Trowser.Api;

public partial class TrowserApiServer
{
private Task HandlePostSecuritySsrfScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySsrfScanAsync);

internal async Task<object> BuildSecuritySsrfScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SSRF probes issue real HTTP requests with internal/metadata URLs");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        SsrfRequestTemplate? requestTemplate = null;
        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            var url = req.GetString("url");
            if (string.IsNullOrWhiteSpace(url))
                throw new ApiCommandException(400, "request.url is required when using request template mode.");

            requestTemplate = new SsrfRequestTemplate
            {
                Url = url,
                Method = req.GetString("method") ?? "GET",
                Headers = req.GetStringDictionary("headers"),
                Body = req.HasProperty("body") ? req.GetString("body") :
                    req.HasProperty("json") ? req.GetJsonElement("json")?.GetRawText() : null
            };
        }

        List<string>? explicitUrls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList();
        List<string>? paramNames = body.GetStringList("paramNames") ?? body.GetStringArray("paramNames")?.ToList();
        List<string>? payloads = body.GetStringList("payloads") ?? body.GetStringArray("payloads")?.ToList();

        var (allowedHosts, scopeUrls) = SsrfOptionsBuilder.ParseScope(body);
        explicitUrls = SsrfOptionsBuilder.MergeUrls(explicitUrls, scopeUrls);

        var options = new SsrfOptions
        {
            RequestTemplate = requestTemplate,
            MarkerName = body.GetString("marker") ?? body.GetString("markerName"),
            BaselineValue = body.GetString("baselineValue"),
            ExplicitUrls = explicitUrls,
            AllowedHosts = allowedHosts,
            EndpointHints = SsrfOptionsBuilder.ParseEndpointHints(body),
            ParamNames = paramNames,
            Payloads = payloads,
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            CallbackWaitMs = body.GetInt("callbackWaitMs", 2000),
            IncludeInternalIps = body.GetBool("includeInternalIps", true),
            IncludeProtocolHandlers = body.GetBool("includeProtocolHandlers", true),
            IncludeCallbackProbes = body.GetBool("includeCallbackProbes", true),
            IncludeDomDiscovery = body.GetBool("includeDomDiscovery", true),
            IncludeXxe = body.GetBool("includeXxe", true),
            IncludeUploadXxe = body.GetBool("includeUploadXxe", false),
            XxePayloads = body.GetStringList("xxePayloads") ?? body.GetStringArray("xxePayloads")?.ToList(),
            MinConfidence = body.GetString("minConfidence"),
            CallbackDomain = body.GetString("callbackDomain"),
            UseBackendFetch = body.GetBool("useBackendFetch", false),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", false),
            IncludeScaffoldPaths = body.GetBool("includeScaffoldPaths", true),
            IncludeImdsV2Pivot = body.GetBool("includeImdsV2Pivot", true),
            IncludeCloudMetadataHeaders = body.GetBool("includeCloudMetadataHeaders", true),
        };

        var includeHygiene = body.GetBool("includeHygiene");
        var minConfidence = body.GetString("minConfidence") ?? SecurityConfidence.Likely;
        var depth = SecurityScanDepth.Normalize(body.GetString("depth"));
        try
        {
            var result = await _context.RunSsrfScan(options);
            var findings = result.Findings.Select(f => UnifiedSecurityFinding.Create(
                category: "ssrf",
                title: $"SSRF ({f.Type}): {f.Indicator}",
                severity: f.Severity,
                confidence: f.Confidence,
                endpoint: f.Url,
                method: f.Method,
                param: f.ParamName,
                payload: f.Payload,
                evidence: f.Snippet,
                proofHint: f.Indicator,
                nextActions: f.Confidence.Equals(SecurityConfidence.Confirmed, StringComparison.OrdinalIgnoreCase)
                    ? [SecurityNextActions.CallbackPoll, SecurityNextActions.VerifyWorkflow]
                    : [SecurityNextActions.CallbackPoll],
                extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["type"] = f.Type,
                    ["indicator"] = f.Indicator,
                    ["status"] = f.Status,
                    ["baselineStatus"] = f.BaselineStatus,
                    ["correlationId"] = f.CorrelationId
                })).ToList();

            return new SecurityScanResult
            {
                Message = result.Message,
                Depth = depth,
                CandidatesProbed = result.CandidatesProbed,
                PayloadsSent = result.PayloadsSent,
                Findings = findings,
                Summary = findings.Count > 0
                    ? [$"{findings.Count} SSRF finding(s)."]
                    : ["No SSRF indicators."]
            }.ToApiResponse(includeHygiene, minConfidence);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecuritySsrfOrchestrator(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySsrfOrchestratorAsync);

internal async Task<object> BuildSecuritySsrfOrchestratorAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SSRF orchestrator issues real HTTP requests with internal/metadata URLs");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.SsrfOrchestrator.OrchestratorOptions
        {
            ExplicitUrls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList(),
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            CallbackWaitMs = body.GetInt("callbackWaitMs", 2000),
            IncludeScaffoldPaths = body.GetBool("includeScaffoldPaths", true),
            IncludeImdsV2Pivot = body.GetBool("includeImdsV2Pivot", true),
            IncludeCloudMetadataHeaders = body.GetBool("includeCloudMetadataHeaders", true),
            IncludeXxe = body.GetBool("includeXxe", true),
            IncludeUploadXxe = body.GetBool("includeUploadXxe", false),
            IncludeOpenRedirect = body.GetBool("includeOpenRedirect", true),
            IncludeJwtHeaderAbuse = body.GetBool("includeJwtHeaderAbuse", true),
            IncludeCallbackProbes = body.GetBool("includeCallbackProbes", true),
            IncludeChainAnalysis = body.GetBool("includeChainAnalysis", true),
            RegisterChainFindings = body.GetBool("registerChainFindings", true),
            CallbackDomain = body.GetString("callbackDomain"),
            MinConfidence = body.GetString("minConfidence"),
            UseBackendFetch = body.GetBool("useBackendFetch", false),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", false)
        };

        try
        {
            var result = await _context.RunSsrfOrchestrator(options, _chainCatalog);
            return new
            {
                message = result.Message,
                totalFindings = result.TotalFindings,
                stepsRun = result.StepsRun,
                errors = result.Errors,
                callbackInteractions = result.CallbackInteractions,
                ssrf = result.Ssrf == null ? null : new
                {
                    message = result.Ssrf.Message,
                    candidatesProbed = result.Ssrf.CandidatesProbed,
                    payloadsSent = result.Ssrf.PayloadsSent,
                    findings = result.Ssrf.Findings
                },
                openRedirect = result.OpenRedirect == null ? null : new
                {
                    message = result.OpenRedirect.Message,
                    candidatesProbed = result.OpenRedirect.CandidatesProbed,
                    payloadsSent = result.OpenRedirect.PayloadsSent,
                    findings = result.OpenRedirect.Findings
                },
                jwtHeaderAbuse = result.JwtHeaderAbuse == null ? null : new
                {
                    result.JwtHeaderAbuse.IsClean,
                    result.JwtHeaderAbuse.EndpointsTested,
                    findings = result.JwtHeaderAbuse.Findings,
                    summary = result.JwtHeaderAbuse.Summary
                },
                chainAnalysis = result.ChainAnalysis
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityOpenRedirectScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityOpenRedirectScanAsync);

internal async Task<object> BuildSecurityOpenRedirectScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Open redirect probes issue real HTTP requests with external redirect targets");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        List<string>? explicitUrls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList();
        List<string>? paramNames = body.GetStringList("paramNames") ?? body.GetStringArray("paramNames")?.ToList();
        List<string>? payloads = body.GetStringList("payloads") ?? body.GetStringArray("payloads")?.ToList();

        List<EndpointParamHint>? endpointHints = null;
        if (body.HasProperty("endpointHints"))
        {
            endpointHints = new List<EndpointParamHint>();
            var arr = body.GetJsonElement("endpointHints");
            if (arr?.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in arr.Value.EnumerateArray())
                {
                    var hint = new EndpointParamHint
                    {
                        Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                        Method = item.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
                    };
                    if (item.TryGetProperty("paramNames", out var pn) && pn.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var p in pn.EnumerateArray())
                            if (p.ValueKind == JsonValueKind.String)
                                hint.ParamNames.Add(p.GetString() ?? "");
                    }
                    else if (item.TryGetProperty("paramName", out var single))
                        hint.ParamNames.Add(single.GetString() ?? "");
                    if (!string.IsNullOrEmpty(hint.Url) && hint.ParamNames.Count > 0)
                        endpointHints.Add(hint);
                }
            }
        }

        // Accept request template with {{redir}} / §redir§ (same ergonomics as sqli-scan).
        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            var reqUrl = req.GetString("url");
            if (string.IsNullOrWhiteSpace(reqUrl))
                throw new ApiCommandException(400, "request.url is required.");

            var markers = Security.RequestMarkerSubstitute.ListMarkers(
                reqUrl, req.GetString("body"), req.GetStringDictionary("headers"));
            if (markers.Count == 0)
                throw new ApiCommandException(400, Security.InjectionRequestErrors.WithRequestExample(
                    "request template must contain a §marker§ or {{marker}} injection point (e.g. {{redir}})"));

            var (hintUrl, paramName) = ResolveOpenRedirectTemplate(reqUrl!, markers[0]);
            endpointHints ??= [];
            endpointHints.Add(new EndpointParamHint
            {
                Url = hintUrl,
                Method = req.GetString("method") ?? "GET",
                ParamNames = [paramName]
            });
            paramNames ??= [];
            if (!paramNames.Contains(paramName, StringComparer.OrdinalIgnoreCase))
                paramNames.Add(paramName);
        }

        var options = new OpenRedirectOptions
        {
            ExplicitUrls = explicitUrls,
            EndpointHints = endpointHints,
            ParamNames = paramNames,
            Payloads = payloads,
            ProbeHost = body.GetString("probeHost"),
            MaxCandidates = body.GetInt("maxCandidates", 12),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            IncludeDomDiscovery = body.GetBool("includeDomDiscovery", true),
            IncludeAdaptiveBypasses = body.GetBool("includeAdaptiveBypasses", true),
            IncludeSsrfEscalationProbes = body.GetBool("includeSsrfEscalationProbes", true),
            IncludeScaffoldWithExplicit = body.GetBool("includeScaffoldWithExplicit"),
        };

        try
        {
            var result = await _context.RunOpenRedirectScan(options);
            return new
            {
                message = result.Message,
                candidatesProbed = result.CandidatesProbed,
                payloadsSent = result.PayloadsSent,
                warnings = result.Warnings.Count > 0 ? result.Warnings : null,
                findings = result.Findings.Select(f => new
                {
                    f.Title,
                    f.Category,
                    f.Severity,
                    f.Confidence,
                    endpoint = f.Url,
                    f.Url,
                    f.Method,
                    f.ParamName,
                    f.Payload,
                    statusCode = f.Status,
                    baselineStatusCode = f.BaselineStatus,
                    f.Location,
                    f.Indicator,
                    evidence = f.Snippet,
                    f.BypassTechnique,
                    f.Source,
                    f.Snippet
                }).ToList()
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

/// <summary>
/// Map a request URL template with {{redir}} (or similar) to an absolute URL + real query param name
/// for open-redirect discovery.
/// </summary>
private static (string Url, string ParamName) ResolveOpenRedirectTemplate(string urlTemplate, string markerName)
{
    if (!Uri.TryCreate(urlTemplate, UriKind.Absolute, out var uri))
        throw new ApiCommandException(400, "request.url must be an absolute URL.");

    var qb = System.Web.HttpUtility.ParseQueryString(uri.Query);
    string? matchedParam = null;
    foreach (string? key in qb.AllKeys)
    {
        if (key == null) continue;
        var val = qb[key] ?? "";
        if (val.Contains("{{" + markerName + "}}", StringComparison.OrdinalIgnoreCase)
            || val.Contains("§" + markerName + "§", StringComparison.OrdinalIgnoreCase)
            || string.Equals(val, markerName, StringComparison.OrdinalIgnoreCase))
        {
            matchedParam = key;
            qb[key] = "/";
            break;
        }
    }

    if (matchedParam == null)
    {
        // Marker not in a query value — fall back to marker name as param and strip markers from URL.
        matchedParam = markerName;
        var cleaned = Security.RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, "/");
        return (cleaned, matchedParam);
    }

    var builder = new UriBuilder(uri) { Query = qb.ToString() ?? "" };
    return (builder.Uri.AbsoluteUri, matchedParam);
}

private Task HandlePostSecurityCacheDeceptionScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCacheDeceptionScanAsync);

internal async Task<object> BuildSecurityCacheDeceptionScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Cache deception probes issue authenticated and anonymous HTTP requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        List<string>? paths = body.GetStringList("paths") ?? body.GetStringArray("paths")?.ToList();
        List<EndpointParamHint>? endpointHints = null;
        if (body.HasProperty("endpointHints"))
        {
            endpointHints = new List<EndpointParamHint>();
            var arr = body.GetJsonElement("endpointHints");
            if (arr?.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in arr.Value.EnumerateArray())
                {
                    var hint = new EndpointParamHint
                    {
                        Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                        Method = item.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
                    };
                    if (item.TryGetProperty("paramNames", out var pn) && pn.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var p in pn.EnumerateArray())
                            if (p.ValueKind == JsonValueKind.String)
                                hint.ParamNames.Add(p.GetString() ?? "");
                    }
                    if (!string.IsNullOrEmpty(hint.Url))
                        endpointHints.Add(hint);
                }
            }
        }

        var options = new CacheDeceptionOptions
        {
            Paths = paths,
            EndpointHints = endpointHints,
            MaxCandidates = body.GetInt("maxCandidates", 12),
            MinBodySize = body.GetInt("minBodySize", 64),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            RequireSession = body.GetBool("requireSession", true),
        };

        try
        {
            var result = await _context.RunCacheDeceptionScan(options);
            return new
            {
                message = result.Message,
                origin = result.Origin,
                skippedReason = result.SkippedReason,
                candidatesProbed = result.CandidatesProbed,
                elapsedMs = result.ElapsedMs,
                findings = result.Findings
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityCachePoisonScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCachePoisonScanAsync);

internal async Task<object> BuildSecurityCachePoisonScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Cache poison probes inject unkeyed HTTP headers and replay cache-oracle requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new CachePoisonOptions
        {
            Urls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList(),
            Headers = body.GetStringList("headers") ?? body.GetStringArray("headers")?.ToList(),
            CanaryHost = body.GetString("canaryHost"),
            MaxTargets = body.GetInt("maxTargets", 3),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            CacheReplayDelayMs = body.GetInt("cacheReplayDelayMs", 300),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", false),
            IncludeHeaderInjectionFuzz = body.GetBool("includeHeaderInjectionFuzz", false),
            MaxFuzzPayloads = body.GetInt("maxFuzzPayloads", 6),
            BypassHeader = body.GetString("bypassHeader"),
            BypassHeaderValue = body.GetString("bypassHeaderValue"),
            UseQueryBuster = body.GetBool("useQueryBuster", false),
        };

        try
        {
            var result = await _context.RunCachePoisonScan(options);
            return new
            {
                message = result.Message,
                probesRun = result.ProbesRun,
                elapsedMs = result.ElapsedMs,
                findings = result.Findings
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityCacheMap(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCacheMapAsync);

internal async Task<object> BuildSecurityCacheMapAsync(JsonBody body)
    {
        var safety = SafetyGate.Resolve(body);
        var gateError = SafetyGate.RequireAtLeast(safety, SafetyMode.Safe,
            "Cache-map issues extra GETs with unique busters to map the cache key");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var headerMode = safety.AllowsWriteVerbs() && !SafeMode;
        var options = new CacheMapOptions
        {
            Urls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList(),
            MaxTargets = body.GetInt("maxTargets", 2),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            IncludeHeaderProbes = headerMode,
            IncludeFatGet = headerMode,
            HeaderNames = body.GetStringList("headers") ?? body.GetStringArray("headers")?.ToList(),
        };

        try
        {
            var result = await _context.RunCacheMapScan(options);
            return new
            {
                message = result.Message,
                probesRun = result.ProbesRun,
                elapsedMs = result.ElapsedMs,
                identify = result.Identify.ToApiObject(),
                oracle = new
                {
                    usable = result.Oracle.Usable,
                    bodyStable = result.Oracle.BodyStable,
                    firstStatus = result.Oracle.FirstStatus,
                    secondStatus = result.Oracle.SecondStatus,
                    detail = result.Oracle.Detail
                },
                keyComponents = new
                {
                    queryParams = result.KeyComponents.QueryParams,
                    headers = result.KeyComponents.Headers,
                    cookieKeyed = result.KeyComponents.CookieKeyed,
                    pathNormalization = result.KeyComponents.PathNormalization
                },
                comparisons = result.Comparisons,
                findings = result.Findings,
                nextActions = result.NextActions,
                headerProbesRan = headerMode,
                summary = result.Format(includeDetails: false)
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityCachePollutionScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCachePollutionScanAsync);

internal async Task<object> BuildSecurityCachePollutionScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "Cache pollution stores origin errors on the live URL key (no query buster)");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new CachePollutionOptions
        {
            Urls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList(),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            CacheReplayDelayMs = body.GetInt("cacheReplayDelayMs", 300),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", false),
        };

        try
        {
            var result = await _context.RunCachePollutionScan(options);
            return new
            {
                message = result.Message,
                url = result.Url,
                probesRun = result.ProbesRun,
                elapsedMs = result.ElapsedMs,
                identify = result.Identify.ToApiObject(),
                bypassHeader = result.BypassHeader == null ? null : new
                {
                    name = result.BypassHeader.Name,
                    value = result.BypassHeader.Value,
                    description = result.BypassHeader.Description
                },
                phase1 = result.Phase1,
                phase2 = result.Phase2,
                phase3 = result.Phase3,
                findings = result.Findings,
                warnings = result.Warnings,
                nextActions = result.NextActions,
                summary = result.Format(includeDetails: false)
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private async Task HandlePostSecurityShadow(HttpListenerRequest request, HttpListenerResponse response)
    {
        var shadow = _context.SecurityShadow;
        if (shadow == null) { await WriteError(response, 500, "Shadow not initialized"); return; }

        var body = await ReadJsonBody(request);
        var enabled = body.GetBool("enabled", true);

        HashSet<string>? audits = null;
        var auditsArr = body.GetStringArray("audits");
        if (auditsArr != null)
        {
            if (!SecurityShadowManager.TryValidateAuditNames(auditsArr, out var auditError))
                throw new ApiCommandException(400, auditError!);
            audits = auditsArr.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        shadow.Configure(
            enabled,
            audits,
            body.GetString("scope"),
            body.HasProperty("suggestions") ? body.GetBool("suggestions") : null,
            body.HasProperty("deduplication") ? body.GetBool("deduplication") : null,
            body.HasProperty("notifyGui") ? body.GetBool("notifyGui") : null
        );

        if (body.HasProperty("laws"))
            shadow.Config.LawsEnabled = body.GetBool("laws");
        if (body.GetStringArray("disabledLaws") is { } disabled)
            shadow.Config.DisabledLaws = disabled.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (body.HasProperty("activeLawSources"))
        {
            shadow.Config.ActiveLawSources = body.GetStringArray("activeLawSources") is { } active
                ? active.ToHashSet(StringComparer.OrdinalIgnoreCase)
                : null;
        }
        if (body.GetStringArray("lightQuicktests") is { } lightQt)
            shadow.Config.LightQuicktests = lightQt.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (body.GetStringArray("heavyQuicktests") is { } heavyQt)
            shadow.Config.HeavyQuicktests = heavyQt.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (body.HasProperty("runHeavyAfterQuicktest"))
            shadow.Config.RunHeavyAfterQuicktest = body.GetBool("runHeavyAfterQuicktest");
        if (body.HasProperty("serendipityTimer"))
            shadow.Config.SerendipityTimerEnabled = body.GetBool("serendipityTimer");
        if (body.HasProperty("serendipityIntervalSeconds"))
            shadow.Config.SerendipityIntervalSeconds = body.GetInt("serendipityIntervalSeconds", shadow.Config.SerendipityIntervalSeconds);
        if (body.HasProperty("lawsMining"))
            shadow.Config.LawsMiningEnabled = body.GetBool("lawsMining");

        await WriteSuccess(response, new
        {
            enabled = shadow.Config.Enabled,
            audits = shadow.Config.Audits.ToArray(),
            scope = shadow.Config.Scope,
            suggestions = shadow.Config.Suggestions,
            laws = shadow.Config.LawsEnabled,
            disabledLaws = shadow.Config.DisabledLaws.ToArray(),
            activeLawSources = shadow.Config.ActiveLawSources?.ToArray(),
            lightQuicktests = shadow.Config.LightQuicktests.ToArray(),
            heavyQuicktests = shadow.Config.HeavyQuicktests.ToArray(),
            runHeavyAfterQuicktest = shadow.Config.RunHeavyAfterQuicktest,
            serendipityTimer = shadow.Config.SerendipityTimerEnabled,
            message = enabled
                ? "Shadow armed. Will audit on each navigation."
                : "Shadow disabled."
        });
    }

private async Task HandleGetSecurityShadow(HttpListenerRequest request, HttpListenerResponse response)
    {
        var shadow = _context.SecurityShadow;
        if (shadow == null) { await WriteError(response, 500, "Shadow not initialized"); return; }

        var statusOnly = ApiQuery(request)["status"] == "true";
        if (statusOnly)
        {
            await WriteSuccess(response, new
            {
                enabled = shadow.Enabled,
                pagesAudited = shadow.PagesAudited,
                findingsCount = shadow.FindingsCount,
                newSinceLastPoll = shadow.NewSinceLastPoll
            });
            return;
        }

        int.TryParse(ApiQuery(request)["since"], out var sinceId);
        Severity? severity = ApiQuery(request)["severity"]?.ToLowerInvariant() switch
        {
            "info" => Severity.Info,
            "low" => Severity.Low,
            "medium" => Severity.Medium,
            "high" => Severity.High,
            "critical" => Severity.Critical,
            _ => null
        };
        var category = ApiQuery(request)["category"];
        var urlFilter = ApiQuery(request)["url"];

        var findings = shadow.GetFindings(
            sinceId > 0 ? sinceId : null,
            severity,
            category,
            urlFilter
        );
        var suggestions = shadow.GetSuggestions();
        shadow.MarkPolled();

        await WriteSuccess(response, new
        {
            enabled = shadow.Enabled,
            pagesAudited = shadow.PagesAudited,
            findingsCount = shadow.FindingsCount,
            newSinceLastPoll = 0,
            findings = findings.Select(f => new
            {
                id = f.Id,
                timestamp = f.Timestamp,
                url = f.Url,
                audit = f.Audit,
                severity = f.Severity.ToString().ToLowerInvariant(),
                title = f.Title,
                description = f.Description,
                recommendation = f.Recommendation,
                firstSeen = f.FirstSeen,
                occurrences = f.Occurrences,
                seenOnUrls = f.SeenOnUrls.Count > 0 ? f.SeenOnUrls : null,
                seenOnDomains = f.SeenOnDomains.Count > 0 ? f.SeenOnDomains : null
            }),
            suggestions = suggestions.Select(s => new
            {
                id = s.Id,
                timestamp = s.Timestamp,
                trigger = s.Trigger,
                suggestion = s.Suggestion,
                apiCall = s.ApiUrl != null ? new { method = s.ApiMethod, url = s.ApiUrl } : null
            })
        });
    }

private async Task HandlePostSecurityShadowClear(HttpListenerRequest request, HttpListenerResponse response)
    {
        var shadow = _context.SecurityShadow;
        if (shadow == null) { await WriteError(response, 500, "Shadow not initialized"); return; }

        var body = await ReadJsonBody(request);
        var category = body.GetString("category");
        shadow.ClearFindings(category);

        await WriteSuccess(response, new
        {
            message = category != null
                ? $"Cleared {category} findings."
                : "All shadow findings cleared."
        });
    }

private async Task HandleGetShadows(HttpListenerRequest request, HttpListenerResponse response)
    {
        var pm = _context.PowerMode;
        var wh = _context.RedTeamWhisper;
        if (pm == null || wh == null)
        {
            await WriteError(response, 500, "Shadows features not initialized");
            return;
        }

        await WriteSuccess(response, new
        {
            powerMode = new
            {
                enabled = pm.Config.Enabled,
                showOverlays = pm.Config.ShowOverlays
            },
            redTeamWhisper = new
            {
                enabled = wh.Config.Enabled,
                notifyGui = wh.Config.NotifyGui,
                lastHints = wh.LastHints,
                clues = wh.LastClues.Select(c => c.ToApiObject()),
                newClues = wh.LastNewClues.Select(c => c.ToApiObject())
            }
        });
    }

private async Task HandlePostShadows(HttpListenerRequest request, HttpListenerResponse response)
    {
        var pm = _context.PowerMode;
        var wh = _context.RedTeamWhisper;
        if (pm == null || wh == null)
        {
            await WriteError(response, 500, "Shadows features not initialized");
            return;
        }

        var body = await ReadJsonBody(request);

        if (body.HasProperty("powerModeEnabled") || body.HasProperty("powerModeShowOverlays"))
        {
            pm.Configure(
                body.HasProperty("powerModeEnabled") ? body.GetBool("powerModeEnabled") : pm.Config.Enabled,
                body.HasProperty("powerModeShowOverlays") ? body.GetBool("powerModeShowOverlays") : null);
        }

        if (body.HasProperty("whisperEnabled") || body.HasProperty("whisperNotifyGui"))
        {
            wh.Configure(
                body.HasProperty("whisperEnabled") ? body.GetBool("whisperEnabled") : wh.Config.Enabled,
                body.HasProperty("whisperNotifyGui") ? body.GetBool("whisperNotifyGui") : null);
        }

        await _context.SyncPowerModeToAllTabsAsync();

        await WriteSuccess(response, new
        {
            powerMode = new { enabled = pm.Config.Enabled, showOverlays = pm.Config.ShowOverlays },
            redTeamWhisper = new { enabled = wh.Config.Enabled, notifyGui = wh.Config.NotifyGui },
            message = "Shadows settings updated."
        });
    }

private async Task HandlePostSecurityCallbacks(HttpListenerRequest request, HttpListenerResponse response)
    {
        var detector = _context.CallbackDetector;
        if (detector == null) { await WriteError(response, 500, "Callback detector not initialized"); return; }

        var body = await ReadJsonBody(request);
        var mode = body.GetString("mode") ?? "start";

        switch (mode)
        {
            case "start":
                var domain = body.GetString("domain");
                detector.Start(domain);
                await WriteSuccess(response, new
                {
                    active = true,
                    callbackDomain = detector.CallbackDomain,
                    callbackUrl = detector.CallbackUrl,
                    marker = Security.CallbackDetector.MarkerAscii,
                    markerLegacy = Security.CallbackDetector.MarkerLegacy,
                    message = $"OOB callback detection active. Use {Security.CallbackDetector.MarkerAscii} in fuzz payloads " +
                              $"(legacy {Security.CallbackDetector.MarkerLegacy} also accepted). " +
                              $"Poll GET /api/security/callbacks for interactions."
                });
                break;
            case "stop":
                detector.Stop();
                await WriteSuccess(response, new { active = false, message = "OOB callback detection stopped." });
                break;
            case "clear":
                detector.Clear();
                await WriteSuccess(response, new { message = "Callback interactions cleared." });
                break;
            case "status":
                await WriteSuccess(response, new
                {
                    active = detector.Active,
                    callbackDomain = detector.CallbackDomain,
                    callbackUrl = detector.CallbackUrl,
                    interactionCount = detector.GetInteractions().Count,
                    newSinceLastPoll = detector.NewSinceLastPoll
                });
                break;
            default:
                await WriteError(response, 400, $"Unknown mode: {mode}. Use 'start', 'stop', 'status', or 'clear'.");
                break;
        }
    }

private async Task HandleGetSecurityCallbacks(HttpListenerRequest request, HttpListenerResponse response)
    {
        var detector = _context.CallbackDetector;
        if (detector == null) { await WriteError(response, 500, "Callback detector not initialized"); return; }

        int.TryParse(ApiQuery(request)["since"], out var sinceId);
        var interactions = detector.GetInteractions(sinceId > 0 ? sinceId : null);
        detector.MarkPolled();

        await WriteSuccess(response, new
        {
            active = detector.Active,
            callbackDomain = detector.CallbackDomain,
            callbackUrl = detector.CallbackUrl,
            marker = Security.CallbackDetector.MarkerAscii,
            markerLegacy = Security.CallbackDetector.MarkerLegacy,
            interactions = interactions.Select(i => new
            {
                id = i.Id,
                timestamp = i.Timestamp,
                tier = i.Tier,
                type = i.Type,
                from = i.From,
                url = i.Url,
                method = i.Method,
                statusCode = i.StatusCode,
                correlationId = i.CorrelationId,
                finding = i.Finding
            })
        });
    }
}
