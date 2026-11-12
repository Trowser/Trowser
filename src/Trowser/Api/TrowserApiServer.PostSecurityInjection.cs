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
// NOTE: The Build*Async(JsonBody) methods below are the single canonical implementation for each
// action, shared by the REST endpoints (HandlePost* wrappers here) and the matching MCP tools
// (which call them via McpHandler.Host). They return structured data and throw ApiCommandException
// on validation/safety-gate failures so both surfaces behave identically.

private Task HandlePostSecurityXss(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityXssAsync);

internal async Task<object> BuildSecurityXssAsync(JsonBody body) => await BuildSecurityXssPayloadAsync();

private Task HandlePostMixedContent(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildMixedContentAsync);

internal async Task<object> BuildMixedContentAsync(JsonBody body) => await BuildMixedContentPayloadAsync();

private Task HandlePostSecurityPathTraversal(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityPathTraversalAsync);

internal async Task<object> BuildSecurityPathTraversalAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Path traversal probes issue real HTTP requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        List<string>? explicitUrls = body.GetStringList("urls") ?? body.GetStringArray("urls")?.ToList();
        List<string>? paramNames = body.GetStringList("paramNames") ?? body.GetStringArray("paramNames")?.ToList();
        List<string>? payloads = body.GetStringList("payloads") ?? body.GetStringArray("payloads")?.ToList();

        List<string>? pathBases = body.GetStringList("pathBases") ?? body.GetStringArray("pathBases")?.ToList();

        var options = new PathTraversalOptions
        {
            Mode = body.GetString("mode") ?? "query",
            BasePath = body.GetString("basePath"),
            PathBases = pathBases,
            ExplicitUrls = explicitUrls,
            ParamNames = paramNames,
            Payloads = payloads,
            MaxCandidates = body.GetInt("maxCandidates", 12),
            TimeoutMs = body.GetInt("timeout", 15000),
        };

        try
        {
            var result = await _context.RunPathTraversalScan(options);
            return new
            {
                mode = options.Mode ?? "query",
                basePath = options.BasePath,
                pathBases = options.PathBases,
                message = result.Message,
                candidatesProbed = result.CandidatesProbed,
                findings = result.Findings.Select(f => new
                {
                    f.Url,
                    f.BaselineUrl,
                    f.Method,
                    f.ParamName,
                    f.Payload,
                    f.Status,
                    f.BaselineStatus,
                    f.Indicator,
                    f.Snippet,
                    f.Category,
                    f.Title,
                    f.Severity,
                    f.Confidence,
                }).ToList(),
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityWafBypass(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityWafBypassAsync);

internal async Task<object> BuildSecurityWafBypassAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "WAF bypass probes send attack payloads to the target");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        Dictionary<string, string>? headers = body.GetStringDictionary("headers");

        var options = new WafBypassOptions
        {
            Url = body.GetString("url"),
            Method = body.GetString("method") ?? "GET",
            Headers = headers,
            Body = body.HasProperty("body") ? body.GetString("body") :
                body.HasProperty("json") ? body.GetJsonElement("json")?.GetRawText() : null,
            ParamName = body.GetString("paramName") ?? body.GetString("param"),
            BaselineValue = body.GetString("baselineValue") ?? "1",
            ProbePayload = body.GetString("probePayload"),
            Category = body.GetString("category") ?? "sqli",
            Techniques = body.GetStringList("techniques") ?? body.GetStringArray("techniques")?.ToList(),
            TimeoutMs = body.GetInt("timeout", body.GetInt("timeoutMs", 15000)),
            UseBackendFetch = body.GetBool("useBackendFetch", false),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
        };

        try
        {
            var result = await _context.RunWafBypassScan(options);
            return new
            {
                result.TargetUrl,
                result.Method,
                result.ProbePayload,
                result.Category,
                result.WafBlockDetected,
                result.WafIndicators,
                result.Message,
                result.UsableBypasses,
                result.ElapsedMs,
                techniques = result.Techniques.Select(t => new
                {
                    t.Technique,
                    t.Category,
                    t.Verdict,
                    t.Status,
                    t.BaselineStatus,
                    t.DirectBlockStatus,
                    t.BodyLength,
                    t.BaselineBodyLength,
                    t.DurationMs,
                    t.Detail,
                    t.AppliedPayload,
                    t.RequestUrl,
                }).ToList(),
                summary = result.Format(includeDetails: false)
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private async Task HandlePostUpload(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var submit = body.GetBool("submit", false);

        var paths = body.GetStringList("paths") ?? body.GetStringArray("paths")?.ToList();
        var single = body.GetString("path");
        if (paths is not { Count: > 0 } && !string.IsNullOrWhiteSpace(single))
            paths = new List<string> { single! };

        var tempFiles = new List<string>();
        try
        {
            if (body.HasProperty("base64"))
            {
                var b64 = body.GetString("base64");
                if (string.IsNullOrWhiteSpace(b64))
                {
                    await WriteError(response, 400, "Field \"base64\" must be non-empty when provided.");
                    return;
                }

                byte[] bytes;
                try
                {
                    bytes = Convert.FromBase64String(b64);
                }
                catch (FormatException)
                {
                    await WriteError(response, 400, "Invalid base64 in \"base64\" field.");
                    return;
                }

                var name = body.GetString("fileName") ?? "upload.bin";
                var ext = Path.GetExtension(name);
                if (string.IsNullOrEmpty(ext))
                    ext = ".bin";
                var tmp = Path.Combine(Path.GetTempPath(), "trowser-upload-" + Guid.NewGuid().ToString("N") + ext);
                await File.WriteAllBytesAsync(tmp, bytes);
                tempFiles.Add(tmp);
                paths = new List<string> { tmp };
            }

            if (paths is not { Count: > 0 })
            {
                await WriteError(response, 400,
                    "Provide \"path\" (single file), \"paths\" (array of absolute paths), or \"base64\" with optional \"fileName\".");
                return;
            }

            await _context.SetFileInput(selector, paths, timeout > 0 ? timeout : null, submit);

            await WriteSuccess(response, new
            {
                selector,
                files = paths,
                submit,
                staleRefWarning = staleWarning,
                tempNote = tempFiles.Count > 0
                    ? "Temporary file(s) from base64 were written on the host and deleted after the request."
                    : null
            });
        }
        finally
        {
            foreach (var t in tempFiles)
            {
                try
                {
                    File.Delete(t);
                }
                catch
                {
                    // best-effort cleanup
                }
            }
        }
    }

private Task HandlePostSecuritySmuggling(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySmugglingAsync);

internal async Task<object> BuildSecuritySmugglingAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "This sends specially crafted HTTP requests to the target server for request smuggling detection");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
            url = await _context.GetCurrentUrl();

        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
            throw new ApiCommandException(400, "Missing or invalid URL. Provide a 'url' field or navigate to a page first.");

        var techniques = body.GetStringList("techniques");
        var timeoutMs = body.GetInt("timeoutMs", 10000);
        var delayThresholdMs = body.GetInt("delayThresholdMs", 3000);
        var teObfuscations = body.GetBool("teObfuscations", true);

        var result = await Security.HttpRequestSmugglingScanner.RunAsync(
            url, techniques, timeoutMs, delayThresholdMs, teObfuscations);

        return new
        {
            verdict = result.Verdict,
            url = result.Url,
            elapsedMs = result.ElapsedMs,
            summary = result.Summary,
            probesRun = result.ProbesRun,
            findingCount = result.Findings.Count,
            confirmedCount = result.ConfirmedFindings.Count(),
            findings = result.Findings.Select(f => new
            {
                technique = f.Technique,
                severity = f.Severity,
                confidence = f.Confidence,
                findingCategory = f.FindingCategory,
                exploitable = f.Exploitable,
                mitigatingFactors = f.MitigatingFactors,
                confirmationMethod = f.ConfirmationMethod,
                evidence = f.Evidence,
                description = f.Description,
                remediation = f.Remediation,
                rawProbeRequest = f.RawProbeRequest,
                rawTimingBaselineRequest = f.RawTimingBaselineRequest,
                rawCanonicalReferenceRequest = f.RawCanonicalReferenceRequest,
                probeDetails = f.Probe != null ? new
                {
                    baselineMs = f.Probe.BaselineMs,
                    probeMs = f.Probe.ProbeMs,
                    deltaMs = f.Probe.DeltaMs,
                    baselineStatus = f.Probe.BaselineStatus,
                    probeStatus = f.Probe.ProbeStatus,
                    obfuscation = f.Probe.Obfuscation,
                } : null,
            }).ToList(),
            headerNormalization = new
            {
                acceptsDuplicateCL = result.HeaderNormalization.AcceptsDuplicateCL,
                acceptsObfuscatedTE = result.HeaderNormalization.AcceptsObfuscatedTE,
                obfuscationsAccepted = result.HeaderNormalization.ObfuscationsAccepted,
                obfuscationsAcceptedRfcCompliant = result.HeaderNormalization.ObfuscationsAcceptedRfcCompliant,
                rejectsBothCLAndTE = result.HeaderNormalization.RejectsBothCLAndTE,
                riskNote = result.HeaderNormalization.RiskNote,
            },
            infrastructure = new
            {
                httpVersion = result.Infrastructure.HttpVersion,
                alpn = result.Infrastructure.Alpn,
                serverHeader = result.Infrastructure.ServerHeader,
                viaHeaders = result.Infrastructure.ViaHeaders,
                proxyLikely = result.Infrastructure.ProxyLikely,
                proxyEvidence = result.Infrastructure.ProxyEvidence,
            },
        };
    }

private Task HandlePostSecurityHostHeader(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityHostHeaderAsync);

internal async Task<object> BuildSecurityHostHeaderAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "This sends HTTP requests with manipulated Host/X-Forwarded-Host headers to the target");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var evilHost = body.GetString("evilHost") ?? HostHeaderInjectionScanner.DefaultEvilHost;
        var method = body.GetString("method") ?? "GET";
        var probes = body.GetStringList("probes");
        var timeoutMs = body.GetInt("timeoutMs", 15000);
        var maxBodyChars = body.GetInt("maxBodyChars", 32768);
        var includeBrowserCookies = body.GetBool("includeBrowserCookies", true);
        var discoverFromNetwork = body.GetBool("discoverFromNetwork");
        var maxTargets = body.GetInt("maxTargets", 5);
        var headers = body.GetStringDictionary("headers");

        string? fetchBody = body.GetString("body");
        string? contentType = null;
        if (headers != null && headers.TryGetValue("Content-Type", out var ct))
            contentType = ct;
        if (fetchBody == null && body.HasProperty("json"))
        {
            fetchBody = body.GetRawJson("json");
            headers ??= new Dictionary<string, string>();
            headers.TryAdd("Content-Type", "application/json");
            contentType = "application/json";
        }

        var sw = Stopwatch.StartNew();
        var targets = new List<HostHeaderInjectionScanner.DiscoveredTarget>();

        if (discoverFromNetwork)
        {
            var currentUrl = await _context.GetCurrentUrl();
            string? scopeHost = null;
            if (!string.IsNullOrWhiteSpace(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var curUri))
                scopeHost = curUri.Host;

            targets = HostHeaderInjectionScanner.DiscoverTargetsFromNetwork(
                _context.Network.Entries, scopeHost, maxTargets);
        }

        var explicitUrl = body.GetString("url");
        if (!string.IsNullOrWhiteSpace(explicitUrl))
        {
            targets.Insert(0, new HostHeaderInjectionScanner.DiscoveredTarget
            {
                Url = explicitUrl,
                Method = method,
                Body = fetchBody,
                ContentType = contentType,
                Reason = "Explicit URL from request",
            });
        }
        else if (targets.Count == 0)
        {
            var url = await _context.GetCurrentUrl();
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
                throw new ApiCommandException(400,
                    "Missing URL. Provide 'url', enable discoverFromNetwork after browsing, or navigate to a page first.");

            targets.Add(new HostHeaderInjectionScanner.DiscoveredTarget
            {
                Url = url,
                Method = method,
                Body = fetchBody,
                ContentType = contentType,
                Reason = "Current page URL",
            });
        }

        // Dedupe by path (ignore method/query variants from network discovery)
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var uniqueTargets = new List<HostHeaderInjectionScanner.DiscoveredTarget>();
        foreach (var t in targets)
        {
            var key = HostHeaderInjectionScanner.GetTargetDedupKey(t.Url);
            if (seen.Add(key))
                uniqueTargets.Add(t);
        }

        var scanResults = new List<object>();
        var totalFindings = 0;

        foreach (var target in uniqueTargets)
        {
            string? cookieHeader = null;
            if (includeBrowserCookies)
                cookieHeader = await _context.GetCookieHeaderForUrl(target.Url);

            var result = await HostHeaderInjectionScanner.RunAsync(new HostHeaderInjectionScanner.HostHeaderScanOptions
            {
                Url = target.Url,
                Method = target.Method,
                Body = target.Body ?? fetchBody,
                ContentType = target.ContentType ?? contentType,
                EvilHost = evilHost,
                Probes = probes,
                CookieHeader = string.IsNullOrEmpty(cookieHeader) ? null : cookieHeader,
                ExtraHeaders = headers,
                TimeoutMs = timeoutMs,
                MaxBodyChars = maxBodyChars,
            });

            totalFindings += result.Findings.Count;
            scanResults.Add(new
            {
                url = result.Url,
                method = result.Method,
                reason = target.Reason,
                evilHost = result.EvilHost,
                canonicalHost = result.CanonicalHost,
                elapsedMs = result.ElapsedMs,
                summary = result.Summary,
                probesRun = result.ProbesRun,
                requestsRun = result.RequestsRun,
                findingCount = result.Findings.Count,
                findings = result.Findings.Select(f => new
                {
                    probe = f.Probe,
                    severity = f.Severity,
                    reflectionType = f.ReflectionType,
                    description = f.Description,
                    evidence = f.Evidence,
                    remediation = f.Remediation,
                }).ToList(),
                baseline = new
                {
                    status = result.Baseline.Status,
                    durationMs = result.Baseline.DurationMs,
                    locationHeader = result.Baseline.LocationHeader,
                    error = result.Baseline.Error,
                },
                probes = result.Probes.Select(p => new
                {
                    probe = p.Probe,
                    status = p.Status,
                    durationMs = p.DurationMs,
                    reflected = p.Reflected,
                    severity = p.Severity,
                    reflectionLocations = p.ReflectionLocations,
                    locationHeader = p.LocationHeader,
                    evidenceSnippet = p.EvidenceSnippet,
                    error = p.Error,
                    rawRequest = p.RawRequest,
                }).ToList(),
            });
        }

        sw.Stop();
        var overallSummary = totalFindings > 0
            ? $"{totalFindings} host-header reflection finding(s) across {scanResults.Count} target(s)."
            : $"No host-header reflection detected across {scanResults.Count} target(s).";

        return new
        {
            evilHost,
            elapsedMs = sw.ElapsedMilliseconds,
            targetCount = scanResults.Count,
            findingCount = totalFindings,
            summary = overallSummary,
            discoveredFromNetwork = discoverFromNetwork,
            targets = scanResults,
        };
    }

private Task HandlePostSecuritySqliScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySqliScanAsync);

internal async Task<object> BuildSecuritySqliScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SQLi scan sends crafted requests to your server");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        string? url;
        string method;
        Dictionary<string, string>? headers;
        string? bodyTemplate;

        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            url = req.GetString("url");
            if (string.IsNullOrWhiteSpace(url))
                throw new ApiCommandException(400, Security.InjectionRequestErrors.WithRequestExample("request.url is required."));

            method = req.GetString("method") ?? "GET";
            headers = req.GetStringDictionary("headers");
            bodyTemplate = null;
            if (req.HasProperty("body"))
                bodyTemplate = req.GetString("body");
            else if (req.HasProperty("json"))
            {
                var je = req.GetJsonElement("json");
                if (je != null) bodyTemplate = je.Value.GetRawText();
            }
        }
        else
        {
            // Shorthand: { url, param, method? } → inject §param§ into query (or replace existing value).
            url = body.GetString("url");
            var param = body.GetString("param") ?? body.GetString("paramName");
            if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(param))
            {
                var fetchShaped = !string.IsNullOrWhiteSpace(url)
                    && (body.HasProperty("json") || body.HasProperty("body"));
                throw new ApiCommandException(400, Security.InjectionRequestErrors.MissingSqliTemplate(fetchShaped));
            }

            method = body.GetString("method") ?? "GET";
            headers = body.GetStringDictionary("headers");
            bodyTemplate = body.GetString("body");
            url = InjectQueryParamMarker(url!, param!);
            // Classic PHP/form sinks often require sibling fields (Submit, tokens). Clone from live DOM.
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrEmpty(bodyTemplate))
            {
                url = await Security.FormProbeCloner.MergeGetFormSiblingsAsync(
                    _context, url!, param!, _context.OperationCancellation);
            }
        }

        var baseline = body.GetString("baselineValue") ?? "1";
        var depth = body.GetString("depth");
        var includeTimeBased = body.HasProperty("includeTimeBased")
            ? body.GetBool("includeTimeBased")
            : InjectionScanDepth.Resolve(depth).IncludeTimeBasedDefault;
        var timeoutMs = body.GetInt("timeoutMs", 15000);
        var maxBodyChars = body.GetInt("maxResponseBodyChars", 131072);
        List<string>? customPayloads = body.GetStringArray("payloads");
        var useBackendFetch = body.GetBool("useBackendFetch");
        var includeBrowserCookies = body.GetBool("includeBrowserCookies");
        var includeOrmClosurePayloads = body.GetBool("includeOrmClosurePayloads")
            || InjectionScanDepth.Resolve(depth).IncludeOrmClosure;
        var includeHygiene = body.GetBool("includeHygiene");
        var minConfidence = body.GetString("minConfidence") ?? SecurityConfidence.Likely;

        try
        {
            var result = await Security.HttpSecurityProbes.RunSqliScanAsync(
                _context, url!, method, headers, bodyTemplate, baseline, customPayloads,
                includeTimeBased, timeoutMs, maxBodyChars, useBackendFetch, includeBrowserCookies,
                includeOrmClosurePayloads, ct: _context.OperationCancellation, depth: depth);
            return result.ToSecurityScanResult().ToApiResponse(includeHygiene, minConfidence);
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

/// <summary>
/// Rewrite <paramref name="url"/> so <paramref name="param"/>'s value is the injection marker §param§.
/// Markers must remain literal (not percent-encoded) so <see cref="Security.RequestMarkerSubstitute"/> can find them.
/// </summary>
private static string InjectQueryParamMarker(string url, string param)
{
    var marker = "§" + param + "§";
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        throw new ApiCommandException(400, "url must be an absolute URL.");

    var parts = new List<string>();
    var query = uri.Query.TrimStart('?');
    if (!string.IsNullOrEmpty(query))
    {
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var key = eq >= 0 ? Uri.UnescapeDataString(part[..eq]) : Uri.UnescapeDataString(part);
            if (key.Equals(param, StringComparison.OrdinalIgnoreCase))
                continue;
            parts.Add(part);
        }
    }

    parts.Add($"{Uri.EscapeDataString(param)}={marker}");
    return uri.GetLeftPart(UriPartial.Path) + "?" + string.Join("&", parts);
}

private Task HandlePostSecuritySqliLoginSweep(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySqliLoginSweepAsync);

internal async Task<object> BuildSecuritySqliLoginSweepAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SQLi login sweep sends crafted login requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.SqliLoginSweep.SqliLoginSweepOptions
        {
            MaxLoginUrls = body.GetInt("maxLoginUrls", 12),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            LoginUrls = body.GetStringArray("loginUrls")
        };

        try
        {
            var result = await _context.RunSqliLoginSweep(options);
            return FormatSqliLoginSweepResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityNosqlScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityNosqlScanAsync);

internal async Task<object> BuildSecurityNosqlScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "NoSQL scan sends operator injection payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        string? urlTemplate = null;
        string? bodyTemplate = null;
        Dictionary<string, string>? reqHeaders = null;
        string? method = null;
        string? paramName = null;
        if (body.HasProperty("request"))
        {
            var req = body.GetObject("request");
            if (req != null)
            {
                urlTemplate = req.RootElement.TryGetProperty("url", out var u) ? u.GetString() : null;
                method = req.RootElement.TryGetProperty("method", out var m) ? m.GetString() : null;
                paramName = req.RootElement.TryGetProperty("paramName", out var pn) ? pn.GetString() : null;
                if (req.RootElement.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                {
                    reqHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var prop in h.EnumerateObject())
                        reqHeaders[prop.Name] = prop.Value.GetString() ?? prop.Value.ToString();
                }

                if (req.RootElement.TryGetProperty("json", out var je))
                    bodyTemplate = je.GetRawText();
                else if (req.RootElement.TryGetProperty("body", out var be))
                    bodyTemplate = be.GetString();
            }
        }

        var options = new Security.NosqlScanProbe.NosqlScanOptions
        {
            UrlTemplate = urlTemplate,
            Method = method,
            Headers = reqHeaders,
            BodyTemplate = bodyTemplate,
            ParamName = paramName,
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            SparseThreshold = body.GetInt("sparseThreshold", InjectionScaffold.DefaultSparseThreshold),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            ExcludeTransportEndpoints = body.GetBool("excludeTransportEndpoints", true),
            ScanDepth = body.GetString("scanDepth"),
            PayloadProfile = PayloadProfileExtensions.Parse(body.GetString("payloadProfile"))
        };

        try
        {
            var result = await _context.RunNosqlScan(options);
            return FormatNosqlScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityLdapScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLdapScanAsync);

internal async Task<object> BuildSecurityLdapScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "LDAP scan sends filter break-out payloads to login endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.LdapScanProbe.LdapScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            LoginUrls = body.GetStringArray("loginUrls")
        };

        try
        {
            var result = await _context.RunLdapScan(options);
            return FormatLdapScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecuritySstiPolyglotScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySstiPolyglotScanAsync);

internal async Task<object> BuildSecuritySstiPolyglotScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SSTI polyglot scan sends template payloads in GET query parameters");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.SstiPolyglotScanProbe.SstiPolyglotScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            MaxProbes = body.GetInt("maxProbes", 48),
            MaxParams = body.GetInt("maxParams", 0),
            TimeoutMs = body.GetInt("timeoutMs", 12000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            Paths = body.GetStringArray("paths")?.ToList(),
            Params = body.GetStringArray("params")?.ToList()
        };

        try
        {
            var result = await _context.RunSstiPolyglotScan(options);
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecuritySstiStoredScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySstiStoredScanAsync);

internal async Task<object> BuildSecuritySstiStoredScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Stored SSTI scan POSTs template payloads to profile endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.SstiStoredScanProbe.SstiStoredScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            ProfileUrls = body.GetStringArray("profileUrls")?.ToList()
        };

        try
        {
            var result = await _context.RunSstiStoredScan(options);
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityPrototypePollutionScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityPrototypePollutionScanAsync);

internal async Task<object> BuildSecurityPrototypePollutionScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Prototype pollution scan POSTs __proto__ payloads to JSON endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.PrototypePollutionScanProbe.PrototypePollutionScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeScaffold = body.GetBool("includeScaffold", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            CandidateUrls = body.GetStringArray("candidateUrls")?.ToList()
        };

        try
        {
            var result = await _context.RunPrototypePollutionScan(options);
            return result;
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecuritySstiScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySstiScanAsync);

internal async Task<object> BuildSecuritySstiScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "SSTI scan sends template injection payloads to your server");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = BuildSstiScanOptions(body);
        var includeHygiene = body.GetBool("includeHygiene");
        var minConfidence = body.GetString("minConfidence") ?? SecurityConfidence.Likely;
        try
        {
            var result = await _context.RunSstiScan(options);
            return result.ToSecurityScanResult().ToApiResponse(includeHygiene, minConfidence);
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityParserProbe(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityParserProbeAsync);

internal async Task<object> BuildSecurityParserProbeAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Parser-probe sends alternate Content-Type and body-shape requests");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = BuildParserProbeOptions(body);
        try
        {
            var result = await _context.RunParserProbe(options);
            return FormatParserProbeResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityDeserializationScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityDeserializationScanAsync);

internal async Task<object> BuildSecurityDeserializationScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Deserialization scan sends node-serialize gadgets and parser payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.DeserializationScanProbe.DeserializationScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 8),
            TimeoutMs = body.GetInt("timeoutMs", 15000),
            IncludeJavaStub = body.GetBool("includeJavaStub", true),
            IncludePhpStub = body.GetBool("includePhpStub", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true)
        };

        try
        {
            var result = await _context.RunDeserializationScan(options);
            return FormatDeserializationScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityFileUploadScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityFileUploadScanAsync);

internal async Task<object> BuildSecurityFileUploadScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "File upload scan sends oversize, executable, and polyglot multipart payloads");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.FileUploadScanProbe.FileUploadScanOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", 12000),
            IncludeXxe = body.GetBool("includeXxe", true),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true),
            TryDomReplayWhenSpaShell = body.GetBool("tryDomReplayWhenSpaShell", false),
            Urls = body.GetStringArray("urls")
        };

        try
        {
            var result = await _context.RunFileUploadScan(options);
            return FormatFileUploadScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityCmdCanary(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCmdCanaryAsync);

internal async Task<object> BuildSecurityCmdCanaryAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Cmd-canary sends shell/template injection canaries to your server");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = BuildCmdCanaryOptions(body);
        try
        {
            var result = await _context.RunCmdCanary(options);
            return FormatCmdCanaryResult(result);
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (TimeoutException ex)
        {
            throw new ApiCommandException(408, ex.Message);
        }
    }

private Task HandlePostSecurityCstiScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityCstiScanAsync);

internal async Task<object> BuildSecurityCstiScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "CSTI scan navigates with template injection payloads in the browser");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = BuildCstiScanOptions(body);
        try
        {
            var result = await _context.RunCstiScan(options);
            return new
            {
                result.Message,
                result.CandidatesProbed,
                result.ElapsedMs,
                enginesTested = result.EnginesTested,
                hasFindings = result.HasFindings,
                findings = result.Findings.Select(f => new
                {
                    f.Url,
                    parameter = f.Parameter,
                    f.Source,
                    f.Engine,
                    basicExpression = f.BasicExpression,
                    f.EvaluatedToken,
                    f.CodeExecution,
                    f.Sinks,
                    f.Severity
                }),
                probes = result.Probes.Select(p => new
                {
                    p.Url,
                    p.ParamName,
                    p.Source,
                    p.Engine,
                    hasFindings = p.HasFindings,
                    rows = p.Result.Rows.Select(r => new
                    {
                        r.Payload,
                        r.Level,
                        r.ExpressionEvaluated,
                        r.EvaluatedToken,
                        r.CodeExecution,
                        r.Sinks,
                        r.Severity
                    }),
                    p.Result.ElapsedMs
                })
            };
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityXssScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityXssScanAsync);

internal async Task<object> BuildSecurityXssScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "XSS scan injects payloads via fetch/navigation in the browser");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = BuildXssScanOptions(body);
        var includeHygiene = body.GetBool("includeHygiene");
        var minConfidence = body.GetString("minConfidence") ?? SecurityConfidence.Likely;
        try
        {
            var result = await _context.RunXssScan(options);
            return result.ToSecurityScanResult(result.ZeroResultHints).ToApiResponse(includeHygiene, minConfidence);
        }
        catch (ArgumentException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }
}
