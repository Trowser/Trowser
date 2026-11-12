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
    #region AuthZ Handlers

    /// <summary>
    /// Execute a single fetch through the WebView2 browser context and return parsed status + body.
    /// Reuses the same code path as POST /api/fetch.
    /// </summary>
    private async Task<(int status, string body)> InternalFetchAsync(
        string url, string method, Dictionary<string, string>? headers, string? bodyContent)
    {
        var (status, body, _, _) = await InternalFetchFullAsync(url, method, headers, bodyContent);
        return (status, body);
    }

    private async Task<(int status, string body, bool redirected, string? finalUrl)> InternalFetchFullAsync(
        string url, string method, Dictionary<string, string>? headers, string? bodyContent)
    {
        try
        {
            var resultJson = await _context.Fetch(url, method, headers, bodyContent, 30000);
            using var doc = JsonDocument.Parse(resultJson);
            var root = doc.RootElement;
            var status = root.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
            var body = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            var redirected = root.TryGetProperty("redirected", out var r) && r.ValueKind == JsonValueKind.True;
            var finalUrl = root.TryGetProperty("url", out var u) ? u.GetString() : null;
            return (status, body, redirected, finalUrl);
        }
        catch (Exception ex)
        {
            return (0, ex.Message, false, null);
        }
    }

    private async Task HandlePostAuthzProbe(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var endpoints = body.GetJsonElement("endpoints");
        var classify = body.GetBool("classify", true);
        var ensureOrigin = body.GetBool("ensureOrigin");

        if (endpoints == null || endpoints.Value.ValueKind != JsonValueKind.Array)
        {
            await WriteError(response, 400,
                "Field 'endpoints' is required: array of { url, method?, headers?, json?, body? }");
            return;
        }

        // Navigate to the target origin if needed (ensures cookies are sent)
        if (ensureOrigin)
        {
            string? firstUrl = null;
            foreach (var ep in endpoints.Value.EnumerateArray())
            {
                if (ep.ValueKind == JsonValueKind.String)
                    firstUrl = ep.GetString();
                else if (ep.TryGetProperty("url", out var u))
                    firstUrl = u.GetString();
                if (firstUrl != null) break;
            }
            if (firstUrl != null && Uri.TryCreate(firstUrl, UriKind.Absolute, out var targetUri))
            {
                var currentUrl = await _context.GetCurrentUrl();
                if (Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
                {
                    if (!string.Equals($"{currentUri.Scheme}://{currentUri.Authority}",
                        $"{targetUri.Scheme}://{targetUri.Authority}", StringComparison.OrdinalIgnoreCase))
                    {
                        await _context.ForceNavigateAsync($"{targetUri.Scheme}://{targetUri.Authority}/", true);
                    }
                }
            }
        }

        var results = new List<object>();
        int allowed = 0, denied = 0, errors = 0;
        var defaultPeer = body.GetString("peer")?.Trim();

        foreach (var ep in endpoints.Value.EnumerateArray())
        {
            string? url;
            string method = "GET";
            Dictionary<string, string>? headers = null;
            string? fetchBody = null;
            string? endpointPeer = defaultPeer;

            if (ep.ValueKind == JsonValueKind.String)
            {
                url = ep.GetString();
            }
            else
            {
                url = ep.TryGetProperty("url", out var u) ? u.GetString() : null;
                method = ep.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET";
                if (ep.TryGetProperty("headers", out var h)) headers = ParseHeadersFromJson(h);
                if (ep.TryGetProperty("json", out var j))
                {
                    fetchBody = j.GetRawText();
                    headers ??= new Dictionary<string, string>();
                    headers.TryAdd("Content-Type", "application/json");
                }
                else if (ep.TryGetProperty("body", out var b))
                {
                    fetchBody = b.GetString();
                }

                if (ep.TryGetProperty("peer", out var p) && p.ValueKind == JsonValueKind.String)
                    endpointPeer = p.GetString()?.Trim();
            }

            if (string.IsNullOrWhiteSpace(url)) continue;

            int status;
            string bodyText;
            if (!string.IsNullOrWhiteSpace(endpointPeer))
            {
                var peerFetchBody = new Dictionary<string, object?> { ["url"] = url, ["method"] = method };
                if (headers != null) peerFetchBody["headers"] = headers;
                if (fetchBody != null)
                {
                    var ct = headers?.GetValueOrDefault("Content-Type") ?? "";
                    if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
                    {
                        try { peerFetchBody["json"] = JsonSerializer.Deserialize<object>(fetchBody); }
                        catch { peerFetchBody["body"] = fetchBody; }
                    }
                    else peerFetchBody["body"] = fetchBody;
                }

                var peerFetchTimeout = peerFetchBody.TryGetValue("timeout", out var pt) && pt is int ptm
                    ? ptm
                    : peerFetchBody.TryGetValue("timeout", out var pto) && pto is long ptl
                        ? (int)ptl
                        : 0;
                var peerResp = await Peers.ForwardAsync(endpointPeer, "POST", "/api/fetch-direct",
                    JsonSerializer.Serialize(peerFetchBody, JsonOptions),
                    timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(peerFetchTimeout));
                status = 0;
                bodyText = peerResp.Body ?? "";
                if (peerResp.Success || peerResp.StatusCode == 200)
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(peerResp.Body ?? "{}");
                        if (doc.RootElement.TryGetProperty("data", out var data))
                        {
                            status = data.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                            bodyText = data.TryGetProperty("body", out var pb) ? pb.GetString() ?? "" : "";
                        }
                    }
                    catch { /* keep raw */ }
                }
            }
            else
            {
                (status, bodyText) = await InternalFetchAsync(url, method, headers, fetchBody);
            }

            var bodyLen = bodyText.Length;
            var bodyHash = ComputeShortHash(bodyText);

            string? classification = null;
            if (classify)
            {
                if (status >= 200 && status < 300) { classification = "allowed"; allowed++; }
                else if (status >= 400 && status < 500) { classification = "denied"; denied++; }
                else if (status >= 500) { classification = "error"; errors++; }
                else if (status == 0) { classification = "error"; errors++; }
                else { classification = "other"; }
            }

            var entry = new Dictionary<string, object?>
            {
                ["url"] = url,
                ["method"] = method,
                ["status"] = status,
                ["bodyLength"] = bodyLen,
                ["bodyHash"] = bodyHash
            };
            if (!string.IsNullOrWhiteSpace(endpointPeer)) entry["peer"] = endpointPeer;
            if (classification != null) entry["classification"] = classification;
            if (status >= 400 || status == 0)
            {
                var snippet = bodyText.Length > 200 ? bodyText[..200] : bodyText;
                entry["errorSnippet"] = snippet;
            }
            results.Add(entry);
        }

        await WriteSuccess(response, new
        {
            results,
            summary = new { total = results.Count, allowed, denied, errors }
        });
    }

    private async Task HandlePostAuthzDiff(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            var result = await BuildAuthzDiffAsync(body);
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    internal async Task<object> BuildAuthzDiffAsync(JsonBody body)
    {
        var peerNames = body.GetStringArray("peers")?.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                        ?? [];
        var legacyPeer = body.GetString("peer")?.Trim();
        if (peerNames.Count == 0 && !string.IsNullOrWhiteSpace(legacyPeer))
            peerNames.Add(legacyPeer);

        var endpoints = body.GetJsonElement("endpoints");
        if (peerNames.Count == 0)
            throw new ApiCommandException(400, "Field 'peer' or 'peers[]' (registered peer name(s)) is required.");
        if (endpoints == null || endpoints.Value.ValueKind != JsonValueKind.Array)
            throw new ApiCommandException(400,
                "Field 'endpoints' is required: array of URL strings or { url, method?, headers?, json?, body? } objects.");

        var leakTokens = new List<string>();
        var leakTokensEl = body.GetJsonElement("leakTokens");
        if (leakTokensEl != null && leakTokensEl.Value.ValueKind == JsonValueKind.Array)
        {
            foreach (var lt in leakTokensEl.Value.EnumerateArray())
                if (lt.GetString() is { } s) leakTokens.Add(s);
        }

        var bodyMatch = body.TryGetRoot(out var root)
            ? AuthzBodyMatchOptions.Parse(root)
            : new AuthzBodyMatchOptions();
        var parsedEndpoints = AuthzComparisonService.ParseEndpoints(endpoints.Value);
        var options = new AuthzComparisonOptions
        {
            IncludeBody = body.GetBool("includeBody"),
            IncludeBodyOnMismatch = body.GetBool("includeBodyOnMismatch"),
            LeakTokens = leakTokens,
            EnsureOrigin = body.GetBool("ensureOrigin", true),
            BodyMatch = bodyMatch
        };

        var peerResults = new List<object>();
        foreach (var peerName in peerNames)
        {
            var result = await AuthzComparisonService.RunForPeerAsync(
                _context, Peers, peerName, parsedEndpoints, options);
            peerResults.Add(AuthzComparisonService.ToResponseObject(result, bodyMatch));
        }

        return peerNames.Count == 1
            ? peerResults[0]!
            : new { peers = peerResults, peerCount = peerNames.Count };
    }

    private static readonly string[][] SmartFuzzPayloads =
    [
        // Boundary values
        ["", "null", "undefined", "0", "-1", "99999999", "true", "false"],
        // Type confusion
        ["[]", "{}", "[null]", "NaN", "Infinity", "-Infinity"],
        // Long strings
        [new string('A', 1000), new string('A', 10000)],
        // Special characters
        ["<script>alert(1)</script>", "' OR '1'='1", "{{7*7}}", "${7*7}",
         "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
         "%00", "\0", "\r\n", "\t", "\x00"],
        // Unicode edge cases
        ["\uFEFF", "\u0000", "\u202E", "é", "中文", "🔥"],
        // Format strings
        ["%s%s%s%s%s", "%d%d%d%d%d", "%x%x%x%x%x", "%n%n%n%n%n"],
    ];

    private static List<Dictionary<string, string>> GenerateSmartPayloads(
        List<Dictionary<string, string>> baselines)
    {
        var generated = new List<Dictionary<string, string>>();
        if (baselines.Count == 0) return generated;

        var paramNames = baselines[0].Keys.Where(k => k != "body" && k != "headers").ToList();
        if (paramNames.Count == 0) return generated;

        foreach (var paramName in paramNames)
        {
            foreach (var payloadSet in SmartFuzzPayloads)
            {
                foreach (var payload in payloadSet)
                {
                    var set = new Dictionary<string, string>(baselines[0]);
                    set[paramName] = payload;
                    generated.Add(set);
                }
            }
        }

        return generated;
    }

    private async Task HandlePostAuthzFuzz(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var endpoint = body.GetString("endpoint");
        var method = body.GetString("method") ?? "GET";
        var paramSets = body.GetJsonElement("parameterSets");
        var classify = body.GetBool("classify", true);
        var detectCrashPattern = body.GetBool("detectCrashPattern", true);
        var headersTemplate = body.GetStringDictionary("headers");
        var bodyTemplate = body.GetString("bodyTemplate");
        var autoPayloads = body.GetBool("autoPayloads", false);

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            await WriteError(response, 400, "Field 'endpoint' is required (URL template with {param} placeholders).");
            return;
        }
        if (paramSets == null || paramSets.Value.ValueKind != JsonValueKind.Array)
        {
            await WriteError(response, 400, "Field 'parameterSets' is required: array of { paramName: value, ... } objects.");
            return;
        }

        var results = new List<object>();
        int allowed = 0, denied = 0, errors = 0, crashes = 0;

        var crashPatterns = new[] {
            "NullPointerException", "NullReferenceException", "NullPointer",
            "java.lang.NullPointerException", "500 Internal Server Error",
            "stack trace", "Traceback (most recent call last)",
            "FATAL", "Unhandled Exception", "at System.",
            "at java.", "at org.springframework",
            "ORA-", "SQL syntax", "MySQLSyntaxError"
        };

        var baselines = new List<Dictionary<string, string>>();

        foreach (var paramSet in paramSets.Value.EnumerateArray())
        {
            var url = endpoint;
            string? fetchBody = null;
            var headers = headersTemplate != null ? new Dictionary<string, string>(headersTemplate) : null;

            if (paramSet.ValueKind == JsonValueKind.Object)
            {
                var substitutions = new Dictionary<string, string>();
                foreach (var prop in paramSet.EnumerateObject())
                {
                    if (prop.Name == "body")
                    {
                        fetchBody = prop.Value.ValueKind == JsonValueKind.String
                            ? prop.Value.GetString()
                            : prop.Value.GetRawText();
                        if (fetchBody != null && (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("[")))
                        {
                            headers ??= new Dictionary<string, string>();
                            headers.TryAdd("Content-Type", "application/json");
                        }
                    }
                    else if (prop.Name == "headers" && prop.Value.ValueKind == JsonValueKind.Object)
                    {
                        headers ??= new Dictionary<string, string>();
                        foreach (var h in prop.Value.EnumerateObject())
                            headers[h.Name] = h.Value.GetString() ?? "";
                    }
                    else
                    {
                        var val = prop.Value.ValueKind == JsonValueKind.String
                            ? prop.Value.GetString() ?? ""
                            : prop.Value.GetRawText();
                        substitutions[prop.Name] = val;
                        url = url.Replace($"{{{prop.Name}}}", Uri.EscapeDataString(val));
                    }
                }

                if (autoPayloads && substitutions.Count > 0)
                    baselines.Add(substitutions);

                if (bodyTemplate != null && fetchBody == null)
                {
                    fetchBody = bodyTemplate;
                    foreach (var kv in substitutions)
                        fetchBody = fetchBody.Replace($"{{{kv.Key}}}", kv.Value);
                    if (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("["))
                    {
                        headers ??= new Dictionary<string, string>();
                        headers.TryAdd("Content-Type", "application/json");
                    }
                }
            }

            FuzzClassifyResult(url, method, endpoint, paramSet, headers, fetchBody, bodyTemplate,
                classify, detectCrashPattern, crashPatterns, results,
                ref allowed, ref denied, ref errors, ref crashes,
                await InternalFetchAsync(url, method, headers, fetchBody));
        }

        if (autoPayloads && baselines.Count > 0)
        {
            var smartSets = GenerateSmartPayloads(baselines);
            foreach (var paramDict in smartSets)
            {
                var url = endpoint;
                foreach (var kv in paramDict)
                    url = url.Replace($"{{{kv.Key}}}", Uri.EscapeDataString(kv.Value));

                string? fetchBody = null;
                var headers = headersTemplate != null ? new Dictionary<string, string>(headersTemplate) : null;
                if (bodyTemplate != null)
                {
                    fetchBody = bodyTemplate;
                    foreach (var kv in paramDict)
                        fetchBody = fetchBody.Replace($"{{{kv.Key}}}", kv.Value);
                    if (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("["))
                    {
                        headers ??= new Dictionary<string, string>();
                        headers.TryAdd("Content-Type", "application/json");
                    }
                }

                FuzzClassifyResult(url, method, endpoint, paramDict, headers, fetchBody, bodyTemplate,
                    classify, detectCrashPattern, crashPatterns, results,
                    ref allowed, ref denied, ref errors, ref crashes,
                    await InternalFetchAsync(url, method, headers, fetchBody));
            }
        }

        await WriteSuccess(response, new
        {
            endpoint,
            method,
            results,
            summary = new { total = results.Count, allowed, denied, errors, crashes }
        });
    }

    private static void FuzzClassifyResult(
        string url, string method, string endpoint, object paramSet,
        Dictionary<string, string>? headers, string? fetchBody, string? bodyTemplate,
        bool classify, bool detectCrashPattern, string[] crashPatterns,
        List<object> results,
        ref int allowed, ref int denied, ref int errors, ref int crashes,
        (int status, string bodyText) fetchResult)
    {
        var (status, bodyText) = fetchResult;
        var bodyHash = ComputeShortHash(bodyText);

        string? classification = null;
        bool isCrash = false;

        if (classify)
        {
            if (status >= 200 && status < 300) { classification = "allowed"; allowed++; }
            else if (status >= 400 && status < 500) { classification = "denied"; denied++; }
            else if (status >= 500) { classification = "error"; errors++; }
            else { classification = "error"; errors++; }
        }

        if (detectCrashPattern && status >= 500)
        {
            foreach (var pattern in crashPatterns)
            {
                if (bodyText.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    isCrash = true;
                    crashes++;
                    break;
                }
            }
        }

        var entry = new Dictionary<string, object?>
        {
            ["url"] = url,
            ["method"] = method,
            ["parameters"] = paramSet,
            ["status"] = status,
            ["bodyLength"] = bodyText.Length,
            ["bodyHash"] = bodyHash
        };
        if (classification != null) entry["classification"] = classification;
        if (isCrash) entry["crash"] = true;
        if (status >= 400 || status == 0)
            entry["errorSnippet"] = bodyText.Length > 500 ? bodyText[..500] : bodyText;
        results.Add(entry);
    }

    private async Task HandlePostAuthzBoundary(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            var result = await BuildAuthzBoundaryAsync(body);
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    internal async Task<object> BuildAuthzBoundaryAsync(JsonBody body)
    {
        if (!body.TryGetRoot(out var root))
            throw new ApiCommandException(400, "Request body is required.");

        var specs = AuthzBoundaryService.ParseSpecs(root, out var parseError);
        if (parseError != null)
            throw new ApiCommandException(400, parseError);

        var bodyMatch = AuthzBodyMatchOptions.Parse(root);
        return await AuthzBoundaryService.RunAsync(_context, Peers, specs, bodyMatch);
    }

    private async Task HandlePostAuthzRoleMatrix(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var identities = body.GetStringArray("identities");
        if (identities == null || identities.Count < 2)
        {
            await WriteError(response, 400,
                "Field 'identities' is required: array of at least two captured identity names (e.g. [\"user\", \"admin\"]).");
            return;
        }

        List<Security.AttackSurfaceEndpoint>? surface = null;
        if (body.GetBool("discoverFromAttackSurface", true))
        {
            var map = _context.CheckAttackSurface(hostFilter: body.GetString("host"));
            surface = map.Endpoints;
        }

        var result = await Security.AuthzRoleMatrixService.RunAsync(_context, _identityStore,
            new Security.AuthzRoleMatrixService.MatrixOptions
            {
                Identities = identities,
                Endpoints = body.GetStringArray("endpoints"),
                AttackSurface = surface,
                IncludeAdminEndpoints = body.GetBool("includeAdminEndpoints", true),
                MaxEndpoints = body.GetInt("maxEndpoints", 20),
                TimeoutMs = body.GetInt("timeoutMs", 15000)
            });

        await WriteSuccess(response, result);
    }

    #region Access Model

    private async Task HandleGetAuthzModel(HttpListenerRequest request, HttpListenerResponse response)
    {
        var query = ApiQuery(request);
        try
        {
            var result = await BuildAuthzModelGetAsync(
                query["host"]?.Trim(),
                string.Equals(query["seed"], "true", StringComparison.OrdinalIgnoreCase));
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    private async Task HandlePutAuthzModel(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            var result = await BuildAuthzModelSetAsync(body);
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    /// <summary>Shared MCP entry point: dispatches to get/set based on <c>mode</c> (default "get").</summary>
    internal async Task<object> BuildAuthzModelAsync(JsonBody body)
    {
        var mode = (body.GetString("mode") ?? "get").Trim().ToLowerInvariant();
        if (mode == "set")
            return await BuildAuthzModelSetAsync(body);

        return await BuildAuthzModelGetAsync(body.GetString("host")?.Trim(), body.GetBool("seed"));
    }

    private async Task<object> BuildAuthzModelGetAsync(string? host, bool seed)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            var currentUrl = await _context.GetCurrentUrl();
            host = Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri)
                ? Security.Authz.AuthzHostKey.FromUri(uri)
                : null;
        }
        else
        {
            host = Security.Authz.AuthzHostKey.Canonical(host);
        }

        if (string.IsNullOrWhiteSpace(host) || !Security.Authz.AccessModelStore.IsValidHost(host))
            throw new ApiCommandException(400,
                "Could not determine a host. Pass 'host' (e.g. example.com) or navigate the browser to the target first.");

        var model = _accessModelStore.GetOrCreate(host);

        if (seed)
        {
            var surface = _context.CheckAttackSurface(hostFilter: host);
            var seededCount = Security.Authz.AccessModelSeeder.Seed(model, surface.Endpoints);
            if (seededCount > 0)
                _accessModelStore.Save(model);
        }

        _context.LiveAuthzShadow?.ApplySessionClassifications(model);
        return ToAccessModelResponse(model);
    }

    private async Task<object> BuildAuthzModelSetAsync(JsonBody body)
    {
        var host = body.GetString("host")?.Trim();
        if (!string.IsNullOrWhiteSpace(host))
            host = Security.Authz.AuthzHostKey.Canonical(host);
        if (string.IsNullOrWhiteSpace(host) || !Security.Authz.AccessModelStore.IsValidHost(host))
            throw new ApiCommandException(400, "Field 'host' is required (hostname or host:port). example.com:443 is example.com. A non-default port stays on the key.");

        var model = _accessModelStore.GetOrCreate(host);
        var resourcesUpdated = 0;
        var identitiesUpdated = 0;

        if (body.GetJsonElement("resources") is { ValueKind: JsonValueKind.Array } resourcesEl)
        {
            if (resourcesEl.GetArrayLength() == 0)
                model.Resources.Clear();
            foreach (var r in resourcesEl.EnumerateArray())
            {
                var method = r.TryGetProperty("method", out var m) ? m.GetString()?.Trim() : null;
                var urlTemplate = r.TryGetProperty("urlTemplate", out var u) ? u.GetString()?.Trim() : null;
                if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(urlTemplate)) continue;

                var sensitivity = ParseEnum<Security.Authz.AccessSensitivity>(
                    r.TryGetProperty("sensitivity", out var s) ? s.GetString() : null, Security.Authz.AccessSensitivity.Unknown);
                var ownership = ParseEnum<Security.Authz.AccessOwnership>(
                    r.TryGetProperty("ownership", out var o) ? o.GetString() : null, Security.Authz.AccessOwnership.Unknown);
                var source = ParseEnum<Security.Authz.AccessSource>(
                    r.TryGetProperty("source", out var src) ? src.GetString() : null, Security.Authz.AccessSource.Human);
                var notes = r.TryGetProperty("notes", out var n) ? n.GetString() : null;
                var confidence = r.TryGetProperty("confidence", out var c) && c.ValueKind == JsonValueKind.Number
                    ? c.GetDouble()
                    : (source is Security.Authz.AccessSource.Human or Security.Authz.AccessSource.Ai ? 1.0 : 0.3);

                model.Resources[Security.Authz.AccessModelResource.KeyOf(method, urlTemplate)] = new Security.Authz.AccessModelResource
                {
                    Method = method,
                    UrlTemplate = urlTemplate,
                    Sensitivity = sensitivity,
                    Ownership = ownership,
                    Source = source,
                    Confidence = Math.Clamp(confidence, 0.0, 1.0),
                    Notes = notes
                };
                resourcesUpdated++;
            }
        }

        if (body.GetJsonElement("identities") is { ValueKind: JsonValueKind.Array } identitiesEl)
        {
            if (identitiesEl.GetArrayLength() == 0)
                model.Identities.Clear();
            foreach (var i in identitiesEl.EnumerateArray())
            {
                var name = i.TryGetProperty("name", out var n) ? n.GetString()?.Trim() : null;
                if (string.IsNullOrWhiteSpace(name)) continue;

                var role = i.TryGetProperty("role", out var r) ? r.GetString() : null;
                var tier = i.TryGetProperty("tier", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetInt32() : 0;
                var ownerTags = new List<string>();
                if (i.TryGetProperty("ownerTags", out var tags) && tags.ValueKind == JsonValueKind.Array)
                {
                    foreach (var tag in tags.EnumerateArray())
                        if (tag.GetString() is { Length: > 0 } tagStr) ownerTags.Add(tagStr);
                }

                model.Identities.RemoveAll(existing => existing.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                model.Identities.Add(new Security.Authz.AccessModelIdentity
                {
                    Name = name,
                    Role = role,
                    Tier = tier,
                    OwnerTags = ownerTags
                });
                identitiesUpdated++;
            }
        }

        _accessModelStore.Save(model);
        return new
        {
            resourcesUpdated,
            identitiesUpdated,
            model = ToAccessModelResponse(model)
        };
    }

    private static TEnum ParseEnum<TEnum>(string? value, TEnum fallback) where TEnum : struct, Enum =>
        !string.IsNullOrWhiteSpace(value) && Enum.TryParse<TEnum>(value, true, out var parsed) ? parsed : fallback;

    private static object ToAccessModelResponse(Security.Authz.AccessModel model) => new
    {
        host = model.Host,
        updatedAt = model.UpdatedAt,
        identities = model.Identities.Select(i => new
        {
            i.Name,
            i.Role,
            i.Tier,
            i.OwnerTags
        }),
        resources = model.Resources.Values
            .OrderBy(r => r.UrlTemplate, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Method, StringComparer.OrdinalIgnoreCase)
            .Select(r => new
            {
                r.Method,
                r.UrlTemplate,
                sensitivity = r.Sensitivity.ToString(),
                ownership = r.Ownership.ToString(),
                source = r.Source.ToString(),
                r.Confidence,
                expectedCrossIdentityOutcome = r.ExpectedCrossIdentityOutcome,
                isUnclassified = r.IsUnclassified,
                r.Notes,
                r.UpdatedAt
            }),
        summary = new
        {
            resourceCount = model.Resources.Count,
            identityCount = model.Identities.Count,
            unclassifiedCount = model.Resources.Values.Count(r => r.IsUnclassified),
            humanOrAiClassifiedCount = model.Resources.Values.Count(r =>
                r.Source is Security.Authz.AccessSource.Human or Security.Authz.AccessSource.Ai)
        }
    };

    #endregion

    #region Live Authz Shadow

    private async Task HandlePostAuthzShadow(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            var result = await BuildAuthzShadowAsync(body);
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    /// <summary>
    /// Shared REST/MCP entry point. <c>mode</c>: enable | disable | status (default) | results | clear | export | import.
    /// The shadow itself is created once per <see cref="AutomationContext"/> (GUI wiring); this only
    /// configures it and reads back state — it never runs outside a live GUI session.
    /// </summary>
    internal Task<object> BuildAuthzShadowAsync(JsonBody body)
    {
        var shadow = _context.LiveAuthzShadow;
        if (shadow == null)
            throw new ApiCommandException(400,
                "Live Authz Shadow is not available in this context (GUI-only feature; not wired up in headless/CLI mode).");

        var mode = (body.GetString("mode") ?? "status").Trim().ToLowerInvariant();
        switch (mode)
        {
            case "enable":
            {
                var safetyMode = body.GetString("safetyMode")?.Trim().ToLowerInvariant();
                if (safetyMode is not (null or "passive" or "safe" or "active" or "aggressive"))
                    throw new ApiCommandException(400, "safetyMode must be one of: passive, safe, active, aggressive.");
                var peers = body.GetStringArray("peers")?.ToList();
                shadow.Configure(true, safetyMode, peers);
                return Task.FromResult<object>(shadow.GetStatus());
            }
            case "disable":
                shadow.Configure(false);
                return Task.FromResult<object>(shadow.GetStatus());
            case "clear":
                shadow.ClearResults();
                return Task.FromResult<object>(shadow.GetStatus());
            case "results":
            {
                var sinceId = body.GetInt("sinceId");
                Security.Authz.AuthzVerdictKind? verdict = null;
                var verdictStr = body.GetString("verdict");
                if (!string.IsNullOrWhiteSpace(verdictStr) &&
                    Enum.TryParse<Security.Authz.AuthzVerdictKind>(verdictStr, true, out var parsedVerdict))
                    verdict = parsedVerdict;

                var results = shadow.GetResults(sinceId > 0 ? sinceId : null, verdict);
                shadow.MarkPolled();
                return Task.FromResult<object>(new
                {
                    status = shadow.GetStatus(),
                    results = results.Select(ProjectShadowResult)
                });
            }
            case "export":
            {
                var bundle = shadow.ExportBundle();
                var path = body.GetString("path")?.Trim();
                if (string.IsNullOrEmpty(path))
                    return Task.FromResult<object>(bundle);

                if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
                    throw new ApiCommandException(400, guardError ?? "Export path rejected.");
                try
                {
                    var dir = Path.GetDirectoryName(full);
                    if (!string.IsNullOrEmpty(dir))
                        Directory.CreateDirectory(dir);
                    File.WriteAllText(full, JsonSerializer.Serialize(bundle, Security.Authz.AuthzShadowBundle.JsonOptions));
                    return Task.FromResult<object>(new { writtenTo = full, bundle });
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
                {
                    throw new ApiCommandException(400, "Could not write the authz shadow bundle: " + ex.Message);
                }
            }
            case "import":
            {
                Security.Authz.AuthzShadowBundle? bundle = null;
                var path = body.GetString("path")?.Trim();
                try
                {
                    if (!string.IsNullOrEmpty(path))
                    {
                        if (!ExportPathGuard.TryResolveRead(path, out var full, out var guardError))
                            throw new ApiCommandException(400, guardError ?? "Import path rejected.");
                        var json = File.ReadAllText(full);
                        bundle = JsonSerializer.Deserialize<Security.Authz.AuthzShadowBundle>(json, Security.Authz.AuthzShadowBundle.JsonOptions);
                    }
                    else if (body.GetJsonElement("bundle") is { ValueKind: JsonValueKind.Object } element)
                    {
                        bundle = JsonSerializer.Deserialize<Security.Authz.AuthzShadowBundle>(element.GetRawText(), Security.Authz.AuthzShadowBundle.JsonOptions);
                    }
                }
                catch (JsonException ex)
                {
                    throw new ApiCommandException(400, "Authz shadow bundle is not valid JSON: " + ex.Message);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    throw new ApiCommandException(400, "Could not read the authz shadow bundle: " + ex.Message);
                }

                if (bundle == null)
                    throw new ApiCommandException(400, "Provide 'path' (a bundle file) or 'bundle' (the export object).");

                try
                {
                    return Task.FromResult(shadow.ImportBundle(bundle, body.GetBool("replaceResults")));
                }
                catch (ArgumentException ex)
                {
                    throw new ApiCommandException(400, ex.Message);
                }
            }
            default:
                return Task.FromResult<object>(shadow.GetStatus());
        }
    }

    private static object ProjectShadowResult(Security.Authz.LiveAuthzShadowResult r) => new
    {
        r.Id,
        r.Timestamp,
        r.Host,
        r.Method,
        r.Url,
        r.UrlTemplate,
        r.Peer,
        verdict = r.Verdict.ToString(),
        r.Confidence,
        r.Reason,
        r.ExpectedOutcome,
        r.NeedsClassification,
        r.OwnerStatus,
        r.PeerStatus,
        r.OwnerBodyLength,
        r.PeerBodyLength,
        r.PeerFinalUrl,
        r.PeerError,
        r.OwnerTokenCount,
        r.PeerAuthApplied,
        r.OwnerBodyMissing,
        r.HtmlShell,
        r.DuplicateHtmlShell,
        r.PeerMutated
    };

    #endregion

    #region BAC Coverage Report

    private async Task HandlePostAuthzCoverage(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            var result = await BuildAuthzCoverageAsync(body);
            await WriteSuccess(response, result);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex.StatusCode, ex.Message);
        }
    }

    /// <summary>
    /// Build a <see cref="Security.Authz.BacCoverageReport"/> for a host: cross-references the access
    /// model (declared intent) against the attack surface map (what's out there) and any Live Authz
    /// Shadow results (what's actually been tested), so coverage/gaps/findings are all in one place.
    /// </summary>
    internal async Task<object> BuildAuthzCoverageAsync(JsonBody body)
    {
        var host = body.GetString("host")?.Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            var currentUrl = await _context.GetCurrentUrl();
            host = Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri)
                ? Security.Authz.AuthzHostKey.FromUri(uri)
                : null;
        }
        else
        {
            host = Security.Authz.AuthzHostKey.Canonical(host);
        }

        if (string.IsNullOrWhiteSpace(host) || !Security.Authz.AccessModelStore.IsValidHost(host))
            throw new ApiCommandException(400,
                "Could not determine a host. Pass 'host' (e.g. example.com) or navigate the browser to the target first. " +
                "example.com, example.com:443, and example.com:80 are one host. A non-default port stays on the key.");

        var model = _accessModelStore.GetOrCreate(host);
        _context.LiveAuthzShadow?.ApplySessionClassifications(model);
        var surface = _context.CheckAttackSurface(hostFilter: host);
        var endpoints = surface.Endpoints
            .Where(ep => CoverageEndpointOnHost(ep, host))
            .ToList();
        var shadow = _context.LiveAuthzShadow;
        var shadowResults = shadow?.GetResults(host: host) ?? [];
        var skips = new List<Security.Authz.AuthzShadowSkip>();
        if (shadow != null)
        {
            skips.AddRange(shadow.GetSkips().Where(s =>
                Security.Authz.AuthzHostKey.Canonical(s.Host).Equals(host, StringComparison.OrdinalIgnoreCase)));
        }
        foreach (var saved in model.SkippedRequests)
        {
            skips.Add(new Security.Authz.AuthzShadowSkip
            {
                Host = model.Host,
                Method = saved.Method,
                UrlTemplate = saved.UrlTemplate,
                Kind = saved.Kind
            });
        }

        string? pageHost = null;
        try
        {
            var currentUrl = await _context.GetCurrentUrl();
            if (Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
                pageHost = Security.Authz.AuthzHostKey.FromUri(pageUri);
        }
        catch
        {
            // Coverage still names the requested host when the page URL is unavailable.
        }

        var report = Security.Authz.BacCoverageReport.Build(model, endpoints, shadowResults, skips, pageHost);

        var includeMarkdown = body.GetBool("markdown", true);
        return new
        {
            host = report.Host,
            generatedAt = report.GeneratedAt,
            identities = report.Identities.Select(i => new { i.Name, i.Role, i.Tier }),
            attackSurfaceEndpointCount = report.AttackSurfaceEndpointCount,
            coverage = new
            {
                numerator = report.CoverageNumerator,
                denominator = report.CoverageDenominator,
                testedPercent = report.CoveragePercent,
                percent = report.CoveragePercent
            },
            findingsByVerdict = report.FindingsByVerdict,
            gaps = report.Gaps,
            nextActions = report.NextActions,
            markdown = includeMarkdown ? report.ToMarkdown() : null
        };
    }

    private static bool CoverageEndpointOnHost(Security.AttackSurfaceEndpoint ep, string canonicalHost)
    {
        if (string.IsNullOrEmpty(ep.Url) || !Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
            return true;
        return Security.Authz.AuthzHostKey.FromUri(uri).Equals(canonicalHost, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Identity (capture / apply / handoff)

    private async Task<bool> TryRouteIdentityByNameAsync(string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        const string prefix = "/api/identity/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var name = Uri.UnescapeDataString(path[prefix.Length..].Trim('/'));
        if (string.IsNullOrEmpty(name) ||
            name.Equals("capture", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("apply", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("handoff", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        switch (method)
        {
            case "GET":
                await HandleGetIdentitySnapshot(request, response, name);
                return true;
            case "DELETE":
                await HandleDeleteIdentity(response, name);
                return true;
            default:
                return false;
        }
    }

    private async Task HandleGetSessionIdentity(HttpListenerRequest request, HttpListenerResponse response)
    {
        var payload = await SessionIdentityIntrospection.BuildLivePayloadAsync(_context, SessionName);
        await WriteSuccess(response, payload);
    }

    /// <summary>Gate-free cookie header for a URL (used by fetch identityOverride.peer).</summary>
    private async Task HandleGetSessionCookieHeader(HttpListenerRequest request, HttpListenerResponse response)
    {
        var url = ApiQuery(request)["url"];
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Query parameter 'url' is required (absolute URL).");
            return;
        }

        var snapshot = await _context.GetBrowserCookieSnapshotForUrl(url);
        var names = snapshot.Scopes.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        await WriteSuccess(response, new
        {
            url,
            cookieSourceUrl = snapshot.CookieSourceUrl,
            cookieHeader = snapshot.Header,
            cookieNames = names,
            count = names.Count
        });
    }

    private async Task HandleGetIdentities(HttpListenerResponse response)
    {
        var identities = _identityStore.List();
        await WriteSuccess(response, new { count = identities.Count, identities });
    }

    private async Task HandleGetIdentitySnapshot(HttpListenerRequest request, HttpListenerResponse response, string name)
    {
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Invalid identity name.");
            return;
        }

        var snapshot = _identityStore.Load(name);
        if (snapshot == null)
        {
            await WriteError(response, 404, $"Identity '{name}' not found.");
            return;
        }

        var reveal = string.Equals(ApiQuery(request)["reveal"], "true", StringComparison.OrdinalIgnoreCase);
        await WriteSuccess(response, _identityStore.ToResponsePayload(snapshot, reveal));
    }

    private async Task HandleDeleteIdentity(HttpListenerResponse response, string name)
    {
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Invalid identity name.");
            return;
        }

        var removed = _identityStore.Delete(name);
        await WriteSuccess(response, new { removed, name });
    }

    private async Task HandlePostIdentityCapture(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name")?.Trim();
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Required: name (1-64 chars, alphanumeric plus . _ -).");
            return;
        }

        var includeAuthHeaders = !body.HasProperty("includeAuthHeaders") || body.GetBool("includeAuthHeaders");
        var authHeaderMaxAgeMinutes = body.HasProperty("authHeaderMaxAgeMinutes")
            ? Math.Clamp(body.GetInt("authHeaderMaxAgeMinutes", 30), 1, 240)
            : 30;

        var snapshot = await _identityStore.CaptureAsync(
            _context, name!, SessionName, includeAuthHeaders, authHeaderMaxAgeMinutes);

        await WriteSuccess(response, new
        {
            captured = snapshot.Name,
            metadata = snapshot.Metadata,
            cookieCount = snapshot.Cookies.Count,
            localStorageCount = snapshot.LocalStorage.Count,
            sessionStorageCount = snapshot.SessionStorage.Count,
            authHeaderCount = snapshot.AuthHeaders.Count
        });
    }

    private async Task HandlePostIdentityApply(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name")?.Trim();
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Required: name.");
            return;
        }

        var target = (body.GetString("target") ?? "self").Trim().ToLowerInvariant();
        if (target == "peer")
        {
            await HandlePostIdentityApplyToPeer(body, response, name!);
            return;
        }

        var verify = body.GetJsonElement("verify") is { } verifyEl
            ? ParseIdentityVerify(verifyEl)
            : null;
        var navigateTo = body.GetString("navigateTo");

        try
        {
            var result = await _identityStore.ApplyAsync(_context, name!, navigateTo, verify);
            await WriteSuccess(response, result);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 404, ex.Message);
        }
    }

    private async Task HandlePostPeerIdentityApply(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peerName = body.GetString("peer");
        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "Required: peer (registered peer name).");
            return;
        }

        var forwardBody = new Dictionary<string, object?>
        {
            ["name"] = body.GetString("name"),
            ["target"] = "self",
            ["navigateTo"] = body.GetString("navigateTo")
        };
        if (body.GetJsonElement("verify") is { } verifyEl)
            forwardBody["verify"] = JsonSerializer.Deserialize<object>(verifyEl.GetRawText());

        var json = JsonSerializer.Serialize(forwardBody, JsonOptions);
        var peerResp = await Peers.ForwardAsync(peerName, "POST", "/api/identity/apply", json,
            timeoutMs: PeerRegistry.OperationTimeoutMs);
        await WritePeerForwardResponse(response, peerResp);
    }

    private async Task HandlePostIdentityApplyToPeer(JsonBody body, HttpListenerResponse response, string name)
    {
        var peerName = body.GetString("peer");
        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "target=peer requires 'peer' (registered peer name).");
            return;
        }

        var forwardBody = new Dictionary<string, object?>
        {
            ["name"] = name,
            ["target"] = "self",
            ["navigateTo"] = body.GetString("navigateTo")
        };
        if (body.GetJsonElement("verify") is { } verifyEl)
            forwardBody["verify"] = JsonSerializer.Deserialize<object>(verifyEl.GetRawText());

        var json = JsonSerializer.Serialize(forwardBody, JsonOptions);
        var peerResp = await Peers.ForwardAsync(peerName, "POST", "/api/identity/apply", json,
            timeoutMs: PeerRegistry.OperationTimeoutMs);
        await WritePeerForwardResponse(response, peerResp);
    }

    private async Task HandlePostIdentityHandoff(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var action = body.GetString("action") ?? "start";

        if (action == "cancel")
        {
            var cancelName = body.GetString("name")?.Trim();
            if (!IdentityStore.IsValidName(cancelName))
            {
                await WriteError(response, 400, "cancel requires valid 'name'.");
                return;
            }

            var cancelled = _identityHandoff.Cancel(cancelName!);
            await WriteSuccess(response, new { cancelled, name = cancelName });
            return;
        }

        if (action == "status")
        {
            await HandleGetIdentityHandoff(request, response, body);
            return;
        }

        var name = body.GetString("name")?.Trim();
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Required: name.");
            return;
        }

        var timeoutMs = body.HasProperty("timeoutMs") ? body.GetInt("timeoutMs", 300_000) : 300_000;
        var livenessUrl = body.GetString("livenessUrl");

        var state = await _identityHandoff.StartAsync(_context, name!, timeoutMs, livenessUrl);
        await WriteSuccess(response, new
        {
            status = state.Status,
            name = state.Name,
            expiresAt = state.ExpiresAt,
            livenessUrl = state.LivenessUrl,
            baseline = new
            {
                cookieCount = state.BaselineCookieCount,
                localStorageCount = state.BaselineLocalStorageCount,
                sessionStorageCount = state.BaselineSessionStorageCount,
                livenessStatus = state.BaselineLivenessStatus
            },
            message = state.Message
        });
    }

    private async Task HandleGetIdentityHandoff(HttpListenerRequest request, HttpListenerResponse response, JsonBody? bodyOverride = null)
    {
        var body = bodyOverride ?? await ReadJsonBody(request);
        var name = body.GetString("name")?.Trim() ?? ApiQuery(request)["name"]?.Trim();
        if (!IdentityStore.IsValidName(name))
        {
            await WriteError(response, 400, "Required query/body parameter: name.");
            return;
        }

        var autoCapture = !body.HasProperty("autoCapture") || body.GetBool("autoCapture", true);
        var state = await _identityHandoff.PollAsync(_context, name!, SessionName, autoCapture);
        await WriteSuccess(response, new
        {
            status = state.Status,
            name = state.Name,
            capturedIdentity = state.CapturedIdentity,
            expiresAt = state.ExpiresAt == default ? null : (DateTime?)state.ExpiresAt,
            message = state.Message
        });
    }

    private static IdentityVerifyOptions? ParseIdentityVerify(JsonElement verifyEl)
    {
        if (verifyEl.ValueKind != JsonValueKind.Object)
            return null;

        var el = verifyEl;
        var url = el.TryGetProperty("url", out var u) ? u.GetString() : null;
        if (string.IsNullOrWhiteSpace(url)) return null;

        var expectStatus = el.TryGetProperty("expectStatus", out var es) && es.ValueKind == JsonValueKind.Number
            ? es.GetInt32()
            : 200;
        var method = el.TryGetProperty("method", out var m) ? m.GetString() : "GET";
        Dictionary<string, string>? headers = null;
        if (el.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
            headers = ParseHeadersFromJson(h);
        var fetchBody = el.TryGetProperty("body", out var b) ? b.GetString() : null;
        var timeoutMs = el.TryGetProperty("timeoutMs", out var t) && t.ValueKind == JsonValueKind.Number
            ? t.GetInt32()
            : 30_000;

        return new IdentityVerifyOptions
        {
            Url = url!,
            ExpectStatus = expectStatus,
            Method = method,
            Headers = headers,
            Body = fetchBody,
            TimeoutMs = timeoutMs
        };
    }

    private async Task RunPhasedScenarioAsync(HttpListenerResponse response, JsonElement root, JsonBody body)
    {
        if (!root.TryGetProperty("phases", out var phases) || phases.ValueKind != JsonValueKind.Object)
        {
            await WriteError(response, 400, "phases object required for phased scenario.");
            return;
        }

        var scenarioSafety = SafetyGate.Resolve(body);
        if (!root.TryGetProperty("safetyMode", out _))
        {
            if (body.HasProperty("safetyMode")) { /* resolved from body */ }
            else scenarioSafety = SafetyMode.Safe;
        }
        if (SafetyGate.RequireAtLeast(scenarioSafety, SafetyMode.Active, "Phased scenario") is { } scenarioGateError)
        {
            await WriteError(response, 400, scenarioGateError);
            return;
        }

        if (!phases.TryGetProperty("oracle", out var oracle) || oracle.ValueKind != JsonValueKind.Object)
        {
            await WriteError(response, 400, "phases.oracle is required.");
            return;
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("safetyMode", "active");
            if (root.TryGetProperty("name", out var nameEl))
            {
                writer.WritePropertyName("name");
                nameEl.WriteTo(writer);
            }
            foreach (var phaseName in new[] { "setup", "trigger", "cleanup" })
            {
                if (phases.TryGetProperty(phaseName, out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    writer.WritePropertyName(phaseName);
                    arr.WriteTo(writer);
                }
            }
            writer.WritePropertyName("oracle");
            oracle.WriteTo(writer);
            if (body.GetBool("exportEvidence") || (root.TryGetProperty("exportEvidence", out var ee) && ee.ValueKind == JsonValueKind.True))
                writer.WriteBoolean("exportEvidence", true);
            writer.WriteEndObject();
        }

        using var workflowDoc = JsonDocument.Parse(stream.ToArray());
        var service = new WorkflowVerifyService();
        var result = await service.RunAsync(workflowDoc.RootElement, BuildWorkflowDependencies());
        await WriteSuccess(response, new
        {
            format = "phases",
            name = result.Name,
            verified = result.Verified,
            failurePhase = result.FailurePhase,
            oracle = result.Oracle,
            setup = result.Setup,
            trigger = result.Trigger,
            cleanup = result.Cleanup,
            evidenceBundlePath = result.EvidenceBundlePath,
            elapsedMs = result.ElapsedMs
        });
    }

    private async Task<Dictionary<string, object?>> ExecuteIdentityScenarioStepAsync(JsonElement step, string? stepId, int index)
    {
        var action = step.TryGetProperty("action", out var actEl) ? actEl.GetString()?.ToLowerInvariant() : null;
        var name = step.TryGetProperty("name", out var nameEl) ? nameEl.GetString()?.Trim() : null;

        if (!IdentityStore.IsValidName(name))
            return new Dictionary<string, object?> { ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["success"] = false, ["error"] = "Identity step requires valid 'name'." };

        try
        {
            if (action == "capture")
            {
                var includeAuthHeaders = !step.TryGetProperty("includeAuthHeaders", out var iah) || iah.ValueKind != JsonValueKind.False;
                var snapshot = await _identityStore.CaptureAsync(_context, name!, SessionName, includeAuthHeaders);
                return new Dictionary<string, object?>
                {
                    ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["action"] = "capture",
                    ["success"] = true, ["name"] = name, ["cookieCount"] = snapshot.Cookies.Count
                };
            }

            if (action == "apply")
            {
                string? navigateTo = step.TryGetProperty("navigateTo", out var navEl) && navEl.ValueKind == JsonValueKind.String
                    ? navEl.GetString() : null;
                IdentityVerifyOptions? verify = null;
                if (step.TryGetProperty("verify", out var verifyEl) && verifyEl.ValueKind == JsonValueKind.Object)
                    verify = ParseIdentityVerify(verifyEl);

                var target = step.TryGetProperty("target", out var targetEl) && targetEl.ValueKind == JsonValueKind.String
                    ? targetEl.GetString()?.Trim().ToLowerInvariant() : "self";

                if (target == "peer")
                {
                    var peer = step.TryGetProperty("peer", out var peerEl) ? peerEl.GetString()?.Trim() : null;
                    if (string.IsNullOrWhiteSpace(peer))
                        return new Dictionary<string, object?> { ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["success"] = false, ["error"] = "target=peer requires 'peer'." };

                    var forwardBody = new Dictionary<string, object?> { ["name"] = name, ["target"] = "self", ["navigateTo"] = navigateTo };
                    if (verify != null)
                        forwardBody["verify"] = new { verify.Url, verify.ExpectStatus, verify.Method, verify.Headers, verify.Body, verify.TimeoutMs };
                    var peerResp = await Peers.ForwardAsync(peer, "POST", "/api/identity/apply",
                        JsonSerializer.Serialize(forwardBody, JsonOptions),
                        timeoutMs: PeerRegistry.OperationTimeoutMs);
                    return new Dictionary<string, object?>
                    {
                        ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["action"] = "apply",
                        ["success"] = peerResp.Success || peerResp.StatusCode == 200,
                        ["peer"] = peer, ["peerStatus"] = peerResp.StatusCode, ["peerBody"] = peerResp.Body
                    };
                }

                var result = await _identityStore.ApplyAsync(_context, name!, navigateTo, verify);
                return new Dictionary<string, object?>
                {
                    ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["action"] = "apply",
                    ["success"] = verify == null || result.Verified,
                    ["name"] = name, ["applied"] = result.Applied, ["verified"] = result.Verified,
                    ["verifyStatus"] = result.VerifyStatus, ["verifyError"] = result.VerifyError
                };
            }

            return new Dictionary<string, object?> { ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["success"] = false, ["error"] = "Unknown identity action. Use capture or apply." };
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object?> { ["index"] = index, ["id"] = stepId, ["type"] = "identity", ["success"] = false, ["error"] = ex.Message };
        }
    }

    private async Task WritePeerForwardResponse(HttpListenerResponse response, PeerResponse peerResp)
    {
        if (!peerResp.Success && peerResp.StatusCode != 200)
        {
            await WriteError(response, peerResp.StatusCode > 0 ? peerResp.StatusCode : 502,
                peerResp.Body ?? "Peer request failed.");
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(peerResp.Body ?? "{}");
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                await WriteSuccess(response, data);
                return;
            }
        }
        catch { /* fall through */ }

        await WriteSuccess(response, new { peerResponse = peerResp.Body });
    }

    #endregion

    /// <summary>
    /// Gate-free server-side fetch that uses the browser's cookies (including HttpOnly).
    /// Unlike POST /api/fetch (which runs fetch() in the WebView2 JavaScript context and
    /// requires the gate), this endpoint uses HttpClient with cookies extracted from the
    /// CookieManager. This is the endpoint used by peer/fetch to avoid gate contention.
    /// </summary>
    private async Task HandlePostFetchDirect(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Missing required field: url");
            return;
        }

        var method = body.GetString("method") ?? "GET";
        var headers = body.GetHttpHeadersDictionary("headers");
        var timeout = body.GetInt("timeout", 30000);
        // Default true preserves peer/fetch + authz/diff behavior. Set false for portable-token
        // proofs that must send only the caller Cookie/Authorization header.
        var includeBrowserCookies = body.HasProperty("includeBrowserCookies")
            ? body.GetBool("includeBrowserCookies")
            : true;

        var cookies = body.GetString("cookies");
        var identityOverride = FetchCookieResolver.ParseIdentityOverride(body);
        var cookieResolution = await FetchCookieResolver.ResolveAsync(
            _context, Peers, _identityStore, url, headers, cookies, identityOverride,
            body.HasProperty("includeBrowserCookies") ? body.GetBool("includeBrowserCookies") : null,
            cookiesSpecified: body.HasProperty("cookies"));
        if (cookieResolution.Error != null)
        {
            await WriteError(response, 400, cookieResolution.Error);
            return;
        }

        headers = cookieResolution.Headers;
        includeBrowserCookies = cookieResolution.IncludeBrowserCookies;

        string? fetchBody = body.GetString("body");
        if (fetchBody == null && body.HasProperty("json"))
        {
            fetchBody = body.GetRawJson("json");
            headers = HttpHeaderDictionary.PrepareForJsonBody(headers);
        }

        try
        {
            var result = await DirectFetchHelper.FetchAsync(
                _context, url, method, headers, fetchBody, timeout,
                allowAutoRedirect: true, includeBrowserCookies: includeBrowserCookies);

            if (result.Error != null)
            {
                await WriteError(response, 500, $"Server-side fetch failed: {result.Error}");
                return;
            }

            await WriteSuccess(response, new
            {
                ok = result.Ok,
                status = result.Status,
                statusText = result.StatusText,
                redirected = result.Redirected,
                type = "direct",
                url = result.FinalUrl ?? url,
                headers = result.Headers,
                body = result.Body,
                transport = result.Transport,
                cookiesSent = result.CookiesSent,
                cookieSourceUrl = result.CookieSourceUrl,
                cookieScopes = result.CookieScopes.Select(s => new { s.Name, s.Domain, s.Path }).ToList(),
                includeBrowserCookies = result.IncludedBrowserCookies,
                identityUsed = FetchIdentity.Describe(
                    result.IncludedBrowserCookies,
                    result.CookiesSent,
                    cookieResolution.IdentitySource,
                    headers != null && headers.TryGetValue("Cookie", out var callerCookie) && !string.IsNullOrWhiteSpace(callerCookie)),
                identitySource = cookieResolution.IdentitySource
            });
        }
        catch (TaskCanceledException)
        {
            await WriteError(response, 504, $"Server-side fetch timed out after {timeout}ms.");
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, $"Server-side fetch failed: {ex.Message}");
        }
    }

    /// <summary>Compute a short SHA-256 prefix for body comparison.</summary>
    private static string ComputeShortHash(string input)
    {
        if (string.IsNullOrEmpty(input)) return "empty";
        var bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes[..8]).ToLowerInvariant();
    }

    /// <summary>
    /// Heuristic: does a redirect final URL or response body look like an access-denied or login page?
    /// Catches patterns like ASP.NET WebForms redirecting to AccessDenied.aspx or Login.aspx.
    /// </summary>
    private static bool AuthzLooksLikeDenialRedirect(string finalUrl, string body)
    {
        var urlLower = finalUrl.ToLowerInvariant();
        if (urlLower.Contains("accessdenied") || urlLower.Contains("access-denied") ||
            urlLower.Contains("unauthorized") || urlLower.Contains("forbidden") ||
            urlLower.Contains("login") || urlLower.Contains("signin") ||
            urlLower.Contains("sign-in") || urlLower.Contains("sso") ||
            urlLower.Contains("auth") || urlLower.Contains("returnurl") ||
            urlLower.Contains("redirect"))
            return true;

        if (string.IsNullOrEmpty(body) || body.Length > 50_000) return false;
        var bodyLower = body.ToLowerInvariant();
        return bodyLower.Contains("access denied") || bodyLower.Contains("not authorized") ||
               bodyLower.Contains("you do not have permission") || bodyLower.Contains("login required") ||
               bodyLower.Contains("sign in to continue") || bodyLower.Contains("403") ||
               bodyLower.Contains("unauthorized");
    }

    private static Dictionary<string, string>? ParseHeadersFromJson(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        var result = new Dictionary<string, string>();
        foreach (var prop in el.EnumerateObject())
            result[prop.Name] = prop.Value.GetString() ?? "";
        return result;
    }

    #endregion
}
