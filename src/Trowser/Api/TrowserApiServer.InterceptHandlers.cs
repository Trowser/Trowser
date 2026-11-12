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
    #region Intercept Handlers

    private async Task HandleGetIntercepts(HttpListenerResponse response)
    {
        var rules = _context.GetInterceptRules();
        var pending = _context.GetPendingRequests();
        await WriteSuccess(response, new
        {
            ruleCount = rules.Count,
            pendingCount = pending.Count,
            rules = rules.Select(r => new
            {
                urlPattern = r.UrlPattern,
                method = r.Method
            }).ToList(),
            pending = pending.Select(p => new
            {
                requestId = p.Id,
                url = p.Url,
                method = p.Method,
                resourceType = p.ResourceType,
                matchedPattern = p.MatchedPattern,
                headers = p.Headers,
                timestamp = p.Timestamp
            }).ToList()
        });
    }

    private async Task HandlePostIntercept(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var urlPattern = body.GetString("urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
        {
            await WriteError(response, 400, "Missing required field: urlPattern (regex pattern)");
            return;
        }

        var method = body.GetString("method");
        _context.AddInterceptRule(urlPattern, method, silent: true);

        await WriteSuccess(response, new
        {
            added = urlPattern,
            method,
            totalRules = _context.GetInterceptRules().Count
        });
    }

    private async Task HandlePostInterceptRemove(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var urlPattern = body.GetString("urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
        {
            await WriteError(response, 400, "Missing required field: urlPattern");
            return;
        }

        var method = body.GetString("method");
        _context.RemoveInterceptRule(urlPattern, method);
        await WriteSuccess(response, new
        {
            removed = urlPattern,
            method,
            totalRules = _context.GetInterceptRules().Count
        });
    }

    private async Task HandlePostInterceptContinue(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var requestId = body.GetInt("requestId", -1);
        if (requestId < 0)
        {
            await WriteError(response, 400, "Missing required field: requestId");
            return;
        }

        var decision = new InterceptDecision
        {
            Action = InterceptAction.Continue,
            ModifiedUrl = body.GetString("url"),
            ModifiedMethod = body.GetString("method"),
            ModifiedHeaders = body.GetStringDictionary("headers")
        };

        if (!_context.ResolvePendingRequest(requestId, decision))
        {
            await WriteError(response, 404, $"No pending request with ID {requestId}");
            return;
        }

        await WriteSuccess(response, new { continued = requestId });
    }

    private async Task HandlePostInterceptFulfill(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var requestId = body.GetInt("requestId", -1);
        if (requestId < 0)
        {
            await WriteError(response, 400, "Missing required field: requestId");
            return;
        }

        var statusCode = body.GetInt("status", 200);
        if (statusCode == 0) statusCode = body.GetInt("statusCode", 200);

        var decision = new InterceptDecision
        {
            Action = InterceptAction.Fulfill,
            StatusCode = statusCode,
            Body = body.GetString("body"),
            ResponseHeaders = body.GetStringDictionary("headers")
        };

        if (!_context.ResolvePendingRequest(requestId, decision))
        {
            await WriteError(response, 404, $"No pending request with ID {requestId}");
            return;
        }

        await WriteSuccess(response, new { fulfilled = requestId, statusCode });
    }

    private async Task HandlePostInterceptAbort(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var requestId = body.GetInt("requestId", -1);
        if (requestId < 0)
        {
            await WriteError(response, 400, "Missing required field: requestId");
            return;
        }

        var decision = new InterceptDecision { Action = InterceptAction.Abort };

        if (!_context.ResolvePendingRequest(requestId, decision))
        {
            await WriteError(response, 404, $"No pending request with ID {requestId}");
            return;
        }

        await WriteSuccess(response, new { aborted = requestId });
    }

    private async Task HandlePostInterceptReplay(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var requestId = body.GetInt("requestId", -1);
        if (requestId < 0)
        {
            await WriteError(response, 400, "Missing required field: requestId");
            return;
        }

        var pending = _context.GetPendingRequest(requestId);
        if (pending == null)
        {
            await WriteError(response, 404, $"No pending request with ID {requestId}");
            return;
        }

        var concurrency = Math.Clamp(body.GetInt("concurrency", 5), 1, 25);
        var includeBody = body.GetBool("includeBody", false);
        var useBrowserCookies = body.GetBool("useBrowserCookies", false);
        string? cookieHeader = null;
        if (useBrowserCookies)
            cookieHeader = await _context.GetCookieHeaderForUrl(pending.Url);

        var result = await RunLoadTest(
            pending.Url, pending.Method, pending.Headers, pending.Body,
            concurrency, includeBody, cookieHeader);

        await WriteSuccess(response, result);
    }

    private async Task HandlePostLoadTest(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        if (SafetyGate.RequireActive(body, "Load-test") is { } loadGateError)
        {
            await WriteError(response, 400, loadGateError);
            return;
        }

        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Missing required field: url");
            return;
        }

        var method = body.GetString("method") ?? "GET";
        var headers = body.GetStringDictionary("headers") ?? new Dictionary<string, string>();
        string? requestBody = body.GetString("body");
        if (requestBody == null && body.HasProperty("bodyBase64"))
        {
            var b64 = body.GetString("bodyBase64");
            if (!string.IsNullOrEmpty(b64))
            {
                try
                {
                    requestBody = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                }
                catch (FormatException)
                {
                    await WriteError(response, 400, "bodyBase64 is not valid Base64.");
                    return;
                }
            }
        }

        if (requestBody == null && body.HasProperty("bodyFile"))
        {
            var filePath = body.GetString("bodyFile");
            if (!string.IsNullOrEmpty(filePath))
            {
                try
                {
                    requestBody = await ExportPathGuard.ReadLocalTextAsync(filePath);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                {
                    await WriteError(response, 400, $"bodyFile not found: {filePath}");
                    return;
                }
                catch (Exception ex)
                {
                    await WriteError(response, 400, $"Failed to read bodyFile: {ex.Message}");
                    return;
                }
            }
        }

        var concurrency = Math.Clamp(body.GetInt("concurrency", 5), 1, 25);
        var includeBody = body.GetBool("includeBody", false);
        var useBrowserCookies = body.GetBool("useBrowserCookies", false);
        string? cookieHeader = null;
        if (useBrowserCookies)
            cookieHeader = await _context.GetCookieHeaderForUrl(url);

        var result = await RunLoadTest(url, method, headers, requestBody, concurrency, includeBody, cookieHeader);
        await WriteSuccess(response, result);
    }

    private const int LoadTestBodySnippetLength = 200;

    private static bool HeadersContainCookie(Dictionary<string, string> headers) =>
        headers.Keys.Any(k => k.Equals("Cookie", StringComparison.OrdinalIgnoreCase));

    private static async Task<object> RunLoadTest(
        string url, string method, Dictionary<string, string> headers,
        string? requestBody, int concurrency, bool includeBody, string? cookieHeader = null)
    {
        using var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AllowAutoRedirect = false,
            MaxConnectionsPerServer = concurrency
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        var overallSw = System.Diagnostics.Stopwatch.StartNew();

        var tasks = Enumerable.Range(0, concurrency).Select(async index =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var msg = new HttpRequestMessage(new HttpMethod(method), url);
                if (requestBody != null)
                {
                    msg.Content = new StringContent(requestBody, Encoding.UTF8);
                    if (headers.TryGetValue("Content-Type", out var ct))
                    {
                        msg.Content.Headers.Remove("Content-Type");
                        msg.Content.Headers.TryAddWithoutValidation("Content-Type", ct);
                    }
                }
                foreach (var kv in headers)
                {
                    if (kv.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                        kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                        kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
                        msg.Content?.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                }

                if (!string.IsNullOrEmpty(cookieHeader) && !HeadersContainCookie(headers))
                    msg.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

                var resp = await client.SendAsync(msg);
                sw.Stop();
                var body = await resp.Content.ReadAsStringAsync();

                var respHeaders = new Dictionary<string, string>();
                foreach (var h in resp.Headers)
                    respHeaders[h.Key] = string.Join(", ", h.Value);
                foreach (var h in resp.Content.Headers)
                    respHeaders[h.Key] = string.Join(", ", h.Value);

                return new
                {
                    index,
                    status = (int)resp.StatusCode,
                    ms = (int)sw.ElapsedMilliseconds,
                    headers = respHeaders,
                    bodySnippet = includeBody ? body
                        : (body.Length > LoadTestBodySnippetLength
                            ? body[..LoadTestBodySnippetLength] + "..."
                            : body),
                    error = (string?)null
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new
                {
                    index,
                    status = 0,
                    ms = (int)sw.ElapsedMilliseconds,
                    headers = new Dictionary<string, string>(),
                    bodySnippet = "",
                    error = (string?)ex.Message
                };
            }
        });

        var responses = await Task.WhenAll(tasks);
        overallSw.Stop();

        var successful = responses.Where(r => r.status > 0).ToArray();
        var timings = successful.Select(r => r.ms).OrderBy(t => t).ToArray();
        var statusGroups = responses.GroupBy(r => r.status)
            .ToDictionary(g => g.Key.ToString(), g => g.Count());

        return new
        {
            request = new { method, url },
            concurrency,
            purpose = "rate-limit-audit",
            completed = responses.Length,
            errors = responses.Count(r => r.error != null),
            durationMs = (int)overallSw.ElapsedMilliseconds,
            summary = timings.Length > 0 ? new
            {
                avgMs = (int)timings.Average(),
                minMs = timings.First(),
                maxMs = timings.Last(),
                p95Ms = timings[(int)(timings.Length * 0.95)]
            } : null,
            statusCodes = statusGroups,
            responses
        };
    }

    private static readonly HashSet<string> BrowserBlockedMethods =
        new(StringComparer.OrdinalIgnoreCase) { "TRACE", "CONNECT" };

    private async Task HandlePostFetch(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Missing required field: url");
            return;
        }

        var delayBeforeFetch = Math.Clamp(body.GetInt("delayMs", 0), 0, 120_000);
        if (delayBeforeFetch > 0)
            await Task.Delay(delayBeforeFetch, _context.OperationCancellation);

        var method = body.GetString("method") ?? "GET";
        var headers = body.GetHttpHeadersDictionary("headers");
        var timeout = body.GetInt("timeout", 30000);
        var redirect = body.GetString("redirect");

        string? fetchBody = body.GetString("body");
        if (fetchBody == null && body.HasProperty("bodyBase64"))
        {
            var b64 = body.GetString("bodyBase64");
            if (!string.IsNullOrEmpty(b64))
            {
                try
                {
                    fetchBody = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                }
                catch (FormatException)
                {
                    await WriteError(response, 400, "bodyBase64 is not valid Base64.");
                    return;
                }
            }
        }

        if (fetchBody == null && body.HasProperty("bodyFile"))
        {
            var filePath = body.GetString("bodyFile");
            if (!string.IsNullOrEmpty(filePath))
            {
                try
                {
                    fetchBody = await ExportPathGuard.ReadLocalTextAsync(filePath);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                {
                    await WriteError(response, 400, $"bodyFile not found: {filePath}");
                    return;
                }
                catch (Exception ex)
                {
                    await WriteError(response, 400, $"Failed to read bodyFile: {ex.Message}");
                    return;
                }
            }
        }

        if (fetchBody == null && body.HasProperty("json"))
        {
            fetchBody = body.GetRawJson("json");
            headers = HttpHeaderDictionary.PrepareForJsonBody(headers);
        }

        int? tabTarget;
        try
        {
            int? tabIndexArg = null;
            if (body.HasProperty("tabIndex"))
            {
                var ti = body.GetInt("tabIndex", -1);
                if (ti < 0)
                {
                    await WriteError(response, 400, "tabIndex must be >= 0 when provided.");
                    return;
                }

                tabIndexArg = ti;
            }

            tabTarget = _context.ResolveTabTarget(tabIndexArg, body.GetString("urlMatch"));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        string resultJson;
        try
        {
            resultJson = await _context.InvokeOnTabAsync(tabTarget, async () =>
            {
                var cookies = body.GetString("cookies");
                var identityOverride = FetchCookieResolver.ParseIdentityOverride(body);
                var includeBrowserCookies = body.HasProperty("includeBrowserCookies")
                    ? body.GetBool("includeBrowserCookies")
                    : (bool?)null;

                var cookieResolution = await FetchCookieResolver.ResolveAsync(
                    _context, Peers, _identityStore, url, headers, cookies, identityOverride, includeBrowserCookies,
                    cookiesSpecified: body.HasProperty("cookies"));
                if (cookieResolution.Error != null)
                    throw new ApiCommandException(400, cookieResolution.Error);

                var resolvedHeaders = cookieResolution.Headers;

                if (BrowserBlockedMethods.Contains(method) || body.GetBool("serverSide") || cookieResolution.ForceServerSide)
                {
                    await HandleServerSideFetch(
                        response, url, method, resolvedHeaders, fetchBody, timeout, redirect,
                        cookieResolution.IncludeBrowserCookies, cookieResolution.IdentitySource);
                    return "";
                }

                return await _context.Fetch(url, method, resolvedHeaders, fetchBody, timeout, redirect, markSynthetic: false);
            });
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex);
            return;
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 500, $"Fetch failed: {ex.Message}");
            return;
        }

        if (string.IsNullOrEmpty(resultJson))
            return;

        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        var responseHeaders = new Dictionary<string, string>();
        if (root.TryGetProperty("headers", out var hdrs) && hdrs.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in hdrs.EnumerateObject())
                responseHeaders[prop.Name] = prop.Value.GetString() ?? "";
        }

        var pageCookies = await CookieNamesForUrlAsync(url);
        await WriteSuccess(response, new
        {
            ok = root.GetProperty("ok").GetBoolean(),
            status = root.GetProperty("status").GetInt32(),
            statusText = root.GetProperty("statusText").GetString(),
            redirected = root.TryGetProperty("redirected", out var rd) && rd.ValueKind == JsonValueKind.True,
            type = root.TryGetProperty("type", out var rt) ? rt.GetString() : null,
            url = root.TryGetProperty("url", out var ru) ? ru.GetString() : null,
            headers = responseHeaders,
            body = root.TryGetProperty("body", out var bdy) ? bdy.GetString() : "",
            durationMs = root.TryGetProperty("durationMs", out var dms) && dms.TryGetInt64(out var dm) ? dm : (long?)null,
            cookiesSent = pageCookies,
            includeBrowserCookies = true,
            identityUsed = "browser-page"
        });
    }

    private async Task<List<string>> CookieNamesForUrlAsync(string url)
    {
        try
        {
            var snapshot = await _context.GetBrowserCookieSnapshotForUrl(url);
            return CookieHeaderSanitizer.CookieNames(snapshot.Header);
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Server-side fetch (HttpClient + browser cookie jar). Used for TRACE/CONNECT and <c>serverSide: true</c>.
    /// </summary>
    private async Task HandleServerSideFetch(HttpListenerResponse response,
        string url, string method, Dictionary<string, string>? headers, string? body, int timeout, string? redirect,
        bool includeBrowserCookies = true, string? identitySource = null)
    {
        var allowRedirect = redirect is not ("manual" or "error");
        var sw = Stopwatch.StartNew();
        try
        {
            var result = await DirectFetchHelper.FetchAsync(
                _context, url, method, headers, body, timeout, allowRedirect, includeBrowserCookies);
            sw.Stop();

            if (result.Error != null)
            {
                await WriteError(response, 500, $"Server-side fetch failed: {result.Error}");
                return;
            }

            var callerCookie = headers != null
                && headers.TryGetValue("Cookie", out var callerCookieHeader)
                && !string.IsNullOrWhiteSpace(callerCookieHeader);
            await WriteSuccess(response, new
            {
                ok = result.Ok,
                status = result.Status,
                statusText = result.StatusText,
                redirected = result.Redirected,
                type = "server-side",
                url = result.FinalUrl ?? url,
                headers = result.Headers,
                body = result.Body,
                durationMs = sw.ElapsedMilliseconds,
                transport = result.Transport,
                cookiesSent = result.CookiesSent,
                cookieSourceUrl = result.CookieSourceUrl,
                cookieScopes = result.CookieScopes.Select(s => new { s.Name, s.Domain, s.Path }).ToList(),
                includeBrowserCookies = result.IncludedBrowserCookies,
                identityUsed = FetchIdentity.Describe(
                    result.IncludedBrowserCookies, result.CookiesSent, identitySource, callerCookie),
                identitySource,
                note = BrowserBlockedMethods.Contains(method)
                    ? $"{method} is not supported by browser fetch() — this request was made server-side via HttpClient."
                    : null
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, $"Server-side {method} request failed: {ex.Message}");
        }
    }

    private async Task HandlePostFetchBatch(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var concurrent = body.GetBool("concurrent", true);
        var arr = body.GetArray("requests");
        if (arr == null || arr.Count == 0)
        {
            await WriteError(response, 400, "Provide a non-empty 'requests' array.");
            return;
        }

        var items = new List<FetchBatchRequestItem>();
        foreach (var doc in arr)
        {
            var jb = new JsonBody(doc);
            var url = jb.GetString("url");
            if (string.IsNullOrWhiteSpace(url))
            {
                await WriteError(response, 400, "Each request must include a non-empty 'url'.");
                return;
            }

            var method = jb.GetString("method") ?? "GET";
            var headers = jb.GetHttpHeadersDictionary("headers");
            var timeout = jb.GetInt("timeout", 30000);
            string? fetchBody = jb.GetString("body");
            if (fetchBody == null && jb.HasProperty("bodyBase64"))
            {
                var b64 = jb.GetString("bodyBase64");
                if (!string.IsNullOrEmpty(b64))
                {
                    try
                    {
                        fetchBody = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                    }
                    catch (FormatException)
                    {
                        await WriteError(response, 400, "Invalid bodyBase64 in requests array.");
                        return;
                    }
                }
            }

            if (fetchBody == null && jb.HasProperty("bodyFile"))
            {
                var filePath = jb.GetString("bodyFile");
                if (!string.IsNullOrEmpty(filePath))
                {
                    try
                    {
                        fetchBody = await ExportPathGuard.ReadLocalTextAsync(filePath);
                    }
                    catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                    {
                        await WriteError(response, 400, $"bodyFile not found: {filePath}");
                        return;
                    }
                    catch (Exception ex)
                    {
                        await WriteError(response, 400, $"Failed to read bodyFile: {ex.Message}");
                        return;
                    }
                }
            }

            if (fetchBody == null && jb.HasProperty("json"))
            {
                fetchBody = jb.GetRawJson("json");
                headers = HttpHeaderDictionary.PrepareForJsonBody(headers);
            }

            var itemCookies = jb.GetString("cookies");
            var itemOverride = FetchCookieResolver.ParseIdentityOverride(jb);
            var itemIncludeCookies = jb.HasProperty("includeBrowserCookies")
                ? jb.GetBool("includeBrowserCookies")
                : (bool?)null;

            var itemResolution = await FetchCookieResolver.ResolveAsync(
                _context, Peers, _identityStore, url, headers, itemCookies, itemOverride, itemIncludeCookies,
                cookiesSpecified: jb.HasProperty("cookies"));
            if (itemResolution.Error != null)
            {
                await WriteError(response, 400, itemResolution.Error);
                return;
            }

            items.Add(new FetchBatchRequestItem
            {
                Url = url,
                Method = method,
                Headers = itemResolution.Headers,
                Body = fetchBody,
                TimeoutMs = timeout,
                Redirect = jb.GetString("redirect"),
                UseServerSide = itemResolution.ForceServerSide || jb.GetBool("serverSide"),
                IncludeBrowserCookies = itemResolution.IncludeBrowserCookies,
                IdentitySource = itemResolution.IdentitySource
            });
        }

        var results = await _context.FetchBatchAsync(items, concurrent, markSynthetic: false);
        // Accept includeBody (singular) as alias — matches network/fetch naming used elsewhere.
        var includeBodies = body.GetBool("includeBodies", false) || body.GetBool("includeBody", false);
        var bodyMaxChars = body.HasProperty("bodyMaxChars")
            ? body.GetInt("bodyMaxChars", 200)
            : body.GetInt("maxBodyChars", 200);
        var includeTiming = body.GetBool("includeTiming", true);

        await WriteSuccess(response, new
        {
            concurrent,
            count = results.Count,
            results = results.Select(r => new
            {
                r.Index,
                request = new
                {
                    url = r.RequestUrl,
                    method = r.RequestMethod,
                    body = r.RequestBody
                },
                r.Ok,
                r.Status,
                r.StatusText,
                r.Redirected,
                responseType = r.ResponseType,
                responseUrl = r.ResponseUrl,
                r.Headers,
                body = includeBodies
                    ? (bodyMaxChars <= 0 ? r.Body : (r.Body != null && r.Body.Length > bodyMaxChars ? r.Body[..bodyMaxChars] + "..." : r.Body))
                    : null,
                bodyLen = r.Body?.Length ?? 0,
                durationMs = includeTiming ? r.DurationMs : (long?)null,
                r.Error,
                cookiesSent = r.CookiesSent,
                includeBrowserCookies = r.IncludeBrowserCookies,
                identityUsed = r.IdentityUsed,
                identitySource = r.IdentitySource
            }).ToList()
        });
    }

    #endregion
}
