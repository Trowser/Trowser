using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Trowser.Security;

namespace Trowser.Automation;

/// <summary>
/// When WebView2 omits <see cref="CoreWebView2.WebResourceResponseReceived"/> (common for
/// document POST navigations in subframes), synthesize <see cref="NetworkEntry"/> rows from CDP.
/// </summary>
internal sealed class CdpNetworkBackfillTracker
{
    private sealed class PendingRequest
    {
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
        public DateTime StartedUtc { get; init; }
        public string? FrameId { get; init; }
        public Dictionary<string, string> RequestHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public int StatusCode { get; set; }
        public string ReasonPhrase { get; set; } = "";
        public Dictionary<string, string> ResponseHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public string ResourceType { get; set; } = "";
        public bool ServedFromCache { get; set; }
        public bool ResponseSeen { get; set; }
    }

    private readonly ConcurrentDictionary<string, PendingRequest> _pending = new();

    internal bool TryGetRequestHeaders(string requestId, out Dictionary<string, string> headers)
    {
        if (_pending.TryGetValue(requestId, out var p))
        {
            headers = new Dictionary<string, string>(p.RequestHeaders, StringComparer.OrdinalIgnoreCase);
            return true;
        }

        headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        return false;
    }

    internal bool TryGetPendingForSse(
        string requestId,
        out string method,
        out string url,
        out int statusCode,
        out Dictionary<string, string> responseHeaders,
        out Dictionary<string, string> requestHeaders)
    {
        method = "";
        url = "";
        statusCode = 0;
        responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        requestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!_pending.TryGetValue(requestId, out var p))
            return false;

        method = p.Method;
        url = p.Url;
        statusCode = p.StatusCode;
        responseHeaders = new Dictionary<string, string>(p.ResponseHeaders, StringComparer.OrdinalIgnoreCase);
        requestHeaders = new Dictionary<string, string>(p.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        return p.ResponseSeen && !string.IsNullOrEmpty(url);
    }

    internal static bool HeadersIndicateEventStream(IReadOnlyDictionary<string, string> headers)
    {
        foreach (var kv in headers)
        {
            if (!kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                continue;
            if (kv.Value.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>Returns the CDP request headers when the event was stored, so the caller can merge them onto the WebView2 log row.</summary>
    public Dictionary<string, string>? OnRequestWillBeSent(JsonElement root)
    {
        if (!root.TryGetProperty("requestId", out var idEl)) return null;
        var requestId = idEl.GetString();
        if (string.IsNullOrEmpty(requestId)) return null;
        if (!root.TryGetProperty("request", out var request)) return null;

        var method = request.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET";
        var url = request.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(url) || url.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return null;

        string? frameId = root.TryGetProperty("frameId", out var f) ? f.GetString() : null;

        var reqHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (request.TryGetProperty("headers", out var hdrs))
        {
            foreach (var prop in hdrs.EnumerateObject())
                reqHeaders[prop.Name] = prop.Value.GetString() ?? "";
        }

        _pending[requestId] = new PendingRequest
        {
            Method = method,
            Url = url,
            StartedUtc = DateTime.UtcNow,
            FrameId = frameId,
            RequestHeaders = reqHeaders
        };

        return reqHeaders;
    }

    /// <summary>
    /// When <c>fetch</c> follows a redirect, WebView2 may only log the final hop — record the
    /// <c>redirectResponse</c> from CDP when present.
    /// </summary>
    public void TryLogRedirectFollowRequest(BrowserTab tab, JsonElement root)
    {
        if (!root.TryGetProperty("redirectResponse", out var redirectResponse)) return;
        if (!root.TryGetProperty("request", out var followRequest)) return;

        var redirectUrl = redirectResponse.TryGetProperty("url", out var ru) ? ru.GetString() ?? "" : "";
        var status = redirectResponse.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        if (string.IsNullOrEmpty(redirectUrl) || status is < 300 or > 399) return;

        var hopMethod = ResolveRedirectHopMethod(redirectUrl, status, followRequest);

        if (tab.HasRecentNetworkEntry(hopMethod, redirectUrl, status, TimeSpan.FromSeconds(12)))
            return;

        var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (redirectResponse.TryGetProperty("headers", out var hdrs))
        {
            foreach (var prop in hdrs.EnumerateObject())
                HttpHeaderUtils.SetMerged(responseHeaders, prop.Name, prop.Value.GetString() ?? "");
        }

        var reason = redirectResponse.TryGetProperty("statusText", out var rp) ? rp.GetString() ?? "" : "";
        var requestBody = tab.TakeRequestBody(hopMethod, redirectUrl);
        var setCookie = tab.TakeSetCookieHeaders(hopMethod, redirectUrl);
        if (setCookie != null)
            HttpHeaderUtils.SetMerged(responseHeaders, "Set-Cookie", setCookie);

        var followUrl = followRequest.TryGetProperty("url", out var fu) ? fu.GetString() ?? "" : "";
        var resourceType = root.TryGetProperty("type", out var typeEl)
            ? MapCdpResourceType(typeEl.GetString())
            : "Fetch";

        tab.Network.Add(new NetworkEntry
        {
            Method = hopMethod,
            Url = redirectUrl,
            StatusCode = status,
            ReasonPhrase = reason,
            ResourceType = string.IsNullOrEmpty(resourceType) ? "Fetch" : resourceType,
            ResponseHeaders = responseHeaders,
            RequestBody = requestBody,
            Timestamp = DateTime.UtcNow,
            ResponseSource = "cdp-redirect-hop",
            RedirectedToUrl = followUrl
        });
    }

    private string ResolveRedirectHopMethod(string redirectUrl, int status, JsonElement followRequest)
    {
        foreach (var pending in _pending.Values)
        {
            if (pending.ResponseSeen
                && pending.StatusCode == status
                && string.Equals(pending.Url, redirectUrl, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrEmpty(pending.Method))
                return pending.Method;
        }

        var followMethod = followRequest.TryGetProperty("method", out var fm) ? fm.GetString() ?? "GET" : "GET";
        if (!followMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            return followMethod;

        if (redirectUrl.Contains("login", StringComparison.OrdinalIgnoreCase)
            || redirectUrl.Contains("signin", StringComparison.OrdinalIgnoreCase))
            return "POST";

        return "GET";
    }

    /// <summary>Finalize redirect responses early — <c>loadingFinished</c> may not run before the follow-up request.</summary>
    public void ScheduleFinalizeIfRedirect(BrowserTab tab, CoreWebView2 core, JsonElement root)
    {
        if (!root.TryGetProperty("requestId", out var idEl)) return;
        var requestId = idEl.GetString();
        if (string.IsNullOrEmpty(requestId)) return;
        if (!_pending.TryGetValue(requestId, out var pending) || !pending.ResponseSeen) return;
        if (pending.StatusCode is < 300 or > 399) return;

        _ = TryFinalizeAsync(tab, core, requestId);
    }

    public void OnResponseReceived(JsonElement root)
    {
        if (!root.TryGetProperty("requestId", out var idEl)) return;
        var requestId = idEl.GetString();
        if (string.IsNullOrEmpty(requestId)) return;
        if (!root.TryGetProperty("response", out var response)) return;
        if (!_pending.TryGetValue(requestId, out var pending)) return;

        pending.ResponseSeen = true;
        pending.StatusCode = response.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        pending.ReasonPhrase = response.TryGetProperty("statusText", out var rp) ? rp.GetString() ?? "" : "";
        pending.ServedFromCache = JsonTrue(response, "fromDiskCache")
                                  || JsonTrue(response, "fromPrefetchCache")
                                  || JsonTrue(response, "fromServiceWorker");

        if (response.TryGetProperty("headers", out var hdrs))
        {
            foreach (var prop in hdrs.EnumerateObject())
                HttpHeaderUtils.SetMerged(pending.ResponseHeaders, prop.Name, prop.Value.GetString() ?? "");
        }

        if (root.TryGetProperty("type", out var typeEl))
            pending.ResourceType = MapCdpResourceType(typeEl.GetString());
        else if (response.TryGetProperty("mimeType", out var mime))
            pending.ResourceType = GuessFromMime(mime.GetString());
    }

    public async Task TryFinalizeAsync(BrowserTab tab, CoreWebView2 core, string requestId)
    {
        if (!_pending.TryRemove(requestId, out var pending) || !pending.ResponseSeen)
            return;

        // Give WebView2 a moment to emit WebResourceResponseReceived for the same hop.
        await Task.Delay(80).ConfigureAwait(true);

        // Drop the header cache either way. The WebView2 row merges it on the way in;
        // a CDP-only row already has these headers on the pending request.
        tab.TakeCdpRequestHeaders(pending.Method, pending.Url);

        if (pending.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            return;

        var existing = tab.FindRecentNetworkEntry(
            pending.Method, pending.Url, pending.StatusCode, TimeSpan.FromSeconds(4));
        var missingHeaders = existing == null
            ? null
            : NetworkCaptureLimits.MissingRequestHeaders(existing.RequestHeaders, pending.RequestHeaders);
        var captureBody = existing == null
            ? ShouldCaptureResponseBody(pending)
            : existing.ResponseBody == null && NetworkCaptureLimits.ShouldCaptureResponseBody(
                existing.ResourceType, existing.ContentType);

        if (existing != null && !captureBody && (missingHeaders == null || missingHeaders.Count == 0))
            return;

        string? responseBody = null;
        if (captureBody)
            responseBody = await ReadResponseBodyAsync(core, requestId, pending).ConfigureAwait(true);

        if (existing != null)
        {
            tab.Network.TrySupplement(existing.Id, responseBody, missingHeaders);
            return;
        }

        var requestBody = tab.TakeRequestBody(pending.Method, pending.Url);
        var durationMs = tab.TakeRequestDuration(pending.Method, pending.Url);
        var servedFromCache = tab.TryTakeServedFromCache(pending.Method, pending.Url) ?? pending.ServedFromCache;

        var responseHeaders = new Dictionary<string, string>(pending.ResponseHeaders, StringComparer.OrdinalIgnoreCase);
        var setCookie = tab.TakeSetCookieHeaders(pending.Method, pending.Url);
        if (setCookie != null)
            HttpHeaderUtils.SetMerged(responseHeaders, "Set-Cookie", setCookie);

        var entry = new NetworkEntry
        {
            Method = pending.Method,
            Url = pending.Url,
            StatusCode = pending.StatusCode,
            ReasonPhrase = pending.ReasonPhrase,
            ResourceType = string.IsNullOrEmpty(pending.ResourceType) ? "Other" : pending.ResourceType,
            RequestHeaders = pending.RequestHeaders,
            ResponseHeaders = responseHeaders,
            RequestBody = requestBody,
            ResponseBody = responseBody,
            Timestamp = pending.StartedUtc,
            DurationMs = durationMs,
            ServedFromCache = servedFromCache,
            ResponseSource = "cdp-backfill",
            CdpFrameId = pending.FrameId
        };

        tab.Network.Add(entry);
    }

    private static bool ShouldCaptureResponseBody(PendingRequest pending)
    {
        var ct = pending.ResponseHeaders.TryGetValue("Content-Type", out var v) ? v : "";
        return NetworkCaptureLimits.ShouldCaptureResponseBody(pending.ResourceType, ct);
    }

    private static async Task<string?> ReadResponseBodyAsync(CoreWebView2 core, string requestId, PendingRequest pending)
    {
        var maxChars = HeadersIndicateEventStream(pending.ResponseHeaders)
            ? NetworkCaptureLimits.MaxEventStreamBodyChars
            : NetworkCaptureLimits.MaxTextBodyChars;

        try
        {
            var param = JsonSerializer.Serialize(new { requestId });
            var raw = await core.CallDevToolsProtocolMethodAsync("Network.getResponseBody", param)
                .ConfigureAwait(true);
            using var doc = JsonDocument.Parse(raw);
            var body = doc.RootElement.GetProperty("body").GetString() ?? "";
            var base64 = doc.RootElement.TryGetProperty("base64Encoded", out var b) && b.GetBoolean();
            if (base64)
            {
                var bytes = Convert.FromBase64String(body);
                var text = Encoding.UTF8.GetString(bytes, 0, Math.Min(bytes.Length, maxChars));
                if (bytes.Length > maxChars)
                    text += "...(truncated)";
                return text;
            }
            if (body.Length > maxChars)
                return body[..maxChars] + "...(truncated)";
            return body;
        }
        catch
        {
            // Body optional — status line + Set-Cookie still matter for audits.
            return null;
        }
    }

    private static bool JsonTrue(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;

    private static string MapCdpResourceType(string? type) => (type ?? "").ToLowerInvariant() switch
    {
        "document" => "Document",
        "stylesheet" => "Stylesheet",
        "image" => "Image",
        "media" => "Media",
        "font" => "Font",
        "script" => "Script",
        "xhr" => "XHR",
        "fetch" => "Fetch",
        "eventsource" => "Fetch",
        "websocket" => "WebSocket",
        "manifest" => "Manifest",
        _ => "Other"
    };

    private static string GuessFromMime(string? mime)
    {
        if (string.IsNullOrEmpty(mime)) return "Other";
        if (mime.Contains("html", StringComparison.OrdinalIgnoreCase)) return "Document";
        if (mime.Contains("javascript", StringComparison.OrdinalIgnoreCase)) return "Script";
        if (mime.Contains("json", StringComparison.OrdinalIgnoreCase)) return "Fetch";
        if (mime.Contains("css", StringComparison.OrdinalIgnoreCase)) return "Stylesheet";
        return "Other";
    }
}
