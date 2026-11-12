using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Microsoft.Win32;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Recording;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.Authz;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region Console Capture (per-tab)

    private async void Tab_InjectConsoleCapture(BrowserTab tab, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (!e.IsSuccess) return;

        const string script = """
            (function() {
                if (window.__trowserConsoleHooked) return;
                window.__trowserConsoleHooked = true;

                const origLog = console.log;
                const origWarn = console.warn;
                const origError = console.error;
                const origInfo = console.info;

                function capture(level, args) {
                    try {
                        var msg = Array.from(args).map(a => {
                            if (typeof a === 'string') return a;
                            try { return JSON.stringify(a); } catch { return String(a); }
                        }).join(' ');
                        window.chrome.webview.postMessage(JSON.stringify({
                            type: '__trowser_console',
                            level: level,
                            message: msg
                        }));
                    } catch {}
                }

                console.log = function() { capture('log', arguments); origLog.apply(console, arguments); };
                console.warn = function() { capture('warning', arguments); origWarn.apply(console, arguments); };
                console.error = function() { capture('error', arguments); origError.apply(console, arguments); };
                console.info = function() { capture('info', arguments); origInfo.apply(console, arguments); };

                window.addEventListener('error', function(e) {
                    capture('error', ['Uncaught ' + (e.error ? e.error.toString() : e.message)]);
                });
                window.addEventListener('unhandledrejection', function(e) {
                    capture('error', ['Unhandled Promise Rejection: ' + (e.reason ? e.reason.toString() : 'unknown')]);
                });
            })();
            """;

        try
        {
            await tab.WebView.CoreWebView2.ExecuteScriptAsync(script);
        }
        catch (Exception ex) { TrowserLog.Warn($"Console capture injection failed: {ex.Message}"); }
    }

    private void Tab_WebMessageReceived(
        BrowserTab tab,
        CoreWebView2WebMessageReceivedEventArgs e,
        string? frameName = null,
        string? frameOrigin = null,
        bool isFrame = false)
    {
        try
        {
            var json = e.WebMessageAsJson;

            // postMessage(object) → WebMessageAsJson is a JSON object string.
            // postMessage(JSON.stringify(object)) → WebMessageAsJson is a JSON-encoded
            // string (double-encoded). Unwrap if needed so both patterns work.
            if (json.Length > 2 && json[0] == '"')
            {
                var inner = System.Text.Json.JsonSerializer.Deserialize<string>(json);
                if (inner != null) json = inner;
            }

            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!root.TryGetProperty("type", out var typeProp)) return;
            var msgType = typeProp.GetString();

            if (msgType == "__trowser_rt")
            {
                // Untrusted page evidence (see trowserkit/SECURITY.md). Never trigger actions.
                tab.RuntimeEvents.Ingest(root, frameName, frameOrigin);
                return;
            }

            if (msgType == "__trowser_async")
            {
                var id = root.GetProperty("id").GetString() ?? "";
                // postMessage may deliver result as a JSON string (JSON.stringify from JS) or as a nested object/array.
                // JsonElement.GetString() only works for ValueKind.String — objects yield null and broke Fetch()/fuzzer parsing.
                string? result = root.TryGetProperty("result", out var rp) ? UnwrapAsyncResultElement(rp) : null;
                string? error = root.TryGetProperty("error", out var ep) ? ep.GetString() : null;
                _automationContext?.HandleAsyncCallback(id, result, error);
                return;
            }

            if (msgType == "__trowser_welcome")
            {
                HandleWelcomeMessage(tab, root.Clone());
                return;
            }

            if (msgType == "__trowser_dialog")
            {
                if (root.TryGetProperty("dialog", out var dialogProp))
                {
                    var dialogType = dialogProp.TryGetProperty("type", out var dt) ? dt.GetString() ?? "" : "";
                    var dialogMsg = dialogProp.TryGetProperty("message", out var dm) ? dm.GetString() ?? "" : "";
                    var defaultVal = dialogProp.TryGetProperty("defaultValue", out var dv) && dv.ValueKind == System.Text.Json.JsonValueKind.String
                        ? dv.GetString() : null;
                    tab.LastDialog = new Automation.DialogInfo
                    {
                        Type = dialogType,
                        Message = dialogMsg,
                        DefaultValue = defaultVal
                    };
                }
                return;
            }

            if (msgType == "__trowser_record")
            {
                // Capture is injected only into the top frame; anything from a child frame,
                // or without the token, is a page forging gestures.
                if (isFrame
                    || !root.TryGetProperty("token", out var recordTokenProp)
                    || recordTokenProp.ValueKind != System.Text.Json.JsonValueKind.String
                    || recordTokenProp.GetString() != Recording.ScriptRecorder.RecordToken)
                    return;

                if (IsActiveTab(tab) && root.TryGetProperty("action", out var actionProp))
                {
                    // One capture stream, several sinks — membership is CapturedActionRouting
                    // (e.g. scroll is Mirror-only so .csx recordings stay compact).
                    if (_recorder.IsRecording && CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Script, actionProp))
                        _recorder.RecordAction(actionProp);

                    if (_sessionLogger.IsLogging && CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Journal, actionProp))
                        LogRecordedActionToSession(actionProp);

                    // Keep the human-readable narration buffer up to date (feeds "Add to bug" steps).
                    if ((_recorder.IsRecording || _sessionLogger.IsLogging)
                        && CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Narration, actionProp))
                        RecordNarration(actionProp);

                    if (_mirrorController is { IsActive: true }
                        && CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Mirror, actionProp))
                        _mirrorController.Enqueue(actionProp);
                }
                return;
            }

            if (msgType == "__trowser_console")
            {
                var levelStr = root.GetProperty("level").GetString() ?? "log";
                var message = root.GetProperty("message").GetString() ?? "";

                var level = levelStr switch
                {
                    "warning" => ConsoleLevel.Warning,
                    "error" => ConsoleLevel.Error,
                    "info" => ConsoleLevel.Info,
                    _ => ConsoleLevel.Log
                };

                var entry = new ConsoleEntry
                {
                    Level = level,
                    Message = message,
                    Source = "",
                    Line = 0,
                    Timestamp = DateTime.UtcNow
                };

                tab.Console.Add(entry);

                if (IsActiveTab(tab))
                {
                    var color = level switch
                    {
                        ConsoleLevel.Error => "#F44747",
                        ConsoleLevel.Warning => "#CCA700",
                        ConsoleLevel.Info => "#569CD6",
                        _ => "#6A9955"
                    };
                    LogColoredToOutput(entry.ToString(), color);
                }
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"WebMessage processing failed: {ex.Message}"); }
    }

    /// <summary>
    /// Normalize <c>__trowser_async</c> result payloads for C# parsing. WebView may surface
    /// <see cref="System.Text.Json.JsonValueKind.String"/> (JSON.stringify output) or a nested Object/Array.
    /// </summary>
    private static string? UnwrapAsyncResultElement(System.Text.Json.JsonElement el) => el.ValueKind switch
    {
        System.Text.Json.JsonValueKind.String => el.GetString(),
        System.Text.Json.JsonValueKind.Object or System.Text.Json.JsonValueKind.Array => el.GetRawText(),
        System.Text.Json.JsonValueKind.Null => null,
        System.Text.Json.JsonValueKind.True => "true",
        System.Text.Json.JsonValueKind.False => "false",
        System.Text.Json.JsonValueKind.Number => el.GetRawText(),
        _ => el.GetRawText()
    };

    #endregion

    #region Network Logging (per-tab)

    private const int MaxBodyCaptureBytes = NetworkCaptureLimits.MaxTextBodyChars;

    private async void EnableCdpNetworkCapture(BrowserTab tab, CoreWebView2 coreWv2)
    {
        try
        {
            await coreWv2.CallDevToolsProtocolMethodAsync("Network.enable", "{}");

            coreWv2.GetDevToolsProtocolEventReceiver("Network.requestWillBeSent")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var request = root.GetProperty("request");
                    var method = request.GetProperty("method").GetString()!;
                    var url = request.GetProperty("url").GetString()!;
                    tab.CacheCdpRequestMapping(requestId, method, url);
                    tab.MapCdpCacheRequest(requestId, method, url);
                    var cdpHeaders = tab.CdpBackfill.OnRequestWillBeSent(root);
                    tab.CdpBackfill.TryLogRedirectFollowRequest(tab, root);
                    if (cdpHeaders != null)
                        tab.CacheCdpRequestHeaders(method, url, cdpHeaders);

                    // Form POST navigations often have no Request.Content in WebResourceRequested;
                    // CDP postData is the reliable source for traditional application/x-www-form-urlencoded bodies.
                    if (request.TryGetProperty("postData", out var postDataEl)
                        && postDataEl.ValueKind == JsonValueKind.String)
                    {
                        var postData = postDataEl.GetString();
                        if (!string.IsNullOrEmpty(postData)
                            && NetworkEntry.MethodMayHaveRequestBody(method))
                            tab.CacheRequestBody(method, url, postData);
                    }

                    if (request.TryGetProperty("headers", out var reqHdrs))
                    {
                        foreach (var prop in reqHdrs.EnumerateObject())
                        {
                            if (prop.Name.Equals("Last-Event-ID", StringComparison.OrdinalIgnoreCase))
                            {
                                var lastId = prop.Value.GetString();
                                tab.Sse.NoteLastEventIdHeader(requestId, lastId);
                                break;
                            }
                        }
                    }
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.responseReceived")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString();
                    if (string.IsNullOrEmpty(requestId) || !root.TryGetProperty("response", out var response))
                        return;
                    var servedFromCache = JsonTrue(response, "fromDiskCache")
                        || JsonTrue(response, "fromPrefetchCache")
                        || JsonTrue(response, "fromServiceWorker");
                    tab.NoteCdpResponseCache(requestId, servedFromCache);
                    tab.CdpBackfill.OnResponseReceived(root);
                    tab.CdpBackfill.ScheduleFinalizeIfRedirect(tab, coreWv2, root);

                    if (tab.TryResolveCdpRequest(requestId, out var sseMethod, out var sseUrl))
                    {
                        var mime = response.TryGetProperty("mimeType", out var mimeEl)
                            ? mimeEl.GetString() ?? ""
                            : "";
                        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        if (response.TryGetProperty("headers", out var hdrs))
                        {
                            foreach (var prop in hdrs.EnumerateObject())
                                headers[prop.Name] = prop.Value.GetString() ?? "";
                        }

                        var isEventStreamMime = mime.Contains("event-stream", StringComparison.OrdinalIgnoreCase)
                            || CdpNetworkBackfillTracker.HeadersIndicateEventStream(headers);
                        if (isEventStreamMime)
                        {
                            var status = response.TryGetProperty("status", out var st) ? st.GetInt32() : 0;

                            string? initiator = null;
                            if (root.TryGetProperty("initiator", out var init)
                                && init.TryGetProperty("url", out var initUrl))
                                initiator = initUrl.GetString();

                            var reqHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            if (tab.CdpBackfill.TryGetRequestHeaders(requestId, out var fromCdp))
                                reqHeaders = fromCdp;

                            tab.Sse.EnsureConnection(requestId, sseUrl, sseMethod, initiator, status, headers, reqHeaders);

                            var reason = response.TryGetProperty("statusText", out var rp) ? rp.GetString() ?? "" : "";
                            tab.LogEventStreamNetworkRow(sseMethod, sseUrl, status, reason, reqHeaders, headers, requestId);
                            _ = Trowser.Security.Sse.SseCdpLiveBodySync.StartStreamingAsync(tab, coreWv2, requestId);
                        }
                    }
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.dataReceived")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString();
                    if (string.IsNullOrEmpty(requestId)) return;
                    if (!root.TryGetProperty("data", out var dataEl)) return;
                    var data = dataEl.GetString();
                    if (string.IsNullOrEmpty(data)) return;
                    tab.Sse.OnNetworkDataReceived(requestId, data, base64: true, tab);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.eventSourceMessageReceived")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var eventName = root.TryGetProperty("eventName", out var en) ? en.GetString() : null;
                    var eventId = root.TryGetProperty("eventId", out var ei) ? ei.GetString() : null;
                    var data = root.TryGetProperty("data", out var d) ? d.GetString() ?? "" : "";

                    if (!tab.TryResolveCdpRequest(requestId, out var method, out var url))
                        return;

                    tab.Sse.EnsureConnection(requestId, url, method, null, null, null, null);
                    tab.Sse.OnMessageReceived(requestId, eventName, eventId, data);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.loadingFinished")
                .DevToolsProtocolEventReceived += async (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var requestId = json.RootElement.GetProperty("requestId").GetString();
                    if (!string.IsNullOrEmpty(requestId))
                    {
                        await Trowser.Security.Sse.SseCdpLiveBodySync.PollRequestAsync(tab, requestId);
                        await tab.CdpBackfill.TryFinalizeAsync(tab, coreWv2, requestId);
                        tab.Sse.OnStreamFinished(requestId, tab);
                    }
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.requestServedFromCache")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var requestId = json.RootElement.GetProperty("requestId").GetString();
                    if (!string.IsNullOrEmpty(requestId))
                        tab.NoteCdpMemoryCache(requestId);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.responseReceivedExtraInfo")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    if (root.TryGetProperty("headers", out var headers))
                    {
                        foreach (var prop in headers.EnumerateObject())
                        {
                            if (prop.Name.Equals("set-cookie", StringComparison.OrdinalIgnoreCase))
                            {
                                tab.CacheCdpSetCookie(requestId, prop.Value.GetString()!);
                                break;
                            }
                        }
                    }
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Fetch.requestPaused")
                .DevToolsProtocolEventReceived += async (s, e) =>
            {
                await CdpFetchMockBridge.HandleRequestPausedAsync(tab, coreWv2, e.ParameterObjectAsJson);
            };

            // ── WebSocket CDP events ──
            coreWv2.GetDevToolsProtocolEventReceiver("Network.webSocketCreated")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var url = root.GetProperty("url").GetString()!;
                    string? initiator = null;
                    if (root.TryGetProperty("initiator", out var init) &&
                        init.TryGetProperty("url", out var initUrl))
                        initiator = initUrl.GetString();
                    tab.WebSocket.OnWebSocketCreated(requestId, url, initiator);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.webSocketHandshakeResponseReceived")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var resp = root.GetProperty("response");
                    var status = resp.GetProperty("status").GetInt32();
                    var headers = new Dictionary<string, string>();
                    if (resp.TryGetProperty("headers", out var hdrs))
                        foreach (var prop in hdrs.EnumerateObject())
                            headers[prop.Name] = prop.Value.GetString() ?? "";
                    tab.WebSocket.OnHandshakeResponse(requestId, status, headers);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.webSocketFrameSent")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var response = root.GetProperty("response");
                    var data = response.GetProperty("payloadData").GetString() ?? "";
                    var opcode = response.TryGetProperty("opcode", out var op) ? op.GetInt32() : 1;
                    tab.WebSocket.OnFrameSent(requestId, data, opcode);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.webSocketFrameReceived")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    var response = root.GetProperty("response");
                    var data = response.GetProperty("payloadData").GetString() ?? "";
                    var opcode = response.TryGetProperty("opcode", out var op) ? op.GetInt32() : 1;
                    tab.WebSocket.OnFrameReceived(requestId, data, opcode);
                }
                catch { /* best-effort */ }
            };

            coreWv2.GetDevToolsProtocolEventReceiver("Network.webSocketClosed")
                .DevToolsProtocolEventReceived += (s, e) =>
            {
                try
                {
                    using var json = System.Text.Json.JsonDocument.Parse(e.ParameterObjectAsJson);
                    var root = json.RootElement;
                    var requestId = root.GetProperty("requestId").GetString()!;
                    tab.WebSocket.OnWebSocketClosed(requestId);
                }
                catch { /* best-effort */ }
            };
        }
        catch (Exception ex) { TrowserLog.Warn($"CDP Network capture setup failed: {ex.Message}"); }
    }

    private async void Tab_WebResourceResponseReceived(BrowserTab tab, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        try
        {
            var requestHeaders = new Dictionary<string, string>();
            foreach (var header in e.Request.Headers)
                requestHeaders[header.Key] = header.Value;
            NetworkCaptureLimits.MergeMissingRequestHeaders(
                requestHeaders, tab.TakeCdpRequestHeaders(e.Request.Method, e.Request.Uri));

            var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var header in e.Response.Headers)
                HttpHeaderUtils.SetMerged(responseHeaders, header.Key, header.Value);

            var resourceType = GuessResourceType(e.Request.Uri, responseHeaders);

            var contentType = "";
            if (responseHeaders.TryGetValue("Content-Type", out var ct))
                contentType = ct;
            else if (responseHeaders.TryGetValue("content-type", out var ct2))
                contentType = ct2;

            bool isTextResponse = NetworkCaptureLimits.ShouldCaptureResponseBody(resourceType, contentType);
            var isEventStream = contentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase);

            var loggedMethod = ResolveLoggedRequestMethod(tab, e.Request.Method, e.Request.Uri);

            if (isEventStream)
            {
                var existing = tab.FindRecentNetworkEntry(
                    loggedMethod, e.Request.Uri, e.Response.StatusCode, TimeSpan.FromSeconds(45));
                if (existing != null)
                {
                    tab.TryLinkOpenSseToNetworkEntry(loggedMethod, e.Request.Uri, existing.Id);
                    return;
                }
            }

            string? responseBody = null;
            if (isTextResponse)
            {
                // For fulfilled (mock/intercept) responses, GetContentAsync fails with COM errors
                // ("Klassen har inte registrerats" / "Class has not been registered").
                // Use cached body when available.
                responseBody = tab.TakeResponseBody(e.Request.Method, e.Request.Uri);
                var canHaveBody = ResponseCanHaveBody(e.Request.Method, e.Response.StatusCode, responseHeaders);
                if (!isEventStream && responseBody == null && canHaveBody)
                {
                    try
                    {
                        using var stream = await e.Response.GetContentAsync();
                        if (stream != null)
                            responseBody = await ReadStreamCapped(stream, MaxBodyCaptureBytes);
                    }
                    catch (Exception ex) when (IsTransientWebViewComError(ex)) { /* expected during navigation */ }
                    catch (Exception ex) { TrowserLog.Warn($"Response body capture failed: {ex.Message}"); }
                }
            }
            var requestBody = tab.TakeRequestBody(loggedMethod, e.Request.Uri)
                                ?? (loggedMethod != e.Request.Method
                                    ? tab.TakeRequestBody(e.Request.Method, e.Request.Uri)
                                    : null);
            var durationMs = tab.TakeRequestDuration(loggedMethod, e.Request.Uri)
                             ?? tab.TakeRequestDuration(e.Request.Method, e.Request.Uri);
            var servedFromCache = tab.TryTakeServedFromCache(loggedMethod, e.Request.Uri)
                                  ?? tab.TryTakeServedFromCache(e.Request.Method, e.Request.Uri);
            if (servedFromCache == null)
            {
                // Images and fonts skip the body read, so give a queued CDP cache event one turn.
                await Task.Yield();
                servedFromCache = tab.TryTakeServedFromCache(e.Request.Method, e.Request.Uri);
            }

            // WebView2 strips Set-Cookie from response headers for security.
            // Merge from CDP capture if available.
            var setCookie = tab.TakeSetCookieHeaders(loggedMethod, e.Request.Uri)
                            ?? tab.TakeSetCookieHeaders(e.Request.Method, e.Request.Uri);
            if (setCookie != null)
                HttpHeaderUtils.SetMerged(responseHeaders, "Set-Cookie", setCookie);

            var fulfilled = tab.TakeFulfilledResponse(loggedMethod, e.Request.Uri)
                            ?? tab.TakeFulfilledResponse(e.Request.Method, e.Request.Uri);
            var responseSource = fulfilled?.ResponseSource
                ?? (servedFromCache == true ? "cache" : "network");

            var entry = new NetworkEntry
            {
                Method = loggedMethod,
                Url = e.Request.Uri,
                AuthzPeerFirstSlotId = tab.TakeAuthzPeerFirstSlot(loggedMethod, e.Request.Uri)
                                        ?? tab.TakeAuthzPeerFirstSlot(e.Request.Method, e.Request.Uri),
                StatusCode = e.Response.StatusCode,
                ReasonPhrase = e.Response.ReasonPhrase,
                ResourceType = resourceType,
                RequestHeaders = requestHeaders,
                ResponseHeaders = responseHeaders,
                RequestBody = requestBody,
                ResponseBody = responseBody,
                Timestamp = DateTime.UtcNow,
                DurationMs = durationMs,
                IsTrowserGenerated = tab.TakeSyntheticRequest(e.Request.Method, e.Request.Uri),
                ServedFromCache = servedFromCache == true,
                ResponseSource = responseSource,
                MockRuleKey = fulfilled?.MockRuleKey
            };

            var entryId = tab.Network.Add(entry);
            if (isEventStream)
            {
                tab.TryLinkOpenSseToNetworkEntry(loggedMethod, e.Request.Uri, entryId);
                if (!string.IsNullOrEmpty(responseBody))
                    tab.Sse.OnNetworkEntryBodyUpdated(tab, entryId);
            }

            if (_automationContext != null &&
                tab.MatchesCurrentMainDocumentNavigation(e.Request.Method, e.Request.Uri))
            {
                await _automationContext.TryCaptureDirectDocumentDownloadAsync(
                    tab,
                    e.Request.Uri,
                    e.Response.StatusCode,
                    responseHeaders,
                    responseBody);
            }

            // SAML capture: if armed, check for SAMLRequest/SAMLResponse parameters
            if (tab.SamlCapture.IsArmed)
                tab.SamlCapture.TryCapture(entry);
        }
        catch (Exception ex) when (IsTransientWebViewComError(ex)) { /* navigation / stream race */ }
        catch (Exception ex) { TrowserLog.Warn($"Network response capture failed: {ex.Message}"); }
    }

    private static bool ResponseCanHaveBody(string method, int statusCode, Dictionary<string, string> responseHeaders)
    {
        if (string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
            return false;

        // RFC7230/7231: these statuses never carry response payloads.
        if ((statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 205 || statusCode == 304)
            return false;

        if (TryGetHeaderValue(responseHeaders, "Content-Length", out var contentLengthRaw))
        {
            var firstValue = contentLengthRaw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(firstValue) && long.TryParse(firstValue, out var contentLength) && contentLength == 0)
                return false;
        }

        return true;
    }

    private static bool TryGetHeaderValue(Dictionary<string, string> headers, string headerName, out string value)
    {
        if (headers.TryGetValue(headerName, out var directValue) && directValue != null)
        {
            value = directValue;
            return true;
        }

        if (headers.TryGetValue(headerName.ToLowerInvariant(), out var lowerValue) && lowerValue != null)
        {
            value = lowerValue;
            return true;
        }

        value = string.Empty;
        return false;
    }

    /// <summary>
    /// Form POST navigations are sometimes reported to WebView2 as GET while CDP captured POST postData.
    /// </summary>
    private static string ResolveLoggedRequestMethod(BrowserTab tab, string webViewMethod, string url)
    {
        if (webViewMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            return webViewMethod;

        if (tab.PeekRequestBody("POST", url) != null)
            return "POST";

        return webViewMethod;
    }

    /// <summary>
    /// WebView2 exposes multipart bodies in <see cref="CoreWebView2WebResourceRequestedEventArgs"/> without
    /// file attachment bytes in <c>Request.Content</c>. Reading the stream and assigning a new one sends
    /// empty file parts to the server (WebView2Feedback #2162). Leave the native stream untouched.
    /// Non-multipart bodies (JSON, urlencoded, raw binary) are fully materialized and safe to re-stream for logging.
    /// Intercept "Continue" with a modified body on multipart still cannot attach files — WebView2 limitation.
    /// </summary>
    private static bool WebView2MultipartMustPreserveNativeContentStream(CoreWebView2WebResourceRequest request)
    {
        foreach (var header in request.Headers)
        {
            if (header.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)
                && header.Value.Contains("multipart/", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private const string MultipartBodyLogPlaceholder =
        "[multipart request body — file bytes omitted in WebView2; not captured to preserve upload]";

    private async void Tab_WebResourceRequested(BrowserTab tab, CoreWebView2WebResourceRequestedEventArgs e)
    {
        tab.CacheRequestTimestamp(e.Request.Method, e.Request.Uri);

        // Request Editor: NavigateWithWebResourceRequest does not send CreateWebResourceRequest
        // headers (Chromium rebuilds navigation headers). Re-apply them here, where WebView2
        // still allows SetHeader on the outgoing request. Cookie/Host/Connection may still
        // be owned by Chromium — the editor warns about those.
        Dictionary<string, string>? overlayHeaders = null;
        if (tab.TryConsumeRequestHeaderOverlay(
                e.Request.Method,
                e.Request.Uri,
                e.ResourceContext == CoreWebView2WebResourceContext.Document,
                out overlayHeaders)
            && overlayHeaders != null)
        {
            foreach (var kv in overlayHeaders)
            {
                if (string.IsNullOrWhiteSpace(kv.Key) || kv.Key.StartsWith(':'))
                    continue;
                try
                {
                    if (e.Request.Headers.Contains(kv.Key))
                        e.Request.Headers.RemoveHeader(kv.Key);
                    e.Request.Headers.SetHeader(kv.Key, kv.Value);
                }
                catch (Exception ex)
                {
                    TrowserLog.Warn($"Request-editor header '{kv.Key}' not applied: {ex.Message}");
                }
            }
        }

        ApplySessionHeaderOverrides(e.Request.Headers, overlayHeaders);

        // Capture request body for methods that may carry one so it can be included in the network log.
        // This runs for all requests before intercept/mock processing.
        var reqMethod = e.Request.Method;
        var preserveMultipartStream = WebView2MultipartMustPreserveNativeContentStream(e.Request);
        if (preserveMultipartStream && NetworkEntry.MethodMayHaveRequestBody(reqMethod))
            tab.CacheRequestBody(reqMethod, e.Request.Uri, MultipartBodyLogPlaceholder);

        if (e.Request.Content != null && NetworkEntry.MethodMayHaveRequestBody(reqMethod) && !preserveMultipartStream)
        {
            try
            {
                using var ms = new MemoryStream();
                e.Request.Content.CopyTo(ms);
                var bodyBytes = ms.ToArray();
                var body = bodyBytes.Length <= MaxBodyCaptureBytes
                    ? Encoding.UTF8.GetString(bodyBytes)
                    : Encoding.UTF8.GetString(bodyBytes, 0, MaxBodyCaptureBytes) + "...(truncated)";
                tab.CacheRequestBody(reqMethod, e.Request.Uri, body);
                e.Request.Content = new MemoryStream(bodyBytes);
            }
            catch (Exception ex) { TrowserLog.Warn($"Request body pre-capture failed: {ex.Message}"); }
        }

        // 1. Intercept rules (breakpoints) take priority
        if (tab.HasInterceptRules)
        {
            var interceptRule = tab.FindMatchingIntercept(e.Request.Uri, e.Request.Method);
            if (interceptRule != null)
            {
                if (interceptRule.AutoFulfill != null)
                {
                    var auto = interceptRule.AutoFulfill;
                    tab.CacheResponseBody(e.Request.Method, e.Request.Uri, auto.Body);
                    tab.CacheFulfilledResponse(e.Request.Method, e.Request.Uri,
                        new BrowserTab.FulfilledResponseMarker("intercept-fulfill", interceptRule.UrlPattern));
                    e.Response = BuildMockResponse(tab, auto.StatusCode, auto.Body, auto.ResponseHeaders);
                    return;
                }

                var deferral = e.GetDeferral();
                var headers = new Dictionary<string, string>();
                foreach (var h in e.Request.Headers)
                    headers[h.Key] = h.Value;

                string? requestBody = null;
                var preserveMultipartForIntercept = WebView2MultipartMustPreserveNativeContentStream(e.Request);
                if (preserveMultipartForIntercept)
                    requestBody = MultipartBodyLogPlaceholder;
                else if (e.Request.Content != null)
                {
                    try
                    {
                        using var ms = new MemoryStream();
                        e.Request.Content.CopyTo(ms);
                        var bodyBytes = ms.ToArray();
                        requestBody = Encoding.UTF8.GetString(bodyBytes);
                        e.Request.Content = new MemoryStream(bodyBytes);
                    }
                    catch (Exception ex) { TrowserLog.Warn($"Request body capture failed: {ex.Message}"); }
                }

                var pending = new PendingRequest
                {
                    Url = e.Request.Uri,
                    Method = e.Request.Method,
                    Headers = headers,
                    Body = requestBody,
                    ResourceType = e.ResourceContext.ToString(),
                    MatchedPattern = interceptRule.UrlPattern,
                    Deferral = deferral,
                    EventArgs = e
                };

                tab.AddPendingRequest(pending);
                Dispatcher.Invoke(() =>
                {
                    UpdateInterceptStatusDisplay();
                    if (!interceptRule.Silent)
                        ShowBreakpointHitDialog(pending);
                });

                try
                {
                    var decision = await pending.WaitForDecision(TimeSpan.FromSeconds(120));

                    switch (decision.Action)
                    {
                        case InterceptAction.Continue:
                            if (decision.ModifiedUrl != null)
                                e.Request.Uri = decision.ModifiedUrl;
                            if (decision.ModifiedMethod != null)
                                e.Request.Method = decision.ModifiedMethod;
                            if (decision.ModifiedHeaders != null)
                                foreach (var kv in decision.ModifiedHeaders)
                                    e.Request.Headers.SetHeader(kv.Key, kv.Value);
                            if (decision.ModifiedBody != null)
                                e.Request.Content = new MemoryStream(
                                    Encoding.UTF8.GetBytes(decision.ModifiedBody));
                            break;

                        case InterceptAction.Fulfill:
                            tab.CacheResponseBody(e.Request.Method, e.Request.Uri, decision.Body);
                            tab.CacheFulfilledResponse(e.Request.Method, e.Request.Uri,
                                new BrowserTab.FulfilledResponseMarker("intercept-fulfill", interceptRule.UrlPattern));
                            e.Response = BuildMockResponse(tab, decision.StatusCode,
                                decision.Body, decision.ResponseHeaders);
                            break;

                        case InterceptAction.Abort:
                            e.Response = tab.WebView.CoreWebView2.Environment
                                .CreateWebResourceResponse(null, 0, "Blocked", "");
                            break;
                    }
                }
                finally
                {
                    deferral.Complete();
                    tab.RemovePendingRequest(pending.Id);
                    Dispatcher.Invoke(UpdateInterceptStatusDisplay);
                }

                return;
            }
        }

        // Live Authz Shadow: replay state-changing requests to peers before the owner session sends them.
        var mockWouldFulfill = tab.HasMockRules
            && tab.FindMatchingMock(e.Request.Uri, e.Request.Method) != null;
        if (_liveAuthzShadow != null && e.Response == null && !mockWouldFulfill)
        {
            var pageUrl = tab.WebView.CoreWebView2?.Source ?? "";
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in e.Request.Headers)
                headers[h.Key] = h.Value;

            var outgoing = new LiveAuthzShadow.OutgoingAuthzRequest
            {
                Method = reqMethod,
                Url = e.Request.Uri,
                ResourceType = e.ResourceContext.ToString(),
                RequestHeaders = headers,
                RequestBody = tab.PeekRequestBody(reqMethod, e.Request.Uri),
                PageUrl = pageUrl,
                IsTrowserGenerated = false
            };

            if (!preserveMultipartStream
                && _liveAuthzShadow.TryBeginPeerFirstWrite(outgoing) is int slotId)
            {
                var authzDeferral = e.GetDeferral();
                try
                {
                    await _liveAuthzShadow.RunPeerFirstReplaysAsync(slotId);
                    tab.PushAuthzPeerFirstSlot(reqMethod, e.Request.Uri, slotId);
                }
                finally
                {
                    authzDeferral.Complete();
                }
            }
        }

        // 2. Mock rules (auto-respond)
        if (!tab.HasMockRules) return;

        if (e.Request.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            var preflight = tab.FindMockPreflightResponse(e.Request.Uri);
            if (preflight != null)
            {
                var preflightDeferral = e.GetDeferral();
                try
                {
                    preflight.EnsureDefaultCorsHeaders();
                    var corsHeaders = new Dictionary<string, string>(preflight.Headers, StringComparer.OrdinalIgnoreCase);
                    corsHeaders["Access-Control-Max-Age"] = "86400";
                    tab.CacheFulfilledResponse(e.Request.Method, e.Request.Uri,
                        new BrowserTab.FulfilledResponseMarker("mock-preflight", preflight.UrlPattern));
                    e.Response = BuildMockResponse(tab, 204, null, corsHeaders);
                }
                finally
                {
                    preflightDeferral.Complete();
                }

                return;
            }

            return;
        }

        var mock = tab.FindMatchingMock(e.Request.Uri, e.Request.Method);
        if (mock == null) return;

        var mockDeferral = e.GetDeferral();
        try
        {
            if (mock.DelayMs > 0)
                await Task.Delay(mock.DelayMs);

            tab.CacheResponseBody(e.Request.Method, e.Request.Uri, mock.Body);
            tab.CacheFulfilledResponse(e.Request.Method, e.Request.Uri,
                new BrowserTab.FulfilledResponseMarker("mock", mock.UrlPattern));
            e.Response = BuildMockResponse(tab, mock.StatusCode, mock.Body, mock.Headers);
        }
        finally
        {
            mockDeferral.Complete();
        }
    }

    private static void ApplySessionHeaderOverrides(
        CoreWebView2HttpRequestHeaders headers,
        Dictionary<string, string>? skipNames)
    {
        foreach (var ov in HeaderOverrideSettings.GetEnabled())
        {
            if (string.IsNullOrWhiteSpace(ov.Name) || ov.Name.StartsWith(':'))
                continue;
            if (skipNames != null && skipNames.ContainsKey(ov.Name))
                continue;
            try
            {
                if (headers.Contains(ov.Name))
                    headers.RemoveHeader(ov.Name);
                headers.SetHeader(ov.Name, ov.Value);
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"Header override '{ov.Name}' not applied: {ex.Message}");
            }
        }
    }

    private CoreWebView2WebResourceResponse BuildMockResponse(BrowserTab tab,
        int statusCode, string? body, Dictionary<string, string>? headers)
    {
        var bodyStream = body != null
            ? new MemoryStream(Encoding.UTF8.GetBytes(body))
            : (Stream?)null;

        var headerLines = headers?.Count > 0
            ? string.Join("\r\n", headers.Select(h => $"{h.Key}: {h.Value}"))
            : "";

        var reason = statusCode switch
        {
            200 => "OK", 201 => "Created", 204 => "No Content",
            301 => "Moved Permanently", 302 => "Found", 304 => "Not Modified",
            400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden",
            404 => "Not Found", 405 => "Method Not Allowed",
            429 => "Too Many Requests", 408 => "Request Timeout",
            500 => "Internal Server Error", 502 => "Bad Gateway",
            503 => "Service Unavailable", 504 => "Gateway Timeout",
            _ => "Mock Response"
        };

        return tab.WebView.CoreWebView2.Environment.CreateWebResourceResponse(
            bodyStream, statusCode, reason, headerLines);
    }

    private static async Task<string?> ReadStreamCapped(Stream stream, int maxBytes)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        var buffer = new char[8192];
        var sb = new StringBuilder(Math.Min(maxBytes, 4096));
        while (sb.Length < maxBytes)
        {
            var toRead = Math.Min(buffer.Length, maxBytes - sb.Length);
            var read = await reader.ReadAsync(buffer.AsMemory(0, toRead));
            if (read == 0) break;
            sb.Append(buffer, 0, read);
        }

        return sb.Length == 0 ? null : sb.ToString();
    }

    private static bool JsonTrue(System.Text.Json.JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var el) && el.ValueKind == System.Text.Json.JsonValueKind.True;

    /// <summary>
    /// WebView2 GetContentAsync() throws COM errors when the response stream is no longer
    /// accessible — typically during navigation (pipe closing) or for synthetic responses
    /// (class not registered). These are harmless; body capture is best-effort.
    /// </summary>
    private static bool IsTransientWebViewComError(Exception ex)
    {
        const int REGDB_E_CLASSNOTREG = unchecked((int)0x80040154);
        const int ERROR_NO_DATA       = unchecked((int)0x800700E8);
        const int E_HANDLE            = unchecked((int)0x80070006);
        const int E_UNEXPECTED        = unchecked((int)0x8000FFFF);

        for (var cur = ex; cur != null; cur = cur.InnerException)
        {
            if (cur.HResult is REGDB_E_CLASSNOTREG or ERROR_NO_DATA or E_HANDLE or E_UNEXPECTED)
                return true;
        }

        return false;
    }

    private static string GuessResourceType(string url, Dictionary<string, string> responseHeaders)
    {
        var contentType = "";
        if (responseHeaders.TryGetValue("Content-Type", out var ct))
            contentType = ct;
        else if (responseHeaders.TryGetValue("content-type", out var ct2))
            contentType = ct2;

        if (contentType.Contains("text/html")) return "Document";
        if (contentType.Contains("javascript")) return "Script";
        if (contentType.Contains("text/css")) return "Stylesheet";
        if (contentType.Contains("image/")) return "Image";
        if (contentType.Contains("font/") || contentType.Contains("woff")) return "Font";
        if (contentType.Contains("application/json")) return "Fetch";
        if (contentType.Contains("application/xml") || contentType.Contains("text/xml")) return "Fetch";
        if (contentType.Contains("text/event-stream")) return "Fetch";

        var path = url.Split('?')[0].Split('#')[0].ToLowerInvariant();
        if (path.EndsWith(".js")) return "Script";
        if (path.EndsWith(".css")) return "Stylesheet";
        if (path.EndsWith(".png") || path.EndsWith(".jpg") || path.EndsWith(".gif") ||
            path.EndsWith(".svg") || path.EndsWith(".webp") || path.EndsWith(".ico")) return "Image";
        if (path.EndsWith(".woff") || path.EndsWith(".woff2") || path.EndsWith(".ttf")) return "Font";
        if (path.EndsWith(".json")) return "Fetch";
        if (path.EndsWith(".html") || path.EndsWith(".htm")) return "Document";

        return "Other";
    }

    #endregion
}
