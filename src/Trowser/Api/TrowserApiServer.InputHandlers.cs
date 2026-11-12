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
    #region Keyboard Handler

    private async Task HandlePostKey(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var key = body.GetString("key");
        if (string.IsNullOrWhiteSpace(key))
        {
            await WriteError(response, 400, "Missing required field: key");
            return;
        }

        // Optional: target element by ref/selector/locator, or null for active element
        string? selector = null;
        string? staleWarning = null;
        if (body.HasProperty("ref") || body.HasProperty("selector") ||
            body.HasProperty("role") || body.HasProperty("label") ||
            body.HasProperty("getByText") || body.HasProperty("byText") || body.HasProperty("placeholder") || body.HasProperty("testId"))
        {
            var (resolved, error, warning) = ResolveSelector(body);
            if (resolved == null)
            {
                await WriteError(response, 400, error!);
                return;
            }
            selector = resolved;
            staleWarning = warning;
        }

        // Parse modifiers array
        string[]? modifiers = null;
        if (body.HasProperty("modifiers"))
        {
            var modArray = body.GetStringArray("modifiers");
            if (modArray != null)
                modifiers = modArray.ToArray();
        }

        var timeout = body.GetInt("timeout", 0);
        var before = await _context.CapturePageState();
        try
        {
            await _context.PressKey(key, selector, modifiers, timeout > 0 ? timeout : null);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }
        await Task.Delay(50);
        var after = await _context.CapturePageState();
        var changes = AutomationContext.DiffPageState(before, after);
        var active = await _context.GetActiveElementSummary();
        var targetLabel = selector
            ?? (active.TryGetValue("description", out var desc) ? desc?.ToString() : null)
            ?? "(active element)";

        await WriteSuccess(response, new
        {
            key,
            target = targetLabel,
            activeElement = active,
            modifiers = modifiers ?? Array.Empty<string>(),
            staleRefWarning = staleWarning,
            changes
        });
    }

    #endregion

    #region Cookie Handlers

    private async Task HandleGetCookies(HttpListenerRequest request, HttpListenerResponse response)
    {
        var cookies = await _context.GetCookies();
        var nameFilter = ApiQuery(request)["name"];
        var currentUrl = await _context.GetCurrentUrl();
        string? currentDomain = null;
        try { currentDomain = new Uri(currentUrl).Host; } catch { }

        if (!string.IsNullOrEmpty(nameFilter))
        {
            var match = cookies.FirstOrDefault(c => c["name"]?.ToString() == nameFilter);
            await WriteSuccess(response, match ?? (object?)null);
            return;
        }

        var allEmpty = cookies.Count > 0 && cookies.All(c =>
            c.TryGetValue("value", out var v) && (v == null || v.ToString() == ""));

        string? domainWarning = null;
        if (cookies.Count == 0 || allEmpty)
        {
            domainWarning = string.IsNullOrEmpty(currentDomain)
                ? "No cookies available for the current page."
                : $"No cookies in the jar for {currentDomain}. Log in or browse authenticated flows on this host, then retry.";
        }

        await WriteSuccess(response, new { count = cookies.Count, currentDomain, warning = domainWarning, cookies });
    }

    private async Task HandlePostCookieSet(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name");
        var value = body.GetString("value") ?? "";
        if (string.IsNullOrWhiteSpace(name))
        {
            await WriteError(response, 400, "Missing required field: name");
            return;
        }

        await _context.SetCookie(
            name, value,
            domain: body.GetString("domain"),
            path: body.GetString("path"),
            secure: body.HasProperty("secure") ? body.GetBool("secure") : null,
            httpOnly: body.HasProperty("httpOnly") ? body.GetBool("httpOnly") : null,
            sameSite: body.GetString("sameSite")
        );

        await WriteSuccess(response, new { set = name, value });
    }

    private async Task HandlePostCookieDelete(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name");
        if (string.IsNullOrWhiteSpace(name))
        {
            await WriteError(response, 400, "Missing required field: name");
            return;
        }

        await _context.DeleteCookie(name, body.GetString("domain"), body.GetString("path"));
        await WriteSuccess(response, new { deleted = name });
    }

    #endregion

    #region MCP Handler

    /// <summary>
    /// Per-request MCP pack from <c>?mode=</c> (preferred) or <c>X-Trowser-Mcp-Mode</c>.
    /// Invalid values are ignored (settings default applies).
    /// </summary>
    private static ExternalMcpMode? ResolveMcpModeOverride(HttpListenerRequest request)
    {
        var queryMode = request.QueryString["mode"];
        var fromQuery = McpClientConfig.TryParseMode(queryMode);
        if (fromQuery != null) return fromQuery;

        var header = request.Headers["X-Trowser-Mcp-Mode"];
        return McpClientConfig.TryParseMode(header);
    }

    /// <summary>
    /// Streamable HTTP: no standalone SSE stream and no client-driven session delete.
    /// Spec requires 405 (not 404) so clients stop probing.
    /// </summary>
    private static async Task HandleMcpMethodNotAllowed(HttpListenerResponse response)
    {
        response.StatusCode = 405;
        response.Headers["Allow"] = "POST, OPTIONS";
        response.ContentType = "application/json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(
            "{\"error\":\"SSE stream and session DELETE are not offered; use POST for JSON-RPC\"}");
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    /// <summary>
    /// Empty POST /mcp — accept as a no-op (Cursor occasionally sends these).
    /// </summary>
    private Task HandleMcpEmptyPost(HttpListenerResponse response)
    {
        response.Headers.Add("Mcp-Session-Id", _mcpHandler.SessionId);
        response.StatusCode = 202;
        response.Close();
        return Task.CompletedTask;
    }

    private async Task HandleMcp(HttpListenerRequest request, HttpListenerResponse response, string? bodyPreRead = null)
    {
        string body;
        if (!string.IsNullOrEmpty(bodyPreRead))
            body = bodyPreRead;
        else
        {
            using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            body = await reader.ReadToEndAsync();
        }

        if (string.IsNullOrWhiteSpace(body))
        {
            // True empty probes → 202. A request that claimed a body but yielded none is an
            // error (e.g. lost pre-read), not a Streamable HTTP no-op — never 202 here.
            if (request.ContentLength64 > 0)
            {
                response.Headers.Add("Mcp-Session-Id", _mcpHandler.SessionId);
                response.StatusCode = 200;
                response.ContentType = "application/json; charset=utf-8";
                response.ContentEncoding = Encoding.UTF8;
                var err = Encoding.UTF8.GetBytes(
                    "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error: empty request body\"}}");
                response.ContentLength64 = err.Length;
                await response.OutputStream.WriteAsync(err);
                response.Close();
                return;
            }

            await HandleMcpEmptyPost(response);
            return;
        }

        var modeOverride = ResolveMcpModeOverride(request);
        var (responseJson, isNotification) = await _mcpHandler.HandleAsync(body, modeOverride);

        // MCP session header
        response.Headers.Add("Mcp-Session-Id", _mcpHandler.SessionId);

        // Notifications (no id) may omit a body with 202. A JSON-RPC *request* must never
        // get an empty 202 — Cursor treats that as hang → MCP -32001 timeout.
        if (isNotification)
        {
            response.StatusCode = 202;
            response.Close();
            return;
        }

        if (responseJson == null)
        {
            response.StatusCode = 200;
            response.ContentType = "application/json; charset=utf-8";
            response.ContentEncoding = Encoding.UTF8;
            var err = Encoding.UTF8.GetBytes(
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error: empty MCP response\"}}");
            response.ContentLength64 = err.Length;
            await response.OutputStream.WriteAsync(err);
            response.Close();
            return;
        }

        response.StatusCode = 200;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentEncoding = Encoding.UTF8;
        var bytes = Encoding.UTF8.GetBytes(responseJson);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    #endregion

    #region Viewport Handlers

    private async Task HandleGetViewport(HttpListenerResponse response)
    {
        var (width, height) = await _context.GetViewportSize();
        var isOverridden = _context.ViewportOverride.HasValue;
        await WriteSuccess(response, new
        {
            width,
            height,
            isOverridden,
            presets = AutomationContext.ViewportPresets
                .Select(p => new { name = p.Key, width = p.Value.Width, height = p.Value.Height })
                .ToList()
        });
    }

    private async Task HandlePostViewport(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var preset = body.GetString("preset");
        if (!string.IsNullOrWhiteSpace(preset))
        {
            try
            {
                await _context.SetViewport(preset);
            }
            catch (ArgumentException ex)
            {
                await WriteError(response, 400, ex.Message);
                return;
            }
            var (w, h) = await _context.GetViewportSize();
            await WriteSuccess(response, new
            {
                preset,
                width = w,
                height = h,
                isOverridden = _context.ViewportOverride.HasValue
            });
            return;
        }

        var width = body.GetInt("width", 0);
        var height = body.GetInt("height", 0);

        if (width > 0 && height > 0)
        {
            try
            {
                await _context.SetViewport(width, height);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                await WriteError(response, 400, ex.Message);
                return;
            }
            var (w, h) = await _context.GetViewportSize();
            await WriteSuccess(response, new { width = w, height = h, isOverridden = true });
            return;
        }

        await WriteError(response, 400,
            "Provide 'width' and 'height' (pixels), or 'preset' (SmallPhone, BigPhone, LandscapePhone, SmallPad, BigPad, Desktop, BigDesktop).");
    }

    #endregion

    #region Screen Curtain Handlers

    private async Task HandleGetScreenCurtain(HttpListenerResponse response)
    {
        await WriteSuccess(response, new { enabled = _context.ScreenCurtainEnabled });
    }

    private async Task HandlePostScreenCurtain(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        bool enabled;
        if (body.HasProperty("toggle") && body.GetBool("toggle"))
        {
            enabled = await _context.ToggleScreenCurtain();
        }
        else if (body.HasProperty("enabled"))
        {
            enabled = await _context.SetScreenCurtain(body.GetBool("enabled"));
        }
        else
        {
            await WriteError(response, 400, "Provide 'enabled' (bool) or 'toggle': true.");
            return;
        }

        await WriteSuccess(response, new { enabled });
    }

    #endregion

    #region Tab Handlers

    private async Task HandleGetTabs(HttpListenerResponse response)
    {
        var tabs = _context.GetTabs();
        await WriteSuccess(response, new
        {
            count = tabs.Count,
            activeTab = _context.GetActiveTabIndex(),
            tabs = tabs.Select(t => new
            {
                index = t.Index,
                id = t.Id,
                title = t.Title,
                url = t.Url,
                isActive = t.IsActive,
                owner = t.Owner,
                networkEntryCount = t.NetworkEntryCount,
                consoleEntryCount = t.ConsoleEntryCount
            }).ToList(),
            tabOwnershipWarning = _context.LastTabOwnershipWarning
        });
    }

    private async Task HandlePostNewTab(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var url = body.GetString("url");
        var owner = body.GetString("owner") ?? TabOwners.Agent;

        try
        {
            var tabIndex = await _context.NewTab(url, owner);
            var tabs = _context.GetTabs();
            var newTab = tabs.FirstOrDefault(t => t.Index == tabIndex);
            await WriteSuccess(response, new
            {
                tabIndex,
                id = newTab?.Id ?? 0,
                title = newTab?.Title ?? "",
                url = newTab?.Url ?? url ?? "",
                owner = newTab?.Owner ?? owner,
                totalTabs = _context.GetTabCount()
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, $"Failed to create tab: {ex.Message}");
        }
    }

    private async Task HandlePostCloseTab(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.HasProperty("tabIndex") && !body.HasProperty("index"))
        {
            await WriteError(response, 400, "Missing required field: tabIndex");
            return;
        }

        var tabIndex = body.HasProperty("tabIndex")
            ? body.GetInt("tabIndex", -1)
            : body.GetInt("index", -1);

        try
        {
            await _context.CloseTab(tabIndex);
            await WriteSuccess(response, new
            {
                closed = tabIndex,
                activeTab = _context.GetActiveTabIndex(),
                totalTabs = _context.GetTabCount()
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostSwitchTab(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.HasProperty("tabIndex"))
        {
            await WriteError(response, 400, "Missing required field: tabIndex");
            return;
        }

        var tabIndex = body.GetInt("tabIndex", -1);

        try
        {
            _context.SwitchTab(tabIndex);
            var tab = _context.ActiveTab;
            await WriteSuccess(response, new
            {
                activeTab = tabIndex,
                title = tab.Title,
                url = tab.Url,
                owner = tab.Owner
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    #endregion

    #region Dialog Handlers

    private async Task HandleGetDialog(HttpListenerResponse response)
    {
        var dialog = _context.GetDialogSnapshot();
        if (dialog == null)
        {
            await WriteSuccess(response, new { hasDialog = false });
            return;
        }

        await WriteSuccess(response, new
        {
            hasDialog = true,
            type = dialog.Type,
            message = dialog.Message,
            defaultValue = dialog.DefaultValue
        });
    }

    private async Task HandlePostDialogHandle(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var accept = body.GetBool("accept", true);
        var promptText = body.GetString("promptText");

        _context.SetDialogHandling(accept, promptText);
        await _context.TryApplyDialogConfigAsync();

        await WriteSuccess(response, new
        {
            accept,
            promptText,
            message = accept
                ? "Dialogs will be accepted" + (promptText != null ? $" with text \"{promptText}\"" : "")
                : "Dialogs will be dismissed",
            note = "Policy is stored in-memory and applies to native ScriptDialogOpening handlers even when JavaScript is frozen."
        });
    }

    #endregion

    #region WebMCP Handlers

    private async Task HandleGetWebMcp(HttpListenerResponse response)
    {
        var tools = await _context.GetWebMcpTools();
        await WriteSuccess(response, new
        {
            tools,
            count = tools.Count,
            detected = tools.Count > 0
        });
    }

    private async Task HandlePostWebMcpCall(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var toolName = body.GetString("tool");
        if (string.IsNullOrWhiteSpace(toolName))
        {
            await WriteError(response, 400, "Missing required field: tool (name of the WebMCP tool to call)");
            return;
        }

        var argsJson = body.GetRawJson("arguments");
        var result = await _context.CallWebMcpTool(toolName, argsJson);
        await WriteSuccess(response, result);
    }

    #endregion

    #region Mock Handlers

    private async Task HandleGetMocks(HttpListenerResponse response)
    {
        var rules = _context.GetMockRules();
        await WriteSuccess(response, new
        {
            count = rules.Count,
            rules = rules.Select(r => new
            {
                urlPattern = r.UrlPattern,
                method = r.Method,
                statusCode = r.StatusCode,
                body = r.Body?.Length > 200 ? r.Body[..200] + "..." : r.Body,
                headers = r.Headers,
                delayMs = r.DelayMs
            }).ToList()
        });
    }

    private async Task HandlePostMock(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var urlPattern = body.GetString("urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
        {
            await WriteError(response, 400, "Missing required field: urlPattern");
            return;
        }

        var statusCode = body.GetInt("status", 200);
        if (statusCode == 0) statusCode = body.GetInt("statusCode", 200);

        var delayMs = body.GetInt("delay", 0);
        if (delayMs == 0) delayMs = body.GetInt("delayMs", 0);

        var headers = body.GetStringDictionary("headers");

        _context.MockResponse(
            urlPattern,
            statusCode: statusCode,
            body: body.GetString("body"),
            method: body.GetString("method"),
            headers: headers,
            delayMs: delayMs
        );

        await WriteSuccess(response, new
        {
            mocked = urlPattern,
            statusCode,
            method = body.GetString("method"),
            delayMs,
            totalMocks = _context.GetMockRules().Count
        });
    }

    private async Task HandlePostMockRemove(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var urlPattern = body.GetString("urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
        {
            await WriteError(response, 400, "Missing required field: urlPattern");
            return;
        }

        var removed = _context.RemoveMock(urlPattern);
        if (!removed)
        {
            await WriteError(response, 404, $"No mock matched urlPattern: {urlPattern}");
            return;
        }

        await WriteSuccess(response, new { removed = true, urlPattern, totalMocks = _context.GetMockRules().Count });
    }

    #endregion

    #region Network Throttle Handlers

    private async Task HandleGetNetworkThrottle(HttpListenerResponse response)
    {
        var state = _context.ThrottleState;
        var presets = AutomationContext.GetThrottlePresets()
            .Select(p => new { name = p.Key, downloadKbps = p.Value.DownloadKbps, uploadKbps = p.Value.UploadKbps, latencyMs = p.Value.LatencyMs, offline = p.Value.Offline })
            .ToList();

        if (state == null)
        {
            await WriteSuccess(response, new { enabled = false, presets });
            return;
        }

        await WriteSuccess(response, new
        {
            enabled = true,
            downloadKbps = state.DownloadKbps,
            uploadKbps = state.UploadKbps,
            latencyMs = state.LatencyMs,
            offline = state.Offline,
            presets
        });
    }

    private async Task HandlePostNetworkThrottle(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var preset = body.GetString("preset");

        if (!string.IsNullOrWhiteSpace(preset))
        {
            await _context.SetNetworkThrottle(preset);
            var state = _context.ThrottleState!;
            await WriteSuccess(response, new
            {
                enabled = true,
                preset,
                downloadKbps = state.DownloadKbps,
                uploadKbps = state.UploadKbps,
                latencyMs = state.LatencyMs,
                offline = state.Offline
            });
            return;
        }

        var downloadKbps = body.GetDouble("downloadKbps", 0);
        var uploadKbps = body.GetDouble("uploadKbps", 0);
        var latencyMs = body.GetInt("latencyMs", 0);
        var offline = body.GetBool("offline", false);

        if (downloadKbps == 0 && uploadKbps == 0 && latencyMs == 0 && !offline)
        {
            await WriteError(response, 400, "Provide 'preset' (e.g. '3G', 'Slow3G', '4G', 'Offline') or custom values (downloadKbps, uploadKbps, latencyMs, offline).");
            return;
        }

        await _context.SetNetworkThrottle(downloadKbps, uploadKbps, latencyMs, offline);
        await WriteSuccess(response, new { enabled = true, downloadKbps, uploadKbps, latencyMs, offline });
    }

    private async Task HandleDeleteNetworkThrottle(HttpListenerResponse response)
    {
        await _context.ClearNetworkThrottle();
        await WriteSuccess(response, new { enabled = false, message = "Network throttling disabled." });
    }

    #endregion

    #region Wait-for-Network Handler

    private async Task HandlePostWaitForNetwork(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var urlPattern = body.GetString("urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
        {
            await WriteError(response, 400, "Missing required field: urlPattern (URL substring to match).");
            return;
        }

        var method = body.GetString("method");
        var status = body.HasProperty("status") ? (int?)body.GetInt("status", 0) : null;
        var timeout = body.GetInt("timeout", 10000);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var entry = await _context.WaitForRequest(urlPattern, method, status, timeout);
            sw.Stop();
            await WriteSuccess(response, new
            {
                matched = true,
                url = entry.Url,
                method = entry.Method,
                status = entry.StatusCode,
                resourceType = entry.ResourceType,
                elapsedMs = sw.ElapsedMilliseconds
            });
        }
        catch (TimeoutException)
        {
            sw.Stop();
            await WriteSuccess(response, new
            {
                matched = false,
                urlPattern,
                method = method,
                status = status,
                timeoutMs = timeout,
                elapsedMs = sw.ElapsedMilliseconds
            });
        }
    }

    #endregion

    #region Storage Handlers

    private async Task HandleGetStorage(HttpListenerRequest request, HttpListenerResponse response)
    {
        var qs = ApiQuery(request);
        var type = qs["type"] ?? "local";
        var key = qs["key"];
        int? tabTarget;
        try
        {
            int? tabIndexArg = null;
            if (int.TryParse(qs["tabIndex"], out var ti))
            {
                if (ti < 0)
                {
                    await WriteError(response, 400, "tabIndex must be >= 0 when provided.");
                    return;
                }

                tabIndexArg = ti;
            }

            tabTarget = _context.ResolveTabTarget(tabIndexArg, qs["urlMatch"]);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        try
        {
            await _context.InvokeOnTabAsync(tabTarget, async () =>
            {
                if (type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
                    || type.Equals("idb", StringComparison.OrdinalIgnoreCase))
                {
                    var db = qs["db"];
                    var store = qs["store"];
                    var limitStr = qs["limit"];
                    int? limit = int.TryParse(limitStr, out var lim) ? lim : null;
                    var snap = await _context.GetIndexedDb(db, store, limit);
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        var flat = await _context.GetIndexedDbFlat(db, store, limit);
                        flat.TryGetValue(key, out var value);
                        await WriteSuccess(response, new { type = "indexeddb", key, value, origin = snap.Origin });
                        return 0;
                    }

                    await WriteSuccess(response, new
                    {
                        type = "indexeddb",
                        origin = snap.Origin,
                        method = snap.Method,
                        truncated = snap.Truncated,
                        databaseCount = snap.DatabaseCount,
                        recordCount = snap.RecordCount,
                        databases = snap.Databases
                    });
                    return 0;
                }

                if (!string.IsNullOrWhiteSpace(key))
                {
                    var value = await _context.GetStorageItem(type, key);
                    await WriteSuccess(response, new { type, key, value });
                    return 0;
                }

                var entries = await _context.GetAllStorage(type);
                await WriteSuccess(response, new { type, count = entries.Count, entries });
                return 0;
            });
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostStorageSet(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var type = body.GetString("type") ?? "local";
        var key = body.GetString("key");
        var value = body.GetString("value");

        if (type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
            || type.Equals("idb", StringComparison.OrdinalIgnoreCase))
        {
            await WriteError(response, 400, "IndexedDB write via set is not supported. Use delete/clear for IndexedDB.");
            return;
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            await WriteError(response, 400, "Missing required field: key");
            return;
        }
        if (value == null)
        {
            await WriteError(response, 400, "Missing required field: value");
            return;
        }

        await _context.SetStorageItem(type, key, value);
        await WriteSuccess(response, new { type, key, value });
    }

    private async Task HandlePostStorageDelete(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var type = body.GetString("type") ?? "local";
        var key = body.GetString("key");
        var database = body.GetString("database") ?? body.GetString("db");
        var store = body.GetString("store");

        if (type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
            || type.Equals("idb", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(database) && !string.IsNullOrWhiteSpace(store))
            {
                await _context.ClearIndexedDbStore(database, store);
                await WriteSuccess(response, new { type = "indexeddb", database, store, message = $"Cleared store '{store}' in database '{database}'." });
                return;
            }
            if (!string.IsNullOrWhiteSpace(database) || !string.IsNullOrWhiteSpace(key))
            {
                var dbName = database ?? key!;
                await _context.DeleteIndexedDb(dbName);
                await WriteSuccess(response, new { type = "indexeddb", database = dbName, message = $"Deleted IndexedDB database '{dbName}'." });
                return;
            }
            await WriteError(response, 400, "For indexeddb delete, provide database (or key) and optional store.");
            return;
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            await WriteError(response, 400, "Missing required field: key");
            return;
        }

        await _context.DeleteStorageItem(type, key);
        await WriteSuccess(response, new { type, key, message = $"Key '{key}' removed from {type}Storage." });
    }

    private async Task HandlePostStorageClear(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var type = body.GetString("type") ?? "local";
        var database = body.GetString("database") ?? body.GetString("db");
        if (type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
            || type.Equals("idb", StringComparison.OrdinalIgnoreCase))
        {
            await _context.ClearIndexedDbAsync(database);
            await WriteSuccess(response, new { type = "indexeddb", database, message = string.IsNullOrEmpty(database) ? "All IndexedDB databases cleared." : $"IndexedDB databases matching '{database}' cleared." });
            return;
        }
        await _context.ClearStorage(type);
        await WriteSuccess(response, new { type, message = $"{type}Storage cleared." });
    }

    private async Task HandlePostMandelbrot(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var centerX = body.GetDouble("centerX", -0.5);
        var centerY = body.GetDouble("centerY", 0.0);
        var zoom = body.GetDouble("zoom", 1.0);
        var opacity = body.GetDouble("opacity", 0.6);
        var maxIterations = body.GetInt("maxIterations", 256);

        await _context.Mandelbrot(centerX, centerY, zoom, opacity, maxIterations);
        await WriteSuccess(response, new { message = "Mandelbrot rendered.", centerX, centerY, zoom, opacity, maxIterations });
    }

    #endregion
}
