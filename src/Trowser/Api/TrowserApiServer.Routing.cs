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
    #region Request Routing

    /// <summary>
    /// Validates the bearer API key in constant time. Returns true when <see cref="ApiKeyRequired"/>
    /// is off or the presented key matches. A required but empty key rejects everything.
    /// </summary>
    private bool IsApiKeyValid(HttpListenerRequest request)
    {
        if (!ApiKeyRequired)
            return true;
        if (string.IsNullOrEmpty(_apiKey))
            return false;

        var authHeader = request.Headers["Authorization"];
        var providedKey = authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true
            ? authHeader[7..].Trim()
            : null;
        if (providedKey == null)
            return false;

        var provided = Encoding.UTF8.GetBytes(providedKey);
        var expected = Encoding.UTF8.GetBytes(_apiKey);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(provided, expected);
    }

    /// <summary>
    /// True when the request's Host authority is a loopback name. Blocks DNS-rebinding, where a
    /// browser page on an attacker domain (rebound to 127.0.0.1) reaches the local API.
    /// </summary>
    private static bool IsAllowedApiHost(HttpListenerRequest request)
    {
        var host = request.UserHostName; // Host header, may include :port
        if (string.IsNullOrEmpty(host))
            return false;

        // Strip IPv6 brackets / port to get the bare host.
        string h = host;
        if (h.StartsWith("[", StringComparison.Ordinal))
        {
            var close = h.IndexOf(']');
            h = close > 0 ? h.Substring(1, close - 1) : h;
        }
        else
        {
            var colon = h.IndexOf(':');
            if (colon >= 0) h = h.Substring(0, colon);
        }

        return h.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || h == "127.0.0.1"
            || h == "::1";
    }

    /// <summary>True when <paramref name="origin"/> is a loopback origin (used to scope CORS reflection).</summary>
    private static bool IsLoopbackOrigin(string? origin)
    {
        if (string.IsNullOrEmpty(origin))
            return false;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            return false;
        return (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) && uri.IsLoopback;
    }

    /// <summary>
    /// True when the request was sent by a web page on a non-loopback origin. CORS only hides the
    /// response; a no-cors <c>text/plain</c> POST still executes, so such requests are refused
    /// outright. Non-browser clients (curl, MCP, scripts) send neither header.
    /// </summary>
    internal static bool IsCrossSiteBrowserRequest(string? origin, string? secFetchSite)
    {
        if (string.Equals(secFetchSite, "cross-site", StringComparison.OrdinalIgnoreCase))
            return true;
        // "null" comes from sandboxed iframes, data: URLs and file:// pages.
        return !string.IsNullOrEmpty(origin) && !IsLoopbackOrigin(origin);
    }

    private async Task HandleRequestAsync(HttpListenerContext httpContext)
    {
        var request = httpContext.Request;
        var response = httpContext.Response;

        // Defense-in-depth against DNS rebinding: the listener is loopback-only, but a rebound
        // DNS name (attacker.example -> 127.0.0.1) would arrive with a non-loopback Host header.
        // Reject anything whose Host authority isn't localhost/127.0.0.1/[::1]. This holds even
        // when the API key requirement is disabled.
        if (!IsAllowedApiHost(request))
        {
            response.StatusCode = 403;
            try { response.Close(); } catch { /* client gone */ }
            return;
        }

        // Drive-by requests from web pages (any browser on this machine). Also holds when the
        // API key requirement is disabled.
        var origin = request.Headers["Origin"];
        if (IsCrossSiteBrowserRequest(origin, request.Headers["Sec-Fetch-Site"]))
        {
            response.StatusCode = 403;
            try { response.Close(); } catch { /* client gone */ }
            return;
        }

        // CORS: only reflect loopback origins so a cross-origin web page cannot read API responses.
        response.Headers.Add("Access-Control-Allow-Origin", IsLoopbackOrigin(origin) ? origin! : "http://localhost");
        response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Trowser-Mirror");
        response.Headers.Add("Vary", "Origin");

        if (request.HttpMethod == "OPTIONS")
        {
            response.StatusCode = 204;
            response.Close();
            return;
        }

        var path = request.Url?.AbsolutePath?.TrimEnd('/') ?? "";
        var method = request.HttpMethod;
        var mcpBodyBuffered = false;

        // Health check responds immediately -- never waits for the gate or auth
        if (path == "/api/ping" && method == "GET")
        {
            var busyOp = _currentOperation;
            await WriteSuccess(response, BuildPingPayload());
            return;
        }

        // Abort bypasses the gate -- cancels the currently running operation
        if (path == "/api/abort" && method == "POST")
        {
            await HandlePostAbort(request, response);
            return;
        }

        // Force-navigate bypasses the gate — CDP terminate + Page.navigate recovers from frozen pages (DoS / infinite loops)
        if (path == "/api/force-navigate" && method == "POST")
        {
            await HandlePostForceNavigate(request, response);
            return;
        }

        // API key authentication
        if (!IsApiKeyValid(request))
        {
            await WriteError(response, 401, "Unauthorized -- provide API key via Authorization: Bearer <key> header.");
            return;
        }

        // Message display bypasses the gate -- no browser interaction needed
        if (path == "/api/message" && method == "POST")
        {
            await HandlePostMessage(request, response);
            return;
        }

        // Journal note submission bypasses the gate -- in-memory only, no browser interaction
        if (path == "/api/journal" && method == "POST")
        {
            await HandlePostJournal(request, response);
            return;
        }

        if (path == "/api/journal" && method == "PATCH")
        {
            await HandlePatchJournal(request, response);
            return;
        }

        if (path == "/api/journal" && method == "DELETE")
        {
            await HandleDeleteJournal(request, response);
            return;
        }

        if (path == "/api/journal/import" && method == "POST")
        {
            await HandlePostJournalImport(request, response);
            return;
        }

        if (path == "/api/session-memory" && (method == "GET" || method == "POST"))
        {
            if (method == "GET")
                await HandleGetSessionMemory(response);
            else
                await HandlePostSessionMemory(request, response);
            return;
        }

        // Streamable HTTP (2025-03-26): GET opens an optional SSE stream; servers that do not
        // offer one MUST return 405. DELETE terminates a session; we do not — also 405.
        // Returning 404 here makes Cursor/other clients retry and spam connect logs.
        if (path == "/mcp" && (method == "GET" || method == "DELETE"))
        {
            await HandleMcpMethodNotAllowed(response);
            return;
        }

        // Empty POST bodies: some clients probe/keepalive with no JSON. Treat as accepted no-op
        // (same as a notification) instead of -32700 Empty request body noise.
        if (path == "/mcp" && method == "POST" && request.ContentLength64 == 0)
        {
            await HandleMcpEmptyPost(response);
            return;
        }

        // MCP tools/call for browser_force_navigate bypasses the gate (same as POST /api/force-navigate)
        if (path == "/mcp" && method == "POST" && request.ContentLength64 > 0)
        {
            using var mcpReader = new StreamReader(request.InputStream, Encoding.UTF8);
            var mcpBody = await mcpReader.ReadToEndAsync();
            if (string.IsNullOrWhiteSpace(mcpBody))
            {
                await HandleMcpEmptyPost(response);
                return;
            }
            var mcpToolName = McpRoutingHelpers.TryGetToolsCallName(mcpBody);
            if (McpRoutingHelpers.BypassesGate(mcpToolName))
            {
                if (mcpToolName == "browser_force_navigate")
                    _mcpHandler.ForceNavigateBypassGate = true;
                try
                {
                    await HandleMcp(request, response, mcpBody);
                }
                finally
                {
                    _mcpHandler.ForceNavigateBypassGate = false;
                }
                return;
            }

            if (McpRoutingHelpers.IsGateFreeReadOnly(mcpToolName))
            {
                _preReadBody.Value = mcpBody;
                await HandleMcp(request, response, mcpBody);
                return;
            }

            _preReadBody.Value = mcpBody;
            mcpBodyBuffered = true;
        }

        // Safe mode runs before every early return below (gate-free routes included).
        // Passive oauth-flow-test reads the network log only, so its body decides.
        if (SafeMode && path == "/api/security/oauth-flow-test" && method == "POST"
            && !mcpBodyBuffered && _preReadBody.Value == null && request.ContentLength64 > 0)
        {
            using var oauthBodyReader = new StreamReader(request.InputStream, Encoding.UTF8);
            _preReadBody.Value = await oauthBodyReader.ReadToEndAsync();
        }

        if (SafeMode && SafeModePolicy.IsRouteBlocked(path, method, _preReadBody.Value))
        {
            await WriteError(response, 403,
                $"Blocked by safe mode: {method} {path}. Safe mode disables scripting, raw HTTP, mocks, session manipulation and active security probes.");
            return;
        }

        // Read-only endpoints that only access in-memory data bypass the gate.
        // This lets passive observers (LLM coaches, scanners) poll without blocking
        // or being blocked by browser-touching operations.
        if (IsGateFreeReadOnly(path, method))
        {
            try
            {
                await RouteRequestAsync(path, method, request, response);
            }
            catch (ApiCommandException ex)
            {
                await WriteError(response, ex);
            }
            return;
        }

        // Dialog endpoints bypass the gate — policy is in-memory; GET uses LastDialog without RunJs.
        if (path is "/api/dialog" or "/api/dialog/handle" or "/api/dialog/dismiss")
        {
            try
            {
                switch (path)
                {
                    case "/api/dialog" when method == "GET":
                        await HandleGetDialog(response);
                        break;
                    case "/api/dialog/handle" when method == "POST":
                        await HandlePostDialogHandle(request, response);
                        break;
                    case "/api/dialog/dismiss" when method == "POST":
                        _context.ClearDialogSnapshot();
                        await WriteSuccess(response, new { message = "Last dialog cleared." });
                        break;
                    default:
                        await WriteError(response, 404, $"Unknown path: {path}");
                        break;
                }
            }
            catch (ApiCommandException ex)
            {
                await WriteError(response, ex);
            }
            return;
        }

        // Serialize all operations through the gate (one at a time for browser safety).
        // MCP tools/call waits like REST (up to 60s); on timeout return JSON-RPC busy, never empty 202.
        SemaphoreSlim gateLease;
        lock (_gateLock)
            gateLease = _gate;

        if (!await gateLease.WaitAsync(GateWaitTimeout(path, method)))
        {
            if (path == "/mcp")
                await WriteMcpBusyError(response);
            else
                await WriteBusyError(response, path);
            return;
        }

        lock (_gateLock)
            _activeGateLease = gateLease;

        var cts = new CancellationTokenSource();
        ApiClientDisconnect.Link(httpContext, cts);
        _operationCts = cts;
        _currentOperation = $"{method} {path}";
        _context.OperationCancellation = cts.Token;
        if (_sessionLogger != null) _sessionLogger.SuppressGuiActions = true;
        MirrorController?.BeginApiSuppress();

        // Pre-read request body so we can log it and still pass it to the handler.
        // Body is stored in AsyncLocal so a waiter that buffered before the gate keeps its
        // own payload when the previous holder's finally runs (shared-field race → empty MCP 202).
        if (!mcpBodyBuffered)
            _preReadBody.Value = null;
        if (method == "POST" && request.ContentLength64 > 0)
        {
            if (!mcpBodyBuffered)
            {
                // Use UTF-8 for JSON bodies (RFC 8259) instead of request.ContentEncoding which
                // may default to the system codepage when clients omit charset in Content-Type.
                using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
                _preReadBody.Value = await reader.ReadToEndAsync();
            }
        }
        // Mirror-mode forwards replay the tester's GUI on the peer's current tab.
        // Treating them as agent automation opens a new A-tab on the peer.
        var isMirror = IsMirrorForward(request);
        _context.IsAgentAutomation = !isMirror;
        LogApiActionFromBody(method, path, _preReadBody.Value);
        if (!isMirror && ShouldPreferAgentTab(path, method) && !RequestSpecifiesExplicitTab(_preReadBody.Value))
        {
            var warn = await _context.EnsureAgentTabAsync();
            if (!string.IsNullOrEmpty(warn))
                OnShowMessage?.Invoke(warn, "info", 4000);
        }

        // Capture the actual HTTP requests a security scan issues when the caller opts in with
        // {"verbose": true}. WriteSuccess attaches the captured trace to the JSON response.
        using var traceScope = IsTraceableSecurityPath(path) && BodyRequestsVerbose(_preReadBody.Value)
            ? _context.BeginRequestTrace()
            : null;

        try
        {
            await RouteRequestAsync(path, method, request, response);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            await WriteError(response, 499, $"Operation '{method} {path}' was aborted via POST /api/abort.");
            _sessionLogger?.LogApiAction(method, path, isError: true, errorMessage: "Aborted");
        }
        catch (TimeoutException ex)
        {
            await WriteError(response, 504, ex.Message);
            _sessionLogger?.LogApiAction(method, path, isError: true, errorMessage: ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
            _sessionLogger?.LogApiAction(method, path, isError: true, errorMessage: ex.Message);
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex);
            _sessionLogger?.LogApiAction(method, path, isError: true, errorMessage: ex.Message);
        }
        finally
        {
            _context.IsAgentAutomation = false;
            if (_sessionLogger != null) _sessionLogger.SuppressGuiActions = false;
            MirrorController?.EndApiSuppress();
            _preReadBody.Value = null;
            _currentOperation = null;
            _operationCts = null;
            _context.OperationCancellation = CancellationToken.None;
            cts.Dispose();
            gateLease.Release();
            lock (_gateLock)
            {
                if (_activeGateLease == gateLease)
                    _activeGateLease = null;
            }
        }
    }

    private static bool RequestSpecifiesExplicitTab(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            var root = doc.RootElement;
            if (root.TryGetProperty("tabIndex", out var ti) && ti.ValueKind == JsonValueKind.Number)
                return true;

            if (root.TryGetProperty("urlMatch", out var um)
                && um.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(um.GetString()))
                return true;
        }
        catch
        {
            // ignore malformed bodies
        }

        return false;
    }

    private static bool ShouldPreferAgentTab(string path, string method)
    {
        if (method != "POST") return false;
        return path is
            "/api/navigate" or
            "/api/go-back" or
            "/api/go-forward" or
            "/api/force-navigate" or
            "/api/click" or
            "/api/click-at" or
            "/api/type" or
            "/api/hover" or
            "/api/scroll" or
            "/api/select" or
            "/api/key" or
            "/api/upload" or
            "/api/drag" or
            "/api/execute-js" or
            "/api/execute-script";
    }

    /// <summary>
    /// Force-cancels the currently running operation and returns the server to idle.
    /// Bypasses the gate (like /api/ping) so it can be called even when the server is busy.
    /// </summary>
    private async Task HandlePostAbort(HttpListenerRequest request, HttpListenerResponse response)
    {
        // Auth check -- abort requires authentication like any other endpoint
        if (!IsApiKeyValid(request))
        {
            await WriteError(response, 401, "Unauthorized -- provide API key via Authorization: Bearer <key> header.");
            return;
        }

        await WriteSuccess(response, await BuildAbortOperationAsync());
    }

    /// <summary>Shared abort payload for REST and MCP <c>browser_abort</c>.</summary>
    internal async Task<object> BuildAbortOperationAsync()
    {
        var cts = _operationCts;
        var op = _currentOperation;

        if (cts == null || op == null)
        {
            return new
            {
                aborted = (string?)null,
                message = "No operation in progress. Server is already idle."
            };
        }

        cts.Cancel();
        _context.TryTerminatePageScriptsForAbort();

        var (released, forceReset) = await CancelAndTryReleaseGateAsync(op);
        return new
        {
            aborted = op,
            gateForceReset = forceReset,
            message = released
                ? "Operation cancelled. Server is now idle."
                : forceReset
                    ? "Operation did not exit in time; API gate was forcibly reset so new calls can proceed. " +
                      "The UI thread may still be busy — use POST /api/force-navigate if the page is frozen."
                    : "Cancellation signal sent. The operation may take a moment to stop."
        };
    }

    internal object BuildPingPayload() => new
    {
        alive = true,
        port = _port,
        busy = _currentOperation != null,
        currentOperation = SanitizePingOperation(_currentOperation),
        note = "Unauthenticated health check; no browser page state is included."
    };

    private static string? SanitizePingOperation(string? operation)
    {
        if (string.IsNullOrEmpty(operation))
            return null;
        var q = operation.IndexOf('?', StringComparison.Ordinal);
        return q >= 0 ? operation[..q] : operation;
    }

    /// <summary>
    /// CDP-based navigation that bypasses a frozen page JS context. Cancels any in-flight gated operation
    /// so the session can continue after recovery (same idea as <see cref="HandlePostAbort"/>).
    /// </summary>
    private async Task HandlePostForceNavigate(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (!IsApiKeyValid(request))
        {
            await WriteError(response, 401, "Unauthorized -- provide API key via Authorization: Bearer <key> header.");
            return;
        }

        var body = await ReadJsonBody(request);
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Provide \"url\" (e.g. \"about:blank\"). Optional: \"terminateScripts\": true (default).");
            return;
        }

        var terminateScripts = body.HasProperty("terminateScripts")
            ? body.GetBool("terminateScripts", true)
            : true;

        try
        {
            await _context.ForceNavigateAsync(url.Trim(), terminateScripts);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }
        catch (TimeoutException ex)
        {
            await WriteError(response, 504, ex.Message);
            return;
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, ex.Message);
            return;
        }

        var hadOp = _currentOperation;
        var (released, forceReset) = await CancelAndTryReleaseGateAsync(hadOp);

        var after = await _context.CapturePageState();
        await WriteSuccess(response, new
        {
            url = after.Url,
            title = after.Title,
            cancelledStuckOperation = hadOp != null,
            gateForceReset = forceReset,
            message = released
                ? "Page recovered. Server gate is idle."
                : forceReset
                    ? "Navigation completed; API gate was forcibly reset so new calls can proceed."
                    : "Navigation completed; a previous operation may still be releasing the gate."
        });
    }

    /// <summary>
    /// Cancel any in-flight gated operation and resynchronize the semaphore after CDP force navigation
    /// (used by <see cref="HandlePostForceNavigate"/> and MCP <c>browser_force_navigate</c> when bypassing the gate).
    /// </summary>
    private Task<(bool released, bool forceReset)> TryRecoverGateAfterForceNavigateAsync()
    {
        var op = _currentOperation;
        if (_operationCts != null)
            _operationCts.Cancel();
        return CancelAndTryReleaseGateAsync(op);
    }

    /// <summary>
    /// Wait for the active gated operation to release its lease; if it does not, orphan the lease and swap in a fresh gate.
    /// </summary>
    private async Task<(bool released, bool forceReset)> CancelAndTryReleaseGateAsync(string? expectedOperation)
    {
        SemaphoreSlim? held;
        lock (_gateLock)
            held = _activeGateLease;

        if (held != null)
        {
            var acquired = await held.WaitAsync(TimeSpan.FromSeconds(5));
            if (acquired)
            {
                held.Release();
                return (true, false);
            }
        }
        else
        {
            SemaphoreSlim gate;
            lock (_gateLock)
                gate = _gate;
            var acquired = await gate.WaitAsync(TimeSpan.FromSeconds(5));
            if (acquired)
            {
                gate.Release();
                return (true, false);
            }
        }

        var forceReset = ForceResetGateIfStillBlocked(expectedOperation);
        return (forceReset, forceReset);
    }

    /// <summary>
    /// When a gated handler never reaches its <c>finally</c>, clear busy state and replace the gate so new API calls are not blocked forever.
    /// </summary>
    private bool ForceResetGateIfStillBlocked(string? expectedOperation)
    {
        lock (_gateLock)
        {
            if (expectedOperation != null && _currentOperation != expectedOperation)
                return _currentOperation == null;

            _operationCts?.Cancel();
            _operationCts = null;
            _currentOperation = null;
            _context.OperationCancellation = CancellationToken.None;
            _activeGateLease = null;
            _gate = new SemaphoreSlim(1, 1);
            return true;
        }
    }

    /// <summary>True when the JSON-RPC body is <c>tools/call</c> for <c>browser_force_navigate</c>.</summary>
    private static bool IsMcpToolsCallForceNavigate(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("method", out var m) &&
                m.ValueKind == JsonValueKind.String &&
                m.GetString() == "tools/call" &&
                root.TryGetProperty("params", out var p) &&
                p.TryGetProperty("name", out var n) &&
                n.ValueKind == JsonValueKind.String &&
                n.GetString() == "browser_force_navigate")
                return true;
        }
        catch { /* invalid JSON */ }

        return false;
    }

    /// <summary>
    /// JSON-RPC busy response for <c>POST /mcp</c> when the gate wait times out.
    /// Prefer this over REST 503 / empty 202 so MCP clients (Cursor) surface an actionable error.
    /// </summary>
    private async Task WriteMcpBusyError(HttpListenerResponse response)
    {
        var blockedBy = _currentOperation ?? "unknown";
        object? id = null;
        try
        {
            var body = _preReadBody.Value;
            if (!string.IsNullOrWhiteSpace(body))
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("id", out var idEl))
                {
                    id = idEl.ValueKind switch
                    {
                        JsonValueKind.Number when idEl.TryGetInt64(out var n) => n,
                        JsonValueKind.String => idEl.GetString(),
                        _ => null
                    };
                }
            }
        }
        catch { /* keep id null */ }

        response.Headers.Add("Mcp-Session-Id", _mcpHandler.SessionId);
        response.StatusCode = 200;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentEncoding = Encoding.UTF8;
        var message =
            $"Server busy — blocked by: {blockedBy}. Retry after the current operation finishes, " +
            "or call MCP browser_abort (or POST /api/abort). " +
            "Read-only polls (browser_console, browser_network, browser_journal_get, browser_ping) bypass the gate. " +
            "Parallel browser-touching MCP calls are serialized.";
        var payload = JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id,
            error = new
            {
                code = -32000,
                message,
                data = new { busy = true, blockedBy, mcpAbortTool = "browser_abort", restAbort = "POST /api/abort" }
            }
        });
        var bytes = Encoding.UTF8.GetBytes(payload);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    /// <summary>
    /// Writes a detailed 503 error when the gate times out, including what operation is
    /// blocking and whether a JavaScript dialog is pending.
    /// </summary>
    private async Task WriteBusyError(HttpListenerResponse response, string requestedPath)
    {
        var blockedBy = _currentOperation ?? "unknown";

        DialogInfo? lastDialog = null;
        var nativeDialogOpen = false;
        try
        {
            var tab = _context.ActiveTab;
            lastDialog = tab?.LastDialog;
            nativeDialogOpen = tab?.NativeScriptDialogOpen ?? false;
        }
        catch (Exception ex) { TrowserLog.Warn($"Could not read dialog state: {ex.Message}"); }

        var likelyFrozenJs = blockedBy.Contains("execute-js", StringComparison.OrdinalIgnoreCase)
                             || blockedBy.Contains("execute-script", StringComparison.OrdinalIgnoreCase);

        var error = new Dictionary<string, object?>
        {
            ["success"] = false,
            ["error"] = nativeDialogOpen
                ? "Server busy — a native script dialog is being dismissed. Retry shortly."
                : likelyFrozenJs
                    ? $"Server busy — blocked by: {blockedBy}. The page JavaScript context may be frozen (e.g. uncaught native dialog before hooks ran)."
                    : $"Server busy -- blocked by: {blockedBy}. " +
                      "The browser page may be running long synchronous JavaScript.",
            ["blockedBy"] = blockedBy,
            ["requestedPath"] = requestedPath
        };

        if (nativeDialogOpen)
        {
            error["nativeDialogOpen"] = true;
            if (lastDialog != null)
            {
                error["dialogType"] = lastDialog.Type;
                error["dialogMessage"] = lastDialog.Message;
            }
        }
        else if (lastDialog != null)
        {
            error["lastDialogType"] = lastDialog.Type;
            error["lastDialogMessage"] = lastDialog.Message;
        }

        if (nativeDialogOpen)
        {
            error["hint"] =
                "POST /api/dialog/handle (gate-free) sets accept/dismiss policy for native dialogs. " +
                "If the server stays busy, use POST /api/force-navigate to recover a frozen page.";
        }
        else if (likelyFrozenJs)
        {
            error["hint"] =
                "Try POST /api/force-navigate with {\"url\": \"about:blank\"} to terminate stuck scripts (bypasses the gate). " +
                "Then POST /api/abort if needed. POST /api/dialog/handle only sets future dialog policy; " +
                "POST /api/dialog/dismiss clears the last dialog record.";
        }
        else
        {
            error["hint"] =
                "Call POST /api/abort to cancel the stuck operation. " +
                "If the page is frozen, use POST /api/force-navigate. " +
                "POST /api/dialog/handle configures the next dialog (gate-free).";
        }

        await WriteJsonResponse(response, 503, error);
    }

    private async Task RouteRequestAsync(
        string path, string method,
        HttpListenerRequest request, HttpListenerResponse response)
    {
        var applyPacing = !IsGateFreeReadOnly(path, method);
        if (applyPacing)
            await WaitForRequestPacingAsync(path, _context.OperationCancellation);
        try
        {
        switch (path)
        {
            // Informational (ping handled before the gate in HandleRequestAsync)
            case "/api/info" when method == "GET":
                await HandleGetInfo(response);
                break;

            case "" or "/" or "/api" when method == "GET":
                await HandleGetHelp(response);
                break;

            // Page state (read-only)
            case "/api/state" when method == "GET":
                await HandleGetState(request, response);
                break;

            case "/api/frames" when method == "GET":
                await HandleGetFrames(response);
                break;

            case "/api/screenshot/compare" when method == "POST":
                await HandleCompareScreenshots(request, response);
                break;

            case "/api/screenshot" when method == "GET":
                await HandleGetScreenshot(request, response);
                break;

            case "/api/console" when method == "GET":
                await HandleGetConsole(request, response);
                break;

            // Pointers & checkpoints (the pointer primitive). Reads are gate-free (in-memory).
            case "/api/pointer" when method == "POST":
                await RespondAsync(request, response, BuildPointerCreateAsync);
                break;

            case "/api/pointers" when method == "GET":
                await HandleGetPointers(request, response);
                break;

            case "/api/checkpoint" when method == "POST":
                await RespondAsync(request, response, BuildCheckpointCreateAsync);
                break;

            case "/api/checkpoints" when method == "GET":
                await HandleGetCheckpoints(response);
                break;

            // Decisions (agent asks the human to make a call). In-memory, so gate-free.
            case "/api/decision" when method == "POST":
                await RespondAsync(request, response, BuildDecisionAskAsync);
                break;

            case "/api/decisions" when method == "GET":
                await HandleGetDecisions(request, response);
                break;

            case "/api/console/clear" when method == "POST":
                _context.ClearConsoleLog();
                await WriteSuccess(response, new { message = "Console log cleared." });
                break;

            case "/api/network" when method == "GET":
                await HandleGetNetwork(request, response);
                break;

            case "/api/network/har" when method == "GET":
                await HandleGetNetworkHar(request, response);
                break;

            case "/api/network/clear" when method == "POST":
                _context.ClearNetworkLog();
                await WriteSuccess(response, new { message = "Network log cleared." });
                break;

            case "/api/downloads" when method == "GET":
                await HandleGetDownloads(response);
                break;

            case "/api/downloads/wait" when method == "POST":
                await HandlePostDownloadsWait(request, response);
                break;

            case "/api/downloads/assert" when method == "POST":
                await HandlePostDownloadsAssert(request, response);
                break;

            case "/api/downloads/clear" when method == "POST":
                await HandlePostDownloadsClear(request, response);
                break;

            case "/api/clear-all" when method == "POST":
                await HandlePostClearAll(request, response);
                break;

            case "/api/clear-session" when method == "POST":
                await HandlePostClearSession(request, response);
                break;

            case "/api/assertions" when method == "GET":
                await HandleGetAssertions(response);
                break;

            case "/api/interactive" when method == "GET":
                await HandleGetInteractive(request, response);
                break;

            case "/api/page-text" when method == "GET":
                await HandleGetPageText(response);
                break;

            case "/api/page-text/all" when method == "GET":
                await HandleGetAllPageText(response);
                break;

            case "/api/page-text/screen-reader" when method == "GET":
                await HandleGetScreenReaderTexts(response);
                break;

            case "/api/source" when method == "GET":
                await HandleGetSource(response);
                break;

            // Actions (mutations)
            case "/api/navigate" when method == "POST":
                await HandlePostNavigate(request, response);
                break;

            case "/api/go-back" when method == "POST":
                await HandlePostGoBack(request, response);
                break;

            case "/api/go-forward" when method == "POST":
                await HandlePostGoForward(request, response);
                break;

            case "/api/click" when method == "POST":
                await HandlePostClick(request, response);
                break;

            case "/api/click-at" when method == "POST":
                await HandlePostClickAt(request, response);
                break;

            case "/api/drag" when method == "POST":
                await HandlePostDrag(request, response);
                break;

            case "/api/type" when method == "POST":
                await HandlePostType(request, response);
                break;

            case "/api/select" when method == "POST":
                await HandlePostSelect(request, response);
                break;

            case "/api/execute-js" when method == "POST":
                await HandlePostExecuteJs(request, response);
                break;

            case "/api/execute-script" when method == "POST":
                await HandlePostExecuteScript(request, response);
                break;

            case "/api/record/start" when method == "POST":
                await HandlePostRecordStart(request, response);
                break;

            case "/api/record/status" when method == "GET":
                await HandleGetRecordStatus(request, response);
                break;

            case "/api/record/stop" when method == "POST":
                await HandlePostRecordStop(request, response);
                break;

            case "/api/wait" when method == "POST":
                await HandlePostWait(request, response);
                break;

            case "/api/text" when method == "POST":
            case "/api/extract-text" when method == "POST":
                await HandlePostText(request, response);
                break;

            case "/api/attribute" when method == "POST":
                await HandlePostAttribute(request, response);
                break;

            case "/api/property" when method == "POST":
                await HandlePostProperty(request, response);
                break;

            case "/api/extract" when method == "POST":
                await HandlePostExtract(request, response);
                break;

            case "/api/find" when method == "POST":
                await HandlePostFind(request, response);
                break;

            case "/api/find/clear" when method == "POST":
                await _context.ClearFindHighlights();
                await WriteSuccess(response, new { message = "Find highlights cleared." });
                break;

            case "/api/hover" when method == "POST":
                await HandlePostHover(request, response);
                break;

            case "/api/scroll" when method == "POST":
                await HandlePostScroll(request, response);
                break;

            case "/api/accessibility" when method == "POST":
                await HandlePostAccessibility(request, response);
                break;

            case "/api/tab-order" when method == "POST":
                await HandlePostTabOrder(request, response);
                break;

            case "/api/performance" when method == "POST":
                await HandlePostPerformance(request, response);
                break;

            case "/api/resource/snapshot" when method == "POST":
                await HandlePostResourceSnapshot(request, response);
                break;

            case "/api/resource/compare" when method == "POST":
                await HandlePostResourceCompare(request, response);
                break;

            case "/api/resource/probe" when method == "POST":
                await HandlePostResourceProbe(request, response);
                break;

            case "/api/security" when method == "POST":
                await HandlePostSecurity(request, response);
                break;

            case "/api/security/js-libraries" when method == "POST":
                await HandlePostSecurityJsLibraries(request, response);
                break;

            case "/api/security/headers" when method == "POST":
                await HandlePostSecurityHeaders(request, response);
                break;

            case "/api/security/cors" when method == "POST":
                await HandlePostSecurityCors(request, response);
                break;

            case "/api/security/forced-error-scan" when method == "POST":
                await HandlePostSecurityForcedErrorScan(request, response);
                break;

            case "/api/security/trusted-header-bypass" when method == "POST":
                await HandlePostSecurityTrustedHeaderBypass(request, response);
                break;

            case "/api/security/default-credential-canary" when method == "POST":
                await HandlePostSecurityDefaultCredentialCanary(request, response);
                break;

            case "/api/security/discover" when method == "POST":
                await HandlePostSecurityDiscover(request, response);
                break;

            case "/api/security/attack-surface" when method == "POST":
                await HandlePostSecurityAttackSurface(request, response);
                break;

            case "/api/security/api-inventory" when method == "POST":
                await HandlePostSecurityApiInventory(request, response);
                break;

            case "/api/security/clickjack-test" when method == "POST":
                await HandlePostSecurityClickjackTest(request, response);
                break;

            case "/api/security/crawl-light" when method == "POST":
                await HandlePostSecurityCrawlLight(request, response);
                break;

            case "/api/validate-html" when method == "POST":
                await HandlePostValidateHtml(request, response);
                break;

            case "/api/seo" when method == "POST":
                await HandlePostSeo(request, response);
                break;

            case "/api/compatibility" when method == "POST":
                await HandlePostCompatibility(request, response);
                break;

            case "/api/audit-all" when method == "POST":
            case "/api/quicktest" when method == "POST":
                await HandlePostAuditAll(request, response);
                break;

            case "/api/surpriseme" when method == "POST":
                await HandlePostSurpriseMe(request, response);
                break;

            case "/api/check-links" when method == "POST":
                await HandlePostCheckLinks(request, response);
                break;

            case "/api/security/xss" when method == "POST":
                await HandlePostSecurityXss(request, response);
                break;

            case "/api/security/mixed-content" when method == "POST":
                await HandlePostMixedContent(request, response);
                break;

            case "/api/security/cookies" when method == "POST":
                await HandlePostCookieAudit(request, response);
                break;

            case "/api/security/session-id" when method == "POST":
                await HandlePostSessionIdAnalysis(request, response);
                break;

            case "/api/security/reset-token" when method == "POST":
                await HandlePostResetTokenAnalysis(request, response);
                break;

            case "/api/security/token-entropy" when method == "POST":
                await HandlePostTokenEntropyAnalysis(request, response);
                break;

            case "/api/security/source-maps" when method == "POST":
                await HandlePostSourceMaps(request, response);
                break;

            case "/api/security/tech-stack" when method == "POST":
                await HandlePostTechStack(request, response);
                break;

            case "/api/security/js-audit" when method == "POST":
                await HandlePostSecurityJsAudit(request, response);
                break;

            case "/api/security/nuclei-scan" when method == "POST":
                await HandlePostSecurityNucleiScan(request, response);
                break;

            case "/api/security/nuclei-templates" when method == "GET":
                await HandleGetSecurityNucleiTemplates(request, response);
                break;

            case "/api/security/storage" when method == "POST":
                await HandlePostStorageAudit(request, response);
                break;

            case "/api/security/saml-decode" when method == "POST":
                await HandlePostSamlDecode(request, response);
                break;

            case "/api/security/saml-capture" when method == "POST":
                await HandlePostSamlCapture(request, response);
                break;

            case "/api/security/saml-capture" when method == "GET":
                await HandleGetSamlCapture(response);
                break;

            case "/api/security/saml-replay" when method == "POST":
                await HandlePostSamlReplay(request, response);
                break;

            case "/api/security/csrf" when method == "POST":
                await HandlePostSecurityCsrf(request, response);
                break;

            case "/api/security/path-traversal" when method == "POST":
                await HandlePostSecurityPathTraversal(request, response);
                break;

            case "/api/security/ssrf-scan" when method == "POST":
                await HandlePostSecuritySsrfScan(request, response);
                break;

            case "/api/security/ssrf-orchestrator" when method == "POST":
                await HandlePostSecuritySsrfOrchestrator(request, response);
                break;

            case "/api/security/open-redirect-scan" when method == "POST":
                await HandlePostSecurityOpenRedirectScan(request, response);
                break;

            case "/api/security/cache-deception-scan" when method == "POST":
                await HandlePostSecurityCacheDeceptionScan(request, response);
                break;

            case "/api/security/cache-map" when method == "POST":
                await HandlePostSecurityCacheMap(request, response);
                break;

            case "/api/security/cache-pollution-scan" when method == "POST":
                await HandlePostSecurityCachePollutionScan(request, response);
                break;

            case "/api/security/cache-poison-scan" when method == "POST":
                await HandlePostSecurityCachePoisonScan(request, response);
                break;

            case "/api/upload" when method == "POST":
                await HandlePostUpload(request, response);
                break;

            case "/api/security/methods" when method == "POST":
                await HandlePostSecurityMethods(request, response);
                break;

            case "/api/security/smuggling" when method == "POST":
                await HandlePostSecuritySmuggling(request, response);
                break;

            case "/api/security/host-header" when method == "POST":
                await HandlePostSecurityHostHeader(request, response);
                break;

            case "/api/security/waf-bypass" when method == "POST":
                await HandlePostSecurityWafBypass(request, response);
                break;

            case "/api/security/shadow" when method == "POST":
                await HandlePostSecurityShadow(request, response);
                break;

            case "/api/security/firewall-test" when method == "POST":
                await HandlePostFirewallTest(request, response);
                break;

            case "/api/security/shadow" when method == "GET":
                await HandleGetSecurityShadow(request, response);
                break;

            case "/api/security/shadow/clear" when method == "POST":
                await HandlePostSecurityShadowClear(request, response);
                break;

            case "/api/shadow/check" when method == "POST":
                await HandlePostShadowCheck(request, response);
                break;

            case "/api/laws" when method == "GET":
                await HandleGetLaws(request, response);
                break;

            case "/api/laws/validate" when method == "POST":
                await HandlePostLawsValidate(request, response);
                break;

            case "/api/laws/add" when method == "POST":
                await HandlePostLawsAdd(request, response);
                break;

            case "/api/laws/replace" when method == "POST":
                await HandlePostLawsReplace(request, response);
                break;

            case "/api/laws/delete" when method == "POST":
                await HandlePostLawsDelete(request, response);
                break;

            case "/api/laws/check" when method == "POST":
                await HandlePostLawsCheck(request, response);
                break;

            case "/api/laws/proposals" when method == "GET":
                await HandleGetLawProposals(request, response);
                break;

            case "/api/laws/proposals/accept" when method == "POST":
                await HandlePostLawProposalAccept(request, response);
                break;

            case "/api/laws/proposals/reject" when method == "POST":
                await HandlePostLawProposalReject(request, response);
                break;

            case "/api/laws/author" when method == "POST":
                await HandlePostLawsAuthor(request, response);
                break;

            case "/api/security/callbacks" when method == "POST":
                await HandlePostSecurityCallbacks(request, response);
                break;

            case "/api/security/callbacks" when method == "GET":
                await HandleGetSecurityCallbacks(request, response);
                break;

            case "/api/security/trace-input" when method == "POST":
                await HandlePostTraceInput(request, response);
                break;

            case "/api/security/dom-xss-audit" when method == "POST":
                await HandlePostSecurityDomXssAudit(request, response);
                break;

            case "/api/security/client-surface" when method == "POST":
                await HandlePostSecurityClientSurface(request, response);
                break;

            case "/api/security/service-worker-audit" when method == "POST":
                await HandlePostSecurityServiceWorkerAudit(request, response);
                break;

            case "/api/security/postmessage" when method == "POST":
                await HandlePostSecurityPostMessage(request, response);
                break;

            case "/api/security/client-prototype-pollution" when method == "POST":
                await HandlePostSecurityClientPrototypePollution(request, response);
                break;

            case "/api/security/dom-flows" when method == "POST":
                await HandlePostSecurityDomFlows(request, response);
                break;

            case "/api/security/xs-leaks" when method == "POST":
                await HandlePostSecurityXsLeaks(request, response);
                break;

            case "/api/security/xssi-scan" when method == "POST":
                await HandlePostSecurityXssiScan(request, response);
                break;

            case "/api/security/gadget-chains" when method == "POST":
                await HandlePostSecurityGadgetChains(request, response);
                break;

            case "/api/security/gadget-radar" when method == "POST":
                await HandlePostSecurityGadgetRadar(request, response);
                break;

            case "/api/security/sqli-scan" when method == "POST":
                await HandlePostSecuritySqliScan(request, response);
                break;

            case "/api/security/sqli-login-sweep" when method == "POST":
                await HandlePostSecuritySqliLoginSweep(request, response);
                break;

            case "/api/security/nosql-scan" when method == "POST":
                await HandlePostSecurityNosqlScan(request, response);
                break;

            case "/api/security/ldap-scan" when method == "POST":
                await HandlePostSecurityLdapScan(request, response);
                break;

            case "/api/security/ssti-scan" when method == "POST":
                await HandlePostSecuritySstiScan(request, response);
                break;

            case "/api/security/ssti-polyglot-scan" when method == "POST":
                await HandlePostSecuritySstiPolyglotScan(request, response);
                break;

            case "/api/security/ssti-stored-scan" when method == "POST":
                await HandlePostSecuritySstiStoredScan(request, response);
                break;

            case "/api/security/prototype-pollution-scan" when method == "POST":
                await HandlePostSecurityPrototypePollutionScan(request, response);
                break;

            case "/api/security/csti-scan" when method == "POST":
                await HandlePostSecurityCstiScan(request, response);
                break;

            case "/api/security/xss-scan" when method == "POST":
            case "/api/security/xss-dom-audit" when method == "POST":
                await HandlePostSecurityXssScan(request, response);
                break;

            case "/api/security/parser-probe" when method == "POST":
                await HandlePostSecurityParserProbe(request, response);
                break;

            case "/api/security/deserialization-scan" when method == "POST":
                await HandlePostSecurityDeserializationScan(request, response);
                break;

            case "/api/security/file-upload-scan" when method == "POST":
                await HandlePostSecurityFileUploadScan(request, response);
                break;

            case "/api/security/nextjs-rsc-scan" when method == "POST":
                await HandlePostSecurityNextJsRscScan(request, response);
                break;

            case "/api/security/race-condition-scan" when method == "POST":
                await HandlePostSecurityRaceConditionScan(request, response);
                break;

            case "/api/security/captcha-replay-scan" when method == "POST":
                await HandlePostSecurityCaptchaReplayScan(request, response);
                break;

            case "/api/security/llm-redteam-scan" when method == "POST":
                await HandlePostSecurityLlmRedteamScan(request, response);
                break;

            case "/api/security/llm-redteam-probes" when method == "GET":
                await HandleGetSecurityLlmRedteamProbes(response);
                break;

            case "/api/security/llm-endpoint-discover" when method is "GET" or "POST":
                await HandleSecurityLlmEndpointDiscover(request, response);
                break;

            case "/api/security/llm-chat-interact" when method == "POST":
                await HandlePostSecurityLlmChatInteract(request, response);
                break;

            case "/api/security/llm-http-send" when method == "POST":
                await HandlePostSecurityLlmHttpSend(request, response);
                break;

            case "/api/security/llm-http-mcp-list" when method == "POST":
                await HandlePostSecurityLlmHttpMcpList(request, response);
                break;

            case "/api/security/llm-sink-assist" when method == "POST":
                await HandlePostSecurityLlmSinkAssist(request, response);
                break;

            case "/api/security/rate-limit-audit" when method == "POST":
                await HandlePostSecurityRateLimitAudit(request, response);
                break;

            case "/api/security/redos-scan" when method == "POST":
                await HandlePostSecurityReDoSScan(request, response);
                break;

            case "/api/security/body-size-limit-scan" when method == "POST":
                await HandlePostSecurityBodySizeLimitScan(request, response);
                break;

            case "/api/security/costly-operations" when method == "POST":
                await HandlePostSecurityCostlyOperations(request, response);
                break;

            case "/api/security/swaggering" when method == "POST":
            case "/api/security/openapi-smoke" when method == "POST":
                await HandlePostSecuritySwaggering(request, response);
                break;

            case "/api/security/workflow-skip-scan" when method == "POST":
                await HandlePostSecurityWorkflowSkipScan(request, response);
                break;

            case "/api/security/fail-open-scan" when method == "POST":
                await HandlePostSecurityFailOpenScan(request, response);
                break;

            case "/api/security/auth-control-identifier" when method == "POST":
                await HandlePostSecurityAuthControlIdentifier(request, response);
                break;

            case "/api/security/missing-parameter-scan" when method == "POST":
                await HandlePostSecurityMissingParameterScan(request, response);
                break;

            case "/api/security/session-fixation-scan" when method == "POST":
                await HandlePostSecuritySessionFixationScan(request, response);
                break;

            case "/api/security/password-reset-weak-scan" when method == "POST":
                await HandlePostSecurityPasswordResetWeakScan(request, response);
                break;

            case "/api/security/account-enumeration-scan" when method == "POST":
                await HandlePostSecurityAccountEnumerationScan(request, response);
                break;

            case "/api/security/logout-invalidation-probe" when method == "POST":
                await HandlePostSecurityLogoutInvalidationProbe(request, response);
                break;

            case "/api/security/cmd-canary" when method == "POST":
                await HandlePostSecurityCmdCanary(request, response);
                break;

            case "/api/security/supply-chain-scan" when method == "POST":
                await HandlePostSecuritySupplyChainScan(request, response);
                break;

            case "/api/security/osv-check" when method == "POST":
                await HandlePostSecurityOsvCheck(request, response);
                break;

            case "/api/security/jwt-analyze" when method == "POST":
                await HandlePostSecurityJwtAnalyze(request, response);
                break;

            case "/api/security/jwt-forge" when method == "POST":
                await HandlePostSecurityJwtForge(request, response);
                break;

            case "/api/security/jwt-acceptance-sweep" when method == "POST":
                await HandlePostSecurityJwtAcceptanceSweep(request, response);
                break;

            case "/api/security/jwt-header-abuse" when method == "POST":
                await HandlePostSecurityJwtHeaderAbuse(request, response);
                break;

            case "/api/security/cookie-prefix-bypass" when method == "POST":
                await HandlePostSecurityCookiePrefixBypass(request, response);
                break;

            case "/api/security/tls-introspection" when method == "POST":
                await HandlePostSecurityTlsIntrospection(request, response);
                break;

            case "/api/security/auth-bypass-pivot" when method == "POST":
                await HandlePostSecurityAuthBypassPivot(request, response);
                break;

            case "/api/security/rest-scaffold" when method == "POST":
                await HandlePostSecurityRestScaffold(request, response);
                break;

            case "/api/security/path-filter-bypass" when method == "POST":
                await HandlePostSecurityPathFilterBypass(request, response);
                break;

            case "/api/security/harvest-ids" when method == "POST":
                await HandlePostSecurityHarvestIds(request, response);
                break;

            case "/api/security/brute-force" when method == "POST":
                await HandlePostSecurityBruteForce(request, response);
                break;

            case "/api/security/idor-scan" when method == "POST":
                await HandlePostSecurityIdorScan(request, response);
                break;

            case "/api/security/mass-assignment-scan" when method == "POST":
                await HandlePostSecurityMassAssignmentScan(request, response);
                break;

            case "/api/security/mass-assignment-patch" when method == "POST":
                await HandlePostSecurityMassAssignmentPatch(request, response);
                break;

            case "/api/security/mass-assignment-register" when method == "POST":
                await HandlePostSecurityMassAssignmentRegister(request, response);
                break;

            case "/api/security/bfla-probe" when method == "POST":
                await HandlePostSecurityBflaProbe(request, response);
                break;

            case "/api/security/response-field-diff" when method == "POST":
                await HandlePostSecurityResponseFieldDiff(request, response);
                break;

            case "/api/security/auto-scan" when method == "POST":
                await HandlePostSecurityAutoScan(request, response);
                break;

            case "/api/security/secrets-harvest" when method == "POST":
                await HandlePostSecuritySecretsHarvest(request, response);
                break;

            case "/api/security/oidc-analyze" when method == "POST":
                await HandlePostSecurityOidcAnalyze(request, response);
                break;

            case "/api/security/graphql-analyze" when method == "POST":
                await HandlePostSecurityGraphqlAnalyze(request, response);
                break;

            case "/api/security/oauth-flow-test" when method == "POST":
                await HandlePostSecurityOAuthFlowTest(request, response);
                break;

            case "/api/security/verify" when method == "POST":
                await HandlePostSecurityVerify(request, response);
                break;

            case "/api/security/verify/batch" when method == "POST":
                await HandlePostSecurityVerifyBatch(request, response);
                break;

            case "/api/security/verify-workflow" when method == "POST":
                await HandlePostSecurityVerifyWorkflow(request, response);
                break;

            case "/api/security/chain-prove" when method == "POST":
                await HandlePostSecurityChainProve(request, response);
                break;

            case "/api/repro/capture" when method == "POST":
                await HandlePostReproCapture(request, response);
                break;

            case "/api/repro/verify" when method == "POST":
                await HandlePostReproVerify(request, response);
                break;

            case "/api/vpx/export" when method == "GET":
                await HandleGetVpxExport(request, response);
                break;

            case "/api/vpx/import" when method == "POST":
                await HandlePostVpxImport(request, response);
                break;

            case "/api/vpx/clear" when method == "POST":
                await HandlePostVpxClear(response);
                break;

            case "/api/shadows" when method == "GET":
                await HandleGetShadows(request, response);
                break;

            case "/api/shadows" when method == "POST":
                await HandlePostShadows(request, response);
                break;

            case "/api/page-text/structured" when method == "POST":
                await HandlePostStructuredText(request, response);
                break;

            case "/api/consistency" when method == "POST":
                await HandlePostConsistency(request, response);
                break;

            case "/api/third-party" when method == "POST":
                await HandlePostThirdParty(request, response);
                break;

            case "/api/monkey-test" when method == "POST":
                await HandlePostMonkeyTest(request, response);
                break;

            case "/api/monkey-trowser" when method == "POST":
                await HandlePostMonkeyTrowser(request, response);
                break;

            case "/api/settings/scope" when method == "POST":
                await HandlePostSettingsScope(request, response);
                break;

            case "/api/settings/throttle" when method == "GET":
                await HandleGetSettingsThrottle(response);
                break;

            case "/api/settings/throttle" when method == "POST":
                await HandlePostSettingsThrottle(request, response);
                break;

            case "/api/interrupter" when method == "POST":
                await HandlePostInterrupter(request, response);
                break;

            case "/api/attack-form" when method == "POST":
                await HandlePostAttackForm(request, response);
                break;

            case "/api/fuzz" when method == "POST":
                await HandlePostFuzz(request, response);
                break;

            case "/api/fuzz/payloads" when method == "GET":
                await HandleGetFuzzPayloads(response);
                break;

            case "/api/wait-for-navigation" when method == "POST":
                await HandlePostWaitForNavigation(request, response);
                break;

            case "/api/wait-for-final-navigation" when method == "POST":
                await HandlePostWaitForFinalNavigation(request, response);
                break;

            case "/api/wait-for-idle" when method == "POST":
                await HandlePostWaitForIdle(request, response);
                break;

            case "/api/assert/page-contains" when method == "POST":
                await HandlePostAssertPageContains(request, response);
                break;

            case "/api/assert/page-not-contains" when method == "POST":
                await HandlePostAssertPageNotContains(request, response);
                break;

            case "/api/assert/element-visible" when method == "POST":
                await HandlePostAssertElementVisible(request, response);
                break;

            case "/api/assert/element-not-visible" when method == "POST":
                await HandlePostAssertElementNotVisible(request, response);
                break;

            case "/api/assert/element-text" when method == "POST":
                await HandlePostAssertElementText(request, response);
                break;

            case "/api/assert/element-text-batch" when method == "POST":
                await HandlePostAssertElementTextBatch(request, response);
                break;

            case "/api/assert/element-contains-text" when method == "POST":
                await HandlePostAssertElementContainsText(request, response);
                break;

            case "/api/assert/element-attribute" when method == "POST":
                await HandlePostAssertElementAttribute(request, response);
                break;

            case "/api/assert/url" when method == "POST":
                await HandlePostAssertUrl(request, response);
                break;

            case "/api/assert/title" when method == "POST":
                await HandlePostAssertTitle(request, response);
                break;

            case "/api/assert/element-count" when method == "POST":
                await HandlePostAssertElementCount(request, response);
                break;

            case "/api/assert/reset" when method == "POST":
                _context.Assert.Reset();
                await WriteSuccess(response, new { message = "Assertions reset." });
                break;

            case "/api/batch" when method == "POST":
                await HandlePostBatch(request, response);
                break;

            case "/api/test-scenario" when method == "POST":
                await HandlePostTestScenario(request, response);
                break;

            case "/api/state/enrich" when method == "POST":
                await HandlePostStateEnrich(request, response);
                break;

            case "/api/diff-state" when method == "POST":
                await HandlePostDiffState(request, response);
                break;

            case "/api/state/refresh" when method == "POST":
                await HandlePostStateRefresh(request, response);
                break;

            // Keyboard
            case "/api/key" when method == "POST":
                await HandlePostKey(request, response);
                break;

            // Cookies
            case "/api/cookies" when method == "GET":
                await HandleGetCookies(request, response);
                break;

            case "/api/cookies/set" when method == "POST":
                await HandlePostCookieSet(request, response);
                break;

            case "/api/cookies/delete" when method == "POST":
                await HandlePostCookieDelete(request, response);
                break;

            case "/api/cookies/clear" when method == "POST":
                await _context.ClearCookies();
                await WriteSuccess(response, new { message = "All cookies cleared." });
                break;

            // Network Mocking
            case "/api/mock" when method == "GET":
                await HandleGetMocks(response);
                break;

            case "/api/mock" when method == "POST":
                await HandlePostMock(request, response);
                break;

            case "/api/mock/remove" when method == "POST":
                await HandlePostMockRemove(request, response);
                break;

            case "/api/mock/clear" when method == "POST":
                _context.ClearMocks();
                await WriteSuccess(response, new { message = "All mock rules cleared." });
                break;

            // Network Interception (Breakpoints)
            case "/api/intercept" when method == "GET":
                await HandleGetIntercepts(response);
                break;

            case "/api/intercept" when method == "POST":
                await HandlePostIntercept(request, response);
                break;

            case "/api/intercept/remove" when method == "POST":
                await HandlePostInterceptRemove(request, response);
                break;

            case "/api/intercept/clear" when method == "POST":
                _context.ClearInterceptRules();
                await WriteSuccess(response, new { message = "All intercept rules and pending requests cleared." });
                break;

            case "/api/intercept/continue" when method == "POST":
                await HandlePostInterceptContinue(request, response);
                break;

            case "/api/intercept/fulfill" when method == "POST":
                await HandlePostInterceptFulfill(request, response);
                break;

            case "/api/intercept/abort" when method == "POST":
                await HandlePostInterceptAbort(request, response);
                break;

            case "/api/intercept/replay" when method == "POST":
                await HandlePostInterceptReplay(request, response);
                break;

            case "/api/load-test" when method == "POST":
                await HandlePostLoadTest(request, response);
                break;

            case "/api/fetch" when method == "POST":
                await HandlePostFetch(request, response);
                break;

            case "/api/fetch/batch" when method == "POST":
                await HandlePostFetchBatch(request, response);
                break;

            case "/api/fetch-raw" when method == "POST":
                await HandlePostFetchRaw(request, response);
                break;

            case "/api/header-overrides" when method == "GET":
                await HandleGetHeaderOverrides(response);
                break;

            case "/api/header-overrides" when method == "PUT":
                await HandlePutHeaderOverrides(request, response);
                break;

            case "/api/header-overrides" when method == "DELETE":
                await HandleDeleteHeaderOverrides(response);
                break;

            // Viewport
            case "/api/viewport" when method == "GET":
                await HandleGetViewport(response);
                break;

            case "/api/viewport" when method == "POST":
                await HandlePostViewport(request, response);
                break;

            // Environment emulation (geo, locale, timezone, media, UA, permissions)
            case "/api/emulation" when method == "GET":
                await HandleGetEmulation(response);
                break;

            case "/api/emulation" when method == "POST":
                await HandlePostEmulation(request, response);
                break;

            case "/api/emulation" when method == "DELETE":
                await HandleDeleteEmulation(response);
                break;

            // Action timeline (not Playwright zip traces)
            case "/api/trace/start" when method == "POST":
                await HandlePostTraceStart(request, response);
                break;

            case "/api/trace/stop" when method == "POST":
                await HandlePostTraceStop(response);
                break;

            case "/api/trace" when method == "GET":
                await HandleGetTrace(response);
                break;

            case "/api/trace/export" when method == "GET":
                await HandleGetTraceExport(response);
                break;

            // Screen Curtain
            case "/api/screen-curtain" when method == "GET":
                await HandleGetScreenCurtain(response);
                break;

            case "/api/screen-curtain" when method == "POST":
                await HandlePostScreenCurtain(request, response);
                break;

            // Tab Management
            case "/api/tabs" when method == "GET":
                await HandleGetTabs(response);
                break;

            case "/api/tabs/new" when method == "POST":
                await HandlePostNewTab(request, response);
                break;

            case "/api/tabs/close" when method == "POST":
                await HandlePostCloseTab(request, response);
                break;

            case "/api/tabs/switch" when method == "POST":
                await HandlePostSwitchTab(request, response);
                break;

            // Dialog handling routes bypass the gate (see HandleRequestAsync).

            // Network Throttling
            case "/api/network/throttle" when method == "GET":
                await HandleGetNetworkThrottle(response);
                break;

            case "/api/network/throttle" when method == "POST":
                await HandlePostNetworkThrottle(request, response);
                break;

            case "/api/network/throttle" when method == "DELETE":
                await HandleDeleteNetworkThrottle(response);
                break;

            // Wait for Network Request
            case "/api/wait-for-network" when method == "POST":
                await HandlePostWaitForNetwork(request, response);
                break;

            // Web Storage (localStorage / sessionStorage)
            case "/api/storage" when method == "GET":
                await HandleGetStorage(request, response);
                break;

            case "/api/storage" when method == "POST":
                await HandlePostStorageSet(request, response);
                break;

            case "/api/storage/set" when method == "POST":
                await HandlePostStorageSet(request, response);
                break;

            case "/api/storage/delete" when method == "POST":
                await HandlePostStorageDelete(request, response);
                break;

            case "/api/storage/clear" when method == "POST":
                await HandlePostStorageClear(request, response);
                break;

            case "/api/mandelbrot" when method == "POST":
                await HandlePostMandelbrot(request, response);
                break;

            // WebMCP (page-level tool discovery)
            case "/api/webmcp" when method == "GET":
                await HandleGetWebMcp(response);
                break;

            case "/api/webmcp/call" when method == "POST":
                await HandlePostWebMcpCall(request, response);
                break;

            // MCP (Model Context Protocol) endpoint
            case "/mcp" when method == "POST":
                await HandleMcp(request, response, _preReadBody.Value);
                break;

            case "/mcp" when method is "GET" or "DELETE":
                await HandleMcpMethodNotAllowed(response);
                break;

            // Journal endpoints (unified session log)
            case "/api/journal" when method == "GET":
                await HandleGetJournal(request, response);
                break;

            case "/api/journal" when method == "POST":
                await HandlePostJournal(request, response);
                break;

            case "/api/journal" when method == "PATCH":
                await HandlePatchJournal(request, response);
                break;

            case "/api/journal" when method == "DELETE":
                await HandleDeleteJournal(request, response);
                break;

            case "/api/journal/export" when method == "GET":
                await HandleJournalExport(request, response);
                break;

            case "/api/journal/import" when method == "POST":
                await HandlePostJournalImport(request, response);
                break;

            case "/api/session-memory" when method == "GET":
                await HandleGetSessionMemory(response);
                break;

            case "/api/session-memory" when method == "POST":
                await HandlePostSessionMemory(request, response);
                break;

            case "/api/test-data" when method == "GET":
                await HandleGetTestData(request, response);
                break;

            case "/api/inspiration" when method == "GET":
                await HandleGetInspiration(response);
                break;

            case "/api/scripting-help" when method == "GET":
                await HandleGetScriptingHelp(request, response);
                break;

            case "/api/coverage" when method == "GET":
                await HandleGetCoverage(response);
                break;

            case "/api/ssl/certificates" when method == "GET":
                await HandleGetSslCertificates(response);
                break;

            case "/api/ssl/certificates" when method == "POST":
                await HandlePostSslCertificate(request, response);
                break;

            case "/api/ssl/certificates" when method == "DELETE":
                await HandleDeleteSslCertificate(request, response);
                break;

            case "/api/ssl/certificates/active" when method == "GET":
                await HandleGetSslActive(response);
                break;

            case "/api/ssl/certificates/active" when method == "POST":
                await HandlePostSslActive(request, response);
                break;

            // AuthZ testing (cross-instance security)
            case "/api/authz/probe" when method == "POST":
                await HandlePostAuthzProbe(request, response);
                break;

            case "/api/authz/diff" when method == "POST":
                await HandlePostAuthzDiff(request, response);
                break;

            case "/api/authz/fuzz" when method == "POST":
                await HandlePostAuthzFuzz(request, response);
                break;

            case "/api/authz/boundary" when method == "POST":
                await HandlePostAuthzBoundary(request, response);
                break;

            case "/api/authz/role-matrix" when method == "POST":
                await HandlePostAuthzRoleMatrix(request, response);
                break;

            case "/api/authz/model" when method == "GET":
                await HandleGetAuthzModel(request, response);
                break;

            case "/api/authz/model" when method == "PUT":
                await HandlePutAuthzModel(request, response);
                break;

            case "/api/authz/shadow" when method == "POST":
                await HandlePostAuthzShadow(request, response);
                break;

            case "/api/authz/coverage" when method == "POST":
                await HandlePostAuthzCoverage(request, response);
                break;

            case "/api/session/identity" when method == "GET":
                await HandleGetSessionIdentity(request, response);
                break;

            case "/api/session/cookie-header" when method == "GET":
                await HandleGetSessionCookieHeader(request, response);
                break;

            case "/api/identities" when method == "GET":
                await HandleGetIdentities(response);
                break;

            case "/api/identity/capture" when method == "POST":
                await HandlePostIdentityCapture(request, response);
                break;

            case "/api/identity/apply" when method == "POST":
                await HandlePostIdentityApply(request, response);
                break;

            case "/api/peer/identity/apply" when method == "POST":
                await HandlePostPeerIdentityApply(request, response);
                break;

            case "/api/identity/handoff" when method == "POST":
                await HandlePostIdentityHandoff(request, response);
                break;

            case "/api/identity/handoff" when method == "GET":
                await HandleGetIdentityHandoff(request, response);
                break;

            case "/api/identity" when method == "GET":
                await WriteError(response, 410,
                    "GET /api/identity was renamed to GET /api/session/identity (live session introspection). " +
                    "Use GET /api/identities for the captured identity catalog.");
                break;

            case "/api/fetch-direct" when method == "POST":
                await HandlePostFetchDirect(request, response);
                break;

            // Peer management (cross-instance testing)
            case "/api/peers" when method == "GET":
                await HandleGetPeers(response);
                break;

            case "/api/peer/register" when method == "POST":
                await HandlePostPeerRegister(request, response);
                break;

            case "/api/peer/spawn" when method == "POST":
                await HandlePostPeerSpawn(request, response);
                break;

            case "/api/peer/stop" when method == "POST":
                await HandlePostPeerStop(request, response);
                break;

            case "/api/peer/fetch" when method == "POST":
                await HandlePostPeerFetch(request, response);
                break;

            case "/api/peer/state" when method == "POST":
                await HandlePostPeerState(request, response);
                break;

            case "/api/peer/navigate" when method == "POST":
                await HandlePostPeerNavigate(request, response);
                break;

            case "/api/peer/screenshot" when method == "POST":
                await HandlePostPeerScreenshot(request, response);
                break;

            // ── Attack Chain Engine ──
            case "/api/security/chain-analyze" when method == "POST":
                await HandlePostSecurityChainAnalyze(request, response);
                break;

            case "/api/security/chain-findings" when method == "GET":
                await HandleGetSecurityChainFindings(request, response);
                break;

            case "/api/security/findings" when method == "GET":
                await HandleGetSecurityFindings(request, response);
                break;

            case "/api/security/chain-findings" when method == "POST":
                await HandlePostSecurityChainFindings(request, response, implicitAddPayload: false);
                break;

            case "/api/security/chain-findings/add" when method == "POST":
                await HandlePostSecurityChainFindings(request, response, implicitAddPayload: true);
                break;

            case "/api/security/chain-patterns" when method == "GET":
                await HandleGetSecurityChainPatterns(request, response);
                break;

            case "/api/security/chain-patterns" when method == "POST":
                await HandlePostSecurityChainPatterns(request, response);
                break;

            // ── WebSocket Security ──
            case "/api/sse/connections" when method == "GET":
                await HandleGetSseConnections(request, response);
                break;

            case "/api/sse/messages" when method == "GET":
                await HandleGetSseMessages(request, response);
                break;

            case "/api/security/sse-audit" when method == "POST":
                await HandlePostSecuritySseAudit(request, response);
                break;

            case "/api/websocket/connections" when method == "GET":
                await HandleGetWebSocketConnections(request, response);
                break;

            case "/api/websocket/messages" when method == "GET":
                await HandleGetWebSocketMessages(request, response);
                break;

            case "/api/websocket/send" when method == "POST":
                await HandlePostWebSocketSend(request, response);
                break;

            case "/api/websocket/close" when method == "POST":
                await HandlePostWebSocketClose(request, response);
                break;

            case "/api/security/websocket-audit" when method == "POST":
                await HandlePostSecurityWebSocketAudit(request, response);
                break;

            case "/api/security/websocket-fuzz" when method == "POST":
                await HandlePostSecurityWebSocketFuzz(request, response);
                break;

            case "/api/security/websocket-authz" when method == "POST":
                await HandlePostSecurityWebSocketAuthz(request, response);
                break;

            case "/api/security/cswsh-test" when method == "POST":
                await HandlePostSecurityCswshTest(request, response);
                break;

            case "/api/security/subdomain-takeover" when method == "POST":
                await HandlePostSecuritySubdomainTakeover(request, response);
                break;

            default:
                if (await TryRouteOrchestrateAsync(path, method, request, response))
                    break;
                if (await TryRouteIdentityByNameAsync(path, method, request, response))
                    break;
                if (await TryRoutePointerAsync(path, method, request, response))
                    break;
                if (await TryRouteCheckpointAsync(path, method, request, response))
                    break;
                if (await TryRouteDecisionAsync(path, method, request, response))
                    break;
                if (await TryRouteRaceLabAsync(path, method, request, response))
                    break;
                if (method == "GET" && TryParseNetworkEntryId(path, out var networkEntryId))
                {
                    await HandleGetNetworkById(request, response, networkEntryId);
                    break;
                }
                if (path.StartsWith("/api/peer/") && method == "DELETE")
                {
                    var peerName = path.Substring("/api/peer/".Length);
                    await HandleDeletePeer(peerName, response);
                }
                else
                {
                    await WriteError(response, 404, $"Unknown endpoint: {method} {path}");
                }
                break;
        }
        }
        finally
        {
            if (applyPacing)
                RecordRequestPacingComplete();
        }
    }

    /// <summary>
    /// True when a peer forwarded this request as a Mirror Mode replay of a human GUI action.
    /// Those must stay on the current tab — they are not agent automation.
    /// </summary>
    private static bool IsMirrorForward(HttpListenerRequest request)
    {
        var value = request.Headers[PeerRegistry.MirrorRequestHeader];
        return !string.IsNullOrEmpty(value) && !value.Equals("0", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPacedNavigationPath(string path) =>
        path is "/api/navigate" or "/api/go-back" or "/api/go-forward" or "/api/wait-for-navigation" or "/api/wait-for-final-navigation";

    private async Task WaitForRequestPacingAsync(string path, CancellationToken cancellationToken)
    {
        if (_pacingMaxRequestsPerSecond > 0.0001)
        {
            while (true)
            {
                var now = DateTimeOffset.UtcNow;
                if (now >= _pacingNextStartUtc) break;
                var wait = _pacingNextStartUtc - now;
                if (wait > TimeSpan.Zero)
                    await Task.Delay(wait, cancellationToken);
            }
        }

        if (_pacingDelayBetweenNavigationsMs > 0 && IsPacedNavigationPath(path))
            await Task.Delay(_pacingDelayBetweenNavigationsMs, cancellationToken);
    }

    private void RecordRequestPacingComplete()
    {
        if (_pacingMaxRequestsPerSecond > 0.0001)
            _pacingNextStartUtc = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1.0 / _pacingMaxRequestsPerSecond);
    }

    #endregion
}
