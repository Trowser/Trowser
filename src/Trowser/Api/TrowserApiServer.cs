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

/// <summary>
/// Embedded HTTP API server that allows LLMs and external tools to interact with
/// a running Trowser instance in real-time. Exposes page state, interactive elements,
/// and all automation actions as REST endpoints.
/// </summary>
public partial class TrowserApiServer : IDisposable
{
    private HttpListener _listener;
    private readonly AutomationContext _context;
    private readonly ChainPatternCatalog _chainCatalog;
    private readonly IdentityStore _identityStore;
    private readonly Security.Authz.AccessModelStore _accessModelStore = new();
    private readonly PlaybookRegistry _playbookRegistry;
    private readonly PlaybookRunStore _playbookRunStore = new();
    private readonly IdentityHandoffManager _identityHandoff;
    private readonly ScriptEngine _scriptEngine;
    private readonly Dispatcher _dispatcher;
    private readonly object _gateLock = new();
    private SemaphoreSlim _gate = new(1, 1);

    /// <summary>Semaphore instance held by the in-flight gated operation (for abort/recovery).</summary>
    private SemaphoreSlim? _activeGateLease;
    private readonly CancellationTokenSource _cts = new();
    private int _port;
    private readonly int _requestedPort;
    private readonly string _apiKey;
    private readonly string _screenshotDir;
    private readonly McpHandler _mcpHandler;

    /// <summary>Minimum UTC time the next paced API operation may start (end-to-start spacing for <see cref="_pacingMaxRequestsPerSecond"/>).</summary>
    private DateTimeOffset _pacingNextStartUtc = DateTimeOffset.MinValue;

    /// <summary>0 = off. Otherwise minimum interval between <em>ends</em> of consecutive gated operations and <em>starts</em> of the next, via <c>1/rps</c> seconds.</summary>
    private double _pacingMaxRequestsPerSecond;

    /// <summary>Extra delay (ms) before navigation-style endpoints, in addition to RPS spacing.</summary>
    private int _pacingDelayBetweenNavigationsMs;

    /// <summary>Tracks the path of the operation currently holding the gate, for diagnostic 503 messages.</summary>
    private volatile string? _currentOperation;

    /// <summary>CancellationTokenSource for the operation currently holding the gate. Cancelled by POST /api/abort.</summary>
    private volatile CancellationTokenSource? _operationCts;

    /// <summary>
    /// Pre-read request body for the current request async flow.
    /// Must be <see cref="AsyncLocal{T}"/> — requests are accepted via <c>Task.Run</c> and waiters
    /// buffer the body before the gate; a shared field was cleared by the holder's <c>finally</c>,
    /// causing queued <c>POST /mcp</c> <c>tools/call</c> to see an empty body and return HTTP 202.
    /// </summary>
    private readonly AsyncLocal<string?> _preReadBody = new();

    /// <summary>When set, <see cref="ReadJsonBody"/> uses this instead of the real request body (scenario sub-steps).</summary>
    private string? _scenarioBodyOverride;

    /// <summary>When set, <see cref="ApiQuery"/> returns this instead of the real query string (scenario GET steps).</summary>
    private NameValueCollection? _scenarioQueryOverride;

    /// <summary>When non-null, JSON responses are captured here instead of the HTTP response (POST /api/test-scenario steps).</summary>
    private ScenarioResponseCapture? _scenarioResponseCapture;

    private sealed class ScenarioResponseCapture
    {
        public int StatusCode { get; set; } = 200;
        public MemoryStream Stream { get; } = new();
    }

    /// <summary>
    /// Tracks the refGeneration the client last saw (from GET /api/state or GET /api/interactive).
    /// Used for auto-stale-ref detection: if the generation changed since the client last fetched,
    /// action responses include a warning.
    /// </summary>
    private int _clientRefGeneration = -1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public int Port => _port;
    public string ApiKey => _apiKey;
    public bool IsRunning { get; private set; }

    /// <summary>
    /// When true (default), all API requests must provide a valid API key via the
    /// Authorization header. Toggle off to allow unauthenticated access.
    /// </summary>
    public bool ApiKeyRequired { get; set; } = true;

    /// <summary>
    /// Safe mode blocks dangerous operations: JS execution, C# scripting,
    /// network mocking, and cookie manipulation.
    /// </summary>
    public bool SafeMode
    {
        get => _mcpHandler.SafeMode;
        set => _mcpHandler.SafeMode = value;
    }

    /// <summary>
    /// Default tool pack for external <c>POST /mcp</c> clients (core / security).
    /// Overridable per request with <c>?mode=</c> or <c>X-Trowser-Mcp-Mode</c>
    /// (<c>full</c> is an alias of security).
    /// </summary>
    public ExternalMcpMode ExternalMcpMode
    {
        get => _mcpHandler.ExternalPack;
        set => _mcpHandler.ExternalPack = value;
    }

    /// <summary>Named session for WebView2 user data isolation (shown in /api/info).</summary>
    public string SessionName
    {
        get => _sessionName;
        set { _sessionName = value; if (_mcpHandler != null) _mcpHandler.SessionName = value; }
    }
    private string _sessionName = "default";

    /// <summary>Registry of peer Trowser instances for cross-instance testing.</summary>
    public PeerRegistry Peers { get; }

    /// <summary>Optional session logger for /api/journal endpoint and automatic API action logging.</summary>
    public SessionLogger? SessionLogger
    {
        get => _sessionLogger;
        set { _sessionLogger = value; _mcpHandler.SessionLogger = value; }
    }
    private SessionLogger? _sessionLogger;

    /// <summary>
    /// Optional pointer/checkpoint store backing the pointer primitive: REST
    /// <c>/api/pointer(s)</c> + <c>/api/checkpoint(s)</c> and MCP <c>browser_point</c> /
    /// <c>browser_pointers</c> / <c>browser_checkpoint</c>.
    /// </summary>
    public Trowser.Pointers.PointerStore? PointerStore { get; set; }

    /// <summary>
    /// Optional decision store backing the A/B/C/D handoff: REST <c>/api/decision(s)</c> and MCP
    /// <c>browser_decide</c> / <c>browser_decisions</c>.
    /// </summary>
    public Trowser.Decisions.DecisionStore? DecisionStore { get; set; }

    /// <summary>
    /// Optional Mirror Mode controller. When set, REST/MCP gated calls suppress
    /// GUI action fan-out so programmatic driver actions are not mirrored.
    /// </summary>
    public Trowser.Peers.MirrorController? MirrorController { get; set; }

    /// <summary>Volatile session memory for built-in AI Assistant compaction.</summary>
    public SessionMemory? SessionMemory
    {
        get => _sessionMemory;
        set { _sessionMemory = value; _mcpHandler.SessionMemory = value; }
    }
    private SessionMemory? _sessionMemory;

    /// <summary>Optional test data service for /api/test-data endpoint and browser_test_data MCP tool.</summary>
    public TestDataService? TestDataService
    {
        get => _testDataService;
        set { _testDataService = value; _mcpHandler.TestDataService = value; }
    }
    private TestDataService? _testDataService;

    /// <summary>Optional inspiration service for /api/inspiration and MCP browser_inspiration.</summary>
    public InspirationService? InspirationService
    {
        get => _inspirationService;
        set { _inspirationService = value; _mcpHandler.InspirationService = value; }
    }
    private InspirationService? _inspirationService;

    /// <summary>Optional coverage lens for /api/coverage and MCP browser_coverage.</summary>
    public CoverageService? CoverageService
    {
        get => _coverageService;
        set { _coverageService = value; _mcpHandler.CoverageService = value; }
    }
    private CoverageService? _coverageService;

    /// <summary>
    /// Callback invoked when POST /api/message or the browser_send_message MCP tool is called.
    /// Parameters: text, level ("info"/"warning"/"error"), durationMs.
    /// Must be invoked on the UI thread by the subscriber.
    /// </summary>
    public Action<string, string, int>? OnShowMessage { get; set; }

    /// <summary>
    /// How long a gated request waits for the browser lock before returning 503.
    /// GET observation endpoints fail fast so agents can poll without hanging behind long operations.
    /// </summary>
    private static TimeSpan GateWaitTimeout(string path, string method)
    {
        if (method == "GET" && path is "/api/state" or "/api/interactive" or "/api/info" or "/api/page-text")
            return TimeSpan.FromSeconds(5);
        return TimeSpan.FromSeconds(60);
    }

    /// <summary>In-memory read routes that bypass the gate (no WebView2 interaction).</summary>
    private static bool IsGateFreeReadOnly(string path, string method) =>
        (method == "GET" && path is
            "/api/console" or
            "/api/network" or
            "/api/assertions" or
            "/api/journal" or
            "/api/journal/export" or
            "/api/session-memory" or
            "/api/test-data" or
            "/api/inspiration" or
            "/api/coverage" or
            "/api/scripting-help" or
            "/api/security/saml-capture" or
            "/api/security/shadow" or
            "/api/laws" or
            "/api/laws/validate" or
            "/api/laws/add" or
            "/api/laws/replace" or
            "/api/laws/delete" or
            "/api/laws/check" or
            "/api/laws/author" or
            "/api/laws/proposals" or
            "/api/security/callbacks" or
            "/api/shadows" or
            "/api/ssl/certificates" or
            "/api/ssl/certificates/active" or
            "/api/peers" or
            "/api/session/identity" or
            "/api/session/cookie-header" or
            "/api/identities" or
            "/api/security/chain-findings" or
            "/api/security/findings" or
            "/api/security/chain-patterns" or
            "/api/orchestrate/playbooks" or
            "/api/security/llm-redteam-probes" or
            "/api/vpx/export" or
            "/api/vpx/import" or
            "/api/vpx/clear" or
            "/api/websocket/connections" or
            "/api/sse/connections" or
            "/api/sse/messages" or
            "/api/pointers" or
            "/api/checkpoints" or
            "/api/websocket/messages")
        || (method == "GET" && IsNetworkEntryByIdPath(path))
        || (method == "GET" && path.StartsWith("/api/pointer/", StringComparison.OrdinalIgnoreCase))
        || (method == "GET" && path.StartsWith("/api/checkpoint/", StringComparison.OrdinalIgnoreCase))
        || (method == "GET" && path.StartsWith("/api/orchestrate/runs/", StringComparison.OrdinalIgnoreCase))
        || (method == "POST" && path == "/api/security/chain-analyze")
        || (method == "POST" && path == "/api/security/osv-check")
        || (method == "GET" && path == "/api/identity/handoff")
        || path.StartsWith("/api/peer/", StringComparison.OrdinalIgnoreCase)
        || path == "/api/fetch-direct"
        || (method == "GET" && path == "/api/header-overrides");

    /// <summary>
    /// Endpoints that should NOT be logged to the journal — read-only polling, meta,
    /// journal itself (avoid recursion), and gate-free read endpoints.
    /// All GETs are skipped (read-only observations). Gate-bypassed POSTs (/api/journal, /api/message)
    /// are logged separately in their own handlers if needed.
    /// </summary>
    private static bool ShouldSkipJournalLog(string path, string method) =>
        method == "GET"
        || path is "/api/journal" or "/api/journal/export" or "/api/session-memory" or "/api/message" or "/mcp"
        || path is "/api/test-scenario"
        || path is "/api/assert/reset" or "/api/console/clear" or "/api/network/clear"
            or "/api/mock/clear" or "/api/intercept/clear"
        || path.StartsWith("/api/assert/")  // assertions are logged separately via LogApiAssert
        || path.StartsWith("/api/state/")   // state queries (enrich, refresh) are read-only observations
        || path is "/api/text" or "/api/extract-text" or "/api/attribute" or "/api/property" or "/api/extract"
            or "/api/find" or "/api/structured-text"  // data-reading endpoints
        || path is "/api/wait" or "/api/wait-for-navigation" or "/api/wait-for-idle"
            or "/api/wait-for-final-navigation" or "/api/wait-for-network";  // wait helpers

    /// <summary>
    /// Log an API action at the point of receiving the request, extracting key params from the raw body.
    /// This provides a one-line summary of every meaningful API call for the journal narrative.
    /// </summary>
    private void LogApiActionFromBody(string method, string path, string? rawBody)
    {
        if (_sessionLogger == null || ShouldSkipJournalLog(path, method)) return;

        string? details = null;
        if (!string.IsNullOrWhiteSpace(rawBody))
        {
            try
            {
                using var doc = JsonDocument.Parse(rawBody);
                details = ExtractApiSummary(path, doc.RootElement);
            }
            catch { /* non-JSON body — log without details */ }
        }

        try { _sessionLogger.LogApiAction(method, path, details, rawBody: rawBody); }
        catch (Exception ex) { TrowserLog.Warn($"Journal API log failed: {ex.Message}"); }
    }

    /// <summary>Extract a concise human-readable summary from the request body for journal logging.</summary>
    private static string? ExtractApiSummary(string path, JsonElement root)
    {
        var parts = new List<string>();

        // Element target (ref, selector, label, role, placeholder, etc.)
        if (root.TryGetProperty("ref", out var refEl))
        {
            var desc = $"ref {refEl}";
            if (root.TryGetProperty("label", out var lbl)) desc += $" ({lbl})";
            else if (root.TryGetProperty("role", out var r) && root.TryGetProperty("name", out var n)) desc += $" ({r} \"{n}\")";
            parts.Add(desc);
        }
        else if (root.TryGetProperty("selector", out var sel))
            parts.Add(sel.GetString() ?? "");
        else if (root.TryGetProperty("label", out var lab))
            parts.Add($"label \"{lab}\"");
        else if (root.TryGetProperty("role", out var role))
        {
            var name = root.TryGetProperty("name", out var nm) ? nm.GetString() : null;
            parts.Add(name != null ? $"{role} \"{name}\"" : role.GetString() ?? "");
        }
        else if (root.TryGetProperty("byText", out var bt))
            parts.Add($"text \"{bt}\"");
        else if (root.TryGetProperty("placeholder", out var ph))
            parts.Add($"placeholder \"{ph}\"");

        // Action-specific fields
        if (root.TryGetProperty("text", out var text))
        {
            var t = text.GetString() ?? "";
            if (t.Length > 60) t = t[..57] + "...";
            parts.Add($"← \"{t}\"");
        }
        if (root.TryGetProperty("value", out var val))
            parts.Add($"← \"{val}\"");
        if (root.TryGetProperty("key", out var key))
            parts.Add($"key:{key}");
        if (root.TryGetProperty("url", out var url))
        {
            var u = url.GetString() ?? "";
            if (u.Length > 100) u = u[..97] + "...";
            parts.Add(u);
        }
        if (root.TryGetProperty("urlPattern", out var pat))
            parts.Add(pat.GetString() ?? "");
        if (root.TryGetProperty("action", out var act))
            parts.Add(act.GetString() ?? "");
        if (root.TryGetProperty("direction", out var dir))
            parts.Add(dir.GetString() ?? "");
        if (root.TryGetProperty("preset", out var pre))
            parts.Add(pre.GetString() ?? "");
        if (root.TryGetProperty("script", out var scr))
        {
            var s = scr.GetString() ?? "";
            if (s.Length > 60) s = s[..57] + "...";
            parts.Add(s);
        }
        if (root.TryGetProperty("status", out var st) && path.Contains("mock"))
            parts.Add($"→ {st}");
        if (root.TryGetProperty("concurrency", out var conc))
            parts.Add($"×{conc}");
        if (root.TryGetProperty("method", out var mth) && path.Contains("fetch"))
            parts.Add(mth.GetString() ?? "");
        if (root.TryGetProperty("requestId", out var rid))
            parts.Add($"reqId {rid}");

        return parts.Count > 0 ? string.Join(" ", parts) : null;
    }

    public TrowserApiServer(
        AutomationContext context,
        ScriptEngine scriptEngine,
        Dispatcher dispatcher,
        PlaybookRegistry playbookRegistry,
        IdentityStore identityStore,
        ChainPatternCatalog chainCatalog,
        PeerRegistry peers,
        int port = 6923,
        string? apiKey = null,
        bool safeMode = false,
        ExternalMcpMode externalMcpMode = ExternalMcpMode.Core)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        Peers = peers ?? throw new ArgumentNullException(nameof(peers));
        _scriptEngine = scriptEngine ?? throw new ArgumentNullException(nameof(scriptEngine));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _playbookRegistry = playbookRegistry ?? throw new ArgumentNullException(nameof(playbookRegistry));
        _identityStore = identityStore ?? throw new ArgumentNullException(nameof(identityStore));
        _chainCatalog = chainCatalog ?? throw new ArgumentNullException(nameof(chainCatalog));
        _requestedPort = port;
        _port = port;
        _apiKey = apiKey ?? "";

        _screenshotDir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
        Directory.CreateDirectory(_screenshotDir);

        _identityHandoff = new IdentityHandoffManager(_identityStore);

        // HTTP POST /mcp uses ExternalMcpMode (default Core). Built-in Chat
        // InteractionMode (Chat / Economical / Full) uses a separate McpHandler.
        _mcpHandler = new McpHandler(context, _screenshotDir, scriptEngine)
        {
            Mode = Chat.InteractionMode.Full,
            ExternalPack = externalMcpMode,
            ExternalAgentSurface = true,
            SafeMode = safeMode,
            Peers = Peers,
            SessionName = SessionName,
            ChainCatalog = _chainCatalog,
            IdentityStore = _identityStore,
            IdentityHandoff = _identityHandoff
        };
        _mcpHandler.Host = this;
        _mcpHandler.ShowMessageAsync = (text, level, duration) => ShowMessageAsync(text, level, duration);
        _mcpHandler.AuditAllPayloadBuilder = BuildAuditAllResponseDataAsync;
        _mcpHandler.SurpriseMeRunner = BuildSurpriseMeResponseDataAsync;
        _mcpHandler.CryptographicFailuresPayloadBuilder = body => BuildCryptographicFailuresAuditPayloadAsync(body);
        _mcpHandler.AfterSuccessfulForceNavigateAsync = async () => await TryRecoverGateAfterForceNavigateAsync();

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://localhost:{_port}/");
    }

    /// <summary>
    /// The actual port the server bound to (may differ from requested port after fallback).
    /// </summary>
    public int BoundPort => _port;

    /// <summary>
    /// Start listening for HTTP requests. If the requested port is in use,
    /// tries up to 9 consecutive ports before giving up. Use <c>port 0</c>
    /// to bind to any available port.
    /// </summary>
    public void Start()
    {
        if (_requestedPort == 0)
        {
            StartOnAnyPort();
            return;
        }

        const int maxRetries = 10;
        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            var candidatePort = _requestedPort + attempt;
            if (candidatePort > 65535) break;

            try
            {
                if (attempt > 0)
                {
                    _listener.Close();
                    _listener = new HttpListener();
                    _listener.Prefixes.Add($"http://localhost:{candidatePort}/");
                }

                _listener.Start();
                _port = candidatePort;
                IsRunning = true;

                if (attempt > 0)
                    TrowserLog.Info($"Port {_requestedPort} was in use; API server bound to port {_port}");

                _ = Task.Run(() => ListenLoopAsync(_cts.Token));
                return;
            }
            catch (HttpListenerException) when (attempt < maxRetries - 1)
            {
                // Port in use — try next
            }
        }

        IsRunning = false;
        throw new InvalidOperationException(
            $"Could not bind API server: ports {_requestedPort}–{_requestedPort + maxRetries - 1} are all in use.");
    }

    private void StartOnAnyPort()
    {
        var tcpListener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        tcpListener.Start();
        var assignedPort = ((System.Net.IPEndPoint)tcpListener.LocalEndpoint).Port;
        tcpListener.Stop();

        _listener.Close();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://localhost:{assignedPort}/");

        try
        {
            _listener.Start();
            _port = assignedPort;
            IsRunning = true;
            TrowserLog.Info($"API server bound to auto-assigned port {_port}");
            _ = Task.Run(() => ListenLoopAsync(_cts.Token));
        }
        catch
        {
            IsRunning = false;
            throw;
        }
    }

    /// <summary>
    /// Stop listening and clean up.
    /// </summary>
    public void Stop()
    {
        _cts.Cancel();
        IsRunning = false;
        try { _listener.Stop(); } catch (Exception ex) { TrowserLog.Warn($"Listener stop error: {ex.Message}"); }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
        lock (_gateLock)
            _gate.Dispose();
        _listener.Close();
    }

    #region Listen Loop

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener.IsListening)
        {
            try
            {
                var httpContext = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestSafeAsync(httpContext));
            }
            catch (HttpListenerException) when (ct.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex) { TrowserLog.Error("API listen loop error", ex); }
        }
    }

    private async Task HandleRequestSafeAsync(HttpListenerContext httpContext)
    {
        try
        {
            await HandleRequestAsync(httpContext);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("API request handler error", ex);
            var status = IsClientUsageError(ex) ? 400 : 500;
            try { await WriteError(httpContext.Response, status, ex.Message); }
            catch { httpContext.Response.Close(); }
        }
    }

    /// <summary>
    /// Map expected client/usage failures (e.g. cross-origin frame) to HTTP 400 instead of 500.
    /// </summary>
    private static bool IsClientUsageError(Exception ex)
    {
        if (ex is ArgumentException)
            return true;
        if (ex is not InvalidOperationException)
            return false;
        var msg = ex.Message ?? "";
        return msg.StartsWith("crossOrigin", StringComparison.OrdinalIgnoreCase)
               || msg.StartsWith("Frame not found", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("Same-origin frames only", StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Ref Resolution

    /// <summary>
    /// Resolve a CSS selector from either a "ref" (int) or "selector" (string) field in the request body.
    /// Returns the selector string, or null with an error message if neither is valid.
    /// Also returns a stale-ref warning if the page state changed since the client last fetched it.
    /// </summary>
    private (string? selector, string? error, string? staleWarning) ResolveSelector(JsonBody body)
    {
        string? explicitFrame = body.GetString("frame");

        // Try ref first (preferred for LLM agents -- avoids selector escaping issues)
        if (body.HasProperty("ref"))
        {
            var refIndex = body.GetInt("ref", -1);

            // Explicit stale-ref detection: if caller provides refGeneration, verify it matches (hard error)
            if (body.HasProperty("refGeneration"))
            {
                var expectedGen = body.GetInt("refGeneration", -1);
                var currentGen = _context.RefGeneration;
                if (expectedGen != currentGen)
                {
                    return (null, $"Stale refs: your refGeneration={expectedGen} but current is {currentGen}. " +
                        $"The page state has changed since your last GET /api/state. Refresh with GET /api/state before retrying.", null);
                }
            }

            var selector = _context.GetSelectorByRef(refIndex);
            if (selector == null)
                return (null, $"Invalid ref: {refIndex}. Call GET /api/state first to get valid ref numbers.", null);

            // Auto stale-ref warning: if the generation changed since the client last fetched state
            string? warning = null;
            if (_clientRefGeneration >= 0 && _context.RefGeneration != _clientRefGeneration)
            {
                warning = $"Refs may be stale: page state has changed since your last GET /api/state " +
                    $"(your generation={_clientRefGeneration}, current={_context.RefGeneration}). " +
                    $"Consider refreshing with GET /api/state to get current refs.";
            }

            var frame = !string.IsNullOrWhiteSpace(explicitFrame)
                ? explicitFrame
                : _context.GetFrameIdByRef(refIndex);
            return (AutomationContext.ApplyFrame(selector, frame), null, warning);
        }

        // Fall back to selector
        var sel = body.GetString("selector");
        if (!string.IsNullOrWhiteSpace(sel))
            return (AutomationContext.ApplyFrame(sel, explicitFrame), null, null);

        // Try semantic locators
        if (body.HasProperty("role"))
        {
            var role = body.GetString("role") ?? "";
            var name = body.GetString("name");
            var locator = !string.IsNullOrEmpty(name) ? $"@role:{role}:{name}" : $"@role:{role}:";
            return (AutomationContext.ApplyFrame(locator, explicitFrame), null, null);
        }
        if (body.HasProperty("label"))
        {
            var label = body.GetString("label") ?? "";
            return (AutomationContext.ApplyFrame($"@label:{label}", explicitFrame), null, null);
        }
        if (body.HasProperty("getByText") || body.HasProperty("byText"))
        {
            var text = body.GetString("getByText") ?? body.GetString("byText") ?? "";
            return (AutomationContext.ApplyFrame($"@text:{text}", explicitFrame), null, null);
        }
        if (body.HasProperty("placeholder"))
        {
            var ph = body.GetString("placeholder") ?? "";
            return (AutomationContext.ApplyFrame($"@placeholder:{ph}", explicitFrame), null, null);
        }
        if (body.HasProperty("testId"))
        {
            var tid = body.GetString("testId") ?? "";
            return (AutomationContext.ApplyFrame($"@testid:{tid}", explicitFrame), null, null);
        }
        if (body.HasProperty("value"))
        {
            var val = body.GetString("value") ?? "";
            return (AutomationContext.ApplyFrame($"@value:{val}", explicitFrame), null, null);
        }

        return (null, "Provide 'ref', 'selector', or a locator ('role'+'name', 'label', 'byText', 'placeholder', 'testId', 'value').", null);
    }

    #endregion

    #region POST Handlers

    private async Task HandlePostNavigate(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var action = body.GetString("action")?.Trim().ToLowerInvariant();

        if (action is "back" or "forward")
        {
            try
            {
                var before = await _context.CapturePageState();
                if (action == "back")
                    await _context.GoBack();
                else
                    await _context.GoForward();
                var after = await _context.CapturePageState();
                var changes = AutomationContext.DiffPageState(before, after);
                await WriteSuccess(response, new { action, url = after.Url, title = after.Title, changes });
            }
            catch (InvalidOperationException ex)
            {
                await WriteError(response, 400, ex.Message);
            }
            return;
        }

        if (!string.IsNullOrEmpty(action))
        {
            await WriteError(response, 400,
                "Invalid \"action\". Use \"back\" or \"forward\", or omit \"action\" and pass \"url\".");
            return;
        }

        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400,
                "Provide \"url\" to open a page, or \"action\": \"back\" / \"forward\" for session history.");
            return;
        }

        var reload = body.GetBool("reload", false);
        var ignoreCert = body.GetBool("ignoreCertificateErrors", false);
        var beforeUrl = await _context.CapturePageState();
        var targetUrl = url.Trim();
        if (!targetUrl.Contains("://") && !targetUrl.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            targetUrl = "https://" + targetUrl;

        var tab = _context.ActiveTab;
        string navigationKind;
        string? reloadWarning = null;
        if (reload && AutomationContext.UrlEquivalentForNavigate(beforeUrl.Url, targetUrl))
        {
            navigationKind = "reload";
            if (AutomationContext.LastDocumentRequestWasPost(_context.Network.Entries, beforeUrl.Url))
            {
                reloadWarning =
                    "Reload may re-submit the previous form POST (browser refresh semantics). " +
                    "Use navigate without reload for a fresh GET to the same URL.";
            }

            await _context.Reload();
        }
        else if (!reload && AutomationContext.UrlEquivalentForNavigate(beforeUrl.Url, targetUrl))
        {
            navigationKind = "fresh-get";
            tab.LastSameUrlFreshGetDocumentReloaded = null;
            await _context.NavigateFreshGetAsync(targetUrl, ignoreCert);
        }
        else
        {
            navigationKind = "navigate";
            await _context.Navigate(targetUrl, reload, ignoreCert);
        }

        var afterUrl = await _context.CapturePageState();
        var urlChanges = AutomationContext.DiffPageState(beforeUrl, afterUrl);
        var urlChanged = !AutomationContext.UrlEquivalentForNavigate(beforeUrl.Url, afterUrl.Url);
        var navigationOk = tab.LastNavigationSucceeded ?? true;
        var webErrorStatus = tab.LastNavigationWebErrorStatus;

        object? documentReloaded = navigationKind == "fresh-get"
            ? tab.LastSameUrlFreshGetDocumentReloaded
            : null;

        await WriteSuccess(response, new
        {
            url = afterUrl.Url,
            title = afterUrl.Title,
            urlChanged,
            navigationKind,
            reloadWarning,
            documentReloaded,
            navigationOk,
            loadFailed = !navigationOk,
            webErrorStatus,
            changes = urlChanges
        });
    }

    private async Task HandlePostGoBack(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var before = await _context.CapturePageState();
            await _context.GoBack();
            var after = await _context.CapturePageState();
            var changes = AutomationContext.DiffPageState(before, after);
            await WriteSuccess(response, new { url = after.Url, title = after.Title, changes });
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostGoForward(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var before = await _context.CapturePageState();
            await _context.GoForward();
            var after = await _context.CapturePageState();
            var changes = AutomationContext.DiffPageState(before, after);
            await WriteSuccess(response, new { url = after.Url, title = after.Title, changes });
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostClick(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var button = body.GetString("button") ?? "left";
        var clickCount = body.GetInt("clickCount", 1);
        if (clickCount < 1) clickCount = 1;

        var before = await _context.CapturePageState();
        await _context.Click(selector, button, clickCount, timeout > 0 ? timeout : null);
        await Task.Delay(150);
        var after = await _context.CapturePageState();
        var changes = AutomationContext.DiffPageState(before, after);

        await WriteSuccess(response, new { clicked = selector, button, clickCount, staleRefWarning = staleWarning, changes });
    }

    private async Task HandlePostClickAt(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.HasProperty("x") || !body.HasProperty("y"))
        {
            await WriteError(response, 400, "Provide viewport coordinates \"x\" and \"y\" (CSS pixels from the page top-left).");
            return;
        }

        var x = body.GetDouble("x");
        var y = body.GetDouble("y");
        var button = body.GetString("button") ?? "left";
        var clickCount = body.GetInt("clickCount", 1);
        if (clickCount < 1) clickCount = 1;

        try
        {
            var before = await _context.CapturePageState();
            await _context.ClickAt(x, y, button, clickCount);
            await Task.Delay(150);
            var after = await _context.CapturePageState();
            var changes = AutomationContext.DiffPageState(before, after);
            await WriteSuccess(response, new
            {
                x,
                y,
                button,
                clickCount,
                method = "cdp-viewport",
                changes
            });
        }
        catch (ArgumentException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostType(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var html = body.GetString("html");
        var text = ResolveTypeContent(body);
        if (text == null && string.IsNullOrEmpty(html))
        {
            await WriteError(response, 400,
                "Provide 'text' or 'value' (content to type), or 'html' for rich content. " +
                "When the element is already addressed (ref/selector/locator), 'value' is an alias for typed content.");
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var clearFirst = !body.GetBool("append", false) && body.GetBool("clearFirst", true);
        await _context.Type(selector, text ?? "", timeout > 0 ? timeout : null, html, clearFirst);
        await WriteSuccess(response, new { typed = text, html, into = selector, append = !clearFirst, staleRefWarning = staleWarning });
    }

    /// <summary>
    /// Typed content for /api/type: prefer <c>text</c>; accept <c>value</c> as an alias when the element
    /// is already addressed by another locator (so <c>value</c> is not the @value: locator).
    /// Returns null when neither field supplies content (caller may still accept html-only).
    /// Explicit empty <c>text: ""</c> is preserved (clear-only).
    /// </summary>
    private static string? ResolveTypeContent(JsonBody body)
    {
        if (body.HasProperty("text"))
            return body.GetString("text") ?? "";

        // value is content when another locator addresses the element; otherwise value is @value: locator.
        bool hasOtherLocator = body.HasProperty("ref") || body.HasProperty("selector")
            || body.HasProperty("role") || body.HasProperty("label")
            || body.HasProperty("getByText") || body.HasProperty("byText")
            || body.HasProperty("placeholder") || body.HasProperty("testId");

        if (hasOtherLocator && body.HasProperty("value"))
            return body.GetString("value") ?? "";

        return null;
    }

    private async Task HandlePostSelect(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        var value = body.GetString("value");
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var label = body.GetString("label");
        var timeout = body.GetInt("timeout", 0);
        try
        {
            await _context.Select(selector, value ?? "", label, timeout > 0 ? timeout : null);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        var actualState = await _context.GetSelectState(selector);
        var actualVal = actualState.TryGetValue("value", out var av) ? av?.ToString() ?? "" : "";
        var matched = string.IsNullOrEmpty(value)
            ? !string.IsNullOrEmpty(actualVal)
            : actualVal == value;
        await WriteSuccess(response, new
        {
            selected = value,
            label,
            matched,
            @in = selector,
            actual = actualState,
            staleRefWarning = staleWarning
        });
    }

    private async Task HandlePostExecuteJs(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var script = body.GetString("script");
        if (string.IsNullOrWhiteSpace(script))
            script = body.GetString("expression");
        if (string.IsNullOrWhiteSpace(script))
            script = body.GetString("code");
        if (string.IsNullOrWhiteSpace(script))
        {
            await WriteError(response, 400, "Missing required field: script (aliases: expression, code)");
            return;
        }

        var timeout = body.GetInt("timeout", 30_000);
        var frame = body.GetString("frame");
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

        string result;
        try
        {
            result = await _context.InvokeOnTabAsync(tabTarget, async () =>
            {
                try
                {
                    return string.IsNullOrWhiteSpace(frame)
                        ? await _context.ExecuteJs(script, timeout)
                        : await _context.ExecuteJsInFrame(frame, script, timeout);
                }
                catch (TimeoutException ex)
                {
                    throw new ApiCommandException(504, ex.Message);
                }
            });
        }
        catch (ApiCommandException ex)
        {
            await WriteError(response, ex);
            return;
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 500, $"JavaScript error: {ex.Message}");
            return;
        }

        var ingested = _context.ConsumeLastExecuteJsIngestions();

        await WriteSuccess(response, new
        {
            result,
            chainFindingsAdded = ingested.Count > 0
                ? ingested.Select(f => new { f.Id, f.Category, f.Title, f.Severity }).ToList()
                : null
        });
    }

    private async Task HandlePostExecuteScript(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        // Accept both `code` (canonical) and `script` (docs/DX alias).
        var code = body.GetString("code");
        if (string.IsNullOrWhiteSpace(code))
            code = body.GetString("script");
        if (string.IsNullOrWhiteSpace(code))
        {
            await WriteError(response, 400, "Missing required field: code (alias: script)");
            return;
        }

        _context.Laws?.BeginScriptLawSession();
        _context.BeginScriptLogCapture();
        ScriptResult result;
        try
        {
            result = await _scriptEngine.ExecuteAsync(code);
        }
        finally
        {
            _context.Laws?.EndScriptLawSession();
        }

        var logLines = _context.ConsumeScriptLogCapture();
        var lawChecks = _context.Laws?.LastResults
            .Select(r => new
            {
                id = r.LawId,
                name = r.Name,
                verdict = r.Verdict.ToString().ToLowerInvariant(),
                message = r.Message,
                evidence = r.Evidence,
                url = r.ContextUrl
            })
            .ToList();

        if (result.Success)
        {
            // Auto-print assertion summary if any assertions were made
            if (_context.Assert.TotalCount > 0)
            {
                _context.Assert.Summary();
            }

            await WriteSuccess(response, new
            {
                success = true,
                returnValue = result.ReturnValue?.ToString(),
                elapsedMs = result.ElapsedMs,
                log = logLines.Count > 0 ? logLines : null,
                lawChecks = lawChecks is { Count: > 0 } ? lawChecks : null,
                assertions = new
                {
                    passed = _context.Assert.PassCount,
                    failed = _context.Assert.FailCount,
                    total = _context.Assert.TotalCount,
                    allPassed = _context.Assert.AllPassed
                }
            });
        }
        else
        {
            await WriteSuccess(response, new
            {
                success = false,
                error = result.Error,
                elapsedMs = result.ElapsedMs,
                log = logLines.Count > 0 ? logLines : null,
                lawChecks = lawChecks is { Count: > 0 } ? lawChecks : null
            });
        }
    }

    private async Task HandlePostSurpriseMe(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, await BuildSurpriseMeResponseDataAsync());
    }

    /// <summary>Shared by <see cref="HandlePostSurpriseMe"/> and MCP <c>browser_surpriseme</c>.</summary>
    internal async Task<object> BuildSurpriseMeResponseDataAsync()
    {
        _context.Assert.Reset();
        var result = await _scriptEngine.ExecuteAsync("await SurpriseMe();");

        if (_context.Assert.TotalCount > 0)
            _context.Assert.Summary();

        return new
        {
            success = result.Success,
            quicktest = _context.LastSurpriseQuicktest,
            error = result.Success ? null : result.Error,
            elapsedMs = result.ElapsedMs,
            assertions = new
            {
                passed = _context.Assert.PassCount,
                failed = _context.Assert.FailCount,
                total = _context.Assert.TotalCount,
                allPassed = _context.Assert.AllPassed
            }
        };
    }

    private async Task HandlePostWait(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var timeout = body.GetInt("timeout", 10000);

        // Support locators in addition to plain selectors
        string? selector = body.GetString("selector");
        if (string.IsNullOrWhiteSpace(selector))
        {
            var (resolved, error, _) = ResolveSelector(body);
            if (resolved != null)
                selector = resolved;
        }

        if (string.IsNullOrWhiteSpace(selector))
        {
            await WriteError(response, 400, "Missing required field: selector (or a locator like 'role', 'label', 'testId', etc.)");
            return;
        }

        var state = body.GetString("state") ?? "visible";

        try
        {
            await _context.WaitForElement(selector, timeout, state);
            await WriteSuccess(response, new { found = true, selector, state });
        }
        catch (TimeoutException)
        {
            await WriteSuccess(response, new { found = false, selector, state, timeoutMs = timeout });
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostText(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (body.HasProperty("targets") || body.HasProperty("selectors") || body.HasProperty("patterns"))
        {
            await HandlePostTextBatchExtract(response, body);
            return;
        }

        var (selector, error, staleWarning) = ResolveSelector(body);
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var text = await _context.GetText(selector, timeout > 0 ? timeout : null);
        await WriteSuccess(response, new { text, selector, staleRefWarning = staleWarning });
    }

    /// <summary>
    /// Read text from many elements and/or regex captures over visible (or full) page text — one round-trip for test workflows.
    /// </summary>
    private async Task HandlePostTextBatchExtract(HttpListenerResponse response, JsonBody body)
    {
        var defaultTimeout = body.GetInt("timeout", 0);
        int? timeoutOrNull = defaultTimeout > 0 ? defaultTimeout : null;

        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var targetRows = new List<object>();
        var staleWarnings = new List<string>();

        var targetsList = body.GetArray("targets");
        if (targetsList != null)
        {
            var i = 0;
            foreach (var td in targetsList)
            {
                using (td)
                {
                    var el = td.RootElement;
                    JsonBody itemBody;
                    string key;
                    if (el.ValueKind == JsonValueKind.String)
                    {
                        var sel = el.GetString() ?? "";
                        key = sel;
                        if (string.IsNullOrEmpty(sel))
                        {
                            i++;
                            continue;
                        }

                        itemBody = new JsonBody(JsonDocument.Parse(
                            "{\"selector\":" + JsonSerializer.Serialize(sel) + "}"));
                    }
                    else if (el.ValueKind == JsonValueKind.Object)
                    {
                        itemBody = new JsonBody(JsonDocument.Parse(el.GetRawText()));
                        key = itemBody.GetString("key") ?? itemBody.GetString("name") ?? itemBody.GetString("id") ?? $"_{i}";
                    }
                    else
                    {
                        var errKey = $"_{i}";
                        values[errKey] = null;
                        targetRows.Add(new { key = errKey, error = "target must be a selector string or an object with ref/selector/locators" });
                        i++;
                        continue;
                    }

                    var itemTimeout = itemBody.HasProperty("timeout") ? itemBody.GetInt("timeout", 0) : 0;
                    var t = itemTimeout > 0 ? itemTimeout : timeoutOrNull;

                    var (selector, error, warn) = ResolveSelector(itemBody);
                    if (warn != null) staleWarnings.Add(warn);
                    if (selector == null)
                    {
                        values[key] = null;
                        targetRows.Add(new { key, error });
                        i++;
                        continue;
                    }

                    try
                    {
                        var text = await _context.GetText(selector, t);
                        values[key] = text;
                        targetRows.Add(new { key, selector, text, staleRefWarning = warn });
                    }
                    catch (Exception ex)
                    {
                        values[key] = null;
                        targetRows.Add(new { key, selector, error = ex.Message });
                    }

                    i++;
                }
            }
        }

        var selectorsArr = body.GetStringArray("selectors");
        if (selectorsArr != null)
        {
            foreach (var sel in selectorsArr)
            {
                if (string.IsNullOrEmpty(sel)) continue;
                var key = sel;
                var itemBody = new JsonBody(JsonDocument.Parse(
                    "{\"selector\":" + JsonSerializer.Serialize(sel) + "}"));
                var (selector, error, warn) = ResolveSelector(itemBody);
                if (warn != null) staleWarnings.Add(warn);
                if (selector == null)
                {
                    values[key] = null;
                    targetRows.Add(new { key, error });
                    continue;
                }

                try
                {
                    var text = await _context.GetText(selector, timeoutOrNull);
                    values[key] = text;
                    targetRows.Add(new { key, selector, text, staleRefWarning = warn });
                }
                catch (Exception ex)
                {
                    values[key] = null;
                    targetRows.Add(new { key, selector, error = ex.Message });
                }
            }
        }

        Dictionary<string, string?>? patternResults = null;
        var patternsList = body.GetArray("patterns");
        if (patternsList != null && patternsList.Count > 0)
        {
            patternResults = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            string pageText;
            try
            {
                pageText = string.Equals(body.GetString("pageTextScope"), "all", StringComparison.OrdinalIgnoreCase)
                    ? await _context.GetAllPageText()
                    : await _context.GetPageText();
            }
            catch (Exception ex)
            {
                await WriteError(response, 500, $"Could not read page text for patterns: {ex.Message}");
                return;
            }

            var patIndex = 0;
            foreach (var pd in patternsList)
            {
                using (pd)
                {
                    var pe = pd.RootElement;

                    if (pe.ValueKind == JsonValueKind.String)
                    {
                        var label = pe.GetString()?.Trim() ?? "";
                        if (string.IsNullOrEmpty(label))
                        {
                            patIndex++;
                            continue;
                        }

                        var extracted = TryExtractTextAfterLabel(pageText, label);
                        patternResults[label] = extracted;
                        values[label] = extracted;
                        patIndex++;
                        continue;
                    }

                    if (pe.ValueKind != JsonValueKind.Object)
                    {
                        patIndex++;
                        continue;
                    }

                    var pName = pe.TryGetProperty("name", out var nEl) && nEl.ValueKind == JsonValueKind.String
                        ? nEl.GetString()
                        : pe.TryGetProperty("key", out var kEl) && kEl.ValueKind == JsonValueKind.String
                            ? kEl.GetString()
                            : null;
                    var regex = pe.TryGetProperty("regex", out var rEl) && rEl.ValueKind == JsonValueKind.String
                        ? rEl.GetString()
                        : null;
                    var labelOnly = pe.TryGetProperty("label", out var lblEl) && lblEl.ValueKind == JsonValueKind.String
                        ? lblEl.GetString()?.Trim()
                        : null;

                    var hasGroupProp = pe.TryGetProperty("group", out var gEl) && gEl.ValueKind == JsonValueKind.Number;
                    var group = hasGroupProp ? gEl.GetInt32() : 0;

                    var autoKey = $"pattern{patIndex}";
                    var storeKey = string.IsNullOrEmpty(pName) ? autoKey : pName!;

                    if (string.IsNullOrEmpty(regex) && !string.IsNullOrEmpty(labelOnly))
                    {
                        var extracted = TryExtractTextAfterLabel(pageText, labelOnly);
                        patternResults[storeKey] = extracted;
                        values[storeKey] = extracted;
                        patIndex++;
                        continue;
                    }

                    if (string.IsNullOrEmpty(regex))
                    {
                        patIndex++;
                        continue;
                    }

                    if (TryRegexExtract(pageText, regex!, group, out var extractedRx))
                    {
                        patternResults[storeKey] = extractedRx;
                        values[storeKey] = extractedRx;
                    }
                    else
                    {
                        patternResults[storeKey] = null;
                        values[storeKey] = null;
                    }

                    patIndex++;
                }
            }
        }

        if (targetRows.Count == 0 && (patternResults == null || patternResults.Count == 0))
        {
            await WriteError(response, 400, "Provide non-empty \"targets\", \"selectors\", or \"patterns\" for multi extract.");
            return;
        }

        await WriteSuccess(response, new
        {
            values,
            targets = targetRows.Count > 0 ? targetRows : null,
            patterns = patternResults,
            staleRefWarnings = staleWarnings.Count > 0 ? staleWarnings : null
        });
    }

    /// <summary>
    /// After the first case-insensitive occurrence of <paramref name="label"/>, returns the trimmed remainder
    /// of that logical line (skipping a single leading <c>:</c>, <c>-</c>, or <c>=</c>). Null if the label is not found.
    /// </summary>
    private static string? TryExtractTextAfterLabel(string pageText, string label)
    {
        if (string.IsNullOrEmpty(pageText) || string.IsNullOrEmpty(label)) return null;
        var idx = pageText.IndexOf(label, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var tail = pageText[(idx + label.Length)..].TrimStart();
        if (tail.Length > 0 && (tail[0] == ':' || tail[0] == '-' || tail[0] == '='))
            tail = tail[1..].TrimStart();
        var lineEnd = tail.AsSpan().IndexOfAny('\r', '\n');
        var line = (lineEnd >= 0 ? tail[..lineEnd] : tail).Trim();
        return line;
    }

    private static bool TryRegexExtract(string input, string pattern, int groupIndex, out string? value)
    {
        value = null;
        if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(pattern)) return false;
        try
        {
            var m = Regex.Match(input, pattern, RegexOptions.Singleline, TimeSpan.FromSeconds(2));
            if (!m.Success) return false;
            if (groupIndex < 0) groupIndex = 0;
            if (groupIndex >= m.Groups.Count)
                groupIndex = 0;
            value = m.Groups[groupIndex].Value;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task HandlePostAttribute(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        var attribute = body.GetString("attribute");
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }
        if (string.IsNullOrWhiteSpace(attribute))
        {
            await WriteError(response, 400, "Missing required field: attribute");
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var value = await _context.GetAttribute(selector, attribute, timeout > 0 ? timeout : null);
        await WriteSuccess(response, new { value, attribute, selector, staleRefWarning = staleWarning });
    }

    private async Task HandlePostProperty(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        var property = body.GetString("property");
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }
        if (string.IsNullOrWhiteSpace(property))
        {
            await WriteError(response, 400, "Missing required field: property");
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        var value = await _context.GetProperty(selector, property, timeout > 0 ? timeout : null);
        await WriteSuccess(response, new { value, property, selector, staleRefWarning = staleWarning });
    }

    private async Task HandlePostExtract(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        string? selector;
        string? staleWarning = null;

        if (body.HasProperty("ref") || body.HasProperty("role") || body.HasProperty("label") ||
            body.HasProperty("byText") || body.HasProperty("getByText") ||
            body.HasProperty("placeholder") || body.HasProperty("testId"))
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
        else
        {
            selector = body.GetString("selector");
        }

        if (string.IsNullOrWhiteSpace(selector))
        {
            await WriteError(response, 400, "Missing required field: selector (CSS selector for the elements to extract from)");
            return;
        }

        var fields = body.GetStringDictionary("fields");
        var limit = body.GetInt("limit", 0);
        var data = await _context.Extract(selector, fields, limit);
        await WriteSuccess(response, new { data, count = data.Count, selector, staleRefWarning = staleWarning });
    }

    private async Task HandlePostFind(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var text = body.GetString("text");
        if (string.IsNullOrWhiteSpace(text))
        {
            await WriteError(response, 400, "Missing required field: text (the text to search for)");
            return;
        }

        var caseSensitive = body.GetBool("caseSensitive");
        var regex = body.GetBool("regex");
        var highlight = body.GetBool("highlight");
        var visibleOnly = !body.HasProperty("visibleOnly") || body.GetBool("visibleOnly");
        int? scrollTo = body.HasProperty("scrollTo") ? body.GetInt("scrollTo", 0) : null;

        var result = await _context.FindText(text, caseSensitive, regex, scrollTo, highlight, visibleOnly);
        await WriteSuccess(response, result);
    }

    private async Task HandlePostHover(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, staleWarning) = ResolveSelector(body);
        if (selector == null)
        {
            await WriteError(response, 400, error!);
            return;
        }

        var timeout = body.GetInt("timeout", 0);
        await _context.Hover(selector, timeout > 0 ? timeout : null);
        await WriteSuccess(response, new { hovered = selector, staleRefWarning = staleWarning });
    }

    private async Task HandlePostScroll(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var direction = body.GetString("direction") ?? "down";
        var scrollIntoView = body.GetBool("scrollIntoView");
        var timeout = body.GetInt("timeout", 0);
        double? x = body.HasProperty("x") ? body.GetDouble("x")
            : body.HasProperty("scrollX") ? body.GetDouble("scrollX") : null;
        double? y = body.HasProperty("y") ? body.GetDouble("y")
            : body.HasProperty("scrollY") ? body.GetDouble("scrollY") : null;

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

        await _context.Scroll(selector, direction, scrollIntoView, timeout > 0 ? timeout : null, x, y);
        await WriteSuccess(response, new { scrolled = selector ?? "window", direction, scrollIntoView, x, y, staleRefWarning = staleWarning });
    }

    private async Task HandlePostAccessibility(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildAccessibilityAuditPayloadAsync(body));
    }

    private async Task HandlePostTabOrder(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var options = ParseTabOrderOptions(body);
        var result = await _context.CheckTabOrder(options);
        await WriteSuccess(response, FormatTabOrderResult(result, includeSteps: body.GetBool("includeSteps", true)));
    }

    private static TabOrderOptions ParseTabOrderOptions(JsonBody body) => new()
    {
        Selector = body.GetString("selector"),
        StartSelector = body.GetString("startSelector") ?? body.GetString("start"),
        AutoDetectScope = body.GetBool("autoDetectScope", true),
        StrictScope = body.GetBool("strictScope", true),
        MaxSteps = body.GetInt("maxSteps", 150),
        CheckPositiveTabIndex = body.GetBool("checkPositiveTabIndex", true),
        CheckSkipped = body.GetBool("checkSkipped", true),
        CheckReadingOrder = body.GetBool("checkReadingOrder", true),
        CheckFocusTrap = body.GetBool("checkFocusTrap", true),
        CheckShiftTabConsistency = body.GetBool("checkShiftTabConsistency", true),
        ExpectedOrder = body.GetStringArray("expectedOrder")
    };

    private static object FormatTabOrderResult(TabOrderResult result, bool includeSteps = true) => new
    {
        isClean = result.IsClean,
        url = result.Url,
        title = result.Title,
        scopeSelector = result.ScopeSelector,
        focusContextKind = result.FocusContextKind,
        focusContextLabel = result.FocusContextLabel,
        scopeAutoDetected = result.ScopeAutoDetected,
        focusableCount = result.FocusableCount,
        forwardCycleComplete = result.ForwardCycleComplete,
        backwardChecked = result.BackwardChecked,
        shiftTabConsistencyChecked = result.ShiftTabConsistencyChecked,
        backwardCycleComplete = result.BackwardCycleComplete,
        shiftTabConsistent = result.ShiftTabConsistent,
        expectedOrderMatched = result.ExpectedOrderMatched,
        forwardStepCount = result.ForwardSteps.Count,
        backwardStepCount = result.BackwardSteps.Count,
        issueCount = result.Issues.Count,
        issues = result.Issues.Select(i => new
        {
            category = i.Category,
            severity = i.Severity.ToString().ToLowerInvariant(),
            message = i.Message,
            selector = i.Selector,
            label = i.Label,
            stepIndex = i.StepIndex
        }),
        forwardSteps = includeSteps
            ? result.ForwardSteps.Select(s => new
            {
                s.Index,
                s.Direction,
                s.Selector,
                s.Label,
                s.Tag,
                s.Role,
                tabIndex = s.TabIndex,
                s.Ref,
                s.InScope,
                rect = new { x = s.X, y = s.Y, width = s.Width, height = s.Height }
            })
            : null,
        backwardSteps = includeSteps
            ? result.BackwardSteps.Select(s => new
            {
                s.Index,
                s.Direction,
                s.Selector,
                s.Label,
                s.Tag,
                s.Role,
                tabIndex = s.TabIndex,
                s.Ref,
                s.InScope,
                rect = new { x = s.X, y = s.Y, width = s.Width, height = s.Height }
            })
            : null,
        summary = result.Format(includeSteps: false)
    };

    private async Task HandlePostPerformance(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, await BuildPerformanceAuditPayloadAsync());
    }

    private async Task HandlePostResourceSnapshot(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var snapshot = await _context.CheckResourceSnapshot(body.GetBool("rememberBaseline"));
        await WriteSuccess(response, BuildResourceSnapshotPayload(snapshot));
    }

    private async Task HandlePostResourceCompare(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        ResourceUsage.ResourceSnapshot? baseline = null;

        if (body.HasProperty("baseline"))
        {
            try
            {
                using var baselineDoc = body.GetObject("baseline")
                    ?? throw new ArgumentException("baseline must be a JSON object.");
                baseline = ParseResourceSnapshotFromBody(new JsonBody(baselineDoc));
            }
            catch (ArgumentException ex)
            {
                await WriteError(response, 400, ex.Message);
                return;
            }
        }
        else if (body.GetBool("useRememberedBaseline"))
        {
            baseline = _context.RememberedResourceBaseline;
        }

        if (baseline == null)
        {
            await WriteError(response, 400,
                "Provide \"baseline\" (from POST /api/resource/snapshot) or \"useRememberedBaseline\": true after a snapshot with rememberBaseline: true.");
            return;
        }

        try
        {
            var options = ParseResourceCompareOptions(body);
            var result = await _context.CompareResourceUsage(baseline, options);
            await WriteSuccess(response, BuildResourceProbePayload(result));
        }
        catch (ArgumentException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostResourceProbe(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var options = ParseResourceProbeOptions(body);

        if (ResourceUsage.ResourceProbe.RequiresActiveSafetyMode(options))
        {
            var gateError = SafetyGate.RequireActive(body,
                "Resource probe replays click/type actions that may trigger server-side effects");
            if (gateError != null)
            {
                await WriteError(response, 400, gateError);
                return;
            }
        }

        try
        {
            var result = await _context.RunResourceProbe(options);
            await WriteSuccess(response, BuildResourceProbePayload(result));
        }
        catch (ArgumentException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private static ResourceUsage.ResourceProbeOptions ParseResourceProbeOptions(JsonBody body)
    {
        return new ResourceUsage.ResourceProbeOptions
        {
            Actions = ParseInterrupterActionsFromBody(body),
            Iterations = body.GetInt("iterations", 5),
            GcBetweenIterations = body.GetBool("gcBetweenIterations", true),
            GcBeforeFinal = body.GetBool("gcBeforeFinal", true),
            SettleMs = body.GetInt("settleMs", 500),
            ReloadBetweenIterations = body.GetBool("reloadBetweenIterations"),
            GrowthThresholdPercent = body.GetDouble("growthThresholdPercent", 10),
            ListenerGrowthThreshold = body.GetInt("listenerGrowthThreshold", 50),
            NodeGrowthThreshold = body.GetInt("nodeGrowthThreshold", 100),
        };
    }

    private static ResourceUsage.ResourceProbeOptions ParseResourceCompareOptions(JsonBody body) =>
        new()
        {
            GcBeforeFinal = body.GetBool("gcBeforeFinal", true),
            SettleMs = body.GetInt("settleMs", 500),
            GrowthThresholdPercent = body.GetDouble("growthThresholdPercent", 10),
            ListenerGrowthThreshold = body.GetInt("listenerGrowthThreshold", 50),
            NodeGrowthThreshold = body.GetInt("nodeGrowthThreshold", 100),
        };

    internal static ResourceUsage.ResourceSnapshot ParseResourceSnapshotFromBody(JsonBody body)
    {
        if (!body.HasProperty("heap") || !body.HasProperty("dom"))
            throw new ArgumentException("baseline must include heap and dom objects from POST /api/resource/snapshot.");

        using var heapDoc = body.GetObject("heap")
            ?? throw new ArgumentException("baseline.heap must be an object.");
        using var domDoc = body.GetObject("dom")
            ?? throw new ArgumentException("baseline.dom must be an object.");
        var heapBody = new JsonBody(heapDoc);
        var domBody = new JsonBody(domDoc);

        JsonBody? connBody = null;
        JsonDocument? connDoc = null;
        if (body.HasProperty("connections"))
        {
            connDoc = body.GetObject("connections");
            if (connDoc != null)
                connBody = new JsonBody(connDoc);
        }

        try
        {
            return new ResourceUsage.ResourceSnapshot
            {
                Url = body.GetString("url") ?? "",
                Timestamp = body.HasProperty("timestamp") && DateTime.TryParse(body.GetString("timestamp"), out var ts)
                    ? ts
                    : DateTime.UtcNow,
                JsHeapUsedBytes = heapBody.GetInt64("usedBytes"),
                JsHeapTotalBytes = heapBody.GetInt64("totalBytes"),
                DomNodes = domBody.GetInt("nodes"),
                Documents = domBody.GetInt("documents"),
                Frames = domBody.GetInt("frames"),
                JsEventListeners = domBody.GetInt("listeners"),
                LiveHtmlElements = domBody.HasProperty("liveHtmlElements") ? domBody.GetInt("liveHtmlElements") : null,
                WebSocketsOpen = connBody?.GetInt("webSocketsOpen") ?? 0,
                Flags = body.GetStringArray("flags") ?? []
            };
        }
        finally
        {
            connDoc?.Dispose();
        }
    }

    private async Task<object> BuildResourceSnapshotPayloadAsync()
    {
        var snapshot = await _context.CheckResourceSnapshot();
        return BuildResourceSnapshotPayload(snapshot);
    }

    private static object BuildResourceSnapshotPayload(ResourceUsage.ResourceSnapshot snapshot) => new
    {
        url = snapshot.Url,
        timestamp = snapshot.Timestamp,
        heap = new { usedBytes = snapshot.JsHeapUsedBytes, totalBytes = snapshot.JsHeapTotalBytes },
        dom = new
        {
            nodes = snapshot.DomNodes,
            documents = snapshot.Documents,
            frames = snapshot.Frames,
            listeners = snapshot.JsEventListeners,
            liveHtmlElements = snapshot.LiveHtmlElements
        },
        connections = new { webSocketsOpen = snapshot.WebSocketsOpen },
        flags = snapshot.Flags,
        summary = ResourceUsage.ResourceSnapshotFormatter.Format(snapshot)
    };

    private static object BuildResourceProbePayload(ResourceUsage.ResourceProbeResult result) => new
    {
        url = result.Url,
        timestamp = result.Timestamp,
        isClean = result.IsClean,
        isLikelyLeak = result.IsLikelyLeak,
        isComparison = result.IsComparison,
        baseline = SnapshotDto(result.Baseline),
        final = SnapshotDto(result.Final),
        samples = result.Samples.Select(SnapshotDto).ToList(),
        findings = result.Findings.Select(f => new
        {
            severity = f.Severity.ToString().ToLowerInvariant(),
            category = f.Category,
            title = f.Title,
            description = f.Description,
            recommendation = f.Recommendation,
            confidence = f.Confidence.ToString().ToLowerInvariant(),
            evidence = f.Evidence
        }).ToList(),
        summary = result.Format()
    };

    private static object SnapshotDto(ResourceUsage.ResourceSnapshot s) => new
    {
        url = s.Url,
        timestamp = s.Timestamp,
        heap = new { usedBytes = s.JsHeapUsedBytes, totalBytes = s.JsHeapTotalBytes },
        dom = new
        {
            nodes = s.DomNodes,
            documents = s.Documents,
            frames = s.Frames,
            listeners = s.JsEventListeners,
            liveHtmlElements = s.LiveHtmlElements
        },
        connections = new { webSocketsOpen = s.WebSocketsOpen },
        flags = s.Flags
    };

    
    
    /// <summary>
    /// Full page health audit in one round-trip: accessibility, performance, combined security
    /// (CVE library scan + DOM XSS + mixed content), HTTP security headers, HTML validation, SEO,
    /// JS compatibility, link checking, and GUI consistency. Request body is the union of optional fields from each audit
    /// (<c>level</c>, <c>selector</c>; <c>minIos</c>, <c>minAndroid</c>; <c>scope</c>, <c>external</c>, link-check options).
    /// </summary>
    private async Task HandlePostAuditAll(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildAuditAllResponseDataAsync(body));
    }

    /// <summary>Shared by <see cref="HandlePostAuditAll"/> and MCP <c>browser_audit_all</c>.</summary>
    internal async Task<object> BuildAuditAllResponseDataAsync(JsonBody body)
    {
        var sw = Stopwatch.StartNew();
        var moduleTimings = new List<object>();
        var auditProgress = new AuditAllProgress();
        var auditNetworkScope = ResolveAuditNetworkScopeLabel(body);
        var auditScopeHost = await ResolveAuditScopeHostAsync(body);

        var accessibility = await AuditAllModuleAsync(() => BuildAccessibilityAuditPayloadAsync(body), "Accessibility audit", moduleTimings, auditProgress);
        var performance = await AuditAllModuleAsync(BuildPerformanceAuditPayloadAsync, "Performance audit", moduleTimings, auditProgress);
        var cve = await AuditAllModuleAsync(BuildSecurityAuditPayloadAsync, "CVE security scan", moduleTimings, auditProgress);
        var xss = await AuditAllModuleAsync(BuildSecurityXssPayloadAsync, "DOM XSS scan", moduleTimings, auditProgress);
        var mixedContent = await AuditAllModuleAsync(BuildMixedContentPayloadAsync, "Mixed content scan", moduleTimings, auditProgress);
        var sourceMaps = await AuditAllModuleAsync(BuildSourceMapPayloadAsync, "Source map scan", moduleTimings, auditProgress);

        bool cveClean = GetAnonymousBool(cve, "isClean");
        bool xssClean = GetAnonymousBool(xss, "isClean");
        bool mixedClean = GetAnonymousBool(mixedContent, "isClean");
        bool sourceMapsClean = GetAnonymousBool(sourceMaps, "isClean");
        var security = new
        {
            isClean = cveClean && xssClean && mixedClean && sourceMapsClean,
            cve,
            xss,
            mixedContent,
            sourceMaps
        };

        var securityHeaders = await AuditAllModuleAsync(() => BuildSecurityHeadersAuditPayloadAsync(), "Security headers audit", moduleTimings, auditProgress);
        var cookieSecurity = await AuditAllModuleAsync(BuildCookieAuditPayloadAsync, "Cookie security audit", moduleTimings, auditProgress);
        var storageSecurity = await AuditAllModuleAsync(BuildStorageAuditPayloadAsync, "Storage security audit", moduleTimings, auditProgress);
        var techStack = await AuditAllModuleAsync(BuildTechStackPayloadAsync, "Tech stack detection", moduleTimings, auditProgress);
        ThirdParty.ThirdPartyResult? thirdPartyScan = null;
        object thirdParty;
        try
        {
            thirdPartyScan = await _context.CheckThirdParty();
            thirdParty = BuildThirdPartyPayload(thirdPartyScan);
        }
        catch (Exception ex)
        {
            thirdParty = new { error = $"Third-party inventory failed: {ex.Message}", isClean = (bool?)null };
        }
        var validateHtml = await AuditAllModuleAsync(BuildValidateHtmlAuditPayloadAsync, "HTML validation", moduleTimings, auditProgress);
        var compatibility = await AuditAllModuleAsync(() => BuildCompatibilityAuditPayloadAsync(body), "Compatibility audit", moduleTimings, auditProgress);
        var checkLinks = await AuditAllModuleAsync(() => BuildCheckLinksPayloadAsync(body), "Link check", moduleTimings, auditProgress);
        var consistency = await AuditAllModuleAsync(BuildConsistencyPayloadAsync, "GUI consistency audit", moduleTimings, auditProgress);
        var seo = await AuditAllModuleAsync(BuildSeoAuditPayloadAsync, "SEO audit", moduleTimings, auditProgress);
        var smuggling = await AuditAllModuleAsync(BuildSmugglingPassivePayloadAsync, "Smuggling passive check", moduleTimings, auditProgress);

        object? secretsHarvest = null;
        bool secretsHarvestClean = true;
        if (AuditAllInclude(body, "includeSecretsHarvest", true))
        {
            var safety = SafetyGate.Resolve(body);
            var harvestOpts = new Security.SecretsHarvestPipeline.HarvestOptions
            {
                IncludeJsBundles = safety.AllowsWriteVerbs(),
                IncludeCookiesAndStorage = true,
                IncludeNetworkResponses = true,
                IncludePageText = true,
                IncludeSourceMaps = safety.AllowsWriteVerbs(),
                IncludeHtmlComments = true,
                MaxJsScripts = body.GetInt("maxJsScripts", 12),
                MaxBytesPerFile = Math.Clamp(body.GetInt("maxBytesPerFile", 524_288), 8_192, 2_000_000),
                TimeoutMs = body.GetInt("secretsHarvestTimeoutMs", 20000),
                ScopeHost = auditScopeHost,
                LimitNetworkToScopeHost = !IsAuditNetworkScopeSession(body)
            };
            secretsHarvest = await AuditAllModuleAsync(
                async () =>
                {
                    var r = await Security.SecretsHarvestPipeline.RunAsync(_context, harvestOpts);
                    return new
                    {
                        isClean = r.TotalFindings == 0,
                        totalFindings = r.TotalFindings,
                        warnings = r.Warnings,
                        summary = r.Summary,
                        sourcesScanned = r.SourcesScanned,
                        findings = r.Findings.Take(25).Select(f => new
                        {
                            f.Source,
                            f.Category,
                            f.Severity,
                            f.Location,
                            f.Description,
                            f.Snippet
                        }).ToList(),
                        passiveOnly = !safety.AllowsWriteVerbs(),
                        elapsedMs = r.ElapsedMs
                    };
                },
                "Secrets harvest",
                moduleTimings,
                auditProgress);
            secretsHarvestClean = GetAnonymousBool(secretsHarvest, "isClean");
        }

        object? csrf = null;
        bool csrfClean = true;
        if (body.GetBool("includeCsrf", false) && SafetyGate.Resolve(body).AllowsWriteVerbs())
        {
            csrf = await AuditAllModuleAsync(() => BuildCsrfAuditPayloadAsync(body), "CSRF validation", moduleTimings, auditProgress);
            csrfClean = GetAnonymousBool(csrf, "isClean");
        }

        object? brokenAccessControl = null;
        bool brokenAccessControlClean = true;
        if (AuditAllInclude(body, "includeBrokenAccessControl", true))
        {
            brokenAccessControl = await AuditAllModuleAsync(() => BuildBrokenAccessControlAuditPayloadAsync(body), "Broken access control", moduleTimings, auditProgress);
            brokenAccessControlClean = GetAnonymousBool(brokenAccessControl, "isClean");
        }

        object? misconfiguration = null;
        bool misconfigurationClean = true;
        if (AuditAllInclude(body, "includeMisconfiguration", true))
        {
            misconfiguration = await AuditAllModuleAsync(() => BuildMisconfigurationAuditPayloadAsync(body), "Security misconfiguration", moduleTimings, auditProgress);
            misconfigurationClean = GetAnonymousBool(misconfiguration, "isClean");
        }

        object? supplyChain = null;
        bool supplyChainClean = true;
        if (AuditAllInclude(body, "includeSupplyChain", true))
        {
            if (thirdPartyScan != null)
            {
                supplyChain = await AuditAllModuleAsync(
                    () => BuildSupplyChainAuditPayloadAsync(body, thirdPartyScan),
                    "Supply chain audit",
                    moduleTimings,
                    auditProgress);
            }
            else
            {
                supplyChain = new { error = "Supply chain audit skipped: third-party inventory unavailable.", isClean = (bool?)null };
            }
            supplyChainClean = GetAnonymousBool(supplyChain, "isClean");
        }

        object? cryptographicFailures = null;
        bool cryptographicFailuresClean = true;
        if (AuditAllInclude(body, "includeCryptographicFailures", true))
        {
            cryptographicFailures = await AuditAllModuleAsync(() => BuildCryptographicFailuresAuditPayloadAsync(body), "Cryptographic failures", moduleTimings, auditProgress);
            cryptographicFailuresClean = GetAnonymousBool(cryptographicFailures, "isClean");
        }

        object? injectionFailures = null;
        bool injectionFailuresClean = true;
        if (AuditAllInclude(body, "includeInjectionFailures", true))
        {
            injectionFailures = await AuditAllModuleAsync(() => BuildInjectionFailuresAuditPayloadAsync(body), "Injection failures", moduleTimings, auditProgress);
            injectionFailuresClean = GetAnonymousBool(injectionFailures, "isClean");
        }

        object? integrityFailures = null;
        bool integrityFailuresClean = true;
        if (AuditAllInclude(body, "includeIntegrityFailures", true))
        {
            integrityFailures = await AuditAllModuleAsync(
                () => BuildIntegrityFailuresAuditPayloadAsync(body, thirdPartyScan),
                "Integrity failures",
                moduleTimings,
                auditProgress);
            integrityFailuresClean = GetAnonymousBool(integrityFailures, "isClean");
        }

        object? insecureDesign = null;
        bool insecureDesignClean = true;
        if (AuditAllInclude(body, "includeInsecureDesign", true))
        {
            insecureDesign = await AuditAllModuleAsync(
                () => BuildInsecureDesignAuditPayloadAsync(body),
                "Insecure design",
                moduleTimings,
                auditProgress);
            insecureDesignClean = GetAnonymousBool(insecureDesign, "isClean");
        }

        object? authenticationFailures = null;
        bool authenticationFailuresClean = true;
        if (AuditAllInclude(body, "includeAuthenticationFailures", true))
        {
            authenticationFailures = await AuditAllModuleAsync(
                () => BuildAuthenticationFailuresAuditPayloadAsync(body),
                "Authentication failures",
                moduleTimings,
                auditProgress);
            authenticationFailuresClean = GetAnonymousBool(authenticationFailures, "isClean");
        }

        object? serverSideFetch = null;
        bool serverSideFetchClean = true;
        if (AuditAllInclude(body, "includeServerSideFetch", true))
        {
            serverSideFetch = await AuditAllModuleAsync(
                () => BuildServerSideFetchAuditPayloadAsync(body),
                "Server-side fetch (SSRF)",
                moduleTimings,
                auditProgress);
            serverSideFetchClean = GetAnonymousBool(serverSideFetch, "isClean");
        }

        object? apiInventory = null;
        bool apiInventoryClean = true;
        if (AuditAllInclude(body, "includeApiInventory", true))
        {
            apiInventory = await AuditAllModuleAsync(() => BuildApiInventoryAuditPayloadAsync(body), "API inventory", moduleTimings, auditProgress);
            apiInventoryClean = GetAnonymousBool(apiInventory, "isClean");
        }

        object? clickjack = null;
        bool clickjackClean = true;
        if (body.GetBool("includeClickjack", false))
        {
            clickjack = await AuditAllModuleAsync(() => BuildClickjackAuditPayloadAsync(body), "Clickjacking test", moduleTimings, auditProgress);
            clickjackClean = GetAnonymousBool(clickjack, "isClean");
        }

        object? aiIntegration = null;
        bool aiIntegrationClean = true;
        if (AuditAllInclude(body, "includeAiIntegration", true))
        {
            aiIntegration = await AuditAllModuleAsync(() => BuildAiIntegrationAuditPayloadAsync(body), "AI integration", moduleTimings, auditProgress);
            aiIntegrationClean = GetAnonymousBool(aiIntegration, "isClean");
        }

        object? protocolLayer = null;
        bool protocolLayerClean = true;
        if (AuditAllInclude(body, "includeProtocolLayer", true))
        {
            protocolLayer = await AuditAllModuleAsync(
                () => BuildProtocolLayerAuditPayloadAsync(body, smuggling),
                "Protocol layer (A14)",
                moduleTimings,
                auditProgress);
            protocolLayerClean = GetAnonymousBool(protocolLayer, "isClean");
        }

        sw.Stop();

        bool accessibilityClean = GetAnonymousBool(accessibility, "isClean");
        bool performanceGood = GetAnonymousBool(performance, "isGood");
        bool securityClean = GetAnonymousBool(security, "isClean");
        bool securityHeadersClean = GetAnonymousBool(securityHeaders, "isClean");
        bool cookieSecurityClean = GetAnonymousBool(cookieSecurity, "isClean");
        bool storageSecurityClean = GetAnonymousBool(storageSecurity, "isClean");
        bool htmlValid = GetAnonymousBool(validateHtml, "isValid");
        bool compatibilityOk = GetAnonymousBool(compatibility, "isCompatible");
        bool linksClean = GetAnonymousBool(checkLinks, "isClean");
        bool consistencyClean = GetAnonymousBool(consistency, "isClean");
        bool seoClean = GetAnonymousBool(seo, "isClean");
        bool thirdPartyClean = GetAnonymousBool(thirdParty, "isClean");
        bool smugglingClean = GetAnonymousBool(smuggling, "isClean");

        bool allPassed = accessibilityClean && performanceGood && securityClean && securityHeadersClean
            && cookieSecurityClean && storageSecurityClean && htmlValid && compatibilityOk && linksClean && consistencyClean
            && seoClean && smugglingClean && thirdPartyClean && supplyChainClean && secretsHarvestClean && csrfClean && brokenAccessControlClean
            && misconfigurationClean && cryptographicFailuresClean && injectionFailuresClean
            && integrityFailuresClean && insecureDesignClean && authenticationFailuresClean
            && serverSideFetchClean && apiInventoryClean && clickjackClean && aiIntegrationClean
            && protocolLayerClean;

        var findings = BuildConsolidatedFindings(
            accessibility, performance, cve, xss, mixedContent, sourceMaps,
            securityHeaders, cookieSecurity, storageSecurity, validateHtml,
            compatibility, checkLinks, consistency, seo, smuggling, csrf, brokenAccessControl, misconfiguration,
            thirdParty, supplyChain, apiInventory, clickjack);

        return new
        {
            elapsedMs = sw.ElapsedMilliseconds,
            partial = auditProgress.Partial,
            cancelNote = auditProgress.Partial
                ? "One or more modules were skipped after abort or cancel; completed modules are included below."
                : (string?)null,
            networkScope = auditNetworkScope,
            scopeHost = auditScopeHost,
            moduleTimings,
            summary = new
            {
                allPassed,
                findingCount = findings.Count,
                accessibilityClean,
                performanceGood,
                securityClean,
                securityHeadersClean,
                cookieSecurityClean,
                storageSecurityClean,
                htmlValid,
                compatibilityOk,
                linksClean,
                consistencyClean,
                seoClean,
                smugglingClean,
                thirdPartyClean,
                supplyChainClean,
                secretsHarvestClean,
                csrfClean,
                brokenAccessControlClean,
                misconfigurationClean,
                cryptographicFailuresClean,
                injectionFailuresClean,
                integrityFailuresClean,
                insecureDesignClean,
                authenticationFailuresClean,
                serverSideFetchClean,
                apiInventoryClean,
                clickjackClean,
                aiIntegrationClean,
                protocolLayerClean
            },
            findings,
            accessibility,
            performance,
            security,
            securityHeaders,
            cookieSecurity,
            storageSecurity,
            techStack,
            thirdParty,
            supplyChain,
            validateHtml,
            compatibility,
            checkLinks,
            consistency,
            seo,
            smuggling,
            secretsHarvest,
            csrf,
            brokenAccessControl,
            misconfiguration,
            cryptographicFailures,
            injectionFailures,
            integrityFailures,
            insecureDesign,
            authenticationFailures,
            serverSideFetch,
            apiInventory,
            clickjack,
            aiIntegration,
            protocolLayer
        };
    }

    internal async Task<object> BuildProtocolLayerAuditPayloadAsync(JsonBody body, object smugglingPassive)
    {
        var cached = _context.GetAutoScanFindingsForChain();
        var openRedirectCount = cached.Count(f =>
            f.Scanner.Equals("open-redirect", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("open redirect", StringComparison.OrdinalIgnoreCase));
        var cacheDeceptionCount = cached.Count(f =>
            f.Scanner.Equals("cache-deception", StringComparison.OrdinalIgnoreCase));
        var cachePoisonCount = cached.Count(f =>
            f.Scanner.Equals("cache-poison", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("cache poison", StringComparison.OrdinalIgnoreCase));

        var manualChains = ChainAnalysisService.CollectFindings(_context);
        var cachePoisonChainCount = manualChains.Count(f =>
            f.Category.Contains("header-injection", StringComparison.OrdinalIgnoreCase)
            || f.Category.Contains("cache", StringComparison.OrdinalIgnoreCase));

        var smugglingRisk = smugglingPassive.GetType().GetProperty("risk")?.GetValue(smugglingPassive) as string ?? "unknown";
        var smugglingElevated = smugglingRisk is "medium" or "high";
        var proxyDetected = smugglingPassive.GetType().GetProperty("proxyDetected")?.GetValue(smugglingPassive) is true;

        var wsConnections = _context.ActiveTab.WebSocket.GetConnections()
            .Count(c => c.State is "open" or "connecting");
        var websocketFindingCount = 0;
        foreach (var conn in _context.ActiveTab.WebSocket.GetConnections().Where(c => c.State == "open").Take(3))
        {
            var audit = WebSocketAuditor.Audit(conn, _context.ActiveTab.WebSocket);
            websocketFindingCount += audit.Findings.Count;
        }

        var issueCount = openRedirectCount + cacheDeceptionCount + cachePoisonCount
            + cachePoisonChainCount + websocketFindingCount + (smugglingElevated ? 1 : 0);

        string? recommendation = null;
        if (issueCount > 0 || smugglingElevated || wsConnections > 0)
        {
            recommendation = "Run protocol-layer scans with safetyMode: \"active\" — " +
                "POST /api/security/open-redirect-scan, /api/security/cache-deception-scan (authed session), " +
                "/api/security/cache-poison-scan (when CDN/proxy detected), /api/security/smuggling, " +
                "/api/security/websocket-fuzz when WebSocket connections are active.";
        }

        return new
        {
            isClean = issueCount == 0 && !smugglingElevated,
            openRedirectCount,
            cacheDeceptionCount,
            cachePoisonCount = cachePoisonCount + cachePoisonChainCount,
            smugglingRisk,
            smugglingElevated,
            proxyDetected,
            websocketConnections = wsConnections,
            websocketFindingCount,
            issueCount,
            recommendation
        };
    }

    internal async Task<object> BuildAiIntegrationAuditPayloadAsync(JsonBody body)
    {
        var surface = await _context.RunLlmEndpointDiscover();
        var passiveFindings = new List<object>();

        if (surface.HasAiIntegration)
        {
            foreach (var ep in surface.Endpoints.Take(5))
                passiveFindings.Add(new { category = "llm-endpoint", severity = "info", detail = ep.MatchReason, url = ep.Url });

            if (surface.WebMcpToolCount > 0)
                passiveFindings.Add(new { category = "webmcp-tools", severity = "info", detail = $"{surface.WebMcpToolCount} WebMCP tool(s) exposed to page context" });
        }

        object? activeScan = null;
        var hasActiveFindings = false;
        var safety = SafetyGate.Resolve(body);
        if (safety.AllowsWriteVerbs()
            && body.GetBool("includeActiveLlmRedteam", false)
            && surface.HasAiIntegration)
        {
            var scan = await _context.RunLlmRedTeamScan(new Security.LlmRedTeam.LlmRedTeamScanOptions
            {
                MaxProbes = Math.Clamp(body.GetInt("llmRedteamMaxProbes", 8), 1, 24),
                IncludeWebMcpAbuse = body.GetBool("includeWebMcpAbuse", true),
                IncludeIndirectInjection = false,
                RegisterWhisperHints = true
            });
            activeScan = LlmRedTeamRequestParser.FormatScanResult(scan);
            hasActiveFindings = scan.HasFindings;
        }

        var aiSecrets = 0;
        foreach (var entry in _context.GetPageNetworkLog())
        {
            if (!IsAiRelatedUrl(entry.Url)) continue;
            var bodyText = entry.ResponseBody ?? entry.RequestBody ?? "";
            if (bodyText.Contains("sk-", StringComparison.Ordinal)
                || bodyText.Contains("AKIA", StringComparison.Ordinal))
                aiSecrets++;
        }

        if (aiSecrets > 0)
            passiveFindings.Add(new { category = "llm-secrets-in-traffic", severity = "high", detail = $"{aiSecrets} AI-related response(s) with secret-like patterns" });

        var isPassiveOnly = !safety.AllowsWriteVerbs() || !body.GetBool("includeActiveLlmRedteam", false);
        var hasHighConfidenceEndpoints = surface.Endpoints.Any(e => e.Confidence >= 50);
        var isClean = !hasActiveFindings && aiSecrets == 0
            && !(isPassiveOnly && (surface.HasAiIntegration || hasHighConfidenceEndpoints));
        return new
        {
            isClean,
            surface = LlmRedTeamRequestParser.FormatSurface(surface),
            passiveFindings,
            activeScan,
            passiveOnly = isPassiveOnly,
            hint = surface.HasAiIntegration
                ? isPassiveOnly
                    ? "AI integration detected — set includeActiveLlmRedteam: true with safetyMode: \"active\" for OWASP LLM probe corpus. isClean reflects untested surface."
                    : "Run POST /api/security/llm-redteam-scan with safetyMode: \"active\" for full OWASP LLM probe corpus."
                : "No AI/chat integration detected on current page/network."
        };
    }

    private static bool IsAiRelatedUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        return url.Contains("/chat", StringComparison.OrdinalIgnoreCase)
            || url.Contains("/completion", StringComparison.OrdinalIgnoreCase)
            || url.Contains("/assistant", StringComparison.OrdinalIgnoreCase)
            || url.Contains("/v1/messages", StringComparison.OrdinalIgnoreCase);
    }

    internal async Task<object> BuildApiInventoryAuditPayloadAsync(JsonBody body)
    {
        try
        {
            var surfaceOptions = await ResolveAttackSurfaceOptionsAsync(body);
            surfaceOptions.SpaMode = surfaceOptions.SpaMode || _context.Network.Entries.Count == 0;
            surfaceOptions.CheckSecurityTxt = false;

            if (!body.HasProperty("maxWordPressRestRoutes"))
                surfaceOptions.MaxWordPressRestRoutes = 512;
            if (!body.HasProperty("maxJsScripts"))
                surfaceOptions.MaxJsScripts = 12;
            if (!body.HasProperty("maxProbeOrigins"))
                surfaceOptions.MaxProbeOrigins = 4;

            if (!surfaceOptions.SpaMode && _context.Network.Entries.Count == 0)
            {
                return new
                {
                    isClean = true,
                    skipped = true,
                    note = "No network traffic — browse first or set spaMode: true for passive API inventory."
                };
            }

            var maxSeconds = Math.Clamp(body.GetInt("apiInventoryMaxSeconds", 90), 15, 600);
            using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(_context.OperationCancellation);
            budgetCts.CancelAfter(TimeSpan.FromSeconds(maxSeconds));

            Security.ApiInventoryAnalyzer.InventoryResult inventory;
            try
            {
                inventory = await Security.ApiInventoryPayload.RunForSessionAsync(
                    _context,
                    surfaceOptions,
                    new Security.ApiInventoryAnalyzer.AnalyzeOptions
                    {
                        IncludeAuthDeltaProbes = body.GetBool("includeAuthDeltaProbes", false) &&
                                                 SafetyGate.Resolve(body).AllowsWriteVerbs(),
                        MaxAuthDeltaProbes = Math.Clamp(body.GetInt("maxAuthDeltaProbes", 8), 1, 20)
                    },
                    budgetCts.Token);
            }
            catch (OperationCanceledException) when (budgetCts.IsCancellationRequested
                                                     && !_context.OperationCancellation.IsCancellationRequested)
            {
                return new
                {
                    isClean = (bool?)null,
                    partial = true,
                    timedOut = true,
                    apiInventoryMaxSeconds = maxSeconds,
                    note =
                        "API inventory enrichment exceeded apiInventoryMaxSeconds. " +
                        "Raise apiInventoryMaxSeconds, set includeApiInventory:false for a quick audit-all, " +
                        "or run POST /api/security/api-inventory with explicit attack-surface caps."
                };
            }

            if (body.GetBool("registerChainFindings", true))
            {
                var navUrl = await _context.GetCurrentUrl();
                foreach (var finding in Security.ApiInventoryPayload.ToChainFindings(inventory, navUrl))
                    _context.AddManualChainFinding(finding);
            }

            var payload = Security.ApiInventoryPayload.Serialize(inventory);
            return payload;
        }
        catch (OperationCanceledException) when (_context.OperationCancellation.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new { isClean = (bool?)null, error = ex.Message };
        }
    }

    internal async Task<object> BuildClickjackAuditPayloadAsync(JsonBody body)
    {
        var includeActive = body.GetBool("includeClickjackActive", false) &&
                            SafetyGate.Resolve(body).AllowsWriteVerbs();
        try
        {
            var result = await Security.ClickjackSweep.RunAsync(
                _context,
                new Security.ClickjackSweep.SweepOptions
                {
                    IncludeAttackSurfaceUrls = body.GetBool("includeClickjackSweep", true),
                    IncludeDefaultCandidates = true,
                    MaxUrls = Math.Clamp(body.GetInt("clickjackMaxUrls", 8), 1, 20),
                    IncludeActiveTest = includeActive,
                    IncludeSensitiveOverlayTest = false,
                    TimeoutMs = Math.Clamp(body.GetInt("clickjackTimeoutMs", 8000), 3000, 20000)
                });

            return Security.ClickjackPayload.Serialize(result, sweepMode: true);
        }
        catch (Exception ex)
        {
            return new { isClean = (bool?)null, error = ex.Message };
        }
    }

    internal async Task<object> BuildInjectionFailuresAuditPayloadAsync(JsonBody body)
    {
        var cached = _context.GetAutoScanFindingsForChain();
        var sqliCount = cached.Count(f => f.Scanner.Equals("sqli", StringComparison.OrdinalIgnoreCase));
        var sstiCount = cached.Count(f => f.Scanner.Equals("ssti", StringComparison.OrdinalIgnoreCase)
                                          || f.Title.Contains("SSTI", StringComparison.OrdinalIgnoreCase));
        var cmdCount = cached.Count(f => f.Scanner.Equals("command-injection", StringComparison.OrdinalIgnoreCase)
                                         || f.Scanner.Equals("cmd-canary", StringComparison.OrdinalIgnoreCase)
                                         || f.Title.Contains("Cmd canary", StringComparison.OrdinalIgnoreCase));
        var nosqlCount = cached.Count(f => f.Scanner.Equals("nosql", StringComparison.OrdinalIgnoreCase));
        var ldapCount = cached.Count(f => f.Scanner.Equals("ldap", StringComparison.OrdinalIgnoreCase));
        var parserCount = cached.Count(f =>
            f.Scanner.Equals("deserialization-suspected", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("content-type-confusion", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("parser-differential", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("Parser probe", StringComparison.OrdinalIgnoreCase));
        var deserialCount = cached.Count(f =>
            f.Scanner.Equals("rce-deserialization", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("deserialization-dos", StringComparison.OrdinalIgnoreCase));
        var uploadCount = cached.Count(f =>
            f.Scanner.StartsWith("file-upload", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("xxe-upload", StringComparison.OrdinalIgnoreCase));
        var totalCached = sqliCount + sstiCount + cmdCount + nosqlCount + ldapCount
                          + parserCount + deserialCount + uploadCount;

        object? activeSqli = null;
        var activeFindingCount = 0;
        if (SafetyGate.Resolve(body).AllowsWriteVerbs() && body.GetBool("includeActiveInjectionProbe", true))
        {
            try
            {
                var currentUrl = await _context.GetCurrentUrl();
                if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
                {
                    var origin = uri.GetLeftPart(UriPartial.Authority);
                    var points = InjectionPointDiscovery.DiscoverFromNetwork(_context, origin, 8);
                    var pt = points.FirstOrDefault(p =>
                        Security.RequestMarkerSubstitute.ListMarkers(p.UrlTemplate ?? p.Url, p.BodyTemplate).Count > 0);
                    if (pt != null)
                    {
                        var urlTemplate = pt.UrlTemplate ?? pt.Url;
                        var bodyTemplate = pt.BodyTemplate;
                        if (bodyTemplate != null
                            && Security.RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate).Count == 0
                            && !string.IsNullOrEmpty(pt.ParamName))
                        {
                            bodyTemplate = Security.InjectionJsonBody.InjectMarkerIntoFirstStringField(
                                bodyTemplate, "§INJECT§", pt.ParamName);
                        }

                        var sqliResult = await Security.HttpSecurityProbes.RunSqliScanAsync(
                            _context, urlTemplate, pt.Method, pt.Headers, bodyTemplate,
                            baselineMarkerValue: "1", customPayloads: null,
                            includeTimeBased: false, timeoutMs: body.GetInt("injectionProbeTimeoutMs", 12000),
                            maxBodyChars: 65536, useBackendFetch: body.GetBool("injectionUseBackendFetch", true),
                            includeBrowserCookies: body.GetBool("injectionIncludeBrowserCookies", true));

                        activeFindingCount = sqliResult.Rows.Count(r => r.Types.Count > 0);
                        activeSqli = new
                        {
                            paramName = pt.ParamName,
                            url = pt.Url,
                            findingCount = activeFindingCount,
                            summary = sqliResult.Summary,
                            types = sqliResult.Rows.Where(r => r.Types.Count > 0)
                                .Select(r => new { r.Payload, types = r.Types }).Take(5).ToList()
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                activeSqli = new { error = ex.Message };
            }
        }

        var total = totalCached + activeFindingCount;
        return new
        {
            isClean = total == 0,
            cachedAutoScanFindings = new
            {
                sqli = sqliCount,
                ssti = sstiCount,
                cmdCanary = cmdCount,
                nosql = nosqlCount,
                ldap = ldapCount,
                parserProbe = parserCount,
                deserialization = deserialCount,
                fileUpload = uploadCount,
                total = totalCached
            },
            activeSqliProbe = activeSqli,
            issueCount = total,
            recommendation = totalCached == 0 && activeSqli == null
                ? "Browse the app, then run POST /api/security/auto-scan with safetyMode: \"active\" to populate injection findings."
                : null
        };
    }

    internal async Task<object> BuildIntegrityFailuresAuditPayloadAsync(JsonBody body, ThirdParty.ThirdPartyResult? thirdParty)
    {
        var safety = SafetyGate.Resolve(body);
        var cached = _context.GetAutoScanFindingsForChain();
        var parserCount = cached.Count(f =>
            f.Scanner.Equals("deserialization-suspected", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("content-type-confusion", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("parser-differential", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("Parser probe", StringComparison.OrdinalIgnoreCase));
        var deserialCount = cached.Count(f =>
            f.Scanner.Equals("rce-deserialization", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("deserialization-dos", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("Deserialization:", StringComparison.OrdinalIgnoreCase));
        var uploadCount = cached.Count(f =>
            f.Scanner.StartsWith("file-upload", StringComparison.OrdinalIgnoreCase)
            || f.Scanner.Equals("xxe-upload", StringComparison.OrdinalIgnoreCase));
        var totalCached = parserCount + deserialCount + uploadCount;

        var externalWithoutSri = thirdParty?.Resources.Count(r =>
            !r.HasSri && r.Type is "script" or "stylesheet") ?? 0;

        var ciCdPathsAccessible = 0;
        var manifestPathsAccessible = 0;
        try
        {
            var pageUrl = await _context.GetCurrentUrl();
            if (!string.IsNullOrEmpty(pageUrl) && safety.AllowsWriteVerbs())
            {
                ciCdPathsAccessible = await Security.SupplyChain.CiCdExposureChecker.ProbePathCountAsync(
                    _context, pageUrl, body.GetInt("integrityProbeTimeoutMs", 12_000),
                    body.GetBool("includeBrowserCookies", true));
                manifestPathsAccessible = await Security.SupplyChain.ManifestFetcher.ProbeManifestPathCountAsync(
                    _context, pageUrl, body.GetInt("integrityProbeTimeoutMs", 12_000),
                    body.GetBool("includeBrowserCookies", true));
            }
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        object? activeIntegrity = null;
        var activeCount = 0;
        if (safety.AllowsWriteVerbs() && body.GetBool("includeActiveIntegrityProbe", true))
        {
            try
            {
                var deserial = await _context.RunDeserializationScan(new DeserializationScanProbe.DeserializationScanOptions
                {
                    MaxCandidates = body.GetInt("integrityMaxCandidates", 4),
                    TimeoutMs = body.GetInt("integrityProbeTimeoutMs", 12000)
                });
                var upload = await _context.RunFileUploadScan(new FileUploadScanProbe.FileUploadScanOptions
                {
                    MaxCandidates = body.GetInt("integrityMaxCandidates", 4),
                    TimeoutMs = body.GetInt("integrityProbeTimeoutMs", 12000),
                    IncludeXxe = body.GetBool("includeUploadXxeInIntegrity", true)
                });
                activeCount = deserial.Findings.Count + upload.Findings.Count + upload.XxeFindings.Count;
                activeIntegrity = new
                {
                    deserialization = new { findingCount = deserial.Findings.Count, message = deserial.Message },
                    fileUpload = new
                    {
                        findingCount = upload.Findings.Count,
                        xxeFindingCount = upload.XxeFindings.Count,
                        message = upload.Message
                    }
                };
            }
            catch (Exception ex)
            {
                activeIntegrity = new { error = ex.Message };
            }
        }

        var passiveIssues = (externalWithoutSri > 0 ? 1 : 0)
                            + (ciCdPathsAccessible > 0 ? 1 : 0)
                            + (manifestPathsAccessible > 0 ? 1 : 0);
        var total = totalCached + activeCount + passiveIssues;

        return new
        {
            isClean = total == 0,
            externalWithoutSri,
            ciCdPathsAccessible,
            manifestPathsAccessible,
            cachedAutoScanFindings = new
            {
                parserProbe = parserCount,
                deserialization = deserialCount,
                fileUpload = uploadCount,
                total = totalCached
            },
            activeIntegrityProbe = activeIntegrity,
            issueCount = total,
            recommendation = total == 0
                ? null
                : "Review supplyChain SRI, run POST /api/security/deserialization-scan and POST /api/security/file-upload-scan with safetyMode: \"active\"."
        };
    }

    internal async Task<object> BuildServerSideFetchAuditPayloadAsync(JsonBody body)
    {
        var cached = _context.GetAutoScanFindingsForChain();
        var ssrfCached = cached.Count(f =>
            f.Scanner.Equals("ssrf", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("SSRF", StringComparison.OrdinalIgnoreCase));
        var openRedirectCached = cached.Count(f =>
            f.Scanner.Equals("open-redirect", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("open redirect", StringComparison.OrdinalIgnoreCase));
        var jwtAbuseCached = cached.Count(f =>
            f.Title.Contains("jku", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("x5u", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("jwt-header-abuse", StringComparison.OrdinalIgnoreCase));

        var manualSsrf = ChainAnalysisService.CollectFindings(_context)
            .Count(f => f.Category.Equals("ssrf", StringComparison.OrdinalIgnoreCase));

        object? activeSsrf = null;
        var activeCount = 0;
        if (SafetyGate.Resolve(body).AllowsWriteVerbs() && body.GetBool("includeActiveSsrfProbe", false))
        {
            try
            {
                var orchestrated = await _context.RunSsrfOrchestrator(
                    new Security.SsrfOrchestrator.OrchestratorOptions
                    {
                        MaxCandidates = body.GetInt("ssrfMaxCandidates", 6),
                        TimeoutMs = body.GetInt("ssrfProbeTimeoutMs", 12000),
                        IncludeScaffoldPaths = body.GetBool("includeSsrfScaffold", true),
                        IncludeOpenRedirect = body.GetBool("includeOpenRedirectInSsrf", true),
                        IncludeJwtHeaderAbuse = body.GetBool("includeJwtHeaderAbuseInSsrf", true),
                        IncludeChainAnalysis = false,
                        RegisterChainFindings = true
                    },
                    chainCatalog: _chainCatalog);
                activeCount = orchestrated.TotalFindings;
                activeSsrf = new
                {
                    findingCount = activeCount,
                    message = orchestrated.Message,
                    stepsRun = orchestrated.StepsRun,
                    ssrfFindings = orchestrated.Ssrf?.Findings.Count ?? 0,
                    openRedirectFindings = orchestrated.OpenRedirect?.Findings.Count ?? 0,
                    jwtHeaderAbuseFindings = orchestrated.JwtHeaderAbuse?.Findings.Count ?? 0,
                    callbackInteractions = orchestrated.CallbackInteractions
                };
            }
            catch (Exception ex)
            {
                activeSsrf = new { error = ex.Message };
            }
        }

        var total = ssrfCached + openRedirectCached + jwtAbuseCached + manualSsrf + activeCount;

        return new
        {
            isClean = total == 0,
            cachedAutoScanFindings = new
            {
                ssrf = ssrfCached,
                openRedirect = openRedirectCached,
                jwtHeaderAbuse = jwtAbuseCached,
                total = ssrfCached + openRedirectCached + jwtAbuseCached
            },
            manualChainFindings = manualSsrf,
            activeSsrfProbe = activeSsrf,
            issueCount = total,
            recommendation = total == 0
                ? null
                : "Run POST /api/security/ssrf-orchestrator with safetyMode: \"active\" for scaffold + metadata + IMDSv2 + open-redirect escalation."
        };
    }

    internal async Task<object> BuildInsecureDesignAuditPayloadAsync(JsonBody body)
    {
        var cached = _context.GetAutoScanFindingsForChain();
        var raceCached = cached.Count(f =>
            f.Scanner.Equals("race-condition", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("race condition", StringComparison.OrdinalIgnoreCase));
        var captchaCached = cached.Count(f =>
            f.Scanner.Equals("broken-anti-automation", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("CAPTCHA", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("captcha replay", StringComparison.OrdinalIgnoreCase));
        var workflowCached = cached.Count(f =>
            f.Scanner.Equals("workflow-step-skip", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("workflow step-skip", StringComparison.OrdinalIgnoreCase)
            || f.Title.Contains("step-skip", StringComparison.OrdinalIgnoreCase));

        var shadowRace = 0;
        var shadowCaptcha = 0;
        var shadowWorkflow = 0;
        if (_context.SecurityShadow?.Enabled == true)
        {
            foreach (var f in _context.SecurityShadow.GetFindings())
            {
                var cat = f.Audit?.ToLowerInvariant() ?? "";
                var title = f.Title?.ToLowerInvariant() ?? "";
                if (cat.Contains("race") || title.Contains("race condition")) shadowRace++;
                if (cat.Contains("captcha") || cat.Contains("anti-automation") || title.Contains("captcha"))
                    shadowCaptcha++;
                if (cat.Contains("workflow") || title.Contains("step-skip") || title.Contains("workflow skip"))
                    shadowWorkflow++;
            }
        }

        var totalCached = raceCached + captchaCached + workflowCached;
        var totalShadow = shadowRace + shadowCaptcha + shadowWorkflow;

        object? activeInsecureDesign = null;
        var activeCount = 0;
        if (SafetyGate.Resolve(body).AllowsWriteVerbs() && body.GetBool("includeActiveInsecureDesignProbe", true))
        {
            try
            {
                var maxCandidates = body.GetInt("insecureDesignMaxCandidates", 4);
                var timeoutMs = body.GetInt("insecureDesignProbeTimeoutMs", 8000);
                var includeCookies = body.GetBool("includeBrowserCookies", true);

                var race = await _context.RunRaceConditionScan(new RaceConditionScanProbe.RaceConditionScanOptions
                {
                    MaxCandidates = maxCandidates,
                    BurstSize = body.GetInt("insecureDesignBurstSize", 15),
                    TimeoutMs = timeoutMs,
                    IncludeBrowserCookies = includeCookies
                });
                var captcha = await _context.RunCaptchaReplayScan(new CaptchaReplayScanProbe.CaptchaReplayScanOptions
                {
                    MaxSubmitCandidates = maxCandidates,
                    TimeoutMs = timeoutMs,
                    IncludeBrowserCookies = includeCookies
                });
                var workflow = await _context.RunWorkflowSkipScan(new WorkflowSkipScanProbe.WorkflowSkipScanOptions
                {
                    MaxCandidates = maxCandidates,
                    TimeoutMs = timeoutMs,
                    IncludeBrowserCookies = includeCookies
                });

                activeCount = race.Findings.Count + captcha.Findings.Count + workflow.Findings.Count;
                activeInsecureDesign = new
                {
                    raceCondition = new { findingCount = race.Findings.Count, burstsSent = race.BurstsSent, message = race.Message },
                    captchaReplay = new { findingCount = captcha.Findings.Count, submitEndpointsTested = captcha.SubmitEndpointsTested, message = captcha.Message },
                    workflowSkip = new { findingCount = workflow.Findings.Count, probesSent = workflow.ProbesSent, message = workflow.Message }
                };
            }
            catch (Exception ex)
            {
                activeInsecureDesign = new { error = ex.Message };
            }
        }

        var total = totalCached + totalShadow + activeCount;
        return new
        {
            isClean = total == 0,
            cachedAutoScanFindings = new
            {
                raceCondition = raceCached,
                brokenAntiAutomation = captchaCached,
                workflowStepSkip = workflowCached,
                total = totalCached
            },
            shadowFindings = new
            {
                raceCondition = shadowRace,
                brokenAntiAutomation = shadowCaptcha,
                workflowStepSkip = shadowWorkflow,
                total = totalShadow
            },
            activeInsecureDesignProbe = activeInsecureDesign,
            issueCount = total,
            recommendation = total == 0
                ? null
                : "Review race-condition, captcha-replay, and workflow-skip findings; run dedicated scans with safetyMode: \"active\" after browsing multi-step flows."
        };
    }

    internal async Task<object> BuildAuthenticationFailuresAuditPayloadAsync(JsonBody body)
    {
        var cached = _context.GetAutoScanFindingsForChain();
        int CountScanner(params string[] scanners) => cached.Count(f =>
            scanners.Any(s => f.Scanner.Equals(s, StringComparison.OrdinalIgnoreCase))
            || scanners.Any(s => f.Title.Contains(s, StringComparison.OrdinalIgnoreCase)));

        var sqliLogin = CountScanner("sqli-login-sweep", "sqli login");
        var defaultCreds = CountScanner("default-credential-canary", "default-credential", "default credentials");
        var sessionFix = CountScanner("session-fixation-scan", "session fixation");
        var resetWeak = CountScanner("password-reset-weak", "security question");
        var accountEnum = CountScanner("account-enumeration", "account enum", "user enum");
        var logoutInv = CountScanner("logout-invalidation", "logout invalidation", "session still valid");
        var jwtAccept = CountScanner("jwt-acceptance-sweep", "jwt alg none", "jwt-acceptance");
        var authPivot = CountScanner("auth-bypass-pivot", "authenticated pivot");
        var nosql = CountScanner("nosql");
        var ldap = CountScanner("ldap");

        var shadowOauth = 0;
        var shadowSaml = 0;
        if (_context.SecurityShadow?.Enabled == true)
        {
            foreach (var f in _context.SecurityShadow.GetFindings())
            {
                var t = (f.Title + " " + f.Audit).ToLowerInvariant();
                if (t.Contains("oauth") || t.Contains("oidc") || t.Contains("pkce")) shadowOauth++;
                if (t.Contains("saml")) shadowSaml++;
            }
        }

        var sessionIdGrade = (string?)null;
        var resetTokenFindings = 0;
        var cookieFlagGaps = 0;
        try
        {
            var sid = await Security.SessionIdSampleCollector.CollectAndAnalyzeAsync(_context,
                new Security.SessionIdSampleCollector.CollectOptions
                {
                    MinSamples = body.GetInt("sessionIdMinSamples", 2),
                    PageNetworkOnly = body.GetBool("sessionIdPageNetworkOnly", false)
                });
            sessionIdGrade = sid.Analysis.Samples.FirstOrDefault()?.EntropyAssessment;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        try
        {
            var reset = await Security.ResetTokenSampleCollector.CollectAndAnalyzeAsync(_context,
                new Security.ResetTokenSampleCollector.CollectOptions
                {
                    MinSamples = body.GetInt("resetTokenMinSamples", 2),
                    PageNetworkOnly = body.GetBool("resetTokenPageNetworkOnly", false)
                });
            resetTokenFindings = reset.Analysis.Findings.Count(f => f.Severity >= Security.Severity.Medium);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        try
        {
            var cookies = await BuildCookieAuditPayloadAsync();
            if (!GetAnonymousBool(cookies, "isClean")) cookieFlagGaps = 1;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var totalCached = sqliLogin + defaultCreds + sessionFix + resetWeak + accountEnum + logoutInv
                          + jwtAccept + authPivot + nosql + ldap;
        var passiveIssueCount = totalCached + shadowOauth + shadowSaml + resetTokenFindings + cookieFlagGaps
                                + (sessionIdGrade is "weak" or "critical" ? 1 : 0);

        object? activeAuthProbe = null;
        var activeCount = 0;
        var safety = SafetyGate.Resolve(body);
        if (safety.AllowsWriteVerbs() && body.GetBool("includeActiveAuthenticationProbe", true))
        {
            try
            {
                var timeoutMs = body.GetInt("authProbeTimeoutMs", 12000);
                var sqli = await _context.RunSqliLoginSweep(new Security.SqliLoginSweep.SqliLoginSweepOptions
                {
                    MaxLoginUrls = body.GetInt("authSqliMaxLoginUrls", 4),
                    TimeoutMs = timeoutMs
                });
                var creds = await Security.DefaultCredentialCanary.RunAsync(_context,
                    new Security.DefaultCredentialCanary.CanaryOptions
                    {
                        MaxTargets = body.GetInt("authDefaultCredMaxTargets", 2),
                        MaxPairs = body.GetInt("authDefaultCredMaxPairs", 4),
                        DelayMs = 300,
                        TimeoutMs = timeoutMs,
                        RegisterChainFindings = false
                    });
                var captcha = await _context.RunCaptchaReplayScan(new Security.CaptchaReplayScanProbe.CaptchaReplayScanOptions
                {
                    MaxSubmitCandidates = body.GetInt("authCaptchaMaxCandidates", 3),
                    TimeoutMs = timeoutMs
                });

                activeCount = sqli.Findings.Count + creds.Findings.Count + captcha.Findings.Count;
                activeAuthProbe = new
                {
                    sqliLoginSweep = new { findingCount = sqli.Findings.Count, urlsProbed = sqli.LoginUrlsProbed, message = sqli.Message },
                    defaultCredentialCanary = new { findingCount = creds.Findings.Count, targetsTested = creds.TargetsTested, message = creds.Summary.FirstOrDefault() },
                    captchaReplay = new { findingCount = captcha.Findings.Count, submitEndpointsTested = captcha.SubmitEndpointsTested, message = captcha.Message }
                };
            }
            catch (Exception ex)
            {
                activeAuthProbe = new { error = ex.Message };
            }
        }

        var total = passiveIssueCount + activeCount;
        return new
        {
            isClean = total == 0,
            cachedAutoScanFindings = new
            {
                sqliLoginSweep = sqliLogin,
                defaultCredentials = defaultCreds,
                sessionFixation = sessionFix,
                passwordResetWeak = resetWeak,
                accountEnumeration = accountEnum,
                logoutInvalidation = logoutInv,
                jwtAcceptanceSweep = jwtAccept,
                authBypassPivot = authPivot,
                nosql = nosql,
                ldap = ldap,
                total = totalCached
            },
            shadowFindings = new { oauthOidc = shadowOauth, saml = shadowSaml, total = shadowOauth + shadowSaml },
            passiveSignals = new
            {
                sessionIdEntropyGrade = sessionIdGrade,
                resetTokenFindingCount = resetTokenFindings,
                sessionCookieFlagGaps = cookieFlagGaps
            },
            activeAuthenticationProbe = activeAuthProbe,
            issueCount = total,
            passiveOnly = !safety.AllowsWriteVerbs() || !body.GetBool("includeActiveAuthenticationProbe", true),
            recommendation = total == 0
                ? null
                : "Review authentication findings; run session-fixation-scan, account-enumeration-scan, password-reset-weak-scan, and logout-invalidation-probe with safetyMode: \"active\"."
        };
    }

    internal async Task<object> BuildCryptographicFailuresAuditPayloadAsync(JsonBody body)
    {
        var issueCount = 0;
        var hstsPresent = false;

        try
        {
            var headerResult = await _context.CheckSecurityHeaders();
            hstsPresent = headerResult.IsHttps && headerResult.HasStrictTransportSecurity;
            if (headerResult.IsHttps && !hstsPresent)
                issueCount++;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var mixedContentCount = 0;
        try
        {
            var mc = await BuildMixedContentPayloadAsync();
            if (!GetAnonymousBool(mc, "isClean"))
            {
                mixedContentCount = 1;
                issueCount++;
            }
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var sessionCookieFlagGaps = 0;
        try
        {
            var cookies = await BuildCookieAuditPayloadAsync();
            if (!GetAnonymousBool(cookies, "isClean"))
            {
                sessionCookieFlagGaps = 1;
                issueCount++;
            }
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var storageTokenCount = 0;
        try
        {
            var storage = await BuildStorageAuditPayloadAsync();
            if (!GetAnonymousBool(storage, "isClean"))
            {
                storageTokenCount = 1;
                issueCount++;
            }
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        string? sessionIdEntropyGrade = null;
        var minSamplesMet = false;
        try
        {
            var sid = await Security.SessionIdSampleCollector.CollectAndAnalyzeAsync(_context,
                new Security.SessionIdSampleCollector.CollectOptions
                {
                    MinSamples = body.GetInt("sessionIdMinSamples", 2),
                    PageNetworkOnly = body.GetBool("sessionIdPageNetworkOnly", false)
                });
            minSamplesMet = sid.MinSamplesMet;
            sessionIdEntropyGrade = sid.Analysis.Samples.FirstOrDefault()?.EntropyAssessment;
            issueCount += sid.Analysis.Findings.Count(f => f.Severity >= Security.Severity.Medium);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var jwtIssueCount = 0;
        try
        {
            var jwt = await Security.HttpSecurityProbes.RunJwtAnalyzeAsync(_context, null);
            jwtIssueCount = jwt.Tokens.Sum(t => t.Issues.Count);
            issueCount += jwtIssueCount;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var plaintextPasswordRequests = 0;
        try
        {
            foreach (var entry in _context.Network.Entries)
            {
                if (string.IsNullOrWhiteSpace(entry.RequestBody)) continue;
                plaintextPasswordRequests += Security.NetworkRequestCredentialHeuristics
                    .DetectPlaintextCredentials(entry.Url, entry.Method, entry.RequestBody, entry.ContentType)
                    .Count(h => !h.IsHashed);
            }
            issueCount += plaintextPasswordRequests;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        object? resetTokenAnalysis = null;
        var resetTokenFindingCount = 0;
        try
        {
            var reset = await Security.ResetTokenSampleCollector.CollectAndAnalyzeAsync(_context,
                new Security.ResetTokenSampleCollector.CollectOptions
                {
                    MinSamples = body.GetInt("resetTokenMinSamples", 2),
                    PageNetworkOnly = body.GetBool("resetTokenPageNetworkOnly", false)
                });
            resetTokenFindingCount = reset.Analysis.Findings.Count(f => f.Severity >= Security.Severity.Medium);
            issueCount += resetTokenFindingCount;
            resetTokenAnalysis = new
            {
                isClean = reset.Analysis.IsClean,
                minSamplesMet = reset.MinSamplesMet,
                totalSampleCount = reset.TotalSampleCount,
                resetEndpointsSeen = reset.ResetEndpointsSeen,
                entropyAssessment = reset.Analysis.Samples.FirstOrDefault()?.EntropyAssessment,
                findings = reset.Analysis.Findings.Take(8).Select(f => new
                {
                    severity = f.Severity.ToString().ToLower(),
                    category = f.Category,
                    description = f.Description
                }).ToList(),
                recommendations = reset.Recommendations
            };
        }
        catch (Exception ex)
        {
            resetTokenAnalysis = new { error = ex.Message };
        }

        var safety = SafetyGate.Resolve(body);
        object? jwtSweep = null;
        if (safety.AllowsWriteVerbs() && body.GetBool("includeJwtSweepInCrypto", false))
        {
            try
            {
                var js = await Security.JwtAcceptanceSweep.RunAsync(_context, new Security.JwtAcceptanceSweep.SweepOptions
                {
                    MaxEndpoints = body.GetInt("jwtSweepMaxEndpoints", 8),
                    IncludeAlgVariants = body.GetBool("includeAlgVariants", true),
                    BaseToken = body.GetString("jwtBaseToken")
                });
                jwtSweep = new
                {
                    endpointsTested = js.EndpointsTested,
                    variantFindings = js.VariantFindings,
                    rows = js.Rows.Where(r => r.Finding is "JWT_ALG_NONE_ACCEPTED" or "JWT_ALG_VARIANT_ACCEPTED" or "MISSING_AUTH").Take(10).ToList(),
                    summary = js.Summary
                };
                issueCount += js.Rows.Count(r => r.Finding is "JWT_ALG_NONE_ACCEPTED" or "JWT_ALG_VARIANT_ACCEPTED" or "MISSING_AUTH");
            }
            catch (Exception ex)
            {
                jwtSweep = new { error = ex.Message };
            }
        }

        object? tls = null;
        try
        {
            var tlsResult = await Security.TlsIntrospectionChecker.RunAsync(_context,
                new Security.TlsIntrospectionChecker.IntrospectionOptions
                {
                    MaxOrigins = body.GetInt("tlsMaxOrigins", 5),
                    IncludeLegacyTlsProbes = body.GetBool("includeLegacyTlsProbes", true)
                });
            tls = new
            {
                isClean = tlsResult.IsClean,
                findingCount = tlsResult.Findings.Count,
                origins = tlsResult.Origins.Take(5).ToList(),
                findings = tlsResult.Findings.Take(8).ToList(),
                summary = tlsResult.Summary,
                externalScannerNote = tlsResult.ExternalScannerNote
            };
            issueCount += tlsResult.Findings.Count;
        }
        catch (Exception ex)
        {
            tls = new { isClean = (bool?)null, error = ex.Message };
        }

        return new
        {
            isClean = issueCount == 0,
            issueCount,
            hstsPresent,
            mixedContentCount,
            sessionCookieFlagGaps,
            storageTokenCount,
            sessionIdEntropyGrade,
            minSamplesMet,
            jwtIssueCount,
            plaintextPasswordRequests,
            resetTokenFindingCount,
            resetTokenAnalysis,
            jwtSweep,
            tls,
            passiveOnly = !safety.AllowsWriteVerbs() || !body.GetBool("includeJwtSweepInCrypto", false),
            note = "Passive crypto pass: HSTS, mixed content, cookies, storage, session-id entropy, JWT analyze (exp/missing-exp, MD5 hash claims), plaintext password request bodies, reset-token entropy, TLS introspection. Set safetyMode: \"active\" + includeJwtSweepInCrypto for JWT acceptance sweep."
        };
    }

    internal async Task<object> BuildMisconfigurationAuditPayloadAsync(JsonBody body)
    {
        var pageUrl = await _context.GetCurrentUrl();
        var issueCount = 0;

        object cors;
        try
        {
            var corsResult = await _context.CheckCors();
            cors = new
            {
                isClean = corsResult.IsClean,
                issueCount = corsResult.IssueCount,
                url = corsResult.Url,
                findings = corsResult.Issues.Select(f => new
                {
                    origin = f.Origin,
                    severity = f.Severity?.ToString().ToLower(),
                    description = f.Description
                }).ToList()
            };
            issueCount += corsResult.IssueCount;
        }
        catch (Exception ex)
        {
            cors = new { isClean = (bool?)null, error = ex.Message };
        }

        object discoverSummary;
        try
        {
            var scanner = new Security.EndpointScanner(_context);
            var discover = await scanner.RunAsync("common", "/", 0, spaMode: true);
            var sensitive = discover.Discovered.Where(d =>
                d.StatusCode is >= 200 and < 300 && IsSensitiveDiscoverPath(d.Path)).ToList();
            discoverSummary = new
            {
                isClean = sensitive.Count == 0,
                scannedCount = discover.ScannedCount,
                accessibleCount = discover.Discovered.Count(d => d.StatusCode is >= 200 and < 300),
                accessibleSensitiveCount = sensitive.Count,
                sensitivePaths = sensitive.Take(8).Select(d => new { d.Path, d.StatusCode, d.ContentType }).ToList()
            };
            issueCount += sensitive.Count;
        }
        catch (Exception ex)
        {
            discoverSummary = new { isClean = (bool?)null, error = ex.Message };
        }

        object methods;
        try
        {
            if (!string.IsNullOrEmpty(pageUrl))
            {
                var methodsResult = await Security.HttpMethodsSecurityProbe.RunAsync(pageUrl);
                methods = new
                {
                    isClean = methodsResult.SecurityIssueCount == 0,
                    url = methodsResult.Url,
                    allowedMethods = methodsResult.AllowedMethods,
                    securityIssues = methodsResult.SecurityIssues
                };
                issueCount += methodsResult.SecurityIssueCount;
            }
            else
            {
                methods = new { isClean = true, note = "No page URL loaded" };
            }
        }
        catch (Exception ex)
        {
            methods = new { isClean = (bool?)null, error = ex.Message };
        }

        object? forcedError = null;
        var safety = SafetyGate.Resolve(body);
        if (safety.AllowsWriteVerbs() && body.GetBool("includeForcedErrorInMisconfig", false))
        {
            try
            {
                var fe = await Security.ForcedErrorScanner.RunAsync(_context, new Security.ForcedErrorScanner.ScanOptions
                {
                    MaxEndpoints = body.GetInt("forcedErrorMaxEndpoints", 8),
                    TimeoutMs = body.GetInt("forcedErrorTimeoutMs", 12_000)
                });
                forcedError = new
                {
                    isClean = fe.IsClean,
                    findingCount = fe.Findings.Count,
                    endpointsProbed = fe.EndpointsProbed,
                    findings = fe.Findings.Take(10).ToList()
                };
                issueCount += fe.Findings.Count;
            }
            catch (Exception ex)
            {
                forcedError = new { isClean = (bool?)null, error = ex.Message };
            }
        }

        return new
        {
            isClean = issueCount == 0,
            issueCount,
            cors,
            discoverSummary,
            methods,
            forcedError,
            passiveOnly = !safety.AllowsWriteVerbs() || !body.GetBool("includeForcedErrorInMisconfig", false),
            note = "Passive misconfig pass: document CORS, discover sensitive-path count, HTTP methods on current URL. Set safetyMode: \"active\" + includeForcedErrorInMisconfig for stack-trace probing."
        };
    }

    private static bool IsSensitiveDiscoverPath(string path)
    {
        var p = path.ToLowerInvariant();
        return p.Contains(".env") || p.Contains(".git") || p.Contains("admin") || p.Contains("actuator")
            || p.Contains("phpinfo") || p.Contains("swagger") || p.Contains("api-docs")
            || p.Contains("backup") || p.Contains(".sql") || p.Contains("web.config")
            || p.Contains("server-status") || p.Contains("/debug") || p.Contains("console");
    }

    internal async Task<object> BuildBrokenAccessControlAuditPayloadAsync(JsonBody body)
    {
        var hostFilter = body.GetString("host");
        if (hostFilter == null && !body.GetBool("allHosts", false))
        {
            var pageUrl = await _context.GetCurrentUrl();
            if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
                hostFilter = pageUri.Host;
        }

        var mapper = new Security.AttackSurfaceMapper();
        var surface = mapper.Analyze(_context.Network.Entries, includeAuth: true, hostFilter: hostFilter);
        var documentRoot = Security.SpaShellGuard.FindDocumentRootEndpoint(surface.Endpoints);
        var adminUnauth = surface.Endpoints.Count(ep =>
            ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase)
            && !ep.Auth.Required
            && !Security.SpaShellGuard.IsAttackSurfaceSpaFallback(ep, documentRoot)
            && !Security.SpaShellGuard.IsScannerProbeArtifact(ep.Url));

        object? idorScan = null;
        object? restScaffold = null;
        object? jwtSweep = null;
        var issueCount = adminUnauth;
        var safety = SafetyGate.Resolve(body);

        if (safety.AllowsWriteVerbs())
        {
            if (surface.Endpoints.Count < body.GetInt("restScaffoldSparseThreshold", 3))
            {
                var rs = await Security.RestScaffoldProbes.RunAsync(_context, new Security.RestScaffoldProbes.ScaffoldOptions
                {
                    BaseUrl = await _context.GetCurrentUrl(),
                    TimeoutMs = body.GetInt("bacTimeoutMs", 12000),
                    MaxPaths = body.GetInt("restScaffoldMaxPaths", 12)
                });
                restScaffold = rs;
                issueCount += rs.Findings.Count;
            }

            if (body.GetBool("includeJwtAcceptanceSweep", false))
            {
                var js = await Security.JwtAcceptanceSweep.RunAsync(_context, new Security.JwtAcceptanceSweep.SweepOptions
                {
                    Host = hostFilter,
                    MaxEndpoints = body.GetInt("jwtSweepMaxEndpoints", 8),
                    TimeoutMs = body.GetInt("bacTimeoutMs", 15000),
                    BaseToken = body.GetString("baseToken")
                });
                jwtSweep = js;
                issueCount += js.Rows.Count(r => r.Finding is "JWT_ALG_NONE_ACCEPTED" or "MISSING_AUTH");
            }

            if (body.GetBool("includeIdorInAuditAll", true))
            {
                var autoOpts = new Security.AutoScanPipeline.AutoScanOptions
                {
                    Host = hostFilter,
                    MaxEndpointsPerScanner = body.GetInt("maxEndpointsPerScanner", 3),
                    TimeoutMs = body.GetInt("bacTimeoutMs", 15000),
                    IncludeSqli = false,
                    IncludeCsrf = false,
                    IncludePathTraversal = false,
                    IncludeSsrf = false,
                    IncludeOpenRedirect = false,
                    IncludeSsti = false,
                    IncludeMassAssignment = false,
                    IncludeIdor = true,
                    IdorReadOnlyProbes = true,
                    IncludeApiEnrichment = false,
                    IncludeRestScaffold = false
                };
                var idorOnly = await Security.AutoScanPipeline.RunAsync(_context, autoOpts, chainCatalog: _chainCatalog);
                idorScan = new
                {
                    findings = idorOnly.Findings.Where(f => f.Scanner == "idor").Take(10).Select(f => new
                    {
                        f.Endpoint, f.Method, f.Severity, f.Title, f.Detail
                    }),
                    scannersRun = idorOnly.ScannersRun,
                    summary = idorOnly.Findings.Count(f => f.Scanner == "idor")
                };
                issueCount += idorOnly.Findings.Count(f => f.Scanner == "idor");
            }
        }

        return new
        {
            isClean = issueCount == 0,
            issueCount,
            attackSurface = new
            {
                totalEndpoints = surface.Summary.TotalEndpoints,
                authenticated = surface.Summary.Authenticated,
                unauthenticated = surface.Summary.Unauthenticated,
                highPriority = surface.Summary.HighPriority,
                unauthenticatedAdminEndpoints = adminUnauth
            },
            idorScan,
            restScaffold,
            jwtSweep,
            passiveOnly = !safety.AllowsWriteVerbs(),
            note = safety.AllowsWriteVerbs()
                ? "Active BAC probes ran where enabled (IDOR, REST scaffold when sparse, optional JWT sweep)."
                : "Passive attack-surface auth summary only — set safetyMode: \"active\" for IDOR/rest-scaffold probes."
        };
    }

    internal async Task<object> BuildCsrfAuditPayloadAsync(JsonBody body)
    {
        var maxEndpoints = body.GetInt("maxEndpoints", 5);
        var maxUnprotected = body.GetInt("maxUnprotected", 10);
        var includeGet = body.GetBool("includeGet", false);
        var includeRefererBypass = body.GetBool("includeRefererBypass", true);
        var maxRefererEndpoints = body.GetInt("maxRefererEndpoints", 5);
        var includeJsonApiProbing = body.GetBool("includeJsonApiProbing", true);
        var maxJsonApiProbes = body.GetInt("maxJsonApiProbes", 10);
        var includeCustomHeaderProbes = body.GetBool("includeCustomHeaderProbes", true);
        var maxCustomHeaderProbes = body.GetInt("maxCustomHeaderProbes", 5);
        var includeSameSiteAnalysis = body.GetBool("includeSameSiteAnalysis", true);
        var hostFilter = body.GetString("host");
        if (hostFilter == null && !body.GetBool("allHosts", false))
        {
            var pageUrl = await _context.GetCurrentUrl();
            if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
                hostFilter = pageUri.Host;
        }

        var result = await _context.RunCsrfTest(
            maxEndpoints, maxUnprotected, includeGet, hostFilter,
            includeRefererBypass, maxRefererEndpoints, includeJsonApiProbing, maxJsonApiProbes,
            includeCustomHeaderProbes, maxCustomHeaderProbes, includeSameSiteAnalysis);

        var correlations = body.GetBool("includeCorrelations", true)
            ? await SecurityFindingCorrelator.CorrelateForCsrfScanAsync(
                _context,
                result,
                includeSecretsHarvest: body.GetBool("correlateSecretsHarvest", true),
                includeXss: body.GetBool("correlateXss", true),
                timeoutMs: body.GetInt("correlationTimeoutMs", 10000))
            : [];

        return new
        {
            isClean = result.VulnerableCount == 0 && correlations.All(c => c.Severity is not ("high" or "critical")),
            endpointsTested = result.EndpointsTested,
            unprotectedCount = result.UnprotectedCount,
            vulnerableCount = result.VulnerableCount,
            jsonApiProbesRun = result.JsonApiProbesRun,
            customHeaderProbesRun = result.CustomHeaderProbesRun,
            sameSiteContext = result.SameSiteContext == null ? null : new
            {
                crossSiteCookieRisk = result.SameSiteContext.CrossSiteCookieRisk,
                summary = result.SameSiteContext.Summary,
                sessionCookies = result.SameSiteContext.SessionCookies.Select(c => new
                {
                    c.Name, c.SameSite, c.Secure, c.HttpOnly
                })
            },
            message = result.Message,
            scenarios = result.Scenarios.Select(s => new
            {
                url = s.Url,
                path = s.Path,
                method = s.Method,
                testType = s.TestType,
                severity = s.Severity,
                description = s.Description,
                vulnerable = s.Vulnerable,
                tokenLocation = s.TokenLocation,
                formFields = s.FormFields,
            }).ToList(),
            jsonApiHints = result.JsonApiHints.Select(h => new
            {
                source = h.Source,
                url = h.Url,
                method = h.Method,
                evidence = h.Evidence,
            }).ToList(),
            correlations = correlations.Select(c => new
            {
                id = c.Id,
                severity = c.Severity,
                title = c.Title,
                description = c.Description,
                relatedTools = c.RelatedTools,
                fieldName = c.FieldName,
                url = c.Url,
            }).ToList(),
        };
    }

    private static List<object> BuildConsolidatedFindings(
        object accessibility, object performance, object cve, object xss,
        object mixedContent, object sourceMaps, object securityHeaders,
        object cookieSecurity, object storageSecurity, object validateHtml,
        object compatibility, object checkLinks, object consistency, object seo,
        object smuggling, object? csrf = null, object? brokenAccessControl = null,
        object? misconfiguration = null, object? thirdParty = null, object? supplyChain = null,
        object? apiInventory = null, object? clickjack = null)
    {
        var findings = new List<object>();

        try
        {
            var json = JsonSerializer.Serialize(new
            {
                accessibility, performance, cve, xss, mixedContent, sourceMaps,
                securityHeaders, cookieSecurity, storageSecurity, validateHtml,
                compatibility, checkLinks, consistency, seo, smuggling, csrf, brokenAccessControl, misconfiguration,
                thirdParty, supplyChain, apiInventory, clickjack
            });
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            ExtractAccessibilityFindings(root, findings);
            ExtractPerformanceFindings(root, findings);
            ExtractCveFindings(root, findings);
            ExtractXssFindings(root, findings);
            ExtractMixedContentFindings(root, findings);
            ExtractSourceMapFindings(root, findings);
            ExtractSecurityHeaderFindings(root, findings);
            ExtractCookieFindings(root, findings);
            ExtractStorageFindings(root, findings);
            ExtractHtmlFindings(root, findings);
            ExtractCompatibilityFindings(root, findings);
            ExtractLinkFindings(root, findings);
            ExtractConsistencyFindings(root, findings);
            ExtractSeoFindings(root, findings);
            ExtractSmugglingFindings(root, findings);
            ExtractCsrfFindings(root, findings);
            ExtractBrokenAccessControlFindings(root, findings);
            ExtractMisconfigurationFindings(root, findings);
            ExtractThirdPartyFindings(root, findings);
            ExtractSupplyChainFindings(root, findings);
            ExtractApiInventoryFindings(root, findings);
            ExtractClickjackFindings(root, findings);
        }
        catch { /* best-effort: return whatever was collected */ }

        return findings;
    }

    private static void ExtractApiInventoryFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("apiInventory", out var inv) || inv.ValueKind != JsonValueKind.Object)
            return;
        if (inv.TryGetProperty("skipped", out var sk) && sk.ValueKind == JsonValueKind.True)
            return;

        if (inv.TryGetProperty("summary", out var summary))
        {
            if (summary.TryGetProperty("shadowCount", out var sc) && sc.TryGetInt32(out var shadow) && shadow > 0)
            {
                findings.Add(new
                {
                    module = "apiInventory.shadow",
                    severity = "high",
                    title = $"{shadow} shadow API path(s) outside OpenAPI/spec inventory",
                    comment = "Undocumented routes expand unmonitored attack surface."
                });
            }

            if (summary.TryGetProperty("zombieCandidateCount", out var zc) && zc.TryGetInt32(out var zombie) && zombie > 0)
            {
                findings.Add(new
                {
                    module = "apiInventory.zombie",
                    severity = "high",
                    title = $"{zombie} zombie / deprecated API candidate(s)",
                    comment = "Parallel or legacy API versions may lack current security controls."
                });
            }

            if (summary.TryGetProperty("parallelVersionClusters", out var pc) && pc.TryGetInt32(out var clusters) && clusters > 0)
            {
                findings.Add(new
                {
                    module = "apiInventory.versionClusters",
                    severity = "medium",
                    title = $"{clusters} parallel API version cluster(s) active",
                    comment = "Multiple API versions running concurrently increase inventory drift risk."
                });
            }
        }
    }

    private static void ExtractClickjackFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("clickjack", out var cj) || cj.ValueKind != JsonValueKind.Object)
            return;
        if (cj.TryGetProperty("issueCount", out var ic) && ic.TryGetInt32(out var n) && n > 0)
        {
            findings.Add(new
            {
                module = "clickjack",
                severity = "high",
                title = $"{n} URL(s) missing effective clickjacking protection",
                comment = "Missing X-Frame-Options / CSP frame-ancestors enables UI redressing on sensitive flows."
            });
        }
    }

    private static void ExtractThirdPartyFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("thirdParty", out var tp)) return;
        if (tp.TryGetProperty("externalWithoutSri", out var countEl) && countEl.TryGetInt32(out var n) && n > 0)
        {
            findings.Add(new
            {
                module = "supplyChain.thirdParty",
                severity = "medium",
                title = $"{n} third-party script/stylesheet load(s) without Subresource Integrity",
                comment = "Missing SRI allows CDN or MITM substitution of executable script content."
            });
        }
    }

    private static void ExtractSupplyChainFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("supplyChain", out var sc)) return;

        if (sc.TryGetProperty("manifestPathsAccessible", out var mp) && mp.TryGetInt32(out var m) && m > 0)
        {
            findings.Add(new
            {
                module = "supplyChain.manifest",
                severity = "high",
                title = $"{m} dependency manifest path(s) accessible without authentication",
                comment = "Exposed package.json or lockfiles reveal server-side dependency versions for targeted CVE exploitation."
            });
        }

        if (sc.TryGetProperty("vulnerableDeclaredCount", out var vc) && vc.TryGetInt32(out var v) && v > 0)
        {
            findings.Add(new
            {
                module = "supplyChain.osv",
                severity = "high",
                title = $"{v} declared dependencies match OSV advisories",
                comment = "Run POST /api/security/supply-chain-scan for full manifest and advisory details."
            });
        }

        if (sc.TryGetProperty("ciCdPathsAccessible", out var cp) && cp.TryGetInt32(out var c) && c > 0)
        {
            findings.Add(new
            {
                module = "supplyChain.cicd",
                severity = "high",
                title = $"{c} CI/CD pipeline config path(s) accessible without authentication",
                comment = "Exposed .github/workflows, Jenkinsfile, or .gitlab-ci.yml files reveal deploy secrets and supply-chain attack surface."
            });
        }
    }

    private static void ExtractMisconfigurationFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("misconfiguration", out var mc)) return;

        if (mc.TryGetProperty("cors", out var cors) && cors.TryGetProperty("findings", out var corsFindings))
        {
            foreach (var f in corsFindings.EnumerateArray().Take(5))
            {
                findings.Add(new
                {
                    module = "misconfiguration.cors",
                    severity = f.GetStringOrDefault("severity") ?? "medium",
                    title = f.GetStringOrDefault("description") ?? "CORS misconfiguration",
                    comment = "Permissive CORS on the document URL may allow cross-origin data theft."
                });
            }
        }

        if (mc.TryGetProperty("discoverSummary", out var ds)
            && ds.TryGetProperty("accessibleSensitiveCount", out var cnt)
            && cnt.TryGetInt32(out var n) && n > 0)
        {
            findings.Add(new
            {
                module = "misconfiguration.discover",
                severity = "high",
                title = $"{n} accessible sensitive path(s) from discover wordlist",
                comment = "Exposed admin, config, or debug paths indicate security misconfiguration."
            });
        }

        if (mc.TryGetProperty("methods", out var methods) && methods.TryGetProperty("securityIssues", out var issues))
        {
            foreach (var issue in issues.EnumerateArray().Take(3))
            {
                var text = issue.GetString() ?? "HTTP methods misconfiguration";
                var severity = text.Contains("501", StringComparison.Ordinal) ? "info" : "medium";
                findings.Add(new
                {
                    module = "misconfiguration.methods",
                    severity,
                    title = text,
                    comment = "Dangerous HTTP methods enabled on the document URL."
                });
            }
        }

        if (mc.TryGetProperty("forcedError", out var fe) && fe.TryGetProperty("findings", out var feFindings))
        {
            foreach (var f in feFindings.EnumerateArray().Take(5))
            {
                findings.Add(new
                {
                    module = "misconfiguration.forcedError",
                    severity = f.GetStringOrDefault("severity") ?? "medium",
                    title = f.GetStringOrDefault("title") ?? "Verbose error / stack trace",
                    comment = f.GetStringOrDefault("detail")
                });
            }
        }
    }

    private static void ExtractBrokenAccessControlFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("brokenAccessControl", out var bac)) return;
        if (bac.TryGetProperty("attackSurface", out var surface)
            && surface.TryGetProperty("unauthenticatedAdminEndpoints", out var adminCount)
            && adminCount.TryGetInt32(out var n) && n > 0)
        {
            findings.Add(new
            {
                module = "brokenAccessControl",
                severity = "high",
                title = "Unauthenticated admin-tagged endpoints in attack surface",
                comment = $"{n} endpoint(s) with 'admin' in the path appear reachable without authentication signals."
            });
        }

        if (bac.TryGetProperty("restScaffold", out var rs) && rs.TryGetProperty("findings", out var rsFindings))
        {
            foreach (var row in rsFindings.EnumerateArray().Take(5))
            {
                findings.Add(new
                {
                    module = "brokenAccessControl",
                    severity = row.GetStringOrDefault("severity") ?? "medium",
                    title = row.GetStringOrDefault("finding") ?? "REST scaffold leak",
                    comment = row.GetStringOrDefault("detail") ?? row.GetStringOrDefault("url")
                });
            }
        }
        else if (bac.TryGetProperty("restScaffold", out rs) && rs.TryGetProperty("rows", out var rows))
        {
            foreach (var row in rows.EnumerateArray()
                         .Where(r => r.GetStringOrDefault("result") == "leak")
                         .Take(5))
            {
                findings.Add(new
                {
                    module = "brokenAccessControl",
                    severity = row.GetStringOrDefault("severity") ?? "medium",
                    title = row.GetStringOrDefault("finding") ?? "REST scaffold leak",
                    comment = row.GetStringOrDefault("detail") ?? row.GetStringOrDefault("url")
                });
            }
        }

        if (bac.TryGetProperty("idorScan", out var idor) && idor.TryGetProperty("findings", out var idorFindings))
        {
            foreach (var f in idorFindings.EnumerateArray().Take(5))
            {
                findings.Add(new
                {
                    module = "brokenAccessControl",
                    severity = f.GetStringOrDefault("severity") ?? "high",
                    title = f.GetStringOrDefault("title") ?? "Possible IDOR",
                    comment = f.GetStringOrDefault("detail") ?? f.GetStringOrDefault("endpoint")
                });
            }
        }
    }

    private static void ExtractAccessibilityFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("accessibility", out var a)) return;
        if (!a.TryGetProperty("violations", out var violations)) return;
        foreach (var v in violations.EnumerateArray())
        {
            var impact = v.GetStringOrDefault("impact");
            findings.Add(new
            {
                module = "accessibility",
                severity = impact ?? "moderate",
                title = v.GetStringOrDefault("ruleId") ?? "Unknown rule",
                comment = v.GetStringOrDefault("help")
                    ?? v.GetStringOrDefault("description")
                    ?? "Accessibility violation that may prevent users with disabilities from using this page."
            });
        }
    }

    private static void ExtractPerformanceFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("performance", out var p)) return;
        if (!p.TryGetProperty("metrics", out var metrics)) return;
        foreach (var m in metrics.EnumerateArray())
        {
            var rating = m.GetStringOrDefault("rating");
            if (rating is "good") continue;
            var name = m.GetStringOrDefault("name") ?? "unknown";
            var fullName = m.GetStringOrDefault("fullName") ?? name;
            var comment = name.ToUpperInvariant() switch
            {
                "LCP" => "Largest Contentful Paint measures loading speed — slow LCP makes the page feel sluggish and hurts search ranking.",
                "FID" or "INP" => "Interaction delay measures responsiveness — high values mean the page feels unresponsive to user input.",
                "CLS" => "Cumulative Layout Shift measures visual stability — high CLS means content jumps around unexpectedly as the page loads.",
                "FCP" => "First Contentful Paint measures initial render speed — slow FCP makes users think the page is broken.",
                "TTFB" => "Time to First Byte measures server response time — slow TTFB delays everything else on the page.",
                _ => $"{fullName} is below recommended thresholds, which may degrade user experience."
            };
            findings.Add(new { module = "performance", severity = rating ?? "needs-improvement", title = $"{name}: {rating}", comment });
        }
    }

    private static void ExtractCveFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("cve", out var c)) return;
        if (!c.TryGetProperty("libraries", out var libs)) return;
        foreach (var lib in libs.EnumerateArray())
        {
            if (lib.TryGetProperty("isVulnerable", out var isVuln) && !isVuln.GetBoolean()) continue;
            var libName = lib.GetStringOrDefault("name") ?? "Unknown library";
            var version = lib.GetStringOrDefault("version") ?? "?";
            if (!lib.TryGetProperty("vulnerabilities", out var vulns)) continue;
            foreach (var v in vulns.EnumerateArray())
            {
                findings.Add(new
                {
                    module = "security.cve",
                    severity = v.GetStringOrDefault("severity") ?? "medium",
                    title = $"{libName} {version}: {v.GetStringOrDefault("summary") ?? "known vulnerability"}",
                    comment = $"This library version has a known security vulnerability. Attackers can exploit it to compromise user data or take control of the application. Update to a patched version."
                });
            }
        }
    }

    private static void ExtractXssFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("xss", out var x)) return;
        if (!x.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            findings.Add(new
            {
                module = "security.xss",
                severity = f.GetStringOrDefault("severity") ?? "medium",
                title = f.GetStringOrDefault("description") ?? "DOM XSS finding",
                comment = f.GetStringOrDefault("recommendation")
                    ?? "Cross-site scripting allows attackers to inject malicious scripts that steal user sessions, redirect to phishing pages, or modify page content."
            });
        }
    }

    private static void ExtractCsrfFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("csrf", out var csrf) || csrf.ValueKind == JsonValueKind.Null)
            return;

        if (csrf.TryGetProperty("scenarios", out var scenarios))
        {
            foreach (var s in scenarios.EnumerateArray())
            {
                if (s.TryGetProperty("vulnerable", out var v) && v.ValueKind == JsonValueKind.False)
                    continue;
                findings.Add(new
                {
                    module = "security.csrf",
                    severity = s.GetStringOrDefault("severity") is { Length: > 0 } sev ? sev : "high",
                    title = $"CSRF: {s.GetStringOrDefault("testType") ?? "finding"}",
                    comment = s.GetStringOrDefault("description")
                        ?? "Cross-site request forgery allows attackers to perform actions on behalf of authenticated users."
                });
            }
        }

        if (csrf.TryGetProperty("correlations", out var correlations))
        {
            foreach (var c in correlations.EnumerateArray())
            {
                findings.Add(new
                {
                    module = "security.correlation",
                    severity = c.GetStringOrDefault("severity") ?? "medium",
                    title = c.GetStringOrDefault("title") ?? "Security correlation",
                    comment = c.GetStringOrDefault("description") ?? "Cross-tool security correlation finding."
                });
            }
        }
    }

    private static void ExtractMixedContentFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("mixedContent", out var mc)) return;
        if (!mc.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            var tag = f.GetStringOrDefault("tag") ?? "element";
            var url = f.GetStringOrDefault("url") ?? "";
            findings.Add(new
            {
                module = "security.mixedContent",
                severity = f.GetStringOrDefault("severity") ?? "medium",
                title = $"Mixed content: <{tag}> loads HTTP resource",
                comment = $"Loading HTTP resources on an HTTPS page allows man-in-the-middle attackers to tamper with or replace the content. Browsers may block these requests entirely."
            });
        }
    }

    private static void ExtractSourceMapFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("sourceMaps", out var sm)) return;
        if (!sm.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            findings.Add(new
            {
                module = "security.sourceMaps",
                severity = f.GetStringOrDefault("severity") ?? "low",
                title = f.GetStringOrDefault("description") ?? "Source map exposure",
                comment = "Exposed source maps reveal original source code, internal paths, and variable names — making it easier for attackers to find vulnerabilities."
            });
        }
    }

    private static void ExtractSecurityHeaderFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("securityHeaders", out var sh)) return;
        if (!sh.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            findings.Add(new
            {
                module = "securityHeaders",
                severity = f.GetStringOrDefault("severity") ?? "medium",
                title = $"{f.GetStringOrDefault("header") ?? "Header"}: {f.GetStringOrDefault("description") ?? "issue"}",
                comment = f.GetStringOrDefault("recommendation")
                    ?? "Missing or misconfigured security headers leave the application vulnerable to common web attacks."
            });
        }
    }

    private static void ExtractCookieFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("cookieSecurity", out var cs)) return;
        if (!cs.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            findings.Add(new
            {
                module = "cookieSecurity",
                severity = f.GetStringOrDefault("severity") ?? "medium",
                title = $"Cookie '{f.GetStringOrDefault("cookieName") ?? "?"}': {f.GetStringOrDefault("description") ?? "issue"}",
                comment = f.GetStringOrDefault("recommendation")
                    ?? "Insecure cookie configuration can lead to session hijacking or cross-site request forgery."
            });
        }
    }

    private static void ExtractStorageFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("storageSecurity", out var ss)) return;
        if (!ss.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            findings.Add(new
            {
                module = "storageSecurity",
                severity = f.GetStringOrDefault("severity") ?? "medium",
                title = $"{f.GetStringOrDefault("storageType") ?? "Storage"} '{f.GetStringOrDefault("key") ?? "?"}': {f.GetStringOrDefault("category") ?? "issue"}",
                comment = f.GetStringOrDefault("recommendation")
                    ?? "Sensitive data in browser storage is accessible to any JavaScript on the page, including injected scripts."
            });
        }
    }

    private static void ExtractHtmlFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("validateHtml", out var vh)) return;
        if (!vh.TryGetProperty("messages", out var items)) return;
        foreach (var m in items.EnumerateArray())
        {
            var severity = m.GetStringOrDefault("severity") ?? "warning";
            if (severity == "warning") continue; // only surface errors in consolidated list
            findings.Add(new
            {
                module = "html",
                severity,
                title = m.GetStringOrDefault("message") ?? "HTML validation error",
                comment = $"Invalid HTML can cause rendering differences across browsers, break assistive technology, and reduce search engine crawlability."
            });
        }
    }

    private static void ExtractCompatibilityFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("compatibility", out var c)) return;
        if (!c.TryGetProperty("features", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            var name = f.GetStringOrDefault("name") ?? "Unknown feature";
            var incomp = f.GetStringOrDefault("incompatibleWith");
            findings.Add(new
            {
                module = "compatibility",
                severity = "medium",
                title = $"'{name}' not supported on older browsers",
                comment = incomp != null
                    ? $"This JavaScript feature is not available in {incomp}. Users on those platforms will experience errors or broken functionality."
                    : $"This JavaScript feature requires a newer browser version. Users on older devices may experience errors."
            });
        }
    }

    private static void ExtractLinkFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("checkLinks", out var cl)) return;
        if (!cl.TryGetProperty("links", out var items)) return;
        foreach (var link in items.EnumerateArray())
        {
            var status = link.GetStringOrDefault("status");
            if (status is "ok" or "redirect" or "skipped" or null) continue;
            var url = link.GetStringOrDefault("url") ?? "unknown";
            var statusCode = link.TryGetProperty("statusCode", out var sc) ? sc.GetInt32() : 0;
            findings.Add(new
            {
                module = "links",
                severity = statusCode >= 500 ? "high" : "medium",
                title = $"Broken link: {(url.Length > 80 ? url[..77] + "..." : url)} ({(statusCode > 0 ? statusCode.ToString() : "unreachable")})",
                comment = "Broken links frustrate users, hurt SEO ranking, and signal poor site maintenance. They may also indicate removed resources or misconfigured routes."
            });
        }
    }

    private static void ExtractConsistencyFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("consistency", out var c)) return;
        if (!c.TryGetProperty("findings", out var items)) return;
        foreach (var f in items.EnumerateArray())
        {
            if (f.TryGetProperty("isWarning", out var w) && !w.GetBoolean()) continue;
            findings.Add(new
            {
                module = "consistency",
                severity = "low",
                title = f.GetStringOrDefault("description") ?? "GUI consistency issue",
                comment = "Inconsistent visual styling (fonts, colors, spacing) makes the UI feel unpolished and confuses users about interactive element hierarchy."
            });
        }
    }

    private static void ExtractSeoFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("seo", out var s)) return;
        if (s.TryGetProperty("criticalIssues", out var issues))
        {
            foreach (var issue in issues.EnumerateArray())
            {
                findings.Add(new
                {
                    module = "seo",
                    severity = "high",
                    title = issue.GetString() ?? "SEO issue",
                    comment = "Critical SEO issues prevent search engines from properly indexing the page, reducing organic traffic and discoverability."
                });
            }
        }
    }

    private static void ExtractSmugglingFindings(JsonElement root, List<object> findings)
    {
        if (!root.TryGetProperty("smuggling", out var s)) return;
        var risk = s.GetStringOrDefault("risk");
        bool framing = (s.TryGetProperty("hasAmbiguousFraming", out var af) && af.ValueKind == JsonValueKind.True) ||
                       (s.TryGetProperty("hasMultipleContentLength", out var mcl) && mcl.ValueKind == JsonValueKind.True);
        if (risk is not "high" && !framing) return;

        if (!s.TryGetProperty("indicators", out var indicators)) return;
        foreach (var indicator in indicators.EnumerateArray())
        {
            var text = indicator.GetString();
            if (string.IsNullOrEmpty(text)) continue;
            findings.Add(new
            {
                module = "smuggling",
                severity = "high",
                title = text,
                comment = "Ambiguous HTTP framing in the response (both Transfer-Encoding and Content-Length, or conflicting Content-Length). " +
                    "Run POST /api/security/smuggling with safetyMode: \"active\". Act only on confirmed differential-response (canary 404); " +
                    "Via / CDN headers alone are not smuggling."
            });
        }
    }

    private async Task<object> BuildAccessibilityAuditPayloadAsync(JsonBody body)
    {
        var level = body.GetString("level") ?? "AA";
        var selector = body.GetString("selector");

        var result = await _context.CheckAccessibility(level, selector);

        return new
        {
            isClean = result.IsClean,
            violationCount = result.ViolationCount,
            passCount = result.PassCount,
            incompleteCount = result.Incomplete.Count,
            affectedElementCount = result.AffectedElementCount,
            violations = result.Violations.Select(v => new
            {
                ruleId = v.RuleId,
                impact = v.Impact.ToString().ToLower(),
                description = v.Description,
                help = v.Help,
                helpUrl = v.HelpUrl,
                wcagCriteria = v.WcagCriteria,
                count = v.Count,
                nodes = v.Nodes.Select(n => new
                {
                    html = n.Html?.Length > 200 ? n.Html[..200] + "..." : n.Html,
                    target = n.Target,
                    failureSummary = n.FailureSummary
                }).ToList()
            }).ToList(),
            summary = result.Format(includeNodes: false)
        };
    }

    private async Task<object> BuildPerformanceAuditPayloadAsync()
    {
        var result = await _context.CheckPerformance();

        return new
        {
            isGood = result.IsGood,
            hasPoorMetrics = result.HasPoorMetrics,
            hasMetricsNeedingImprovement = result.HasMetricsNeedingImprovement,
            metrics = result.Metrics.Select(m => new
            {
                name = m.Name,
                fullName = m.FullName,
                value = m.Available ? (double?)m.Value : null,
                unit = m.Unit,
                rating = m.Available ? m.Rating.ToString().ToLower() : "unavailable",
                available = m.Available,
                note = m.Note,
                element = m.Element
            }).ToList(),
            navigation = new
            {
                result.Navigation.RedirectTime,
                result.Navigation.DnsTime,
                result.Navigation.TcpTime,
                result.Navigation.TlsTime,
                result.Navigation.RequestTime,
                result.Navigation.ResponseTime,
                result.Navigation.DomParsingTime,
                result.Navigation.DomContentLoadedTime,
                result.Navigation.PageLoadTime,
                result.Navigation.TransferSize,
                result.Navigation.DecodedBodySize
            },
            resources = new
            {
                result.Resources.TotalCount,
                result.Resources.TotalTransferSize,
                byType = result.Resources.ByType.ToDictionary(
                    kv => kv.Key,
                    kv => new { kv.Value.Count, kv.Value.TotalSize }),
                slowest = result.Resources.Slowest.Select(r => new
                {
                    r.Url, r.Duration, r.Size, r.Type
                }).ToList()
            },
            summary = result.Format(includeNavigation: false, includeResources: false)
        };
    }

    private async Task<object> BuildSecurityAuditPayloadAsync()
    {
        var result = await _context.CheckSecurity();

        return new
        {
            isClean = result.IsClean,
            libraryCount = result.LibraryCount,
            vulnerableCount = result.VulnerableCount,
            vulnerabilityCount = result.VulnerabilityCount,
            hasBundledScripts = result.HasBundledScripts,
            fileContentScanned = result.FileContentScanned,
            caveats = result.Caveats,
            libraries = result.Libraries.Select(l => new
            {
                name = l.Name,
                version = l.Version,
                detectionMethod = l.DetectionMethod,
                isVulnerable = l.IsVulnerable,
                vulnerabilities = l.Vulnerabilities.Select(v => new
                {
                    severity = v.Severity.ToString().ToLower(),
                    summary = v.Summary,
                    cves = v.CVEs,
                    cwes = v.CWEs,
                    info = v.Info,
                    below = v.Below,
                    atOrAbove = v.AtOrAbove
                }).ToList()
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildSecurityHeadersAuditPayloadAsync(JsonBody? body = null)
    {
        var urlList = body?.GetStringArray("urls");
        if (urlList is { Count: > 0 })
        {
            var audits = new List<object>();
            var allFindings = new List<HeaderFinding>();
            foreach (var u in urlList.Take(20))
            {
                if (string.IsNullOrWhiteSpace(u)) continue;
                var one = await _context.CheckSecurityHeadersForUrl(u.Trim());
                allFindings.AddRange(one.Findings);
                audits.Add(new
                {
                    url = one.Url,
                    fetchSucceeded = one.FetchSucceeded,
                    fetchError = one.FetchError,
                    findingCount = one.FindingCount,
                    findings = one.Findings.Select(f => new
                    {
                        header = f.Header,
                        severity = f.Severity.ToString().ToLower(),
                        description = f.Description,
                        recommendation = f.Recommendation,
                        currentValue = f.CurrentValue,
                        reference = f.Reference
                    }).ToList()
                });
            }

            return new
            {
                mode = "multi-url",
                isClean = allFindings.Count == 0,
                findingCount = allFindings.Count,
                audits,
                summary = $"{allFindings.Count} header finding(s) across {audits.Count} URL(s)."
            };
        }

        var result = await _context.CheckSecurityHeaders();

        // Server-side TRACE method check (browser fetch blocks TRACE)
        if (result.FetchSucceeded && !string.IsNullOrEmpty(result.Url))
        {
            try
            {
                var traceFinding = await HeadersChecker.CheckTraceMethodAsync(result.Url);
                if (traceFinding != null)
                    result.Findings.Add(traceFinding);
            }
            catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
        }

        return new
        {
            fetchSucceeded = result.FetchSucceeded,
            fetchError = result.FetchError,
            isClean = result.IsClean,
            findingCount = result.FindingCount,
            isHttps = result.IsHttps,
            findings = result.Findings.Select(f => new
            {
                header = f.Header,
                severity = f.Severity.ToString().ToLower(),
                description = f.Description,
                recommendation = f.Recommendation,
                currentValue = f.CurrentValue,
                reference = f.Reference
            }).ToList(),
            rawHeaders = result.RawHeaders,
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildValidateHtmlAuditPayloadAsync()
    {
        var result = await _context.CheckHtml();

        return new
        {
            isValid = result.IsValid,
            errorCount = result.ErrorCount,
            warningCount = result.WarningCount,
            messages = result.Messages.Select(m => new
            {
                ruleId = m.RuleId,
                severity = m.Severity == HtmlValidation.HtmlSeverity.Error ? "error" : "warning",
                message = m.Message,
                line = m.Line,
                column = m.Column,
                category = m.Category,
                ruleUrl = m.RuleUrl
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildSeoAuditPayloadAsync()
    {
        var r = await _context.RunSeoAuditAsync();
        var critical = r.GetCriticalIssues();
        return new
        {
            isClean = critical.Count == 0,
            url = r.Url,
            title = r.Title,
            description = r.Description,
            robots = r.Robots,
            canonicalUrl = r.CanonicalUrl,
            charset = r.Charset,
            viewport = r.Viewport,
            language = r.Language,
            h1Count = r.H1Count,
            ogTags = r.OgTags,
            twitterTags = r.TwitterTags,
            hreflang = r.Hreflang,
            structuredData = r.StructuredData.Select(SeoStructuredDataItemForApi).ToList(),
            criticalIssues = critical,
            suggestions = r.GetHints(),
            error = r.Error
        };
    }

    private async Task<object> BuildCompatibilityAuditPayloadAsync(JsonBody body)
    {
        int? minIos = body.HasProperty("minIos") ? body.GetInt("minIos") : null;
        int? minAndroid = body.HasProperty("minAndroid") ? body.GetInt("minAndroid") : null;

        var result = await _context.CheckCompatibility(minIos, minAndroid);

        return new
        {
            isCompatible = result.IsCompatible,
            scriptsAnalyzed = result.ScriptsAnalyzed,
            totalBytesAnalyzed = result.TotalBytesAnalyzed,
            skippedScripts = result.SkippedScripts,
            minChromeRequired = result.MinChromeRequired,
            minSafariRequired = result.MinSafariRequired,
            features = result.Features.Select(f => new
            {
                name = f.Name,
                category = f.Category == Compatibility.FeatureCategory.Syntax ? "syntax" : "api",
                chromeMin = f.ChromeMin,
                safariMin = f.SafariMin,
                firefoxMin = f.FirefoxMin,
                occurrences = f.Occurrences,
                foundIn = f.FoundIn,
                mdnUrl = f.MdnUrl,
                incompatibleWith = f.IncompatibleWith
            }).ToList(),
            targets = result.Targets.Select(t => new
            {
                name = t.Name,
                engine = t.Engine,
                version = t.Version,
                riskLevel = t.RiskLevel.ToString().ToLower(),
                unsupportedFeatureCount = t.UnsupportedFeatures.Count
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildSecurityXssPayloadAsync()
    {
        var result = await _context.CheckXss();

        return new
        {
            isClean = result.IsClean,
            findingCount = result.FindingCount,
            findingsByCategory = result.FindingsByCategory,
            findings = result.Findings.Select(f => new
            {
                category = f.Category,
                severity = f.Severity.ToString().ToLower(),
                description = f.Description,
                location = f.Location,
                evidence = f.Evidence,
                recommendation = f.Recommendation,
                confidence = f.Confidence,
                source = f.Source,
                sink = f.Sink
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildMixedContentPayloadAsync()
    {
        var result = await _context.CheckMixedContent();

        return new
        {
            isClean = result.IsClean,
            isHttps = result.IsHttps,
            findingCount = result.FindingCount,
            highCount = result.HighCount,
            mediumCount = result.MediumCount,
            lowCount = result.LowCount,
            findings = result.Findings.Select(f => new
            {
                tag = f.Tag,
                attribute = f.Attribute,
                url = f.Url,
                severity = f.Severity.ToString().ToLower(),
                context = f.Context
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildSourceMapPayloadAsync()
    {
        var result = await _context.CheckSourceMaps();

        return new
        {
            isClean = result.IsClean,
            findingCount = result.FindingCount,
            findings = result.Findings.Select(f => new
            {
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                url = f.Url,
                detail = f.Detail,
                recommendation = f.Recommendation
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildTechStackPayloadAsync()
    {
        var result = await _context.CheckTechStack();

        return new
        {
            detectionCount = result.DetectionCount,
            categories = result.Categories,
            detections = result.Detections.Select(d => new
            {
                name = d.Name,
                version = d.Version,
                category = d.Category,
                confidence = d.Confidence
            }).ToList(),
            frameworks = result.Frameworks.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            servers = result.Servers.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            jsLibraries = result.JsLibraries.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            waf = result.Waf.Select(d => d.Name).ToList(),
            cdn = result.Cdn.Select(d => d.Name).ToList(),
            cache = result.Cache.ToApiObject(),
            elapsedMs = result.ElapsedMs,
            summary = result.Format(includeDetails: false)
        };
    }

    private static object BuildThirdPartyPayload(ThirdParty.ThirdPartyResult result)
    {
        var externalWithoutSri = result.Resources.Count(r =>
            !r.HasSri && r.Type is "script" or "stylesheet");

        var externalScripts = result.Resources.Count(r => r.Type == "script");
        var externalStyles = result.Resources.Count(r => r.Type == "stylesheet");
        var noExternalResources = result.TotalCount == 0;

        return new
        {
            isClean = noExternalResources || externalWithoutSri == 0,
            noExternalResources,
            totalCount = result.TotalCount,
            domainCount = result.DomainCount,
            sriCount = result.SriCount,
            externalWithoutSri,
            externalScriptCount = externalScripts,
            externalStylesheetCount = externalStyles,
            sriCoverageRatio = result.TotalCount > 0
                ? Math.Round((double)result.SriCount / result.TotalCount, 2)
                : 1.0,
            resourcesWithoutSri = result.Resources
                .Where(r => !r.HasSri && r.Type is "script" or "stylesheet")
                .Take(10)
                .Select(r => new { r.Url, r.Type, r.Domain })
                .ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildThirdPartyAuditPayloadAsync()
    {
        var result = await _context.CheckThirdParty();
        return BuildThirdPartyPayload(result);
    }

    private async Task<object> BuildSupplyChainAuditPayloadAsync(JsonBody body, ThirdParty.ThirdPartyResult thirdParty)
    {
        var externalWithoutSri = thirdParty.Resources.Count(r =>
            !r.HasSri && r.Type is "script" or "stylesheet");
        var noExternalResources = thirdParty.TotalCount == 0;
        var retire = await _context.CheckSecurity();

        int manifestPathsAccessible = 0;
        int ciCdPathsAccessible = 0;
        int vulnerableDeclaredCount = 0;
        var safety = SafetyGate.Resolve(body);
        if (safety.AllowsWriteVerbs())
        {
            var pageUrl = await _context.GetCurrentUrl();
            manifestPathsAccessible = await Security.SupplyChain.ManifestFetcher.ProbeManifestPathCountAsync(
                _context, pageUrl, body.GetInt("supplyChainTimeoutMs", 12_000));
            ciCdPathsAccessible = await Security.SupplyChain.CiCdExposureChecker.ProbePathCountAsync(
                _context, pageUrl, body.GetInt("supplyChainTimeoutMs", 12_000));

            if (manifestPathsAccessible > 0)
            {
                var quickScan = await _context.RunSupplyChainScan(new Security.SupplyChain.SupplyChainScanOptions
                {
                    IncludeManifestFetch = true,
                    IncludePathFilterBypass = false,
                    IncludeCveReachability = false,
                    IncludeRetireOsvCrossCheck = true,
                    MaxOsvPackages = 50,
                    TimeoutMs = body.GetInt("supplyChainTimeoutMs", 20_000)
                });
                vulnerableDeclaredCount = quickScan.VulnerableDeclaredCount;
            }
        }

        var isClean = retire.IsClean && (noExternalResources || externalWithoutSri == 0)
                      && manifestPathsAccessible == 0 && ciCdPathsAccessible == 0 && vulnerableDeclaredCount == 0;

        return new
        {
            isClean,
            noExternalResources,
            totalCount = thirdParty.TotalCount,
            sriCount = thirdParty.SriCount,
            retireVulnerableCount = retire.VulnerableCount,
            externalWithoutSri,
            manifestPathsAccessible,
            ciCdPathsAccessible,
            vulnerableDeclaredCount,
            sriCoverageRatio = thirdParty.TotalCount > 0
                ? Math.Round((double)thirdParty.SriCount / thirdParty.TotalCount, 2)
                : 1.0,
            passiveOnly = !safety.AllowsWriteVerbs()
        };
    }

    private async Task<object> BuildCheckLinksPayloadAsync(JsonBody body)
    {
        var scope = body.GetString("scope") ?? "anchors";
        var external = body.GetBool("external", true);
        var timeoutMs = body.GetInt("timeoutMs", 5000);
        var concurrency = body.GetInt("concurrency", 10);
        var delayMs = body.GetInt("delayMs", 100);

        var checker = new LinkChecking.LinkChecker(_context);
        var result = await checker.RunAsync(scope, external, timeoutMs, concurrency, delayMs);

        return new
        {
            isClean = result.IsClean,
            totalLinks = result.TotalLinks,
            checkedCount = result.CheckedCount,
            brokenCount = result.BrokenCount,
            redirectCount = result.RedirectCount,
            skippedCount = result.SkippedCount,
            links = result.Links.Select(l => new
            {
                url = l.Url,
                originalUrl = l.OriginalUrl,
                source = l.Source,
                status = l.Status.ToString().ToLower(),
                statusCode = l.StatusCode,
                redirectUrl = l.RedirectUrl,
                error = l.Error,
                linkText = l.LinkText
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    private async Task<object> BuildConsistencyPayloadAsync()
    {
        var result = await _context.CheckConsistency();

        return new
        {
            isClean = result.IsClean,
            warningCount = result.WarningCount,
            stats = new
            {
                fontFamilies = result.Stats.FontFamilies.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                fontSizes = result.Stats.FontSizes.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                textColors = result.Stats.TextColors.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                backgroundColors = result.Stats.BackgroundColors.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                buttonHeights = result.Stats.ButtonHeights.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                inputHeights = result.Stats.InputHeights.Select(v => new { value = v.Value, count = v.Count }).ToList(),
                spacingValues = result.Stats.SpacingValues.Select(v => new { value = v.Value, count = v.Count }).ToList()
            },
            findings = result.Findings.Select(f => new
            {
                category = f.Category,
                isWarning = f.IsWarning,
                description = f.Description,
                values = f.Values
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    
    
    
    
    
    
    private static readonly HashSet<string> AuditAllQuickProfileDisabled = new(StringComparer.OrdinalIgnoreCase)
    {
        "includeAuthenticationFailures",
        "includeInsecureDesign",
        "includeInjectionFailures",
        "includeBrokenAccessControl",
        "includeServerSideFetch",
        "includeProtocolLayer"
    };

    private static bool IsAuditNetworkScopeSession(JsonBody body)
    {
        var scope = body.GetString("networkScope");
        return !string.IsNullOrWhiteSpace(scope)
               && scope.Equals("session", StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveAuditNetworkScopeLabel(JsonBody body) =>
        IsAuditNetworkScopeSession(body) ? "session" : "page";

    private async Task<string?> ResolveAuditScopeHostAsync(JsonBody body)
    {
        if (IsAuditNetworkScopeSession(body))
            return null;
        var explicitHost = body.GetString("host");
        if (!string.IsNullOrWhiteSpace(explicitHost))
            return SecurityHostScope.ResolveScopeHost(explicitHost, null);
        try
        {
            var pageUrl = await _context.GetCurrentUrl();
            return SecurityHostScope.ResolveScopeHost(null, pageUrl);
        }
        catch
        {
            return null;
        }
    }

    private async Task<Security.AttackSurfaceSessionBuilder.BuildOptions> ResolveAttackSurfaceOptionsAsync(JsonBody body)
    {
        var opts = BuildAttackSurfaceOptionsFromBody(body);
        if (IsAuditNetworkScopeSession(body))
            return opts;
        if (!string.IsNullOrWhiteSpace(opts.HostFilter))
            return opts;
        opts.HostFilter = await ResolveAuditScopeHostAsync(body);
        return opts;
    }

    private static bool AuditAllInclude(JsonBody body, string includeFlag, bool defaultValue)
    {
        if (body.HasProperty(includeFlag))
            return body.GetBool(includeFlag, defaultValue);
        if (string.Equals(body.GetString("profile"), "quick", StringComparison.OrdinalIgnoreCase)
            && AuditAllQuickProfileDisabled.Contains(includeFlag))
            return false;
        return defaultValue;
    }

    private static Security.AttackSurfaceSessionBuilder.BuildOptions BuildAttackSurfaceOptionsFromBody(JsonBody body) =>
        new()
        {
            IncludeParameters = body.GetBool("includeParameters", true),
            IncludeAuth = body.GetBool("includeAuth", true),
            IncludeResponsePatterns = body.GetBool("includeResponsePatterns", true),
            HostFilter = body.GetString("host"),
            IncludeDataUrls = body.GetBool("includeDataUrls", false),
            SpaMode = body.GetBool("spaMode", false),
            CheckSecurityTxt = body.GetBool("checkSecurityTxt", true),
            IncludeApiEnrichment = body.GetBool("includeApiEnrichment", true),
            IncludeOpenApiFromNetwork = body.GetBool("includeOpenApiFromNetwork", true),
            IncludeOpenApiProbes = body.GetBool("includeOpenApiProbes", true),
            IncludeJsBundleHints = body.GetBool("includeJsBundleHints", true),
            IncludeDevArtifactProbes = body.GetBool("includeDevArtifactProbes", true),
            MaxProbeOrigins = Math.Clamp(body.GetInt("maxProbeOrigins", 6), 1, 20),
            MaxJsScripts = Math.Clamp(body.GetInt("maxJsScripts", 24), 1, 80),
            MaxJsBundleBytesPerFile = Math.Clamp(body.GetInt("maxJsBundleBytesPerFile", 524_288), 8192, 2_000_000),
            MaxJsHintPaths = Math.Clamp(body.GetInt("maxJsHintPaths", 200), 16, 2000),
            EnrichmentHttpTimeoutMs = Math.Clamp(body.GetInt("enrichmentHttpTimeoutMs", 12_000), 3_000, 60_000),
            MaxWordPressRestRoutes = Math.Clamp(body.GetInt("maxWordPressRestRoutes", 8000), 64, 50_000)
        };

    
    
    
    private static object BuildSecurityPreflightPayload(IReadOnlyList<NetworkEntry> entries)
    {
        var p = Security.SecurityPreflight.Assess(entries);
        return new
        {
            level = p.Level,
            navigationOnly = p.NavigationOnly,
            totalEntries = p.TotalEntries,
            apiLikeEntries = p.ApiLikeEntries,
            message = p.Message,
            recommendation = p.Recommendation
        };
    }

    private async Task HandlePostValidateHtml(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, await BuildValidateHtmlAuditPayloadAsync());
    }

    private async Task HandlePostSeo(HttpListenerRequest request, HttpListenerResponse response)
    {
        _ = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildSeoAuditPayloadAsync());
    }

    private async Task HandlePostCompatibility(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildCompatibilityAuditPayloadAsync(body));
    }

    private async Task HandlePostCheckLinks(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildCheckLinksPayloadAsync(body));
    }

    
    
    
    
    private static object FormatSamlDecodeResult(SamlDecodeResult result)
    {
        return new
        {
            binding = result.Binding,
            messageType = result.MessageType,
            parameterName = result.ParameterName,
            xml = result.Xml,
            parsed = result.Parsed,
            signature = new
            {
                present = result.Signature.Present,
                algorithm = result.Signature.Algorithm,
                digestAlgorithm = result.Signature.DigestAlgorithm,
                location = result.Signature.Location
            },
            securityFindings = result.SecurityFindings.Select(f => new
            {
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description
            }).ToList(),
            sourceUrl = result.SourceUrl,
            timestamp = result.Timestamp
        };
    }

    
    
    
    private async Task WriteCapturedAssertion(HttpListenerResponse response, SamlCapturedAssertion captured)
    {
        var data = new Dictionary<string, object?>
        {
            ["status"] = "captured",
            ["assertion"] = captured.Xml,
            ["rawBase64"] = captured.RawSamlResponse,
            ["relayState"] = captured.RelayState,
            ["targetUrl"] = captured.TargetUrl,
            ["binding"] = captured.Binding,
            ["timestamp"] = captured.Timestamp,
            ["decoded"] = new
            {
                messageType = captured.Decoded.MessageType,
                parsed = captured.Decoded.Parsed,
                signature = new
                {
                    present = captured.Decoded.Signature.Present,
                    algorithm = captured.Decoded.Signature.Algorithm,
                    location = captured.Decoded.Signature.Location
                },
                securityFindings = captured.Decoded.SecurityFindings.Select(f => new
                {
                    severity = f.Severity.ToString().ToLower(),
                    category = f.Category,
                    description = f.Description
                }).ToList()
            }
        };

        var capturedRequest = _context.SamlCapture.GetCapturedRequest();
        if (capturedRequest != null)
            data["samlRequest"] = FormatCapturedRequest(capturedRequest);

        await WriteSuccess(response, data);
    }

    private static object FormatCapturedRequest(SamlCapturedRequest req)
    {
        return new
        {
            binding = req.Binding,
            url = req.Url,
            timestamp = req.Timestamp,
            decoded = new
            {
                messageType = req.Decoded.MessageType,
                parsed = req.Decoded.Parsed,
                signature = new
                {
                    present = req.Decoded.Signature.Present,
                    algorithm = req.Decoded.Signature.Algorithm,
                    location = req.Decoded.Signature.Location
                },
                securityFindings = req.Decoded.SecurityFindings.Select(f => new
                {
                    severity = f.Severity.ToString().ToLower(),
                    category = f.Category,
                    description = f.Description
                }).ToList()
            }
        };
    }

    
    internal async Task<object> BuildCookieAuditPayloadAsync()
    {
        Security.CookieAuditResult result;
        try
        {
            result = await _context.CheckCookieSecurity();
        }
        catch (InvalidCastException ex) when (ex.Message.Contains("ICoreWebView2Cookie") || ex.Message.Contains("WebView2"))
        {
            return new
            {
                error = "WebView2 runtime does not support the ICoreWebView2Cookie interface. Update the WebView2 Runtime to use cookie auditing.",
                isClean = (bool?)null,
                cookieCount = 0,
                findingCount = 0,
                findings = Array.Empty<object>(),
                checklist = new Dictionary<string, object>(),
                summary = "Cookie audit skipped — WebView2 compatibility error."
            };
        }
        catch (Exception ex)
        {
            return new
            {
                error = $"Cookie audit failed: {ex.Message}",
                isClean = (bool?)null,
                cookieCount = 0,
                findingCount = 0,
                findings = Array.Empty<object>(),
                checklist = new Dictionary<string, object>(),
                summary = $"Cookie audit skipped — {ex.Message}"
            };
        }

        return new
        {
            error = (string?)null,
            isClean = (bool?)result.IsClean,
            cookieCount = result.CookieCount,
            findingCount = result.FindingCount,
            primarySource = result.PrimarySource,
            networkReconciledCookies = result.NetworkReconciledCookies,
            findings = result.Findings.Select(f => new
            {
                cookieName = f.CookieName,
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                recommendation = f.Recommendation
            }).ToList(),
            checklist = result.Checklist.ToDictionary(
                kv => kv.Key,
                kv => (object)new
                {
                    pass = kv.Value.Skipped ? null : (bool?)kv.Value.Pass,
                    skipped = kv.Value.Skipped,
                    issue = kv.Value.Issue,
                    cookies = kv.Value.Cookies
                }),
            summary = result.Format(includeDetails: false)
        };
    }

    
    
    
    internal static Security.TokenEntropySampleCollector.CollectOptions ParseTokenEntropyOptions(JsonBody body)
    {
        List<Security.TokenEntropySampleCollector.TokenTargetSpec>? targets = null;
        var targetDocs = body.GetArray("targets");
        if (targetDocs is { Count: > 0 })
        {
            targets = [];
            foreach (var doc in targetDocs)
            {
                using (doc)
                {
                    var item = new JsonBody(doc);
                    var paramName = item.GetString("paramName") ?? item.GetString("name");
                    if (string.IsNullOrWhiteSpace(paramName)) continue;
                    targets.Add(new Security.TokenEntropySampleCollector.TokenTargetSpec
                    {
                        Name = item.GetString("name") ?? paramName,
                        ParamName = paramName,
                        Source = ParseTokenCollectSource(item.GetString("source"))
                    });
                }
            }
        }

        var hasExplicitTarget = !string.IsNullOrWhiteSpace(body.GetString("paramName")) || targets is { Count: > 0 };
        var presets = body.GetStringList("presets") ?? body.GetStringArray("presets");

        return new Security.TokenEntropySampleCollector.CollectOptions
        {
            Name = body.GetString("name"),
            ParamName = body.GetString("paramName"),
            Source = ParseTokenCollectSource(body.GetString("source")),
            Targets = targets,
            Presets = presets,
            AutoDiscover = body.HasProperty("autoDiscover")
                ? body.GetBool("autoDiscover", true)
                : !hasExplicitTarget && (presets == null || presets.Count == 0),
            MinSamples = body.GetInt("minSamples", 2),
            PageNetworkOnly = body.GetBool("pageNetworkOnly", false),
            ExtraSamples = body.GetStringArray("samples") ?? body.GetStringArray("extraSamples"),
            IncludeDom = body.GetBool("includeDom", true)
        };
    }

    private static Security.TokenEntropySampleCollector.TokenCollectSource ParseTokenCollectSource(string? source) =>
        source?.Trim().ToLowerInvariant() switch
        {
            "query" => Security.TokenEntropySampleCollector.TokenCollectSource.Query,
            "header" => Security.TokenEntropySampleCollector.TokenCollectSource.Header,
            "cookie" => Security.TokenEntropySampleCollector.TokenCollectSource.Cookie,
            "json" => Security.TokenEntropySampleCollector.TokenCollectSource.Json,
            "form" => Security.TokenEntropySampleCollector.TokenCollectSource.Form,
            "dom" => Security.TokenEntropySampleCollector.TokenCollectSource.Dom,
            _ => Security.TokenEntropySampleCollector.TokenCollectSource.Auto
        };

    private static object FormatTokenEntropyPayload(Security.TokenEntropySampleCollector.CollectResult collected) => new
    {
        url = collected.Url,
        isClean = collected.IsClean,
        targetCount = collected.Targets.Count,
        recommendations = collected.Recommendations,
        targets = collected.Targets.Select(t => new
        {
            name = t.Name,
            paramName = t.ParamName,
            source = t.Source,
            isClean = t.Analysis.IsClean,
            minSamplesRequired = t.MinSamplesRequired,
            minSamplesMet = t.MinSamplesMet,
            totalSampleCount = t.TotalSampleCount,
            sampleSources = t.SampleSources,
            recommendations = t.Recommendations,
            samples = t.Analysis.Samples.Select(s => new
            {
                tokenName = s.CookieName,
                currentValue = s.CurrentValue,
                sampleCount = s.SampleCount,
                entropyBitsPerChar = Math.Round(s.EntropyBitsPerChar, 3),
                entropyAssessment = s.EntropyAssessment,
                patterns = s.Patterns
            }).ToList(),
            findings = t.Analysis.Findings.Select(f => new
            {
                tokenName = f.CookieName,
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                recommendation = f.Recommendation
            }).ToList()
        }).ToList()
    };

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private async Task HandlePostTraceInput(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var gateError = SafetyGate.RequireActive(body, "Input tracing sends payloads to the server");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        var delayBeforeTrace = Math.Clamp(body.GetInt("delayMs", 0), 0, 120_000);
        if (delayBeforeTrace > 0)
            await Task.Delay(delayBeforeTrace, _context.OperationCancellation);

        if (!TraceInputRequestParser.TryParse(body, out var options, out var batchPayloads, out var parseError))
        {
            await WriteError(response, 400, parseError!);
            return;
        }

        var tracer = new Security.InputTracer(_context);

        if (options.AutoBypass && batchPayloads == null)
        {
            var result = await tracer.TraceWithAutoBypassAsync(options);
            await WriteSuccess(response, FormatAutoBypassTraceResult(result));
            return;
        }

        if (batchPayloads != null && batchPayloads.Count > 0)
        {
            var result = await tracer.TraceBatchAsync(batchPayloads, options with { AutoBypass = false });
            await WriteSuccess(response, new
            {
                summary = new
                {
                    totalPayloads = result.TotalPayloads,
                    reflected = result.Reflected,
                    renderedInDom = result.RenderedInDom,
                    blockedByCsp = result.BlockedByCsp,
                    serverErrors = result.ServerErrors,
                    sqliIndicatorsDetected = result.SqliIndicatorsDetected,
                    sinkHits = result.SinkHits,
                    worstVerdict = result.WorstVerdict.ToString().ToLowerInvariant()
                },
                elapsedMs = result.ElapsedMs,
                traces = result.Traces.Select(FormatTraceResult)
            });
        }
        else
        {
            var result = await tracer.TraceAsync(options);
            await WriteSuccess(response, FormatTraceResult(result));
        }
    }

    
    
    
    
    private static object FormatSqliLoginSweepResult(Security.SqliLoginSweep.SqliLoginSweepResult result) => new
    {
        result.Message,
        result.LoginUrlsProbed,
        urlsProbed = result.UrlsProbed,
        result.PayloadsSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.UsernameField,
            f.PasswordField,
            f.Payload,
            f.Shape,
            f.Signal,
            f.Evidence
        })
    };

    private static object FormatNosqlScanResult(Security.NosqlScanProbe.NosqlScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.PayloadsSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings
    };

    private static object FormatLdapScanResult(Security.LdapScanProbe.LdapScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings
    };

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private static SstiScanRunner.SstiScanOptions BuildSstiScanOptions(JsonBody body)
    {
        var depth = body.GetString("depth");
        var depthProfile = InjectionScanDepth.Resolve(depth, body.GetInt("maxCandidates", 0));
        var options = new SstiScanRunner.SstiScanOptions
        {
            MaxCandidates = depthProfile.MaxCandidates,
            TimeoutMs = body.GetInt("timeoutMs", body.GetInt("timeout", 15000)),
            ParamName = body.GetString("paramName"),
            Depth = depthProfile.Name
        };

        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            options.UrlTemplate = req.GetString("url");
            options.Method = req.GetString("method") ?? "GET";
            options.Headers = req.GetStringDictionary("headers");
            if (req.HasProperty("body"))
                options.BodyTemplate = req.GetString("body");
            else if (req.HasProperty("json"))
                options.BodyTemplate = req.GetJsonElement("json")?.GetRawText();
        }

        return options;
    }

    
    
    private static XssScanRunner.XssScanOptions BuildXssScanOptions(JsonBody body)
    {
        var depth = body.GetString("depth");
        var depthProfile = InjectionScanDepth.Resolve(depth, body.GetInt("maxCandidates", 0));
        var options = new XssScanRunner.XssScanOptions
        {
            Url = body.GetString("url"),
            ParamName = body.GetString("paramName"),
            IncludeReflected = body.GetBool("includeReflected", true),
            IncludeDom = body.GetBool("includeDom", true),
            IncludeStored = body.HasProperty("includeStored")
                ? body.GetBool("includeStored")
                : depthProfile.IncludeStoredXss,
            MaxCandidates = depthProfile.MaxCandidates,
            TimeoutMs = body.GetInt("timeoutMs", body.GetInt("timeout", 10_000)),
            MaxBypassAttempts = body.HasProperty("maxBypassAttempts")
                ? body.GetInt("maxBypassAttempts", depthProfile.MaxBypassAttempts)
                : depthProfile.MaxBypassAttempts,
            Depth = depthProfile.Name,
            PayloadProfile = PayloadProfileExtensions.Parse(body.GetString("payloadProfile"))
        };

        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            options.RequestUrlTemplate = req.GetString("url");
            options.RequestMethod = req.GetString("method") ?? "GET";
            options.RequestHeaders = req.GetStringDictionary("headers");
            if (req.HasProperty("body"))
                options.RequestBodyTemplate = req.GetString("body");
            else if (req.HasProperty("json"))
                options.RequestBodyTemplate = req.GetJsonElement("json")?.GetRawText();
            if (string.IsNullOrWhiteSpace(options.ParamName))
                options.ParamName = body.GetString("paramName");
        }

        return options;
    }

    private static CstiScanRunner.CstiScanOptions BuildCstiScanOptions(JsonBody body)
    {
        var options = new CstiScanRunner.CstiScanOptions
        {
            Url = body.GetString("url"),
            ParamName = body.GetString("paramName"),
            Escalate = body.GetBool("escalate", false),
            MonitorSinks = body.GetBool("monitorSinks", true),
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", body.GetInt("timeout", 10_000))
        };

        if (body.GetStringArray("engines") is { Count: > 0 } engines)
            options.Engines = engines;
        if (body.GetStringArray("sources") is { Count: > 0 } sources)
            options.Sources = sources;

        return options;
    }

    private static ParserProbe.ParserProbeOptions BuildParserProbeOptions(JsonBody body)
    {
        var options = new ParserProbe.ParserProbeOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 5),
            TimeoutMs = body.GetInt("timeoutMs", body.GetInt("timeout", 15000)),
            IncludeContentTypeMatrix = body.GetBool("includeContentTypeMatrix", true),
            IncludeBodyShapeMatrix = body.GetBool("includeBodyShapeMatrix", true),
            IncludeBrowserCookies = body.HasProperty("includeBrowserCookies")
                ? body.GetBool("includeBrowserCookies")
                : null
        };

        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            options.Url = req.GetString("url");
            options.Method = req.GetString("method") ?? "POST";
            options.Headers = req.GetStringDictionary("headers") ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var cookie = req.GetString("cookie");
            if (!string.IsNullOrWhiteSpace(cookie))
                options.Headers["Cookie"] = cookie;
            if (req.HasProperty("body"))
                options.Body = req.GetString("body");
            else if (req.HasProperty("json"))
                options.Body = req.GetJsonElement("json")?.GetRawText();
        }

        return options;
    }

    private static CmdCanaryProbe.CmdCanaryOptions BuildCmdCanaryOptions(JsonBody body)
    {
        var options = new CmdCanaryProbe.CmdCanaryOptions
        {
            MaxCandidates = body.GetInt("maxCandidates", 10),
            TimeoutMs = body.GetInt("timeoutMs", body.GetInt("timeout", 15000)),
            IncludeSstiTier = body.GetBool("includeSstiTier", true),
            IncludeCallback = body.GetBool("includeCallback"),
            IncludeTiming = body.GetBool("includeTiming"),
            TimingThresholdMs = body.GetInt("timingThresholdMs", 3500),
            CallbackWaitMs = body.GetInt("callbackWaitMs", 2000),
            CallbackDomain = body.GetString("callbackDomain"),
            ParamName = body.GetString("paramName")
        };

        var reqObj = body.GetObject("request");
        if (reqObj != null)
        {
            var req = new JsonBody(reqObj);
            options.UrlTemplate = req.GetString("url");
            options.Method = req.GetString("method") ?? "GET";
            options.Headers = req.GetStringDictionary("headers");
            if (req.HasProperty("body"))
                options.BodyTemplate = req.GetString("body");
            else if (req.HasProperty("json"))
                options.BodyTemplate = req.GetJsonElement("json")?.GetRawText();
        }

        return options;
    }

    private static object FormatParserProbeResult(ParserProbe.ParserProbeResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.SkippedNoSession,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Signal,
            f.Url,
            f.Method,
            f.ProbeKind,
            f.ContentType,
            f.BodyVariant,
            f.BaselineStatus,
            f.ProbeStatus,
            f.Detail
        })
    };

    private static object FormatDeserializationScanResult(DeserializationScanProbe.DeserializationScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Signal,
            f.Url,
            f.Method,
            f.Variant,
            f.Status,
            f.Detail
        })
    };

    private static object FormatFileUploadScanResult(FileUploadScanProbe.FileUploadScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Signal,
            f.Url,
            f.Variant,
            f.Status,
            f.Detail
        }),
        xxeFindings = result.XxeFindings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Signal,
            f.Url,
            f.Shape,
            f.Status,
            f.Detail
        })
    };

    private static object FormatNextJsRscScanResult(NextJsRscScanProbe.NextJsRscScanResult result) => new
    {
        result.Message,
        result.NextJsDetected,
        result.ProbesSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Signal,
            f.Url,
            f.Variant,
            f.Status,
            f.Detail
        })
    };

    private static object FormatRaceConditionScanResult(RaceConditionScanProbe.RaceConditionScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.BurstsSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        hasObservations = result.HasObservations,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.Variant,
            f.AcceptedCount,
            f.TotalRequests,
            f.MatchReason,
            f.Detail
        }),
        observations = result.Observations.Select(o => new
        {
            o.Category,
            o.Severity,
            o.Url,
            o.Detail
        })
    };

    private static object FormatRateLimitAuditResult(RateLimitAuditProbe.RateLimitAuditResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.RequestsSent,
        result.ElapsedMs,
        result.RateLimitRespected,
        http429Responses = result.Http429Responses,
        result.SkippedDueTo429,
        result.BackoffEvents,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.Kind,
            f.MatchReason,
            f.Detail,
            f.Evidence
        })
    };

    private static object FormatReDoSScanResult(ReDoSScanProbe.ReDoSScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.ElapsedMs,
        result.RateLimitRespected,
        result.SkippedDueTo429,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.Param,
            f.Payload,
            f.BaselineSeconds,
            f.AttackSeconds,
            f.Detail
        })
    };

    private static object FormatBodySizeLimitResult(BodySizeLimitProbe.BodySizeLimitResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.ElapsedMs,
        result.RateLimitRespected,
        result.SkippedDueTo429,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.LargestAcceptedBytes,
            f.LargestTierBytes,
            f.Detail,
            f.TierResults
        }),
        limitPresent = result.LimitPresent.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.LargestAcceptedBytes,
            f.LargestTierBytes,
            f.Detail,
            f.TierResults
        })
    };

    private static object FormatCostlyOperationsResult(CostlyOperationsProbe.CostlyOperationsResult result) => new
    {
        result.Message,
        result.SafetyMode,
        result.EntriesExamined,
        result.ProbesSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        checksRun = result.ChecksRun,
        findings = result.Findings.Select(FormatCostlyFinding),
        inferredLeads = result.InferredLeads.Select(FormatCostlyFinding)
    };

    private static object FormatCostlyFinding(CostlyOperationsProbe.CostlyFinding f) => new
    {
        f.Category,
        f.Severity,
        title = f.Title,
        endpoint = f.Endpoint,
        f.Method,
        parameter = f.Parameter,
        f.Detail,
        f.Evidence,
        f.Remediation,
        f.Confidence,
        checkId = f.CheckId,
        relatedProbe = f.RelatedProbe,
        networkEntryId = f.NetworkEntryId
    };

    private static object FormatSwaggeringResult(SwaggeringOrchestrator.SwaggeringResult result) => new
    {
        result.Message,
        result.SafetyMode,
        depth = result.Depth,
        result.ElapsedMs,
        result.Partial,
        result.BudgetExhausted,
        result.OperationsInCatalog,
        result.RequestsSent,
        specSources = result.SpecSources,
        phasesCompleted = result.PhasesCompleted,
        warnings = result.Warnings,
        coverage = new
        {
            result.Coverage.Probed,
            result.Coverage.Skipped,
            result.Coverage.NotProbed,
            result.Coverage.NotReached,
            result.Coverage.Http2xx,
            result.Coverage.Http4xx,
            result.Coverage.Http5xx
        },
        operations = result.Operations.Select(o => new
        {
            o.Method,
            path = o.Path,
            operationId = o.OperationId,
            o.RequiresSecurity,
            outcome = o.Outcome,
            status = o.Status,
            url = o.Url,
            skipReason = o.SkipReason
        }),
        inventory = result.InventorySummary == null ? null : new
        {
            result.InventorySummary.DocumentedCount,
            result.InventorySummary.ShadowCount,
            result.InventorySummary.ZombieCandidateCount,
            result.InventorySummary.OpenApiPathCount
        },
        shadowPaths = result.ShadowPaths,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Phase,
            title = f.Title,
            f.Detail,
            url = f.Url,
            f.Method,
            f.Status,
            f.Variant,
            f.SpecUrl,
            evidence = f.Evidence,
            f.Confidence
        }),
        costlyFindings = result.CostlyFindings.Select(FormatCostlyFinding),
        autoScan = result.AutoScan == null ? null : new
        {
            result.AutoScan.FindingsCount,
            result.AutoScan.EndpointsDiscovered,
            result.AutoScan.ScannersRun,
            result.AutoScan.Partial,
            result.AutoScan.BudgetExhausted,
            findings = result.AutoScan.Findings.Take(40).Select(f => new
            {
                f.Scanner,
                f.Severity,
                f.Title,
                endpoint = f.Endpoint,
                f.Detail
            })
        }
    };

    private static object FormatCaptchaReplayScanResult(CaptchaReplayScanProbe.CaptchaReplayScanResult result) => new
    {
        result.Message,
        result.CaptchaServicesProbed,
        result.SubmitEndpointsTested,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        hasObservations = result.HasObservations,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.CaptchaUrl,
            f.SubmitUrl,
            f.Method,
            f.CaptchaId,
            f.FirstStatus,
            f.ReplayStatus,
            f.Detail
        }),
        observations = result.Observations.Select(o => new
        {
            o.Category,
            o.Severity,
            o.Url,
            o.Detail
        })
    };

    private static object FormatWorkflowSkipScanResult(WorkflowSkipScanProbe.WorkflowSkipScanResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.ProbesSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        hasObservations = result.HasObservations,
        properlyGatedCount = result.ProperlyGated.Count,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Url,
            f.Method,
            f.StageRank,
            f.PathPrefix,
            f.Status,
            f.BodyVariant,
            f.Detail
        }),
        properlyGated = result.ProperlyGated,
        observations = result.Observations.Select(o => new
        {
            o.Category,
            o.Severity,
            o.Url,
            o.Detail
        })
    };

    private static object FormatCmdCanaryResult(CmdCanaryProbe.CmdCanaryResult result) => new
    {
        result.Message,
        result.CandidatesProbed,
        result.PayloadsSent,
        result.ElapsedMs,
        hasFindings = result.HasFindings,
        findings = result.Findings.Select(f => new
        {
            f.Category,
            f.Severity,
            f.Tier,
            f.Url,
            f.Method,
            f.ParamName,
            f.Payload,
            f.Status,
            f.Indicator,
            f.Detail
        })
    };

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private WorkflowDependencies BuildWorkflowDependencies() => new()
    {
        Context = _context,
        IdentityStore = _identityStore,
        Peers = Peers,
        SessionName = SessionName,
        ScreenshotDir = _screenshotDir,
        Cancellation = _context.OperationCancellation
    };

    
    
    
    
    private static object FormatWorkflowVerifyResponse(WorkflowVerifyResult r)
    {
        var effectObserved = r.Trigger.FirstOrDefault(t => t.TryGetValue("type", out var ty) && ty?.ToString() == "inject")
            is { } inj && inj.TryGetValue("effectObserved", out var eo) && eo is bool b && b;
        return new
        {
            verified = r.Verified,
            effectObserved,
            name = r.Name,
            workflowId = r.WorkflowId,
            setupOk = r.SetupOk,
            triggerOk = r.TriggerOk,
            oraclePassed = r.OraclePassed,
            cleanupOk = r.CleanupOk,
            oracle = r.Oracle,
            setup = r.Setup,
            trigger = r.Trigger,
            cleanup = r.Cleanup,
            failurePhase = r.FailurePhase,
            error = r.Error,
            evidenceBundlePath = r.EvidenceBundlePath,
            elapsedMs = r.ElapsedMs,
            capturedVars = r.CapturedVars,
            stepErrors = r.StepErrors,
            // Legacy verify compatibility fields
            cleanedUp = r.CleanupOk,
            evidence = r.Oracle?.Evidence
        };
    }

    private static object FormatExploitVerifyResponse(Security.ExploitVerificationResult r) => new
    {
        r.Verified,
        effectObserved = r.EffectObserved,
        effectValue = r.EffectValue,
        evidence = r.Evidence,
        cleanedUp = r.CleanedUp,
        r.Error,
        r.ElapsedMs
    };

    private static object FormatTraceResult(Security.InputTraceResult t) => new
    {
        payload = t.Payload,
        documentUrl = t.DocumentUrl,
        confirmedXss = Security.XssBypassProbes.IsConfirmedXss(t),
        sinkReached = Security.XssBypassProbes.IsSinkReachConfirmed(t),
        elapsedMs = t.ElapsedMs,
        injection = new
        {
            sourceType = t.Injection.SourceType,
            inputAccepted = t.Injection.InputAccepted,
            domValueBeforeSubmit = t.Injection.DomValueBeforeSubmit,
            treatment = t.Injection.Treatment,
            constraintType = t.Injection.ConstraintType,
            encoding = t.Injection.Encoding,
            navigatedUrl = t.Injection.NavigatedUrl,
            notes = t.Injection.Notes
        },
        network = t.Network != null ? new
        {
            requestFound = t.Network.RequestFound,
            method = t.Network.Method,
            url = t.Network.Url,
            payloadLocation = t.Network.PayloadLocation,
            payloadInRequest = t.Network.PayloadInRequest,
            contentType = t.Network.ContentType,
            parameterName = t.Network.ParameterName
        } : null,
        serverResponse = t.ServerResponse != null ? new
        {
            status = t.ServerResponse.Status,
            contentType = t.ServerResponse.ContentType,
            payloadReflected = t.ServerResponse.PayloadReflected,
            reflectionCount = t.ServerResponse.ReflectionCount,
            reflections = t.ServerResponse.Reflections.Select(r => new
            {
                context = r.Context,
                encoded = r.Encoded,
                surrounding = r.Surrounding,
                dangerous = r.Dangerous,
                reason = r.Reason
            })
        } : null,
        sqliIndicators = t.SqliIndicators?.Select(s => new { engine = s.Engine, pattern = s.Pattern, snippet = s.Snippet }),
        dom = t.Dom != null ? new
        {
            payloadRendered = t.Dom.PayloadRendered,
            renderedCount = t.Dom.RenderedCount,
            context = t.Dom.Context,
            dangerous = t.Dom.Dangerous,
            reason = t.Dom.Reason
        } : null,
        csp = t.Csp != null ? new
        {
            present = t.Csp.Present,
            relevantDirective = t.Csp.RelevantDirective,
            wouldBlock = t.Csp.WouldBlock,
            reason = t.Csp.Reason
        } : null,
        reachMap = t.ReachMap?.Select(r => new
        {
            sink = r.Sink,
            containsReachCanary = r.ContainsReachCanary,
            snippet = r.Snippet,
            pageStack = r.PageStack,
            consequence = r.Consequence
        }),
        sinks = t.Sinks != null ? new
        {
            monitored = t.Sinks.Monitored,
            hitCount = t.Sinks.HitCount,
            payloadReachedSink = t.Sinks.PayloadReachedSink,
            executionConfirmed = t.Sinks.ExecutionConfirmed,
            dialogEffectConfirmed = t.Sinks.DialogEffectConfirmed,
            mostDangerousSink = t.Sinks.MostDangerousSink,
            instrumented = t.Sinks.Instrumented,
            sinksSeen = t.Sinks.SinksSeen,
            sourcesSeen = t.Sinks.SourcesSeen,
            zeroResultReason = t.Sinks.ZeroResultReason,
            hits = t.Sinks.Hits.Select(h => new
            {
                sink = h.Sink,
                containsPayload = h.ContainsPayload,
                snippet = h.Snippet,
                stack = h.Stack,
                classification = h.Classification
            })
        } : null,
        verdict = new
        {
            severity = t.Verdict.Severity.ToString().ToLowerInvariant(),
            summary = t.Verdict.Summary,
            recommendation = t.Verdict.Recommendation
        },
        bypassAttempts = t.ConfirmationAttempts.Select(a => new
        {
            vector = a.Vector,
            payload = a.Payload,
            confirmedXss = a.ConfirmedXss,
            verdict = a.Trace.Verdict.Severity.ToString().ToLowerInvariant(),
            summary = a.Trace.Verdict.Summary
        })
    };

    private static object FormatAutoBypassTraceResult(Security.InputTraceAutoBypassResult r) => new
    {
        autoBypass = true,
        primaryPayload = r.PrimaryPayload,
        primaryOutcome = Security.XssBypassProbes.DescribePrimaryOutcome(r.PrimaryTrace),
        bypassConfirmed = r.BypassConfirmed,
        bypassSummary = r.BypassSummary,
        bypassAttempts = r.BypassAttempts.Select(a => new
        {
            vector = a.Vector,
            payload = a.Payload,
            confirmedXss = a.ConfirmedXss,
            verdict = a.Trace.Verdict.Severity.ToString().ToLowerInvariant(),
            summary = a.Trace.Verdict.Summary
        }),
        urlProbeAttempts = r.UrlProbeAttempts.Select(a => new
        {
            vector = a.Vector,
            payload = a.Payload,
            confirmedXss = a.ConfirmedXss,
            verdict = a.Trace.Verdict.Severity.ToString().ToLowerInvariant(),
            summary = a.Trace.Verdict.Summary
        }),
        // Top-level verdict alias — agents often look for `verdict` and mis-read null when only worstVerdict exists.
        verdict = r.WorstVerdict.ToString().ToLowerInvariant(),
        worstVerdict = r.WorstVerdict.ToString().ToLowerInvariant(),
        elapsedMs = r.ElapsedMs,
        effectiveTrace = FormatTraceResult(r.EffectiveTrace),
        primaryTrace = FormatTraceResult(r.PrimaryTrace),
        successfulBypass = r.SuccessfulBypass != null ? FormatTraceResult(r.SuccessfulBypass) : null
    };

    private async Task HandlePostFirewallTest(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var gateError = SafetyGate.RequireActive(body, "Firewall testing injects scripts and modifies page state");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        HashSet<string>? tests = null;
        var testsArr = body.GetStringArray("tests");
        if (testsArr != null)
            tests = testsArr.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var verbose = body.GetBool("verbose");
        var probes = body.GetStringArray("probes");
        var tester = new Security.FirewallTester(_context);
        var result = await tester.RunAsync(tests, verbose, probes);
        await WriteSuccess(response, FirewallApiPayload.Build(result, verbose));
    }

    private async Task HandlePostStorageAudit(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, await BuildStorageAuditPayloadAsync());
    }

    internal async Task<object> BuildStorageAuditPayloadAsync()
    {
        var result = await _context.CheckStorageSecurity();

        return new
        {
            isClean = result.IsClean,
            localStorageCount = result.LocalStorageCount,
            sessionStorageCount = result.SessionStorageCount,
            findingCount = result.FindingCount,
            findings = result.Findings.Select(f => new
            {
                storageType = f.StorageType,
                key = f.Key,
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                recommendation = f.Recommendation,
                valueSnippet = f.ValueSnippet
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

    internal async Task<object> BuildSmugglingPassivePayloadAsync()
    {
        var headersResult = await _context.CheckSecurityHeaders();

        if (!headersResult.FetchSucceeded)
        {
            return new
            {
                isClean = true,
                risk = "unknown",
                error = headersResult.FetchError ?? "Could not fetch response headers",
                indicators = Array.Empty<string>(),
                recommendation = "Unable to analyze — response headers not available."
            };
        }

        var httpVersion = headersResult.IsHttps ? "unknown-https" : "HTTP/1.1";

        headersResult.RawHeaders.TryGetValue("server", out var serverHeader);

        // Convert lowercase keys to case-insensitive dictionary for the analyzer
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in headersResult.RawHeaders)
            headers[kvp.Key] = kvp.Value;

        var passive = Security.HttpRequestSmugglingScanner.AnalyzePassive(headers, httpVersion, serverHeader);

        return new
        {
            isClean = passive.IsClean,
            risk = passive.Risk,
            indicators = passive.Indicators,
            context = passive.Context,
            hasMultipleContentLength = passive.HasMultipleContentLength,
            hasAmbiguousFraming = passive.HasAmbiguousFraming,
            proxyDetected = passive.ProxyDetected,
            recommendation = passive.Recommendation
        };
    }

    private async Task HandlePostStructuredText(HttpListenerRequest request, HttpListenerResponse response)
    {
        var result = await _context.GetStructuredText();

        await WriteSuccess(response, new
        {
            url = result.Url,
            title = result.Title,
            language = result.Language,
            metaDescription = result.MetaDescription,
            wordCount = result.WordCount,
            headings = result.Headings.Select(h => new { level = h.Level, text = h.Text }).ToList(),
            paragraphs = result.Paragraphs,
            links = result.Links.Select(l => new { text = l.Text, url = l.Url }).ToList(),
            buttons = result.Buttons,
            labels = result.Labels,
            images = result.Images.Select(i => new { alt = i.Alt, src = i.Src }).ToList(),
            allText = result.AllText
        });
    }

    private async Task HandlePostConsistency(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, await BuildConsistencyPayloadAsync());
    }

    private async Task HandlePostTechStack(HttpListenerRequest request, HttpListenerResponse response)
    {
        var result = await _context.CheckTechStack();

        await WriteSuccess(response, new
        {
            detectionCount = result.DetectionCount,
            categories = result.Categories,
            detections = result.Detections.Select(d => new
            {
                name = d.Name,
                version = d.Version,
                category = d.Category,
                evidence = d.Evidence,
                source = d.Source,
                confidence = d.Confidence
            }).ToList(),
            frameworks = result.Frameworks.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            servers = result.Servers.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            jsLibraries = result.JsLibraries.Select(d => d.Name + (d.Version != null ? $" {d.Version}" : "")).ToList(),
            waf = result.Waf.Select(d => d.Name).ToList(),
            cdn = result.Cdn.Select(d => d.Name).ToList(),
            cache = result.Cache.ToApiObject(),
            elapsedMs = result.ElapsedMs,
            summary = result.Format(includeDetails: false)
        });
    }

    private async Task HandlePostThirdParty(HttpListenerRequest request, HttpListenerResponse response)
    {
        var result = await _context.CheckThirdParty();

        await WriteSuccess(response, new
        {
            isClean = result.IsClean,
            totalCount = result.TotalCount,
            domainCount = result.DomainCount,
            domains = result.Domains,
            totalSizeBytes = result.TotalSizeBytes,
            sriCount = result.SriCount,
            resources = result.Resources.Select(r => new
            {
                url = r.Url,
                domain = r.Domain,
                hostname = r.Hostname,
                etldPlus1 = r.EtldPlus1,
                type = r.Type,
                sizeBytes = r.SizeBytes,
                hasSri = r.HasSri,
                integrityHash = r.IntegrityHash
            }).ToList(),
            summary = result.Format(includeDetails: false)
        });
    }

    private async Task HandlePostMonkeyTest(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var gateError = SafetyGate.RequireActive(body, "Monkey testing clicks, types, and submits forms randomly — may trigger server-side actions");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        _ = ShowMessageAsync("Monkey test starting — random actions may trigger server-side effects.", "warning", 10000);

        var options = new MonkeyTestOptions
        {
            Actions = body.GetInt("actions", 500),
            Delay = body.GetInt("delay", 20),
            Seed = body.HasProperty("seed") ? body.GetInt("seed", 0) : null
        };

        var result = await _context.RunMonkeyTest(options);

        await WriteSuccess(response, new
        {
            survived = result.Survived,
            errorCount = result.ErrorCount,
            actionsPerformed = result.ActionsPerformed,
            durationSeconds = result.DurationSeconds,
            seed = result.Seed,
            navigated = result.Navigated,
            startUrl = result.StartUrl,
            endUrl = result.EndUrl,
            fpsDrops = result.FpsDrops,
            lowestFps = result.LowestFps,
            stoppedEarly = result.StoppedEarly,
            errors = result.Errors.Select(e => new
            {
                type = e.Type,
                message = e.Message,
                source = e.Source,
                line = e.Line
            }).ToList(),
            navigationAttempts = result.NavigationAttempts.Select(n => new
            {
                type = n.Type,
                url = n.Url
            }).ToList(),
            uniqueErrors = result.UniqueErrors,
            summary = result.Format(includeDetails: false)
        });
    }

    private async Task HandlePostMonkeyTrowser(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var gateError = SafetyGate.RequireActive(body, "Monkey Trowser systematically clicks elements and fills forms — may trigger server-side actions");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        _ = ShowMessageAsync("Monkey Trowser starting — form fuzzing and element clicks may trigger server-side effects.", "warning", 10000);

        var options = new SmartTestOptions
        {
            FollowLinks = body.GetBool("followLinks", true),
            FuzzForms = body.GetBool("fuzzForms", true),
            MaxPages = body.GetInt("maxPages", 10),
            MaxActionsPerPage = body.GetInt("maxActionsPerPage", 100),
            Scope = body.GetString("scope"),
        };

        var result = await _context.RunSmartMonkey(options);

        await WriteSuccess(response, new
        {
            passed = result.Passed,
            issueCount = result.IssueCount,
            pagesVisited = result.PagesVisited,
            elementsTested = result.ElementsTested,
            formsFuzzed = result.FormsFuzzed,
            durationSeconds = result.DurationSeconds,
            startUrl = result.StartUrl,
            issues = result.Issues.Select(i => new
            {
                page = i.Page,
                element = i.Element,
                action = i.Action,
                issue = i.Issue,
                issueType = i.IssueType
            }).ToList(),
            pageSummaries = result.PageSummaries.Select(p => new
            {
                url = p.Url,
                elementsTested = p.ElementsTested,
                formsFuzzed = p.FormsFuzzed,
                issuesFound = p.IssuesFound
            }).ToList(),
            summary = result.Format(includeDetails: false)
        });
    }

    private async Task HandlePostSettingsScope(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var scope = body.GetString("scope");
        if (string.IsNullOrWhiteSpace(scope))
        {
            await WriteError(response, 400, "Provide a non-empty \"scope\" string (same format as Settings > Navigation Scope or --scope).");
            return;
        }

        scope = scope.Trim();
        if (_context.NavigationGuard == null)
            _context.NavigationGuard = new NavigationGuard(scope);
        else
            _context.NavigationGuard.SetScope(scope);

        await WriteSuccess(response, new
        {
            scope = _context.NavigationGuard.Scope,
            navigationRestricted = _context.NavigationGuard.IsRestricted
        });
    }

    private async Task HandleGetSettingsThrottle(HttpListenerResponse response)
    {
        await WriteSuccess(response, new
        {
            maxRequestsPerSecond = _pacingMaxRequestsPerSecond,
            delayBetweenNavigations = _pacingDelayBetweenNavigationsMs,
            minIntervalMs = _pacingMaxRequestsPerSecond > 0.0001
                ? 1000.0 / _pacingMaxRequestsPerSecond
                : 0
        });
    }

    private async Task HandlePostSettingsThrottle(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.HasProperty("maxRequestsPerSecond") && !body.HasProperty("delayBetweenNavigations"))
        {
            await WriteError(response, 400,
                "Provide at least one of: maxRequestsPerSecond, delayBetweenNavigations (set to 0 to clear that limit).");
            return;
        }

        if (body.HasProperty("maxRequestsPerSecond"))
        {
            _pacingMaxRequestsPerSecond = Math.Clamp(body.GetDouble("maxRequestsPerSecond", 0), 0, 200);
            if (_pacingMaxRequestsPerSecond < 0.0001)
            {
                _pacingMaxRequestsPerSecond = 0;
                _pacingNextStartUtc = DateTimeOffset.MinValue;
            }
        }

        if (body.HasProperty("delayBetweenNavigations"))
            _pacingDelayBetweenNavigationsMs = Math.Clamp(body.GetInt("delayBetweenNavigations", 0), 0, 300_000);

        await WriteSuccess(response, new
        {
            maxRequestsPerSecond = _pacingMaxRequestsPerSecond,
            delayBetweenNavigations = _pacingDelayBetweenNavigationsMs,
            minIntervalMs = _pacingMaxRequestsPerSecond > 0.0001
                ? 1000.0 / _pacingMaxRequestsPerSecond
                : 0
        });
    }

    private async Task HandlePostInterrupter(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var gateError = SafetyGate.RequireActive(body, "Interrupter test reloads the page while injecting API faults — real requests still hit the server");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        _ = ShowMessageAsync("Interrupter test starting — page will reload multiple times to test fault handling.", "warning", 10000);

        var options = new InterrupterOptions
        {
            Url = body.GetString("url"),
            Method = body.GetString("method"),
            Faults = body.GetStringList("faults"),
            MaxEndpoints = body.GetInt("maxEndpoints", 20),
            MinRelevanceScore = body.HasProperty("minRelevanceScore")
                ? body.GetInt("minRelevanceScore", 0)
                : body.GetInt("minScore", 0),
            MergeAttackSurface = body.GetBool("mergeAttackSurface", true),
            WaitForIdle = body.GetBool("waitForIdle"),
            CustomFaults = ParseCustomFaultsFromBody(body),
            Actions = ParseInterrupterActionsFromBody(body),
            AllowedHosts = body.GetStringList("allowedHosts"),
            CooldownMs = body.GetInt("cooldownMs"),
            RestoreUrl = body.GetBool("restoreUrl", true),
        };

        var result = await _context.RunInterrupterTest(options);

        await WriteSuccess(response, new
        {
            endpointsTested = result.EndpointsTested,
            scenarioCount = result.ScenarioCount,
            passed = result.Passed,
            failed = result.Failed,
            durationSeconds = result.DurationSeconds,
            startUrl = result.StartUrl,
            finalUrl = result.FinalUrl,
            loginRedirectDetected = result.LoginRedirectDetected,
            restoreError = result.RestoreError,
            discoveredEndpoints = result.DiscoveredEndpoints.Select(e => new
            {
                urlPattern = e.UrlPattern,
                method = e.Method,
                relevanceScore = e.RelevanceScore,
            }).ToList(),
            scenarios = result.Scenarios.Select(s => new
            {
                endpoint = s.Endpoint,
                method = s.Method,
                faultName = s.FaultName,
                faultDescription = s.FaultDescription,
                passed = s.Passed,
                signals = s.Signals.Select(sig => new
                {
                    type = sig.Type,
                    message = sig.Message,
                    source = sig.Source,
                }).ToList(),
            }).ToList(),
            summary = result.Format(includeDetails: false)
        });
    }

    private static List<CustomFault>? ParseCustomFaultsFromBody(JsonBody body)
    {
        var arr = body.GetArray("customFaults");
        if (arr == null) return null;
        var list = new List<CustomFault>();
        foreach (var doc in arr)
        {
            var item = new JsonBody(doc);
            var name = item.GetString("name");
            if (string.IsNullOrWhiteSpace(name)) continue;
            list.Add(new CustomFault
            {
                Name = name,
                Status = item.GetInt("status", 500),
                Body = item.GetString("body"),
                Headers = item.GetStringDictionary("headers"),
                DelayMs = item.GetInt("delayMs"),
            });
        }
        return list.Count > 0 ? list : null;
    }

    private static List<InterrupterAction>? ParseInterrupterActionsFromBody(JsonBody body)
    {
        var arr = body.GetArray("actions");
        if (arr == null) return null;
        var list = new List<InterrupterAction>();
        foreach (var doc in arr)
        {
            var item = new JsonBody(doc);
            var action = item.GetString("action");
            if (string.IsNullOrWhiteSpace(action)) continue;
            list.Add(new InterrupterAction
            {
                Action = action,
                Ref = item.HasProperty("ref") ? item.GetInt("ref") : null,
                Selector = item.GetString("selector"),
                ByText = item.GetString("byText"),
                Placeholder = item.GetString("placeholder"),
                Role = item.GetString("role"),
                Name = item.GetString("name"),
                Label = item.GetString("label"),
                TestId = item.GetString("testId"),
                Text = item.GetString("text"),
                Value = item.GetString("value"),
                Key = item.GetString("key"),
                DelayMs = item.GetInt("delayMs"),
            });
        }
        return list.Count > 0 ? list : null;
    }

    private async Task HandlePostFuzz(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var gateError = SafetyGate.RequireActive(body, "Request fuzzer sends many requests with potentially malicious payloads");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        FuzzerOptions options;
        try
        {
            options = ParseFuzzerOptions(body);
        }
        catch (ArgumentException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        _ = ShowMessageAsync($"Request Fuzzer starting — {options.AttackType} attack with {options.InjectionPoints.Count} injection point(s).", "warning", 10000);

        FuzzerResult result;
        try
        {
            result = await _context.RunFuzzerTest(options);
        }
        catch (ArgumentException ex)
        {
            await WriteError(response, 400, ex.Message);
            return;
        }

        await WriteSuccess(response, new
        {
            attackType = result.AttackType.ToString().ToLowerInvariant(),
            totalRequests = result.TotalRequests,
            completed = result.Completed,
            errors = result.Errors,
            flagged = result.Flagged,
            stoppedEarly = result.StoppedEarly,
            stopReason = result.StopReason,
            durationSeconds = result.DurationSeconds,
            statusDistribution = result.StatusDistribution,
            timing = result.Timing != null ? new
            {
                avgMs = result.Timing.AvgMs,
                minMs = result.Timing.MinMs,
                maxMs = result.Timing.MaxMs,
                p95Ms = result.Timing.P95Ms,
            } : null,
            results = result.Results.Select(r => new
            {
                index = r.Index,
                payload = r.Payload,
                payloads = r.Payloads,
                payloadIndices = r.PayloadIndices,
                status = r.Status,
                statusText = r.StatusText,
                durationMs = r.DurationMs,
                responseLength = r.ResponseLength,
                body = r.Body,
                bodySnippet = r.BodySnippet,
                flagged = r.Flagged,
                flags = r.Flags.ToString(),
                flagDetails = r.FlagDetails,
                error = r.Error,
                injectedUrl = r.InjectedUrl,
                injectedBody = r.InjectedBody,
                location = r.Location,
            }).ToList(),
            summary = result.Format(includeDetails: false)
        });
    }

    private static FuzzerOptions ParseFuzzerOptions(JsonBody body)
    {
        var requestObj = body.GetObject("request")
            ?? throw new ArgumentException("Missing required field: request");

        var req = new JsonBody(requestObj);
        var url = req.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("Missing required field: request.url");

        var template = new FuzzerRequestTemplate
        {
            Url = url,
            Method = req.GetString("method") ?? "GET",
            Headers = req.GetStringDictionary("headers"),
            Body = req.GetString("body"),
            Json = req.HasProperty("json") ? req.GetJsonElement("json") : null,
        };

        var injectionPoints = new Dictionary<string, FuzzerInjectionPoint>();
        var ipObj = body.GetObject("injectionPoints");
        if (ipObj != null)
        {
            foreach (var prop in ipObj.RootElement.EnumerateObject())
            {
                var ipItem = new JsonBody(JsonDocument.Parse(prop.Value.GetRawText()));
                injectionPoints[prop.Name] = new FuzzerInjectionPoint
                {
                    PayloadSet = ipItem.GetString("payloadSet") ?? prop.Name,
                };
            }
        }

        var payloadSets = new Dictionary<string, List<string>>();
        var psObj = body.GetObject("payloadSets");
        if (psObj != null)
        {
            foreach (var prop in psObj.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Array)
                {
                    var list = new List<string>();
                    foreach (var item in prop.Value.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String)
                            list.Add(item.GetString()!);
                    payloadSets[prop.Name] = list;
                }
            }
        }

        // Auto-detect markers from url/body/headers when injectionPoints omitted.
        if (injectionPoints.Count == 0)
        {
            var bodyForMarkers = template.Body;
            if (bodyForMarkers == null && template.Json != null)
            {
                bodyForMarkers = template.Json is JsonElement je
                    ? je.GetRawText()
                    : JsonSerializer.Serialize(template.Json);
            }

            var defaultSet = payloadSets.Count > 0
                ? payloadSets.Keys.First()
                : "sqli-basic";
            foreach (var marker in Security.RequestMarkerSubstitute.ListMarkers(
                         template.Url, bodyForMarkers, template.Headers))
            {
                injectionPoints[marker] = new FuzzerInjectionPoint { PayloadSet = defaultSet };
            }
        }

        var attackTypeStr = body.GetString("attackType") ?? "sniper";
        var attackType = attackTypeStr.ToLowerInvariant().Replace("-", "") switch
        {
            "sniper" => FuzzerAttackType.Sniper,
            "batteringram" => FuzzerAttackType.BatteringRam,
            "pitchfork" => FuzzerAttackType.Pitchfork,
            "clusterbomb" => FuzzerAttackType.ClusterBomb,
            _ => throw new ArgumentException($"Unknown attack type: {attackTypeStr}. Use: sniper, battering-ram, pitchfork, cluster-bomb")
        };

        var availabilitySafe = body.GetBool("availabilitySafeDefaults", false);
        var maxConcurrency = body.HasProperty("maxConcurrency")
            ? body.GetInt("maxConcurrency", 5)
            : availabilitySafe ? 3 : 5;
        var maxRequests = body.HasProperty("maxRequests")
            ? body.GetInt("maxRequests", 1000)
            : availabilitySafe ? 50 : 1000;
        var delayMs = body.HasProperty("delayMs")
            ? body.GetInt("delayMs")
            : availabilitySafe ? 100 : 0;

        return new FuzzerOptions
        {
            Request = template,
            InjectionPoints = injectionPoints,
            PayloadSets = payloadSets,
            PayloadGenerators = ParsePayloadGenerators(body),
            AttackType = attackType,
            MaxConcurrency = maxConcurrency,
            UseBrowserCookies = body.GetBool("useBrowserCookies", true),
            StopOnStatus = body.GetIntList("stopOnStatus"),
            AcceptableResponseStatuses = body.GetIntList("acceptableResponseStatuses"),
            MaxRequests = maxRequests,
            TimeoutMs = body.GetInt("timeoutMs", 10000),
            DelayMs = delayMs,
            BodySnippetLength = body.GetInt("bodySnippetLength", 500),
            MaxResponseBodyLength = body.GetInt("maxResponseBodyLength", 131072),
            Redirect = body.GetString("redirect"),
            PayloadProfile = PayloadProfileExtensions.Parse(body.GetString("payloadProfile")),
        };
    }

    private static Dictionary<string, List<FuzzerPayloadGenerator>> ParsePayloadGenerators(JsonBody body)
    {
        var result = new Dictionary<string, List<FuzzerPayloadGenerator>>();
        var genObj = body.GetObject("payloadGenerators");
        if (genObj == null) return result;

        foreach (var prop in genObj.RootElement.EnumerateObject())
        {
            if (prop.Value.ValueKind != JsonValueKind.Array) continue;
            var gens = new List<FuzzerPayloadGenerator>();
            foreach (var item in prop.Value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                var g = new JsonBody(JsonDocument.Parse(item.GetRawText()));
                var encodingsList = g.GetStringList("encodings");
                gens.Add(new FuzzerPayloadGenerator
                {
                    Type = g.GetString("type"),
                    From = g.GetInt("from"),
                    To = g.GetInt("to"),
                    Step = g.GetInt("step", 1),
                    Template = g.GetString("template"),
                    BaseSet = g.GetString("baseSet"),
                    Encodings = encodingsList,
                });
            }
            if (gens.Count > 0)
                result[prop.Name] = gens;
        }
        return result;
    }

    private async Task HandleGetFuzzPayloads(HttpListenerResponse response)
    {
        var sets = FuzzerPayloads.BuiltIn.ToDictionary(
            kv => kv.Key,
            kv => new { count = kv.Value.Length, samples = kv.Value.Take(5).ToArray() });
        await WriteSuccess(response, new { payloadSets = sets });
    }

    private async Task HandlePostClearAll(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        HashSet<string>? preserve = null;
        var preserveList = body.GetStringList("preserve");
        if (preserveList != null)
            preserve = new HashSet<string>(preserveList, StringComparer.OrdinalIgnoreCase);

        var result = await _context.ClearAll(preserve);
        await WriteSuccess(response, new
        {
            message = result.Summary,
            cleared = result.Cleared,
            preserved = result.Preserved,
        });
    }

    private async Task HandlePostClearSession(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        // Optional: also wipe the cookie jar when switching lab apps that share a host (e.g. localhost).
        var clearCookies = body.GetBool("clearCookies");
        var result = clearCookies
            ? await _context.ClearAll(new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "storage" })
            : await _context.ClearSession();
        await WriteSuccess(response, new
        {
            message = result.Summary,
            cleared = result.Cleared,
            preserved = result.Preserved,
            clearCookies,
        });
    }

    #endregion


    private async Task HandleGetTestData(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (TestDataService == null)
        {
            await WriteError(response, 503, "Test data service not available.");
            return;
        }

        TestDataKind kind = TestDataService.ActiveKind;
        var kindParam = ApiQuery(request)["kind"];
        if (!string.IsNullOrWhiteSpace(kindParam))
        {
            if (!TestDataService.TryParseKind(kindParam, out kind))
            {
                await WriteError(response, 400, "Invalid kind. Use 'strings' or 'payloads'.");
                return;
            }
        }

        var text = await TestDataService.GetRandomAsync(kind);
        if (text == null)
        {
            var label = kind == TestDataKind.Payloads ? "payloads" : "test data strings";
            await WriteError(response, 404, $"No {label} available.");
            return;
        }

        await WriteSuccess(response, new { text, kind = TestDataService.KindToApiValue(kind) });
    }

    private async Task HandleGetInspiration(HttpListenerResponse response)
    {
        if (InspirationService == null)
        {
            await WriteError(response, 503, "Inspiration service not available.");
            return;
        }

        var message = InspirationService.GetRandom();
        if (message == null)
        {
            await WriteError(response, 404, "No inspiration messages available. Place inspiration_messages.txt next to Trowser.exe.");
            return;
        }

        await WriteSuccess(response, new { message });
    }

    private async Task HandleGetScriptingHelp(HttpListenerRequest request, HttpListenerResponse response)
    {
        var topic = request.QueryString["topic"];
        try
        {
            var text = Scripting.ScriptingHelpCatalog.GetTopic(topic, out var resolved, out var error);
            if (error != null)
            {
                await WriteError(response, 400, error);
                return;
            }

            await WriteSuccess(response, new
            {
                topic = resolved,
                text,
                topics = Scripting.ScriptingHelpCatalog.TopicNames
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, $"Failed to load scripting help: {ex.Message}");
        }
    }

    private async Task HandleGetCoverage(HttpListenerResponse response)
    {
        if (CoverageService == null || SessionLogger == null)
        {
            await WriteError(response, 503, "Coverage service not available.");
            return;
        }

        string? currentUrl = null;
        try { currentUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var snapshot = CoverageService.Build(SessionLogger.GetJournal(), currentUrl);
        await WriteSuccess(response, snapshot.ToPayload());
    }

}

/// <summary>
/// Thrown by shared command builders (<c>Build*</c>) to signal an HTTP-style failure with a status code.
/// REST maps it to <c>WriteError(StatusCode, Message)</c>; MCP maps it to <c>ErrorContent(Message)</c>.
/// This lets one canonical implementation serve both surfaces with identical validation/gating behavior.
/// </summary>
internal sealed class ApiCommandException : Exception
{
    public int StatusCode { get; }
    public string? RequestedSafetyMode { get; }
    public string? EffectiveSafetyMode { get; }
    public string? CappedBy { get; }

    public ApiCommandException(int statusCode, string message) : base(message)
    {
        StatusCode = statusCode;
    }

    public ApiCommandException(
        int statusCode,
        string message,
        string? requestedSafetyMode,
        string? effectiveSafetyMode,
        string? cappedBy) : base(message)
    {
        StatusCode = statusCode;
        RequestedSafetyMode = requestedSafetyMode;
        EffectiveSafetyMode = effectiveSafetyMode;
        CappedBy = cappedBy;
    }

    public ApiCommandException(int statusCode, Security.Orchestration.SafetyGateDenial denial)
        : this(statusCode, denial.Message, denial.RequestedSafetyMode, denial.EffectiveSafetyMode, denial.CappedBy)
    {
    }
}

/// <summary>
/// Simple wrapper around a parsed JSON body for safe property access.
/// </summary>
internal class JsonBody
{
    private readonly JsonDocument? _doc;

    public JsonBody(JsonDocument? doc)
    {
        _doc = doc;
    }

    /// <summary>Root element when a body was parsed; otherwise default (Undefined).</summary>
    public JsonElement RootElement => _doc?.RootElement ?? default;

    /// <summary>Parses MCP tool <c>arguments</c> into the same shape as REST <see cref="ReadJsonBody"/>.</summary>
    public static JsonBody FromToolArguments(JsonElement args)
    {
        if (args.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return new JsonBody(null);
        if (args.ValueKind != JsonValueKind.Object)
            return new JsonBody(null);
        return new JsonBody(JsonDocument.Parse(args.GetRawText()));
    }

    public string? GetString(string property)
    {
        if (_doc == null) return null;
        if (_doc.RootElement.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();
        return null;
    }

    public int GetInt(string property, int defaultValue = 0)
    {
        if (_doc == null) return defaultValue;
        if (_doc.RootElement.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.Number)
            return prop.GetInt32();
        return defaultValue;
    }

    public long GetInt64(string property, long defaultValue = 0)
    {
        if (_doc == null) return defaultValue;
        if (_doc.RootElement.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.Number)
            return prop.GetInt64();
        return defaultValue;
    }

    public double GetDouble(string property, double defaultValue = 0)
    {
        if (_doc == null) return defaultValue;
        if (_doc.RootElement.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.Number)
            return prop.GetDouble();
        return defaultValue;
    }

    public bool GetBool(string property, bool defaultValue = false)
    {
        if (_doc == null) return defaultValue;
        if (_doc.RootElement.TryGetProperty(property, out var prop))
        {
            if (prop.ValueKind == JsonValueKind.True) return true;
            if (prop.ValueKind == JsonValueKind.False) return false;
        }
        return defaultValue;
    }

    public bool HasProperty(string property)
    {
        if (_doc == null) return false;
        return _doc.RootElement.TryGetProperty(property, out _);
    }

    /// <summary>Get an array of strings from a JSON array property.</summary>
    public List<string>? GetStringList(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Array) return null;

        var result = new List<string>();
        foreach (var el in prop.EnumerateArray())
            if (el.ValueKind == JsonValueKind.String)
                result.Add(el.GetString()!);
        return result.Count > 0 ? result : null;
    }

    /// <summary>
    /// Get an array property as a list of JsonDocument wrappers (one per element).
    /// Each element can be wrapped in a new JsonBody for property access.
    /// </summary>
    public List<JsonDocument>? GetArray(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Array) return null;

        var result = new List<JsonDocument>();
        foreach (var el in prop.EnumerateArray())
        {
            var json = el.GetRawText();
            result.Add(JsonDocument.Parse(json));
        }
        return result;
    }

    /// <summary>
    /// Get an array property as a list of strings.
    /// </summary>
    public List<string>? GetStringArray(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Array) return null;

        var result = new List<string>();
        foreach (var el in prop.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.String)
                result.Add(el.GetString() ?? "");
        }
        return result;
    }

    /// <summary>
    /// Get an array property as a list of integers.
    /// </summary>
    public List<int>? GetIntArray(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Array) return null;

        var result = new List<int>();
        foreach (var el in prop.EnumerateArray())
        {
            if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var n))
                result.Add(n);
        }
        return result;
    }

    /// <summary>
    /// Get a property's raw JSON text, preserving all types (numbers, booleans, nested objects).
    /// </summary>
    public string? GetRawJson(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        return prop.GetRawText();
    }

    /// <summary>
    /// Get an object property as a dictionary of string key-value pairs.
    /// </summary>
    public Dictionary<string, string>? GetStringDictionary(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Object) return null;

        var result = new Dictionary<string, string>();
        foreach (var kv in prop.EnumerateObject())
        {
            result[kv.Name] = kv.Value.GetString() ?? kv.Value.ToString();
        }
        return result;
    }

    /// <summary>HTTP request headers (case-insensitive names).</summary>
    public Dictionary<string, string>? GetHttpHeadersDictionary(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        return HttpHeaderDictionary.FromJsonObject(prop);
    }

    /// <summary>Get a nested object property as a JsonDocument for further access.</summary>
    public JsonDocument? GetObject(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        if (prop.ValueKind != JsonValueKind.Object) return null;
        return JsonDocument.Parse(prop.GetRawText());
    }

    /// <summary>Get an array of integers (alias for GetIntArray).</summary>
    public List<int>? GetIntList(string property) => GetIntArray(property);

    /// <summary>Get a property as a raw JsonElement (for passing through as-is).</summary>
    public JsonElement? GetJsonElement(string property)
    {
        if (_doc == null) return null;
        if (!_doc.RootElement.TryGetProperty(property, out var prop)) return null;
        return prop;
    }

    public bool TryGetRoot(out JsonElement root)
    {
        if (_doc == null)
        {
            root = default;
            return false;
        }
        root = _doc.RootElement;
        return true;
    }
}

internal static class JsonElementExtensions
{
    public static string? GetStringOrDefault(this JsonElement el, string propertyName)
    {
        if (el.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString();
        return null;
    }
}
