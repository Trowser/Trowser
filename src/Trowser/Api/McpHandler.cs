using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

/// <summary>
/// MCP (Model Context Protocol) handler for Trowser.
/// Implements Streamable HTTP MCP: JSON-RPC 2.0 over <c>POST /mcp</c>.
/// Does not offer a standalone GET SSE stream or DELETE session teardown (HTTP 405).
/// Exposes browser automation as MCP tools for external agents (Cursor, Claude Code, etc.).
/// </summary>
public partial class McpHandler
{
    private readonly AutomationContext _context;
    private readonly string _screenshotDir;
    private readonly ScriptEngine? _scriptEngine;
    private string _sessionId = Guid.NewGuid().ToString("N")[..16];

    /// <summary>
    /// Tool allow-list mode (Chat / Economical / Full) for the built-in AI Assistant.
    /// External <c>POST /mcp</c> uses <see cref="ExternalPack"/> instead.
    /// </summary>
    public InteractionMode Mode { get; set; } = InteractionMode.Economical;

    /// <summary>
    /// Tool pack for external <c>POST /mcp</c> when <see cref="ExternalAgentSurface"/> is true
    /// (default Core). Overridable per request via <c>?mode=</c> / <c>X-Trowser-Mcp-Mode</c>.
    /// </summary>
    public ExternalMcpMode ExternalPack { get; set; } = ExternalMcpMode.Core;

    /// <summary>
    /// When true, <c>tools/list</c> and <c>tools/call</c> use <see cref="ExternalPack"/>
    /// (core / security). Chat leaves this false so InteractionMode still applies.
    /// </summary>
    public bool ExternalAgentSurface { get; set; }

    public bool SafeMode { get; set; }

    private static readonly AsyncLocal<ExternalMcpMode?> RequestPackOverride = new();

    /// <summary>Effective Chat interaction mode (no per-request override).</summary>
    private InteractionMode EffectiveMode => Mode;

    /// <summary>Effective external pack for the current MCP request (override or <see cref="ExternalPack"/>).</summary>
    private ExternalMcpMode EffectivePack => RequestPackOverride.Value ?? ExternalPack;

    private string EffectiveSurfaceLabel => ExternalAgentSurface
        ? McpClientConfig.FormatMode(EffectivePack)
        : EffectiveMode.ToString();

    /// <summary>
    /// Callback for displaying a message overlay. Wired by TrowserApiServer.
    /// Parameters: text, level, durationMs.
    /// </summary>
    internal Func<string, string, int, Task<(bool Success, string? Error)>>? ShowMessageAsync { get; set; }

    /// <summary>Set by <see cref="TrowserApiServer"/> to share crypto audit JSON with auto-scan MCP/REST.</summary>
    internal Func<JsonBody, Task<object>>? CryptographicFailuresPayloadBuilder { get; set; }

    /// <summary>Set by <see cref="TrowserApiServer"/> to share <c>POST /api/audit-all</c> JSON with <c>browser_audit_all</c>.</summary>
    internal Func<JsonBody, Task<object>>? AuditAllPayloadBuilder { get; set; }

    /// <summary>Set by <see cref="TrowserApiServer"/> to share <c>POST /api/surpriseme</c> JSON with <c>browser_surpriseme</c>.</summary>
    internal Func<Task<object>>? SurpriseMeRunner { get; set; }

    /// <summary>
    /// True while handling <c>POST /mcp</c> with <c>tools/call</c> for <c>browser_force_navigate</c> outside the API gate
    /// (same rationale as <c>POST /api/force-navigate</c>). Used to run gate recovery after CDP navigation.
    /// </summary>
    internal bool ForceNavigateBypassGate { get; set; }

    /// <summary>
    /// Cancels any in-flight gated operation and resynchronizes the semaphore after a successful force-navigate
    /// when <see cref="ForceNavigateBypassGate"/> is true.
    /// </summary>
    internal Func<Task>? AfterSuccessfulForceNavigateAsync { get; set; }

    /// <summary>Optional inspiration service for the browser_inspiration tool.</summary>
    internal InspirationService? InspirationService { get; set; }

    /// <summary>Optional coverage lens for the browser_coverage tool.</summary>
    internal CoverageService? CoverageService { get; set; }

    /// <summary>Optional test data service for the browser_test_data tool.</summary>
    internal TestDataService? TestDataService { get; set; }

    /// <summary>Optional session logger for journal tools.</summary>
    internal SessionLog.SessionLogger? SessionLogger { get; set; }

    /// <summary>Volatile session memory for built-in assistant compaction tools.</summary>
    internal SessionMemory? SessionMemory { get; set; }

    /// <summary>Registry of peer Trowser instances for cross-instance testing.</summary>
    internal PeerRegistry? Peers { get; set; }

    /// <summary>Session name from the parent API server, exposed for identity tools.</summary>
    internal string? SessionName { get; set; }

    /// <summary>Attack chain pattern catalog shared with REST chain endpoints.</summary>
    internal ChainPatternCatalog? ChainCatalog { get; set; }

    /// <summary>Portable identity snapshot store.</summary>
    internal IdentityStore? IdentityStore { get; set; }

    /// <summary>SSO/MFA handoff waiter.</summary>
    internal IdentityHandoffManager? IdentityHandoff { get; set; }

    /// <summary>
    /// Parent API server. Wired by <see cref="TrowserApiServer"/> so MCP tools can invoke the
    /// shared canonical command builders (<c>Build*</c>) and stay byte-for-byte in sync with the
    /// matching REST endpoints instead of duplicating argument parsing and scan logic.
    /// </summary>
    internal TrowserApiServer? Host { get; set; }

    /// <summary>
    /// Compact JSON for MCP tool payloads (snapshots, RenderHost, etc.). Pretty-printing wasted ~33% tokens.
    /// </summary>
    private static readonly JsonSerializerOptions CompactJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public McpHandler(AutomationContext context, string screenshotDir, ScriptEngine? scriptEngine = null)
    {
        _context = context;
        _screenshotDir = screenshotDir;
        _scriptEngine = scriptEngine;
    }

    public string SessionId => _sessionId;

    #region Entry Point

    /// <summary>
    /// Handle a JSON-RPC 2.0 request from an MCP client.
    /// Returns (responseJson, isNotification). For notifications, responseJson is null.
    /// </summary>
    /// <param name="body">JSON-RPC request body.</param>
    /// <param name="packOverride">Optional per-request pack (<c>?mode=</c> / header); null uses <see cref="ExternalPack"/>.</param>
    public async Task<(string? ResponseJson, bool IsNotification)> HandleAsync(
        string body, ExternalMcpMode? packOverride = null)
    {
        var previousOverride = RequestPackOverride.Value;
        RequestPackOverride.Value = packOverride;
        try
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(body); }
            catch { return (RpcError(null, -32700, "Parse error"), false); }

            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return (RpcError(null, -32600, "Request must be a JSON object"), false);

            var method = root.TryGetProperty("method", out var m) ? m.GetString() : null;
            if (method == null)
                return (RpcError(null, -32600, "Missing 'method' field"), false);

            bool isNotification = !root.TryGetProperty("id", out var idEl);
            object? id = isNotification ? null : ReadId(idEl);
            var @params = root.TryGetProperty("params", out var p) ? (JsonElement?)p : null;

            try
            {
                var result = await Route(method, @params);
                if (isNotification) return (null, true);
                return (RpcSuccess(id, result), false);
            }
            catch (MethodNotFoundException)
            {
                return isNotification ? (null, true) : (RpcError(id, -32601, $"Method not found: {method}"), false);
            }
            catch (InvalidParamsException ex)
            {
                return isNotification ? (null, true) : (RpcError(id, -32602, ex.Message), false);
            }
            catch (Exception ex)
            {
                return isNotification ? (null, true) : (RpcError(id, -32603, $"Internal error: {ex.Message}"), false);
            }
        }
        finally
        {
            RequestPackOverride.Value = previousOverride;
        }
    }

    #endregion

    #region JSON-RPC Routing

    private async Task<object> Route(string method, JsonElement? @params) => method switch
    {
        "initialize" => Initialize(),
        "notifications/initialized" => new { },
        "ping" => new { },
        "tools/list" => new { tools = GetListedToolDefinitions() },
        "tools/call" => await ToolsCall(@params),
        _ => throw new MethodNotFoundException()
    };

    #endregion

    #region Tool Implementations

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private static void AppendCsrfScenarioBlock(System.Text.StringBuilder sb, CsrfScenario s)
    {
        var sev = !string.IsNullOrEmpty(s.Severity) ? s.Severity.ToUpperInvariant() : (s.Vulnerable ? "MEDIUM" : "OK");
        var label = s.Vulnerable ? "VULNERABLE" : sev is "LOW" ? "LOW" : "OK";
        sb.AppendLine($"  [{label}] {s.Method} {s.Url}");
        if (!string.IsNullOrEmpty(s.Path))
            sb.AppendLine($"    path: {s.Path}");
        if (!string.IsNullOrEmpty(s.FormFields))
            sb.AppendLine($"    Form fields: {s.FormFields}");
        if (s.MutationIndicators.Count > 0)
            sb.AppendLine($"    Mutation indicators: {string.Join("; ", s.MutationIndicators)}");
        sb.AppendLine($"    {s.Description}");
        sb.AppendLine($"    CSRF token: {s.TokenLocation}");
        if (s.OriginalStatus > 0 || s.TestStatus > 0)
            sb.AppendLine($"    Original status: {s.OriginalStatus} → Test status: {s.TestStatus}");
        if (s.Error != null)
            sb.AppendLine($"    Error: {s.Error}");
        sb.AppendLine();
    }

    
    
    
    
    
    
    
    
    
    
    
    
    private static bool? GetBoolOrNull(JsonElement args, string name)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (args.TryGetProperty(name, out var prop) && prop.ValueKind is JsonValueKind.True or JsonValueKind.False)
            return prop.GetBoolean();
        return null;
    }

    /// <summary>True unless <paramref name="prop"/> is explicitly false. Safe when args is missing or not an object.</summary>
    private static bool GetOptOutBool(JsonElement args, string prop, bool defaultWhenMissing = true)
    {
        if (args.ValueKind != JsonValueKind.Object) return defaultWhenMissing;
        if (!args.TryGetProperty(prop, out var v)) return defaultWhenMissing;
        return v.ValueKind != JsonValueKind.False;
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private WorkflowDependencies BuildWorkflowDependencies() => new()
    {
        Context = _context,
        IdentityStore = IdentityStore ?? new IdentityStore(),
        Peers = Peers,
        SessionName = SessionName,
        ScreenshotDir = _screenshotDir,
        Cancellation = _context.OperationCancellation
    };

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    /// <summary>
    /// Show a warning overlay in the Trowser UI before destructive tests.
    /// Non-blocking — the test proceeds after the overlay is displayed.
    /// </summary>
    private async Task ShowBackendWarning(string message)
    {
        var callback = ShowMessageAsync;
        if (callback != null)
            await callback(message, "warning", 10000);
    }

    
    
    private static Robustness.FuzzerOptions ParseFuzzerOptionsFromMcp(JsonElement args)
    {
        if (!args.TryGetProperty("request", out var reqEl) || reqEl.ValueKind != JsonValueKind.Object)
            throw new ArgumentException("Missing required parameter: request");

        var url = GetString(reqEl, "url");
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("Missing required parameter: request.url");

        string? body = GetString(reqEl, "body");
        object? json = null;
        if (body == null && reqEl.TryGetProperty("json", out var jsonEl))
            json = jsonEl.Clone();

        Dictionary<string, string>? headers = null;
        if (reqEl.TryGetProperty("headers", out var hdrs) && hdrs.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>();
            foreach (var p in hdrs.EnumerateObject())
                headers[p.Name] = p.Value.GetString() ?? p.Value.ToString();
        }

        var template = new Robustness.FuzzerRequestTemplate
        {
            Url = url,
            Method = GetString(reqEl, "method") ?? "GET",
            Headers = headers,
            Body = body,
            Json = json,
        };

        var injectionPoints = new Dictionary<string, Robustness.FuzzerInjectionPoint>();
        if (args.TryGetProperty("injectionPoints", out var ipEl) && ipEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in ipEl.EnumerateObject())
            {
                var payloadSet = prop.Value.ValueKind == JsonValueKind.Object
                    ? GetString(prop.Value, "payloadSet") ?? prop.Name
                    : prop.Name;
                injectionPoints[prop.Name] = new Robustness.FuzzerInjectionPoint { PayloadSet = payloadSet };
            }
        }

        var payloadSets = new Dictionary<string, List<string>>();
        if (args.TryGetProperty("payloadSets", out var psEl) && psEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in psEl.EnumerateObject())
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

        if (injectionPoints.Count == 0)
        {
            var defaultSet = payloadSets.Count > 0 ? payloadSets.Keys.First() : "sqli-basic";
            foreach (var marker in Security.RequestMarkerSubstitute.ListMarkers(
                         template.Url, body, template.Headers))
            {
                injectionPoints[marker] = new Robustness.FuzzerInjectionPoint { PayloadSet = defaultSet };
            }
        }

        var attackTypeStr = GetString(args, "attackType") ?? "sniper";
        var attackType = attackTypeStr.ToLowerInvariant().Replace("-", "") switch
        {
            "sniper" => Robustness.FuzzerAttackType.Sniper,
            "batteringram" => Robustness.FuzzerAttackType.BatteringRam,
            "pitchfork" => Robustness.FuzzerAttackType.Pitchfork,
            "clusterbomb" => Robustness.FuzzerAttackType.ClusterBomb,
            _ => throw new ArgumentException($"Unknown attack type: {attackTypeStr}. Use: sniper, battering-ram, pitchfork, cluster-bomb")
        };

        List<int>? stopOnStatus = null;
        if (args.TryGetProperty("stopOnStatus", out var sosEl) && sosEl.ValueKind == JsonValueKind.Array)
        {
            stopOnStatus = new List<int>();
            foreach (var item in sosEl.EnumerateArray())
                if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out var n))
                    stopOnStatus.Add(n);
        }

        List<int>? acceptableResponseStatuses = null;
        if (args.TryGetProperty("acceptableResponseStatuses", out var arsEl) && arsEl.ValueKind == JsonValueKind.Array)
        {
            acceptableResponseStatuses = new List<int>();
            foreach (var item in arsEl.EnumerateArray())
                if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out var n))
                    acceptableResponseStatuses.Add(n);
        }

        var availabilitySafe = GetBool(args, "availabilitySafeDefaults", false);
        var maxConcurrency = args.TryGetProperty("maxConcurrency", out _)
            ? GetInt(args, "maxConcurrency", 5)
            : availabilitySafe ? 3 : 5;
        var maxRequests = args.TryGetProperty("maxRequests", out _)
            ? GetInt(args, "maxRequests", 1000)
            : availabilitySafe ? 50 : 1000;
        var delayMs = args.TryGetProperty("delayMs", out _)
            ? GetInt(args, "delayMs")
            : availabilitySafe ? 100 : 0;

        return new Robustness.FuzzerOptions
        {
            Request = template,
            InjectionPoints = injectionPoints,
            PayloadSets = payloadSets,
            PayloadGenerators = ParseFuzzerGenerators(args),
            AttackType = attackType,
            MaxConcurrency = maxConcurrency,
            UseBrowserCookies = GetBool(args, "useBrowserCookies", true),
            StopOnStatus = stopOnStatus,
            AcceptableResponseStatuses = acceptableResponseStatuses,
            MaxRequests = maxRequests,
            TimeoutMs = GetInt(args, "timeoutMs", 10000),
            DelayMs = delayMs,
            BodySnippetLength = GetInt(args, "bodySnippetLength", 500),
            MaxResponseBodyLength = GetInt(args, "maxResponseBodyLength", 131072),
            Redirect = GetString(args, "redirect"),
            PayloadProfile = PayloadProfileExtensions.Parse(GetString(args, "payloadProfile")),
        };
    }

    private static Dictionary<string, List<Robustness.FuzzerPayloadGenerator>> ParseFuzzerGenerators(JsonElement args)
    {
        var result = new Dictionary<string, List<Robustness.FuzzerPayloadGenerator>>();
        if (args.ValueKind != JsonValueKind.Object) return result;
        if (!args.TryGetProperty("payloadGenerators", out var genEl) || genEl.ValueKind != JsonValueKind.Object) return result;

        foreach (var prop in genEl.EnumerateObject())
        {
            if (prop.Value.ValueKind != JsonValueKind.Array) continue;
            var gens = new List<Robustness.FuzzerPayloadGenerator>();
            foreach (var item in prop.Value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                List<string>? encodings = null;
                if (item.TryGetProperty("encodings", out var encEl) && encEl.ValueKind == JsonValueKind.Array)
                {
                    encodings = new List<string>();
                    foreach (var e in encEl.EnumerateArray())
                        if (e.ValueKind == JsonValueKind.String) encodings.Add(e.GetString()!);
                }
                gens.Add(new Robustness.FuzzerPayloadGenerator
                {
                    Type = GetString(item, "type"),
                    From = GetInt(item, "from"),
                    To = GetInt(item, "to"),
                    Step = GetInt(item, "step", 1),
                    Template = GetString(item, "template"),
                    BaseSet = GetString(item, "baseSet"),
                    Encodings = encodings,
                });
            }
            if (gens.Count > 0)
                result[prop.Name] = gens;
        }
        return result;
    }

    
    
    
    
    
    
    private static string TruncateNetworkBody(string s, int bodyMaxChars) =>
        bodyMaxChars <= 0 ? s : Truncate(s, bodyMaxChars);

    private static string Truncate(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..maxLen] + "...";

    
    
    
    
    
    
    private object FormatAssertResult()
    {
        var last = _context.Assert.Results.Last();
        var summary = $"Assertions: {_context.Assert.PassCount} passed, {_context.Assert.FailCount} failed";
        var detail = last.Details != null ? $"\n  {last.Details}" : "";
        return TextContent($"{(last.Passed ? "PASS" : "FAIL")}: {last.Description}{detail}\n{summary}");
    }

    
    
    
    
    
    
    
    
    
    
    #endregion

}
