namespace Trowser.Security.LlmRedTeam;

public sealed class LlmProbeDetectorSpec
{
    public string Type { get; init; } = "string_match";
    public List<string> Patterns { get; init; } = [];
    public bool CaseSensitive { get; init; }
    /// <summary>When true, every pattern must match (AND). Default is OR (any pattern).</summary>
    public bool RequireAll { get; init; }
}

public sealed class LlmProbeDefinition
{
    public string Id { get; init; } = "";
    public string Category { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public string Prompt { get; init; } = "";
    public LlmProbeDetectorSpec Detect { get; init; } = new();
    public string Rationale { get; init; } = "";
}

public sealed class LlmProbeResult
{
    public string ProbeId { get; init; } = "";
    public string Category { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public bool Fired { get; init; }
    public string Confidence { get; init; } = "high";
    public string Matched { get; init; } = "";
    public string ResponseExcerpt { get; init; } = "";
    public string Rationale { get; init; } = "";
    public string? Error { get; init; }
    public string Transport { get; init; } = "";
    public string? TargetUrl { get; init; }
}

public sealed class LlmHttpTargetConfig
{
    public string Url { get; init; } = "";
    public string Schema { get; init; } = "openai";
    public string Model { get; init; } = "gpt-3.5-turbo";
    public Dictionary<string, string>? Headers { get; init; }
    public int TimeoutMs { get; init; } = 30000;
    public Dictionary<string, object>? CustomBody { get; init; }
    /// <summary>Raw JSON object text for <c>schema: custom</c> (placeholders in string values).</summary>
    public string? CustomBodyJson { get; init; }
    /// <summary>
    /// Non-JSON body template (typically <c>application/x-www-form-urlencoded</c>) with
    /// <c>{{PROMPT}}</c> / <c>{{MODEL}}</c> placeholders. Set when <c>customBody</c> is a JSON string.
    /// </summary>
    public string? CustomBodyRaw { get; init; }
    public string CustomResponseKey { get; init; } = "response";
    public bool UseBackendFetch { get; init; }
    public bool IncludeBrowserCookies { get; init; } = true;
}

public sealed class LlmChatUiTarget
{
    public string? InputSelector { get; init; }
    public string? SubmitSelector { get; init; }
    public string? ResponseSelector { get; init; }
    public int WaitAfterSubmitMs { get; init; } = 4000;
    /// <summary>When true (default), discover chat selectors from DOM when not explicitly provided.</summary>
    public bool AutoDetect { get; init; } = true;
    /// <summary>Reload the current chat URL before sending (clears stuck Typing… / SPA locks).</summary>
    public bool ResetUi { get; init; }
    /// <summary>
    /// When chat-UI capture fails, try a discoverable HTTP LLM endpoint (confidence ≥ 50).
    /// Default true — chat UIs frequently wedge; HTTP is the reliable assist path.
    /// </summary>
    public bool FailoverToHttp { get; init; } = true;
}

public sealed class LlmEndpointHint
{
    public string Url { get; init; } = "";
    public string Method { get; init; } = "POST";
    public string Source { get; init; } = "network";
    public string MatchReason { get; init; } = "";
    public string? ContentType { get; init; }
    public bool IsSse { get; init; }
    public int Confidence { get; init; }
    public string? SampleRequestBody { get; init; }
}

public sealed class LlmDomDiscovery
{
    public List<LlmChatWidgetHint> Widgets { get; init; } = [];
    public int IframeCopilotCount { get; init; }
}

public sealed class LlmChatWidgetHint
{
    public string InputSelector { get; init; } = "";
    public string? SubmitSelector { get; init; }
    public string? ResponseSelector { get; init; }
    public string Placeholder { get; init; } = "";
    public string MatchReason { get; init; } = "";
}

public sealed class LlmSurfaceSummary
{
    public int ChatEndpointCount { get; init; }
    public int ChatWidgetCount { get; init; }
    public int WebMcpToolCount { get; init; }
    public int IframeCopilotCount { get; init; }
    /// <summary>HTTP JSON-RPC MCP endpoints discovered from traffic (not in-page WebMCP).</summary>
    public int HttpMcpEndpointCount { get; init; }
    /// <summary>True when reCAPTCHA / hCaptcha / Turnstile-like widgets are present on the page.</summary>
    public bool BotGateDetected { get; init; }
    public List<LlmEndpointHint> Endpoints { get; init; } = [];
    public List<LlmChatWidgetHint> ChatWidgets { get; init; } = [];
    public List<LlmHttpMcpHint> HttpMcpEndpoints { get; init; } = [];
    /// <summary>Best inferred HTTP target from traffic (DIY assist — wire format ready to copy).</summary>
    public LlmHttpTargetConfig? SuggestedHttpTarget { get; init; }
    public bool HasAiIntegration =>
        ChatEndpointCount > 0 || ChatWidgetCount > 0 || WebMcpToolCount > 0
        || IframeCopilotCount > 0 || HttpMcpEndpointCount > 0;
}

public sealed class LlmHttpMcpHint
{
    public string Url { get; init; } = "";
    public string Source { get; init; } = "network";
    public int Confidence { get; init; }
    public string MatchReason { get; init; } = "";
    public string? SampleInitializeBody { get; init; }
    public List<string> ToolNames { get; init; } = [];
}

public sealed class LlmChatInteractResult
{
    public bool Success { get; init; }
    public string Prompt { get; init; } = "";
    public string ResponseText { get; init; } = "";
    public string ResponseHtml { get; init; } = "";
    public string? InputSelector { get; init; }
    public string? ResponseSelector { get; init; }
    public bool ResponseChanged { get; init; }
    public string? Warning { get; init; }
    public string? RecoveryHint { get; init; }
    public string? Error { get; init; }
    public int ElapsedMs { get; init; }
}

public sealed class WebMcpAbuseFinding
{
    public string ToolName { get; init; } = "";
    public string PayloadKind { get; init; } = "";
    public string ArgumentJson { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public object? ToolResult { get; init; }
}

public sealed class LlmIndirectInjectionResult
{
    public bool Attempted { get; init; }
    public bool InjectionObserved { get; init; }
    public string InjectedToken { get; init; } = "";
    public string? UploadSelector { get; init; }
    public string? SummarizeUrl { get; init; }
    public string Detail { get; init; } = "";
    public string ResponseExcerpt { get; init; } = "";
}

public sealed class LlmRedTeamScanOptions
{
    /// <summary>auto | http | api | chat | ui. http/api never fall back to chat-UI.</summary>
    public string Mode { get; set; } = "auto";
    /// <summary>Optional preset: smoke (HTTP-only, ≤8 probes).</summary>
    public string? Preset { get; set; }
    public LlmHttpTargetConfig? HttpTarget { get; set; }
    public LlmChatUiTarget? ChatTarget { get; set; }
    public List<string>? ProbeIds { get; set; }
    public List<string>? Categories { get; set; }
    public int MaxProbes { get; set; } = 28;
    public int Concurrency { get; set; } = 2;
    public int TimeoutMs { get; set; } = 30000;
    /// <summary>Delay between probes in chat-ui mode (ms). Helps avoid rate limits.</summary>
    public int ProbeDelayMs { get; set; } = 1000;
    public bool IncludeWebMcpAbuse { get; set; } = true;
    public bool IncludeIndirectInjection { get; set; }
    public bool IncludeUnboundedConsumption { get; set; }
    public bool IncludeRagPoison { get; set; }
    public bool RegisterWhisperHints { get; set; } = true;
    /// <summary>Retry the best chat POST without cookies (anon vs session assist).</summary>
    public bool ProbeAnonymousAccess { get; set; }
    public string? IndirectInjectionToken { get; set; }
    /// <summary>Optional peer Trowser base URL (e.g. http://localhost:6924) for cross-tenant embedding isolation (LLM08).</summary>
    public string? PeerBaseUrl { get; set; }
    /// <summary>Bearer API key for <see cref="PeerBaseUrl"/> llm-chat-interact.</summary>
    public string? PeerApiKey { get; set; }
}

public sealed class LlmUnboundedConsumptionFinding
{
    public string ProbeId { get; init; } = "";
    public string Category { get; init; } = "LLM10_Unbounded_Consumption";
    public string Severity { get; init; } = "medium";
    public bool Fired { get; init; }
    public string Detail { get; init; } = "";
    public string? TargetUrl { get; init; }
    public object? Evidence { get; init; }
}

public sealed class LlmRagPoisonResult
{
    public bool Attempted { get; init; }
    public bool PersistenceObserved { get; init; }
    public bool CrossTenantLeakObserved { get; init; }
    public bool MemoryPoisonObserved { get; init; }
    public string PoisonToken { get; init; } = "";
    public string Detail { get; init; } = "";
    public string ResponseExcerpt { get; init; } = "";
    public List<LlmProbeResult> Findings { get; init; } = [];
}

public sealed class LlmRedTeamScanResult
{
    public string Message { get; init; } = "";
    public LlmSurfaceSummary Surface { get; init; } = new();
    public string Transport { get; init; } = "";
    public int TotalProbes { get; init; }
    public int FiredCount { get; init; }
    public int ElapsedMs { get; init; }
    public List<LlmProbeResult> Results { get; init; } = [];
    /// <summary>Corpus hits only. Prefer <see cref="AllFindings"/> for agent triage.</summary>
    public List<LlmProbeResult> Findings => Results.Where(r => r.Fired).ToList();
    /// <summary>Corpus + adjacent scanner hits (unbounded, rag, webmcp, indirect) in one list.</summary>
    public List<LlmProbeResult> AllFindings { get; init; } = [];
    public List<WebMcpAbuseFinding> WebMcpAbuseFindings { get; init; } = [];
    public LlmIndirectInjectionResult? IndirectInjection { get; init; }
    public List<LlmUnboundedConsumptionFinding> UnboundedConsumptionFindings { get; init; } = [];
    public LlmRagPoisonResult? RagPoison { get; init; }
    public object? Coverage { get; init; }
    public List<string> Warnings { get; init; } = [];
    public bool HasFindings => AllFindings.Count > 0
        || FiredCount > 0
        || WebMcpAbuseFindings.Count > 0
        || IndirectInjection?.InjectionObserved == true
        || UnboundedConsumptionFindings.Any(f => f.Fired)
        || RagPoison?.Findings.Any(f => f.Fired) == true;
}
