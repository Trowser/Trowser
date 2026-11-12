namespace Trowser.Security;

/// <summary>
/// Canonical security finding contract for REST, MCP, and C# scripting.
/// All injection / active scanners should emit <see cref="UnifiedSecurityFinding"/>.
/// </summary>
public static class SecurityConfidence
{
    public const string Confirmed = "confirmed";
    public const string Likely = "likely";
    public const string Tentative = "tentative";

    public static string Normalize(string? value) =>
        (value ?? "").Trim().ToLowerInvariant() switch
        {
            Confirmed or "certain" or "verified" => Confirmed,
            Tentative or "possible" or "low" => Tentative,
            _ => Likely
        };

    public static int Rank(string? value) => Normalize(value) switch
    {
        Confirmed => 3,
        Likely => 2,
        Tentative => 1,
        _ => 0
    };

    public static bool MeetsMinimum(string? value, string? minimum) =>
        Rank(value) >= Rank(string.IsNullOrWhiteSpace(minimum) ? Likely : minimum);
}

/// <summary>Noise tier for non-expert / LLM triage.</summary>
public static class SecurityFindingTier
{
    public const string Exploitable = "exploitable";
    public const string Hygiene = "hygiene";
    public const string Informational = "informational";

    public static string Normalize(string? value) =>
        (value ?? "").Trim().ToLowerInvariant() switch
        {
            Hygiene or "hardening" or "best-practice" => Hygiene,
            Informational or "info" or "observation" => Informational,
            _ => Exploitable
        };
}

/// <summary>Scan breadth for injection scanners (aliases: fast/light → quick, thorough/full → deep).</summary>
public static class SecurityScanDepth
{
    public const string Quick = "quick";
    public const string Standard = "standard";
    public const string Deep = "deep";

    public static string Normalize(string? depth)
    {
        if (string.IsNullOrWhiteSpace(depth))
            return Standard;

        return depth.Trim().ToLowerInvariant() switch
        {
            Quick or "fast" or "light" => Quick,
            Deep or "thorough" or "full" => Deep,
            Standard or "normal" or "default" or "balanced" => Standard,
            _ => Standard
        };
    }
}

/// <summary>One actionable security finding — shared by REST/MCP/scripts.</summary>
public sealed class UnifiedSecurityFinding
{
    public string Id { get; init; } = "";
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public string Confidence { get; init; } = SecurityConfidence.Likely;
    public string Tier { get; init; } = SecurityFindingTier.Exploitable;
    public string? Endpoint { get; init; }
    public string? Method { get; init; }
    public string? Param { get; init; }
    public string? Payload { get; init; }
    public string? Evidence { get; init; }
    public string? ProofHint { get; init; }
    public List<string> NextActions { get; init; } = [];
    /// <summary>Structured follow-ups for MCP agents (tool name + args); mirrors <see cref="NextActions"/>.</summary>
    public List<SecurityNextActionItem> NextActionItems { get; init; } = [];
    /// <summary>Scanner-specific extras (types, engine, context, correlationId, …).</summary>
    public Dictionary<string, object?> Extra { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public static UnifiedSecurityFinding Create(
        string category,
        string title,
        string severity,
        string confidence,
        string? endpoint = null,
        string? method = null,
        string? param = null,
        string? payload = null,
        string? evidence = null,
        string? proofHint = null,
        string tier = SecurityFindingTier.Exploitable,
        IEnumerable<string>? nextActions = null,
        IEnumerable<SecurityNextActionItem>? nextActionItems = null,
        Dictionary<string, object?>? extra = null,
        string? id = null)
    {
        var conf = SecurityConfidence.Normalize(confidence);
        var t = SecurityFindingTier.Normalize(tier);
        var ep = endpoint ?? "";
        var p = param ?? "";
        var pay = payload ?? "";
        var items = nextActionItems?.Where(i => i != null).ToList() ?? [];
        var actionStrings = nextActions?.Where(a => !string.IsNullOrWhiteSpace(a)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
                          ?? [];
        if (items.Count > 0 && actionStrings.Count == 0)
            actionStrings = items.Select(i => i.Summary).Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
        return new UnifiedSecurityFinding
        {
            Id = string.IsNullOrWhiteSpace(id)
                ? $"{category}:{ep}:{p}:{pay}".GetHashCode(StringComparison.OrdinalIgnoreCase).ToString("x8")
                : id!,
            Category = category,
            Title = title,
            Severity = (severity ?? "medium").Trim().ToLowerInvariant(),
            Confidence = conf,
            Tier = t,
            Endpoint = endpoint,
            Method = method,
            Param = param,
            Payload = payload,
            Evidence = evidence,
            ProofHint = proofHint,
            NextActions = actionStrings,
            NextActionItems = items,
            Extra = extra ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        };
    }
}

/// <summary>Standard envelope for active security scan API/script results.</summary>
public sealed class SecurityScanResult
{
    public string Message { get; init; } = "";
    public string Depth { get; init; } = SecurityScanDepth.Standard;
    public int CandidatesProbed { get; init; }
    public int PayloadsSent { get; init; }
    public int ElapsedMs { get; init; }
    /// <summary>Optional coarse-grained steps for long-running scans (e.g. xss-scan DOM phases).</summary>
    public List<string> Progress { get; init; } = [];
    public List<UnifiedSecurityFinding> Findings { get; init; } = [];
    public List<string> Summary { get; init; } = [];
    /// <summary>Scanner-specific diagnostics (rows, baseline, fingerprint, …).</summary>
    public Dictionary<string, object?> Details { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public bool HasFindings => Findings.Count > 0;

    public IReadOnlyList<UnifiedSecurityFinding> FilterForConsumers(
        bool includeHygiene = false,
        string? minConfidence = SecurityConfidence.Likely)
    {
        IEnumerable<UnifiedSecurityFinding> q = Findings;
        if (!includeHygiene)
            q = q.Where(f => f.Tier == SecurityFindingTier.Exploitable);
        if (!string.IsNullOrWhiteSpace(minConfidence))
            q = q.Where(f => SecurityConfidence.MeetsMinimum(f.Confidence, minConfidence));
        return q.ToList();
    }

    /// <summary>Anonymous object suitable for JSON serialization (REST/MCP).</summary>
    public object ToApiResponse(bool includeHygiene = false, string? minConfidence = SecurityConfidence.Likely)
    {
        var findings = FilterForConsumers(includeHygiene, minConfidence);
        var suppressed = Findings.Count - findings.Count;
        var message = findings.Count > 0
            ? $"{findings.Count} finding(s)."
            : suppressed > 0
                ? $"No findings at minConfidence {minConfidence} ({suppressed} lower-confidence signal(s) in summary/rows)."
                : Message;
        var detailsOut = Details.Count > 0
            ? new Dictionary<string, object?>(Details, StringComparer.OrdinalIgnoreCase)
            : null;
        if (detailsOut != null
            && detailsOut.ContainsKey("findingGroups")
            && Findings.Count > 0
            && Findings.All(f => f.Category.Equals("sqli", StringComparison.OrdinalIgnoreCase)))
        {
            detailsOut["findingGroups"] = HttpSecurityProbes.BuildSqliFindingGroups(findings.ToList());
        }

        List<string>? progressOut = Progress.Count > 0 ? Progress : null;
        if (progressOut == null && detailsOut != null && detailsOut.TryGetValue("progress", out var progObj) && progObj is List<string> pl)
            progressOut = pl;

        return new
        {
            message,
            depth = Depth,
            candidatesProbed = CandidatesProbed,
            payloadsSent = PayloadsSent,
            elapsedMs = ElapsedMs,
            hasFindings = findings.Count > 0,
            findingsSuppressedByConfidence = suppressed > 0 ? suppressed : (int?)null,
            summary = Summary,
            findings = findings.Select(ToApiFinding).ToList(),
            progress = progressOut,
            details = detailsOut
        };
    }

    public static object ToApiFinding(UnifiedSecurityFinding f) => new
    {
        f.Id,
        f.Category,
        f.Title,
        f.Severity,
        f.Confidence,
        f.Tier,
        f.Endpoint,
        f.Method,
        f.Param,
        f.Payload,
        f.Evidence,
        f.ProofHint,
        nextActions = f.NextActions,
        nextActionItems = f.NextActionItems.Count > 0
            ? f.NextActionItems.Select(i => i.ToApiObject()).ToList()
            : null,
        extra = f.Extra.Count > 0 ? f.Extra : null
    };
}

/// <summary>One follow-up step for LLM agents — MCP tool plus REST equivalent.</summary>
public sealed class SecurityNextActionItem
{
    public string Summary { get; init; } = "";
    public string McpTool { get; init; } = "";
    public string RestMethod { get; init; } = "POST";
    public string RestPath { get; init; } = "";
    public Dictionary<string, object?> Args { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public object ToApiObject() => new
    {
        summary = Summary,
        mcp = McpTool,
        rest = $"{RestMethod} {RestPath}",
        args = Args.Count > 0 ? Args : null
    };
}

/// <summary>Common nextActions strings for LLM/script follow-up.</summary>
public static class SecurityNextActions
{
    public static IReadOnlyList<SecurityNextActionItem> XssFollowUp(string? param, string? endpoint = null) =>
    [
        TraceInputItem(param, endpoint),
        VerifyWorkflowItem(endpoint, param)
    ];

    public static IReadOnlyList<SecurityNextActionItem> SqliFollowUp(string? param, string? endpoint = null) =>
    [
        SqliRetestItem(param, endpoint),
        VerifyWorkflowItem(endpoint, param)
    ];

    public static SecurityNextActionItem TraceInputItem(string? param, string? endpoint = null)
    {
        var args = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(param)) args["paramName"] = param;
        if (!string.IsNullOrWhiteSpace(endpoint)) args["url"] = endpoint;
        return new SecurityNextActionItem
        {
            Summary = TraceInput(param),
            McpTool = "browser_trace_input",
            RestPath = "/api/security/trace-input",
            Args = args
        };
    }

    public static SecurityNextActionItem VerifyWorkflowItem(string? endpoint = null, string? param = null)
    {
        var args = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(endpoint)) args["url"] = endpoint;
        if (!string.IsNullOrWhiteSpace(param)) args["paramName"] = param;
        return new SecurityNextActionItem
        {
            Summary = VerifyWorkflow,
            McpTool = "browser_security_verify",
            RestPath = "/api/security/verify",
            Args = args
        };
    }

    public static SecurityNextActionItem SqliRetestItem(string? param, string? endpoint = null)
    {
        var args = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(endpoint)) args["url"] = endpoint;
        if (!string.IsNullOrWhiteSpace(param))
        {
            args["paramName"] = param;
            args["note"] = "Compare truthy vs falsy boolean payloads on the same marker";
        }
        return new SecurityNextActionItem
        {
            Summary = SqliRetestTruthyFalsy(param),
            McpTool = "browser_security_sqli_scan",
            RestPath = "/api/security/sqli-scan",
            Args = args
        };
    }

    public static string TraceInput(string? param) =>
        string.IsNullOrWhiteSpace(param)
            ? "POST /api/security/trace-input with the reflected parameter (MCP: browser_trace_input)"
            : $"Trace input for param '{param}' (MCP: browser_trace_input, REST: POST /api/security/trace-input)";

    public static string VerifyWorkflow =>
        "Confirm exploitability with a proof workflow (MCP: browser_security_verify, REST: POST /api/security/verify)";

    public static string ChainProve => "POST /api/security/chain-prove for correlated evidence";

    public static string CallbackPoll => "POST /api/security/callbacks {\"mode\":\"poll\"} for OOB interactions";

    public static string SqliRetestTruthyFalsy(string? param) =>
        string.IsNullOrWhiteSpace(param)
            ? "Re-run sqli-scan comparing truthy vs falsy boolean payloads on the same marker"
            : $"Re-run sqli-scan on '{param}' comparing truthy vs falsy boolean payloads";

    public static string SstiConfirmSecondExpression =>
        "Confirm with a second arithmetic payload (e.g. {{7*8}} → 56) before treating as critical";

    /// <summary>
    /// Stub for set-then-read injection: POST stores the payload (session/cookie/DB), GET renders it.
    /// </summary>
    public static string VerifyDeferredInjectionStub(string setUrl, string? setMethod, string param, string? readUrl) =>
        "POST /api/security/verify — deferred injection stub: " +
        $"setup=[{{method:\"{setMethod ?? "POST"}\", url:\"{setUrl}\", body with {param}=payload}}], " +
        $"trigger=[{{method:\"GET\", url:\"{(string.IsNullOrWhiteSpace(readUrl) ? "<sibling-render-page>" : readUrl)}\"}}], " +
        "oracle={{type:\"body-contains\", value:\"payload-marker or SQL/XSS indicator\"}}";

    public static string VerifyCmdCanaryStub(string url, string? param, string? payload) =>
        "POST /api/security/verify — cmd-canary stub: " +
        $"trigger=[{{method:\"GET/POST\", url:\"{url}\", param:'{param ?? "?"}'={(string.IsNullOrWhiteSpace(payload) ? "id|;id" : TruncatePayload(payload))}}}], " +
        "oracle={{type:\"body-contains\", value:\"uid=|gid=|whoami output\"}}";

    public static string VerifyStoredXssStub(string setUrl, string? readUrl) =>
        "POST /api/security/verify — stored XSS stub: " +
        $"setup=[POST {setUrl} with XSS marker], trigger=[GET {(string.IsNullOrWhiteSpace(readUrl) ? setUrl : readUrl)}], " +
        "oracle={{type:\"dom-sink\" or body-contains unescaped marker}}";

    private static string TruncatePayload(string payload) =>
        payload.Length <= 48 ? payload : payload[..45] + "...";

    public static string PostMessageAudit =>
        "POST /api/security/postmessage — audit message listeners and fuzz origins";

    public static string ClientSurface =>
        "POST /api/security/client-surface — refresh the client-side attack-surface map";

    public static string ClientPrototypePollution =>
        "POST /api/security/client-prototype-pollution — probe URL/hash/postMessage PP gadgets";

    public static string TraceInputMonitorSinks =>
        "POST /api/security/trace-input with monitorSinks:true on the untested source×sink cell";

    public static string GadgetChains =>
        "POST /api/security/gadget-chains — orchestrate radar, clobber, client-PP, and dom-flow probes (MCP: browser_security_gadget_chains)";

    public static string GadgetRadarRead =>
        "POST /api/security/gadget-radar {\"action\":\"read\"} — ranked missing-global and proto-read events (MCP: browser_gadget_radar)";

    public static string DomXssAudit =>
        "POST /api/security/dom-xss-audit — confirm source-to-sink on this page (MCP: browser_dom_xss_audit)";

    public static string DomFlowsObserve =>
        "POST /api/security/dom-flows {\"mode\":\"observe\"} — markup and navigation chains (MCP: browser_dom_flows)";

    public static string ServiceWorkerAudit =>
        "POST /api/security/service-worker-audit — scope, script, and cache review (MCP: browser_security_service_worker_audit)";

    public static string XsLeaks =>
        "POST /api/security/xs-leaks — only with two secret-dependent states (MCP: browser_security_xs_leaks)";

    public static string CstiScan =>
        "POST /api/security/csti-scan — template payload on query/hash (MCP: browser_security_csti_scan)";

    public static string StorageAudit =>
        "POST /api/security/storage — key names only on this map; the audit reads values (MCP: browser_security_storage).";

    public static string ClickjackTest =>
        "POST /api/security/clickjack-test — framing of this document (MCP: browser_security_clickjack_test)";

    public static string CorsScan =>
        "POST /api/security/cors — cross-origin allow-origin on captured responses";

    public static string WebSocketAudit =>
        "POST /api/security/websocket-audit — socket listeners and message handlers";

    public static string SseAudit =>
        "POST /api/security/sse-audit — EventSource streams and event-data handlers";
}

/// <summary>
/// Shared coverage shape for client-side scans (Law 2: never return a dead-end "clean").
/// </summary>
public sealed class ClientScanCoverage
{
    public List<string> Instrumented { get; init; } = [];
    public List<string> SourcesSeen { get; init; } = [];
    public List<string> SinksSeen { get; init; } = [];
    public List<string> ListenersSeen { get; init; } = [];
    public List<string> Untested { get; init; } = [];
    public string? ZeroResultReason { get; init; }
    public string? FrameEnumeration { get; init; }
    public ClientSurfaceCoverageSurfaces? Surfaces { get; init; }

    public object ToApiObject() => new
    {
        instrumented = Instrumented,
        sourcesSeen = SourcesSeen,
        sinksSeen = SinksSeen,
        listenersSeen = ListenersSeen,
        untested = Untested,
        zeroResultReason = ZeroResultReason,
        frameEnumeration = FrameEnumeration,
        surfaces = Surfaces?.ToApiObject()
    };
}
