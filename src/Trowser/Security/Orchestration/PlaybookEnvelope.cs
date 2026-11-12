using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration;

/// <summary>Common request envelope for all playbook orchestrators.</summary>
public sealed class PlaybookRequest
{
    /// <summary>Scope: host, path inclusion/exclusion, identities.</summary>
    public PlaybookScope Scope { get; init; } = new();

    /// <summary>Safety axis: passive | safe | active | aggressive.</summary>
    public SafetyMode SafetyMode { get; init; } = SafetyMode.Safe;

    /// <summary>Scan depth: quick | llm (agent) | standard | deep.</summary>
    public PlaybookDepth Depth { get; init; } = PlaybookDepth.Standard;

    /// <summary>Payload corpus breadth: small (built-in, default) | big (external corpora subsets).</summary>
    public PayloadProfile PayloadProfile { get; init; } = PayloadProfile.Small;

    /// <summary>Run the shared crawl-light step before scanners (default false — browse manually first). Set via <c>crawl</c> or <c>includeCrawl</c>.</summary>
    public bool IncludeCrawl { get; init; }

    /// <summary>Same request with <see cref="IncludeCrawl"/> disabled (nested playbook runs).</summary>
    public PlaybookRequest WithCrawlDisabled() => new()
    {
        Scope = Scope,
        SafetyMode = SafetyMode,
        Depth = Depth,
        PayloadProfile = PayloadProfile,
        IncludeCrawl = false,
        Budget = Budget,
        Evidence = Evidence,
        EmitSuggestedProofs = EmitSuggestedProofs,
        Tags = Tags,
        Format = Format,
        EmbedVpx = EmbedVpx,
        PersistVpx = PersistVpx,
        ResumeRunId = ResumeRunId
    };

    /// <summary>Budget limits.</summary>
    public BudgetLimits Budget { get; init; } = new();

    /// <summary>Evidence mode: none | auto | full.</summary>
    public string Evidence { get; init; } = "auto";

    /// <summary>Whether findings should carry suggestedProof.workflowId.</summary>
    public bool EmitSuggestedProofs { get; init; } = true;

    /// <summary>Free-form tags propagated to findings.</summary>
    public List<string> Tags { get; init; } = [];

    /// <summary>Output format: vpx | vpx-compact | vpx-summary | markdown | sarif.</summary>
    public string Format { get; init; } = "vpx-compact";

    /// <summary>When format=markdown, also attach the VPX doc inline.</summary>
    public bool EmbedVpx { get; init; }

    /// <summary>Store VPX in session for later /api/vpx/export merging.</summary>
    public bool PersistVpx { get; init; } = true;

    /// <summary>Optional: resume an aborted run by ID.</summary>
    public string? ResumeRunId { get; init; }
}

public sealed class PlaybookScope
{
    /// <summary>Target host — defaults to current page origin.</summary>
    public string? Host { get; init; }

    /// <summary>Glob patterns for included paths (e.g. "/api/*").</summary>
    public List<string> IncludePaths { get; init; } = [];

    /// <summary>Glob patterns for excluded paths (e.g. "/logout", "/admin/*").</summary>
    public List<string> ExcludePaths { get; init; } = [];

    /// <summary>Optional regex patterns matched against path+query (in addition to globs).</summary>
    public List<string> ExcludeUrlPatterns { get; init; } = [];

    /// <summary>
    /// When true (default), crawl and probe selection skip logout/sign-out/SLO URLs.
    /// Set false only when intentionally exercising logout (e.g. dedicated authn runs that need crawl discovery).
    /// Logout-invalidation probe still calls logout on purpose regardless of this flag.
    /// </summary>
    public bool ExcludeLogout { get; init; } = true;

    /// <summary>Identity names resolved via IdentityStore (e.g. "anon", "alice", "admin").</summary>
    public List<string> Identities { get; init; } = [];

    /// <summary>When set, scanners focus on this URL only (must appear in the network log).</summary>
    public string? TargetUrl { get; init; }

    /// <summary>Optional HTTP method filter with <see cref="TargetUrl"/> (e.g. POST).</summary>
    public string? TargetMethod { get; init; }
}

public sealed class BudgetLimits
{
    public int MaxSeconds { get; init; } = 120;
    public int MaxRequests { get; init; } = 800;

    /// <summary>
    /// When true, the orchestrator may extend time/request caps mid-run when steps
    /// are making progress but have not finished (up to 3 extensions of 25% each).
    /// </summary>
    public bool Adaptive { get; init; }

    /// <summary>
    /// When true (default), playbooks use the caller-requested budget and may skip steps
    /// rather than silently raising caps. Set false to restore legacy raise-to-recommended behavior.
    /// </summary>
    public bool HonorRequested { get; init; } = true;
}

/// <summary>Common response envelope wrapping VPX output.</summary>
public sealed class PlaybookResponse
{
    public required string PlaybookId { get; init; }
    public required string RunId { get; init; }
    public required PlaybookScope Scope { get; init; }
    public required string SafetyMode { get; init; }
    public required string Depth { get; init; }
    public required string StartedAt { get; init; }
    public required string FinishedAt { get; init; }
    public required List<PlaybookStepResult> StepsExecuted { get; init; }
    public required Dictionary<string, object?> BudgetUsed { get; init; }
    public List<string> Warnings { get; init; } = [];
    public int AssertionsAdded { get; init; }
    public List<NextAction> NextActions { get; init; } = [];

    /// <summary>Present when format=vpx or vpx-compact or vpx-summary.</summary>
    public object? Vpx { get; set; }

    /// <summary>Present when format=markdown.</summary>
    public string? Markdown { get; set; }

    /// <summary>Present when format=sarif.</summary>
    public object? Sarif { get; set; }

    /// <summary>Present when format=markdown and embedVpx=true.</summary>
    public object? VpxAttached { get; set; }

    /// <summary>Present for the full playbook: cross-category chain correlation results.</summary>
    public object? CorrelatedChains { get; set; }

    /// <summary>Estimated wall-clock seconds to complete all non-skipped steps at recommended budget.</summary>
    public int? EstimatedCompletionSeconds { get; set; }

    /// <summary>Suggested HTTP client timeout (estimated completion + 25% buffer, min +30s).</summary>
    public int? SuggestedClientTimeoutSeconds { get; set; }

    /// <summary>Findings suppressed by cross-playbook deduplication (ids/titles).</summary>
    public List<SuppressedFindingInfo>? SuppressedFindings { get; set; }

    /// <summary>
    /// Normalized findings for LLM triage (same objects as <c>vpx.findings</c>).
    /// Always populated so agents need not dig into VPX export shape.
    /// </summary>
    public List<ChainableFinding>? Findings { get; set; }

    /// <summary>Severity histogram for top-level findings (critical/high/medium/low/info).</summary>
    public Dictionary<string, int>? SeverityHistogram { get; set; }

    /// <summary>
    /// True when budget exhausted mid-run or probe steps were skipped — agents must not treat
    /// an empty/partial finding set as a clean bill of health.
    /// </summary>
    public bool CoverageIncomplete { get; set; }

    /// <summary>One-line instruction when <see cref="CoverageIncomplete"/> is true.</summary>
    public string? AgentInstruction { get; set; }

    /// <summary>Internal: full VPX doc for rendering pipeline (not serialized to response).</summary>
    internal object? VpxFull { get; set; }
}

    public sealed class SuppressedFindingInfo
    {
        public string? Id { get; init; }
        public string? Title { get; init; }
        public string? Category { get; init; }
        public string? Severity { get; init; }
        public string? Endpoint { get; init; }
        public string Reason { get; init; } = "cross-playbook-deduplication";
    }

public sealed class PlaybookStepResult
{
    public required string Name { get; init; }
    public required string Status { get; init; }
    public int DurationMs { get; init; }
    public string? Reason { get; init; }

    /// <summary>Step-specific metrics (e.g. endpointsDiscovered, findings count).</summary>
    public Dictionary<string, object?> Metrics { get; init; } = [];
}

public sealed class NextAction
{
    /// <summary>Action type: "verify-workflow", "run-playbook", "manual-check".</summary>
    public required string Action { get; init; }

    public string? WorkflowId { get; init; }
    public string? PlaybookId { get; init; }
    public string? Rationale { get; init; }
}

/// <summary>Dry-run response: the step plan without executing probes.</summary>
public sealed class DryRunResponse
{
    public required string PlaybookId { get; init; }
    public required string SafetyMode { get; init; }
    public required string Depth { get; init; }
    public required List<DryRunStep> Steps { get; init; }
    public required BudgetLimits Budget { get; init; }

    /// <summary>Minimum recommended budget for this playbook at the given depth (before surface adjustment).</summary>
    public BudgetLimits? BaseRecommendedBudget { get; init; }

    /// <summary>Recommended budget after attack-surface and network-log sizing.</summary>
    public BudgetLimits? RecommendedBudget { get; init; }

    /// <summary>Estimated wall-clock seconds for all non-skipped steps.</summary>
    public int EstimatedCompletionSeconds { get; init; }

    /// <summary>Suggested HTTP client timeout (estimated + buffer).</summary>
    public int SuggestedClientTimeoutSeconds { get; init; }

    /// <summary>Attack surface snapshot from the current network log (empty if not browsed).</summary>
    public PlaybookBudgetPlanner.SurfaceSnapshot? Surface { get; init; }

    /// <summary>Human-readable notes explaining budget adjustments.</summary>
    public List<string> BudgetNotes { get; init; } = [];

    /// <summary>
    /// True when one or more probe-heavy steps are marked <see cref="DryRunStep.SkippedByBudget"/>
    /// at the requested budget — coverage would be incomplete if executed as-is.
    /// </summary>
    public bool CoverageIncomplete { get; init; }

    /// <summary>One-line instruction for agents when <see cref="CoverageIncomplete"/> is true.</summary>
    public string? AgentInstruction { get; init; }
}

public sealed class DryRunStep
{
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required string HttpVerbs { get; init; }
    public bool WritesSideEffects { get; init; }
    public bool SkippedByCurrentSafetyMode { get; init; }
    public string? SkipReason { get; init; }

    /// <summary>Estimated seconds for this step at the requested depth and current surface.</summary>
    public int? EstimatedSeconds { get; init; }

    /// <summary>Estimated HTTP requests for this step.</summary>
    public int? EstimatedRequests { get; init; }

    /// <summary>True when the caller's budget would likely omit this step (cumulative estimate).</summary>
    public bool SkippedByBudget { get; init; }
}
