namespace Trowser.Security.ChainEngine;

/// <summary>
/// A normalized finding from any source (shadow, auto-scan, journal, manual)
/// that can participate in attack chain analysis.
/// </summary>
public sealed class ChainableFinding
{
    /// <summary>Unique ID (e.g., "shadow-42", "autoscan-csrf-3").</summary>
    public string Id { get; init; } = "";

    /// <summary>Origin: "shadow", "autoscan", "journal", "manual".</summary>
    public string Source { get; init; } = "";

    /// <summary>
    /// Normalized category: xss, csrf, idor, sqli, missing-httponly, missing-csp,
    /// cors-misconfig, open-redirect, session-fixation, ssrf, path-traversal,
    /// info-leak, weak-auth, missing-rate-limit, timing-oracle, mass-assignment,
    /// missing-samesite, source-maps, mixed-content, header-injection,
    /// content-type-confusion, deserialization-suspected, parser-differential,
    /// command-injection, ssti-confirmed, rce-indicator, credential-exposure, etc.
    /// </summary>
    public string Category { get; init; } = "";

    /// <summary>Severity: low, medium, high, critical.</summary>
    public string Severity { get; init; } = "info";

    /// <summary>Human-readable title.</summary>
    public string Title { get; init; } = "";

    /// <summary>URL or URL pattern of the affected endpoint.</summary>
    public string? Endpoint { get; init; }

    /// <summary>HTTP method if applicable.</summary>
    public string? Method { get; init; }

    /// <summary>Affected parameter or field name.</summary>
    public string? Parameter { get; init; }

    /// <summary>Human-readable detail.</summary>
    public string? Detail { get; init; }

    /// <summary>Evidence snippet (response body, header value, etc.).</summary>
    public string? Evidence { get; init; }

    /// <summary>Actionable remediation guidance.</summary>
    public string? Remediation { get; init; }

    /// <summary>Reference URL (OWASP, MDN, etc.).</summary>
    public string? Reference { get; init; }

    /// <summary>Tags for grouping/filtering.</summary>
    public List<string> Tags { get; init; } = [];
}

/// <summary>
/// A single link in an attack chain pattern, specifying what category of
/// finding is needed and what role it plays in the chain.
/// </summary>
public sealed class ChainLink
{
    /// <summary>The finding category needed at this step (e.g., "csrf", "xss", "missing-httponly").</summary>
    public string RequiredCategory { get; init; } = "";

    /// <summary>Role in the chain: "enabler", "trigger", "amplifier", "exfiltrator".</summary>
    public string Role { get; init; } = "enabler";

    /// <summary>If true, the chain still works without this link but is weaker.</summary>
    public bool Optional { get; init; }

    /// <summary>
    /// Constraint for matching: "same-origin" (findings share origin), "same-endpoint"
    /// (same URL), "state-changing" (POST/PUT/PATCH/DELETE method), or null (no constraint).
    /// </summary>
    public string? Constraint { get; init; }

    /// <summary>
    /// Optional regex matched against the finding endpoint URL/path (e.g. password|email|account).
    /// Findings whose endpoint does not match are excluded from this link.
    /// </summary>
    public string? EndpointPattern { get; init; }
}

/// <summary>
/// A known attack chain pattern that defines how two or more finding categories
/// combine into a higher-impact exploit.
/// </summary>
public sealed class ChainPattern
{
    /// <summary>Unique identifier (e.g., "csrf-stored-xss-worm").</summary>
    public string Id { get; init; } = "";

    /// <summary>Human-readable name (e.g., "CSRF + Stored XSS → Self-Propagating Worm").</summary>
    public string Name { get; init; } = "";

    /// <summary>The severity of the combined chain (usually higher than individual findings).</summary>
    public string ChainedSeverity { get; init; } = "high";

    /// <summary>
    /// Impact category: "account-takeover", "data-breach", "worm", "session-hijack",
    /// "privilege-escalation", "phishing", "defacement", "dos", "rce".
    /// </summary>
    public string Impact { get; init; } = "";

    /// <summary>Ordered links in the chain.</summary>
    public List<ChainLink> Links { get; init; } = [];

    /// <summary>How the chain works, as a template with {0}, {1}, ... for matched finding details.</summary>
    public string Description { get; init; } = "";

    /// <summary>When set, references a built-in proof template (see ProofTemplateCatalog). Enables chain-prove.</summary>
    public string? ProofTemplateId { get; init; }

    /// <summary>
    /// When set, all required links may match but the chain stays a hypothesis until at least one
    /// of these categories appears in the finding pool (e.g. mixed-content for HSTS downgrade).
    /// </summary>
    public List<string> ConfirmationAnyCategories { get; init; } = [];

    /// <summary>Max chained severity when required links match but confirmation is missing.</summary>
    public string? HypothesisSeverityCap { get; init; }

    /// <summary>Tags added to hypothesis/partial chains (e.g. needs-http-probe).</summary>
    public List<string> HypothesisTags { get; init; } = [];
}

/// <summary>
/// A concrete chain candidate matched from actual findings against a pattern.
/// </summary>
public sealed class CandidateChain
{
    /// <summary>The pattern that was matched.</summary>
    public string PatternId { get; init; } = "";

    /// <summary>Human-readable pattern name.</summary>
    public string PatternName { get; init; } = "";

    /// <summary>Alias of <see cref="PatternName"/> for VPX/LLM clients that expect <c>title</c>.</summary>
    public string Title => PatternName;

    /// <summary>Combined severity of the chain.</summary>
    public string ChainedSeverity { get; init; } = "high";

    /// <summary>Impact category.</summary>
    public string Impact { get; init; } = "";

    /// <summary>Confidence score 0.0–1.0 based on constraint satisfaction and finding quality.</summary>
    public double ConfidenceScore { get; init; }

    /// <summary>The actual findings that matched each link.</summary>
    public List<ChainableFinding> MatchedFindings { get; init; } = [];

    /// <summary>Human-readable narrative of the attack scenario.</summary>
    public string Narrative { get; init; } = "";

    /// <summary>Whether automated proof is possible for this chain.</summary>
    public bool Provable { get; init; }

    /// <summary>Identity snapshots required by proof template but not yet captured.</summary>
    public List<string> MissingIdentities { get; init; } = [];

    /// <summary>Static template placeholders that cannot be resolved from matched findings (provable=false).</summary>
    public List<string>? UnresolvedProofPlaceholders { get; init; }

    /// <summary>Explains the severity upgrade from individual findings to chain severity.</summary>
    public SeverityUpgrade? SeverityUpgrade { get; init; }

    /// <summary>matched — pattern satisfied; confirmed — same as <see cref="Provable"/> (automated proof ready).</summary>
    public string Status { get; init; } = "matched";

    public List<string> Tags { get; init; } = [];
}

/// <summary>
/// Documents how a chain's severity exceeds the individual finding severities.
/// </summary>
public sealed class SeverityUpgrade
{
    /// <summary>Original severities of individual findings.</summary>
    public List<string> From { get; init; } = [];

    /// <summary>Combined chain severity.</summary>
    public string To { get; init; } = "";

    /// <summary>Explanation of why the combined impact is higher.</summary>
    public string Reason { get; init; } = "";
}

/// <summary>
/// A partial chain where some required links are missing — used to suggest
/// further testing that might complete the chain.
/// </summary>
public sealed class PartialChain
{
    public string PatternId { get; init; } = "";
    public string PatternName { get; init; } = "";
    /// <summary>Alias of <see cref="PatternName"/> for VPX/LLM clients that expect <c>title</c>.</summary>
    public string Title => PatternName;
    public string ChainedSeverity { get; init; } = "high";
    public string Impact { get; init; } = "";
    public double ConfidenceScore { get; init; }
    public List<ChainableFinding> PresentFindings { get; init; } = [];
    public List<string> MissingCategories { get; init; } = [];
    public int PresentLinkCount { get; init; }
    public int RequiredLinkCount { get; init; }
    public string Note { get; init; } = "";
    public string PotentialNarrative { get; init; } = "";
    public string? SuggestedAction { get; init; }
    public List<string> MissingIdentities { get; init; } = [];

    /// <summary>Always partial — never promoted to confirmed without confirmation gates.</summary>
    public string Status { get; init; } = "partial";

    public List<string> Tags { get; init; } = [];
}

/// <summary>
/// Result from executing chain-prove: evidence of an end-to-end attack chain.
/// </summary>
public sealed class ChainProofResult
{
    public string PatternId { get; init; } = "";
    public bool Proven { get; init; }
    public List<ChainStepResult> Steps { get; init; } = [];
    /// <summary>Short agent-visible one-liner (oracle/step error). Prefer this over parsing <see cref="FailureReason"/>.</summary>
    public string? FailureSummary { get; init; }
    /// <summary>Detailed failure text — may be a JSON-serialized <see cref="StepErrors"/> array.</summary>
    public string? FailureReason { get; init; }
    public string? FailurePhase { get; init; }
    public string? FailureDetail { get; init; }
    public string? Screenshot { get; init; }
    public int ElapsedMs { get; init; }
    public string? WorkflowId { get; init; }
    public string? EvidenceBundlePath { get; init; }
    public string? OracleType { get; init; }
    public object? OracleEvidence { get; init; }
    public string? TemplateExpanded { get; init; }
    public Dictionary<string, string>? AttemptedSubstitutions { get; init; }
    public List<object>? StepErrors { get; init; }
}

/// <summary>
/// Outcome of a single step in a chain proof execution.
/// </summary>
public sealed class ChainStepResult
{
    public int StepIndex { get; init; }
    public string Description { get; init; } = "";
    public bool Succeeded { get; init; }
    public string? Evidence { get; init; }
    public string? Error { get; init; }
    public object? Step { get; init; }
}
