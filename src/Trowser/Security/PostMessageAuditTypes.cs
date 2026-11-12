namespace Trowser.Security;

public sealed class PostMessageAuditOptions
{
    public string SafetyMode { get; init; } = "safe";
    public bool Fuzz { get; init; } = true;
    /// <summary>Legacy cap for total synthetic payloads across listeners.</summary>
    public int MaxPayloads { get; init; } = 8;
    public int MaxPayloadsPerListener { get; init; } = 2;
    public string Depth { get; init; } = SecurityScanDepth.Quick;
    public bool SuggestOnly { get; init; }
    public bool IncludeOutbound { get; init; } = true;
    public int MaxSeconds { get; init; }
    public string? ListenerFilter { get; init; }
    public IReadOnlyList<string>? Topologies { get; init; }
    /// <summary>When false, listeners[] includes session history (Shadow); default scopes to current document.</summary>
    public bool IncludeHistory { get; init; }
    /// <summary>Clear the runtime listener log before enumerating (default when starting on a new document).</summary>
    public bool Reset { get; init; }
    /// <summary>Override mocked attacker origin for active proof (e.g. sibling host bypass).</summary>
    public string? AttackerOrigin { get; init; }
    /// <summary>When the top document has no listeners, navigate into same-origin iframe <c>src</c> URLs and re-enumerate.</summary>
    public bool DescendIframes { get; init; } = true;
}

public sealed class PostMessagePosture
{
    public string? XFrameOptions { get; set; }
    public string? FrameAncestors { get; set; }
    public string? ReferrerPolicy { get; set; }
    public bool FramingLikelyBlocked { get; set; }
    public List<string> RecommendedTopologies { get; set; } = [];
}

public sealed class PostMessageTechniqueResult
{
    public string TechniqueId { get; set; } = "";
    public string Topology { get; set; } = "";
    public string Verdict { get; set; } = "blocked";
    public string Tier { get; set; } = SecurityFindingTier.Hygiene;
    public string Confidence { get; set; } = SecurityConfidence.Tentative;
    public string ConfirmationStatus { get; set; } = "none";
    public bool Mitigated { get; set; }
    public string? MitigationReason { get; set; }
    public string? ListenerId { get; set; }
    public string? PayloadPreview { get; set; }
    public string? Canary { get; set; }
    public string? PocHtml { get; set; }
    public string? Detail { get; set; }
}

public sealed class PostMessageInferredSchema
{
    public string? TypeLiteral { get; set; }
    public string? ActionLiteral { get; set; }
    public string? EventLiteral { get; set; }
    public List<string> HtmlKeys { get; set; } = [];
    public bool PreferJsPayload { get; set; }
}
