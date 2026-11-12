namespace Trowser.Security.Vpx;

/// <summary>
/// Session-scoped record of a runtime proof attempt, exported as VPX <c>proofs[]</c>.
/// </summary>
public sealed class VpxProofRecord
{
    public string Id { get; init; } = "";
    public string FindingId { get; init; } = "";
    public string? RunId { get; init; }
    /// <summary>VPX 1.1 proof outcome. When null, exporters derive from <see cref="OraclePassed"/>.</summary>
    public string? Outcome { get; init; }
    public DateTime ExecutedAtUtc { get; init; }
    public string WorkflowType { get; init; } = "verify-workflow";
    public string? TemplateId { get; init; }
    public string? WorkflowId { get; init; }
    public bool OraclePassed { get; init; }
    public bool? OracleObserved { get; init; }
    public string OracleType { get; init; } = "";
    public object? OracleEvidence { get; init; }
    public string? EvidenceBundlePath { get; init; }
    public string? SurfaceId { get; init; }
    public string? Param { get; init; }
    public string? Payload { get; init; }
    public IReadOnlyList<string>? Limitations { get; init; }
    public IReadOnlyList<string>? ArtifactIds { get; init; }
    public int ElapsedMs { get; init; }
}
