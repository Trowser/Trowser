namespace Trowser.Security.Vpx;

/// <summary>
/// Imported or exported VPX verdict, stored for session merge and re-export.
/// </summary>
public sealed class VpxVerdictRecord
{
    public string? Id { get; init; }
    public string FindingId { get; init; } = "";
    public string? RunId { get; init; }
    public string? ProofId { get; init; }
    public IReadOnlyList<string>? BasedOnProofIds { get; init; }
    public IReadOnlyList<string>? BasedOnAssessmentIds { get; init; }
    public string? SupersedesVerdictId { get; init; }
    public string Exploitability { get; init; } = "hypothesis";
    public string? Disposition { get; init; }
    public string? Justification { get; init; }
    public string? EffectiveSeverity { get; init; }
    public double? Confidence { get; init; }
    public string? RerunToken { get; init; }
    public DateTime? UpdatedAtUtc { get; init; }
    public Dictionary<string, object?>? Remediation { get; init; }
}
