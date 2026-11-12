using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security.Workflow;

public sealed class WorkflowDependencies
{
    public required Automation.AutomationContext Context { get; init; }
    public required IdentityStore IdentityStore { get; init; }
    public PeerRegistry? Peers { get; init; }
    public string? SessionName { get; init; }
    public required string ScreenshotDir { get; init; }
    public CancellationToken Cancellation { get; init; } = CancellationToken.None;
}

public sealed class WorkflowExecutionContext
{
    public Dictionary<string, string> Vars { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Markers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public JsonElement? LastFetch { get; set; }
    public JsonElement? LastTriggerFetch { get; set; }

    public int NetworkMarkerIndex { get; set; }
    public int RefGenerationBeforeTrigger { get; set; }
    public string? ScreenshotBeforeTrigger { get; set; }

    public List<Dictionary<string, object?>> SetupResults { get; } = [];
    public List<Dictionary<string, object?>> TriggerResults { get; } = [];
    public List<Dictionary<string, object?>> CleanupResults { get; } = [];

    public string? WorkflowId { get; set; }
    public string? WorkflowName { get; set; }
}

public sealed class OracleCheckResult
{
    public string Type { get; init; } = "";
    public bool Passed { get; init; }
    public object? Evidence { get; init; }
    public List<object> Artifacts { get; init; } = [];
    public string? Error { get; init; }
}

public sealed class WorkflowVerifyResult
{
    public string? Name { get; init; }
    public string? WorkflowId { get; init; }
    public bool Verified { get; init; }
    public bool SetupOk { get; init; }
    public bool TriggerOk { get; init; }
    public bool OraclePassed { get; init; }
    public bool CleanupOk { get; init; }
    public OracleCheckResult? Oracle { get; init; }
    public List<Dictionary<string, object?>> Setup { get; init; } = [];
    public List<Dictionary<string, object?>> Trigger { get; init; } = [];
    public List<Dictionary<string, object?>> Cleanup { get; init; } = [];
    public string? FailurePhase { get; init; }
    public string? Error { get; init; }
    public string? EvidenceBundlePath { get; init; }
    public int ElapsedMs { get; init; }
    public Dictionary<string, string>? CapturedVars { get; init; }
    public List<object>? StepErrors { get; init; }
}

public sealed class ChainProveRequestContext
{
    public required string PatternId { get; init; }
    public List<ChainEngine.ChainableFinding> Findings { get; init; } = [];
    public bool ExportEvidence { get; init; }
    public bool ConfirmBackend { get; init; }
}

public enum EvidenceRerunVerdict
{
    Verified,
    NotVerified,
    Inconclusive
}

public sealed class EvidenceRerunResult
{
    public EvidenceRerunVerdict Verdict { get; init; }
    public WorkflowVerifyResult? Workflow { get; init; }
    public string? BundlePath { get; init; }
    public string? Error { get; init; }
}
