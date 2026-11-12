namespace Trowser.Security.Orchestration;

/// <summary>
/// Unified safety axis for all playbook orchestration.
/// Replaces the per-endpoint flag soup (confirmBackend, safeDefaults,
/// readOnlyProbes, SafeSecurityProbesOnly, DangerousSecurityProbesOk).
/// </summary>
public enum SafetyMode
{
    /// <summary>Zero outbound probes — only consumes already-captured network/console/source.</summary>
    Passive,

    /// <summary>GET / HEAD / OPTIONS only — no state-changing requests.</summary>
    Safe,

    /// <summary>All verbs against discovered endpoints — may create/modify test data.</summary>
    Active,

    /// <summary>All verbs + stress — may exhaust quotas, trigger WAF bans, fill DB.</summary>
    Aggressive
}

public static class SafetyModeExtensions
{
    public static SafetyMode Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return SafetyMode.Safe;
        return value.Trim().ToLowerInvariant() switch
        {
            "passive" => SafetyMode.Passive,
            "safe" => SafetyMode.Safe,
            "active" => SafetyMode.Active,
            "aggressive" => SafetyMode.Aggressive,
            _ => SafetyMode.Safe
        };
    }

    public static string ToLabel(this SafetyMode mode) => mode switch
    {
        SafetyMode.Passive => "passive",
        SafetyMode.Safe => "safe",
        SafetyMode.Active => "active",
        SafetyMode.Aggressive => "aggressive",
        _ => "safe"
    };

    /// <summary>Whether this mode allows HTTP verbs that modify server state.</summary>
    public static bool AllowsWriteVerbs(this SafetyMode mode) =>
        mode is SafetyMode.Active or SafetyMode.Aggressive;

    /// <summary>Whether this mode allows any outbound HTTP probes at all.</summary>
    public static bool AllowsProbes(this SafetyMode mode) =>
        mode != SafetyMode.Passive;

    /// <summary>Whether stress/load/brute-force probes are permitted.</summary>
    public static bool AllowsStress(this SafetyMode mode) =>
        mode == SafetyMode.Aggressive;

    /// <summary>Bridge to legacy confirmBackend flag.</summary>
    public static bool ToConfirmBackend(this SafetyMode mode) =>
        mode is SafetyMode.Active or SafetyMode.Aggressive;

    /// <summary>Bridge to legacy safeDefaults / readOnlyProbes flags.</summary>
    public static bool ToReadOnlyProbes(this SafetyMode mode) =>
        mode is SafetyMode.Passive or SafetyMode.Safe;

    /// <summary>Bridge to legacy DangerousSecurityProbesOk.</summary>
    public static bool ToDangerousOk(this SafetyMode mode) =>
        mode == SafetyMode.Aggressive;
}
