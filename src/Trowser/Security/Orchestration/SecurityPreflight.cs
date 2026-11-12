namespace Trowser.Security.Orchestration;

/// <summary>
/// Pre-flight guard that enforces safety mode constraints before a playbook runs.
/// Blocks aggressive probes against non-lab hosts, and active probes against
/// production hosts unless explicitly overridden.
/// </summary>
public static class SecurityPreflight
{
    private static readonly HashSet<string> LocalHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "127.0.0.1", "::1", "[::1]"
    };

    /// <summary>
    /// Validates that the requested safety mode is allowed for the given host.
    /// Returns null if allowed, or a refusal message if blocked.
    /// </summary>
    public static string? AssertAllowed(string playbookId, SafetyMode mode, string? host)
    {
        if (mode == SafetyMode.Passive || mode == SafetyMode.Safe)
            return null;

        var resolvedHost = host ?? "unknown";

        if (mode == SafetyMode.Aggressive && !IsLabHost(resolvedHost) && !App.Api.DangerousSecurityProbesOk)
        {
            return $"Aggressive mode blocked for '{resolvedHost}': only allowed against localhost, " +
                   $"*.local, *.test hosts, or when --dangerous-ok is set. " +
                   $"Playbook '{playbookId}' will not run. " +
                   $"Use safetyMode 'active' instead, or start Trowser with --dangerous-ok.";
        }

        if (mode == SafetyMode.Active && !IsLabHost(resolvedHost) && App.Api.SafeSecurityProbesOnly)
        {
            return $"Active mode blocked for '{resolvedHost}': --safe-probes-only is set. " +
                   $"Playbook '{playbookId}' will run in safe mode or use passive probes only.";
        }

        return null;
    }

    /// <summary>Cap mode to the maximum allowed for the given host and CLI settings.</summary>
    public static SafetyMode EffectiveMode(SafetyMode requested, string? host)
    {
        if (App.Api.SafeSecurityProbesOnly)
            return requested < SafetyMode.Safe ? requested : SafetyMode.Safe;

        if (requested == SafetyMode.Aggressive && !IsLabHost(host) && !App.Api.DangerousSecurityProbesOk)
            return SafetyMode.Active;

        return requested;
    }

    internal static bool IsLabHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        var h = host.Contains(':') ? host.Split(':')[0] : host;

        if (LocalHosts.Contains(h)) return true;
        if (h.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return true;
        if (h.EndsWith(".test", StringComparison.OrdinalIgnoreCase)) return true;
        if (h.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }
}
