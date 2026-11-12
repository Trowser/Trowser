using Trowser;

namespace Trowser.Security;

/// <summary>
/// Safe-vs-destructive defaults for IDOR / auto-scan, including CLI globals (<see cref="App.Api"/>).
/// </summary>
public static class SecurityProbeSafety
{
    /// <summary>Effective flags for <see cref="HttpSecurityProbes.RunIdorScanAsync"/> after applying body + CLI precedence.</summary>
    public readonly record struct IdorEffectiveOptions(
        bool IncludeMutatingProbes,
        bool ReadOnlyProbes,
        bool DryRun,
        List<string> Warnings);

    /// <summary>
    /// Precedence: <c>--safe-probes-only</c> wins (no mutating IDOR, read-only verbs).
    /// Then JSON <paramref name="bodySafeDefaults"/>.
    /// Otherwise explicit body properties, with omission defaults controlled by <c>--dangerous-ok</c> (legacy mutating IDOR on).
    /// </summary>
    public static IdorEffectiveOptions ResolveIdor(
        bool bodyHasIncludeMutating,
        bool bodyIncludeMutating,
        bool bodyHasReadOnlyProbes,
        bool bodyReadOnlyProbes,
        bool bodySafeDefaults,
        bool bodyDryRun)
    {
        var warnings = new List<string>();
        var cliSafe = App.Api.SafeSecurityProbesOnly;
        var cliDangerous = App.Api.DangerousSecurityProbesOk;

        if (cliSafe)
            warnings.Add(
                "This instance was started with --safe-probes-only: mutating IDOR probes are disabled and only safe HTTP verbs are used (CLI overrides explicit JSON for destructive IDOR).");

        if (bodySafeDefaults && !cliSafe)
            warnings.Add(
                "safeDefaults: mutating IDOR probes are off and only GET/HEAD/OPTIONS are sent for IDOR checks.");

        if (cliSafe || bodySafeDefaults)
            return new IdorEffectiveOptions(false, true, bodyDryRun, warnings);

        var includeMutating = bodyHasIncludeMutating
            ? bodyIncludeMutating
            : cliDangerous;

        var readOnly = bodyHasReadOnlyProbes && bodyReadOnlyProbes;

        if (includeMutating)
            warnings.Add(
                "DESTRUCTIVE: includeMutatingProbes enables PUT, PATCH, and DELETE for the same URL template as GET — these requests can MODIFY or DELETE real server resources. Use isolated environments, dryRun, or readOnlyProbes.");

        return new IdorEffectiveOptions(includeMutating, readOnly, bodyDryRun, warnings);
    }
}
