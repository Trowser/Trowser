namespace Trowser.Security;

/// <summary>
/// Per-scanner limits for <see cref="SecurityScanDepth"/> on XSS / SQLi / SSTI / SSRF.
/// </summary>
public static class InjectionScanDepth
{
    public sealed class Resolved
    {
        public string Name { get; init; } = SecurityScanDepth.Standard;

        // Shared
        public int MaxCandidates { get; init; } = 10;
        public bool IncludeTimeBasedDefault { get; init; }

        // SQLi
        public bool UseScreeningOnly { get; init; }
        public bool IncludeExtendedPayloads { get; init; } = true;
        public bool IncludeOrmClosure { get; init; }
        public bool IncludeUnionColumnLadder { get; init; }
        public int UnionColumnMax { get; init; } = 8;
        public int TimeSampleCount { get; init; } = 1;

        // XSS
        public bool RunCharSurvivalProbe { get; init; } = true;
        public bool VerifyReflectedInDom { get; init; }
        public int MaxBypassAttempts { get; init; } = 6;
        public bool IncludeStoredXss { get; init; }

        // SSTI
        public bool RequireDualArithmeticConfirm { get; init; } = true;
        public bool IncludeEngineCanary { get; init; }
        public bool TryContentTypeMatrix { get; init; } = true;
    }

    public static Resolved Resolve(string? depth, int? maxCandidatesOverride = null)
    {
        var name = SecurityScanDepth.Normalize(depth);
        var max = maxCandidatesOverride is > 0 ? maxCandidatesOverride.Value : 0;

        return name switch
        {
            SecurityScanDepth.Quick => new Resolved
            {
                Name = name,
                MaxCandidates = max > 0 ? Math.Min(max, 5) : 5,
                IncludeTimeBasedDefault = false,
                UseScreeningOnly = true,
                IncludeExtendedPayloads = false,
                IncludeOrmClosure = false,
                IncludeUnionColumnLadder = false,
                TimeSampleCount = 1,
                RunCharSurvivalProbe = false,
                VerifyReflectedInDom = false,
                MaxBypassAttempts = 3,
                IncludeStoredXss = false,
                RequireDualArithmeticConfirm = true,
                IncludeEngineCanary = false,
                TryContentTypeMatrix = false
            },
            SecurityScanDepth.Deep => new Resolved
            {
                Name = name,
                MaxCandidates = max > 0 ? Math.Min(max, 20) : 15,
                IncludeTimeBasedDefault = true,
                UseScreeningOnly = false,
                IncludeExtendedPayloads = true,
                IncludeOrmClosure = true,
                IncludeUnionColumnLadder = true,
                UnionColumnMax = 10,
                TimeSampleCount = 3,
                RunCharSurvivalProbe = true,
                VerifyReflectedInDom = true,
                MaxBypassAttempts = 10,
                IncludeStoredXss = true,
                RequireDualArithmeticConfirm = true,
                IncludeEngineCanary = true,
                TryContentTypeMatrix = true
            },
            _ => new Resolved
            {
                Name = SecurityScanDepth.Standard,
                MaxCandidates = max > 0 ? Math.Min(max, 12) : 10,
                IncludeTimeBasedDefault = false,
                UseScreeningOnly = false,
                IncludeExtendedPayloads = true,
                IncludeOrmClosure = false,
                IncludeUnionColumnLadder = false,
                UnionColumnMax = 8,
                TimeSampleCount = 2,
                RunCharSurvivalProbe = true,
                VerifyReflectedInDom = true,
                MaxBypassAttempts = 6,
                IncludeStoredXss = false,
                RequireDualArithmeticConfirm = true,
                IncludeEngineCanary = false,
                TryContentTypeMatrix = true
            }
        };
    }
}
