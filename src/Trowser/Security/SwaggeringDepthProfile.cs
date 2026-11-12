namespace Trowser.Security;

public static class SwaggeringDepthProfile
{
    public const string Quick = "quick";
    public const string Standard = "standard";
    public const string Thorough = "thorough";

    public sealed class Resolved
    {
        public string Name { get; init; } = Standard;
        public int MaxStepSeconds { get; init; } = 480;
        public int MaxOperations { get; init; } = 80;
        public int MaxRequestsTotal { get; init; } = 400;
        public int InterRequestDelayMs { get; init; } = 75;
        public int SlowThresholdMs { get; init; } = 8000;
        public bool IncludeAuthDelta { get; init; } = true;
        public bool IncludeForcedError { get; init; } = true;
        public bool IncludeMissingField { get; init; } = true;
        public bool IncludeCostEdge { get; init; } = true;
        public bool IncludeInjectionMicro { get; init; } = true;
        public bool IncludeShadowPaths { get; init; } = true;
        public bool IncludeAutoScan { get; init; } = true;
        public string AutoScanDepth { get; init; } = AutoScanDepthProfile.Quick;
        public int AutoScanMaxStepSeconds { get; init; }
    }

    public static string Normalize(string? depth) => (depth ?? Standard).Trim().ToLowerInvariant() switch
    {
        Quick or "fast" or "light" => Quick,
        Thorough or "deep" or "full" => Thorough,
        _ => Standard
    };

    public static Resolved Resolve(string? depth, int? maxStepSecondsOverride)
    {
        var name = Normalize(depth);
        var resolved = name switch
        {
            Quick => new Resolved
            {
                Name = Quick,
                MaxStepSeconds = 120,
                MaxOperations = 30,
                MaxRequestsTotal = 80,
                IncludeAuthDelta = false,
                IncludeForcedError = false,
                IncludeMissingField = false,
                IncludeCostEdge = false,
                IncludeInjectionMicro = false,
                IncludeShadowPaths = false,
                IncludeAutoScan = false
            },
            Thorough => new Resolved
            {
                Name = Thorough,
                MaxStepSeconds = 1200,
                MaxOperations = 500,
                MaxRequestsTotal = 2500,
                InterRequestDelayMs = 50,
                IncludeAutoScan = true,
                AutoScanDepth = AutoScanDepthProfile.Thorough,
                AutoScanMaxStepSeconds = 600
            },
            _ => new Resolved
            {
                Name = Standard,
                MaxStepSeconds = 480,
                MaxOperations = 120,
                MaxRequestsTotal = 800,
                IncludeAutoScan = true,
                AutoScanDepth = AutoScanDepthProfile.Standard,
                AutoScanMaxStepSeconds = 240
            }
        };

        if (maxStepSecondsOverride is > 0)
        {
            resolved = new Resolved
            {
                Name = resolved.Name,
                MaxStepSeconds = maxStepSecondsOverride.Value,
                MaxOperations = resolved.MaxOperations,
                MaxRequestsTotal = resolved.MaxRequestsTotal,
                InterRequestDelayMs = resolved.InterRequestDelayMs,
                SlowThresholdMs = resolved.SlowThresholdMs,
                IncludeAuthDelta = resolved.IncludeAuthDelta,
                IncludeForcedError = resolved.IncludeForcedError,
                IncludeMissingField = resolved.IncludeMissingField,
                IncludeCostEdge = resolved.IncludeCostEdge,
                IncludeInjectionMicro = resolved.IncludeInjectionMicro,
                IncludeShadowPaths = resolved.IncludeShadowPaths,
                IncludeAutoScan = resolved.IncludeAutoScan,
                AutoScanDepth = resolved.AutoScanDepth,
                AutoScanMaxStepSeconds = resolved.AutoScanMaxStepSeconds
            };
        }

        return resolved;
    }
}
