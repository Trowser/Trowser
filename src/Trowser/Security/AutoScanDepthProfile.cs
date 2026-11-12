namespace Trowser.Security;

/// <summary>
/// Resolves <see cref="AutoScanPipeline.AutoScanOptions.ScanDepth"/> into per-scanner limits.
/// </summary>
public static class AutoScanDepthProfile
{
    public const string Quick = "quick";
    public const string Standard = "standard";
    public const string Thorough = "thorough";

    public sealed class Resolved
    {
        public string Name { get; init; } = Standard;
        public int EffectiveMaxEndpointsPerScanner { get; init; }
        public int PolyglotMaxProbes { get; init; }
        public int PolyglotMaxPaths { get; init; }
        public int PolyglotMaxParams { get; init; }
        public bool PolyglotIncludeScaffold { get; init; }
        public bool PolyglotEnabled { get; init; } = true;
        public int SstiStoredMaxCandidates { get; init; }
        public int PrototypePollutionMaxCandidates { get; init; }
        public bool RunSqliScaffoldWhenSparse { get; init; }
        public bool RunSstiScaffoldWhenSparse { get; init; }
        public int SqliScaffoldCap { get; init; }
        public int SstiScaffoldCap { get; init; }
        /// <summary>
        /// Hard wall-clock budget when the caller did not set <see cref="AutoScanPipeline.AutoScanOptions.MaxStepSeconds"/>.
        /// Prevents indefinite busy-gate hangs; scan returns partial results on expiry.
        /// </summary>
        public int DefaultMaxStepSeconds { get; init; }
    }

    public static string Normalize(string? depth)
    {
        if (string.IsNullOrWhiteSpace(depth))
            return Standard;

        return depth.Trim().ToLowerInvariant() switch
        {
            Quick or "fast" or "light" or "llm" or "agent" or "ai" => Quick,
            Thorough or "deep" or "full" => Thorough,
            Standard or "normal" or "default" or "balanced" => Standard,
            _ => Standard
        };
    }

    public static Resolved Resolve(AutoScanPipeline.AutoScanOptions options)
    {
        var name = Normalize(options.ScanDepth);
        var maxEp = options.MaxEndpointsPerScanner > 0 ? options.MaxEndpointsPerScanner : 5;

        return name switch
        {
            Quick => new Resolved
            {
                Name = Quick,
                EffectiveMaxEndpointsPerScanner = Math.Min(maxEp, 3),
                PolyglotEnabled = true,
                PolyglotMaxProbes = 8,
                PolyglotMaxPaths = 4,
                PolyglotMaxParams = 2,
                PolyglotIncludeScaffold = true,
                SstiStoredMaxCandidates = Math.Min(maxEp, 3),
                PrototypePollutionMaxCandidates = 5,
                RunSqliScaffoldWhenSparse = true,
                RunSstiScaffoldWhenSparse = true,
                SqliScaffoldCap = 4,
                SstiScaffoldCap = 3,
                DefaultMaxStepSeconds = 120
            },
            Thorough => new Resolved
            {
                Name = Thorough,
                EffectiveMaxEndpointsPerScanner = Math.Min(maxEp * 2, 15),
                PolyglotMaxProbes = 0,
                PolyglotMaxPaths = Math.Max(maxEp * 5, 25),
                PolyglotMaxParams = 0,
                PolyglotIncludeScaffold = true,
                SstiStoredMaxCandidates = Math.Max(maxEp, 10),
                PrototypePollutionMaxCandidates = Math.Max(maxEp + 4, 12),
                RunSqliScaffoldWhenSparse = true,
                RunSstiScaffoldWhenSparse = true,
                SqliScaffoldCap = maxEp * 2,
                SstiScaffoldCap = maxEp * 2,
                DefaultMaxStepSeconds = 900
            },
            _ => new Resolved
            {
                Name = Standard,
                EffectiveMaxEndpointsPerScanner = maxEp,
                PolyglotMaxProbes = 24,
                PolyglotMaxPaths = 8,
                PolyglotMaxParams = 4,
                PolyglotIncludeScaffold = false,
                SstiStoredMaxCandidates = maxEp,
                PrototypePollutionMaxCandidates = maxEp + 3,
                RunSqliScaffoldWhenSparse = true,
                RunSstiScaffoldWhenSparse = true,
                SqliScaffoldCap = maxEp,
                SstiScaffoldCap = maxEp,
                DefaultMaxStepSeconds = 210
            }
        };
    }

    /// <summary>
    /// Lighter OpenAPI/JS enrichment for auto-scan (dev-artifact probes are slow and rarely change findings).
    /// </summary>
    public static AttackSurfaceEnrichment.Options EnrichmentOptions(string? scanDepth) =>
        Normalize(scanDepth) switch
        {
            Quick => new AttackSurfaceEnrichment.Options(
                IncludeOpenApiFromNetwork: true,
                IncludeOpenApiProbes: true,
                IncludeJsBundleHints: true,
                IncludeDevArtifactProbes: false,
                MaxProbeOrigins: 3,
                MaxScripts: 8),
            Standard => new AttackSurfaceEnrichment.Options(
                IncludeOpenApiFromNetwork: true,
                IncludeOpenApiProbes: true,
                IncludeJsBundleHints: true,
                IncludeDevArtifactProbes: false,
                MaxProbeOrigins: 4,
                MaxScripts: 14),
            _ => new AttackSurfaceEnrichment.Options()
        };

    /// <summary>
    /// For quick/standard, disables slow niche scanners (thorough keeps them). REST applies the same rules
    /// when the client did not pass explicit include* flags.
    /// </summary>
    public static void ApplyScriptPresets(AutoScanPipeline.AutoScanOptions options)
    {
        if (!options.ApplyDepthScannerPresets || Normalize(options.ScanDepth) == Thorough)
            return;

        options.IncludeCacheDeception = false;
        options.IncludeDeserializationScan = false;
        options.IncludeFileUploadScan = false;

        if (Normalize(options.ScanDepth) == Quick)
            options.IncludeCsrfCorrelations = false;
    }
}
