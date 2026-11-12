using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Builds a fully enriched attack-surface map from the current session (network log + optional SPA + API enrichment).
/// </summary>
public static class AttackSurfaceSessionBuilder
{
    public sealed class BuildOptions
    {
        public bool IncludeParameters { get; set; } = true;
        public bool IncludeAuth { get; set; } = true;
        public bool IncludeResponsePatterns { get; set; } = true;
        public string? HostFilter { get; set; }
        public bool IncludeDataUrls { get; set; }
        public bool SpaMode { get; set; }
        public bool CheckSecurityTxt { get; set; } = true;
        public bool IncludeApiEnrichment { get; set; } = true;
        public bool IncludeOpenApiFromNetwork { get; set; } = true;
        public bool IncludeOpenApiProbes { get; set; } = true;
        public bool IncludeJsBundleHints { get; set; } = true;
        public bool IncludeDevArtifactProbes { get; set; } = true;
        public int MaxProbeOrigins { get; set; } = 6;
        public int MaxJsScripts { get; set; } = 24;
        public int MaxJsBundleBytesPerFile { get; set; } = 524_288;
        public int MaxJsHintPaths { get; set; } = 200;
        public int EnrichmentHttpTimeoutMs { get; set; } = 12_000;
        public int MaxWordPressRestRoutes { get; set; } = 8000;
    }

    public static async Task<AttackSurfaceResult> BuildAsync(
        AutomationContext ctx,
        BuildOptions options,
        CancellationToken ct = default)
    {
        var entries = ctx.Network.Entries;
        if (entries.Count == 0 && !options.SpaMode)
            throw new InvalidOperationException(
                "No network traffic captured. Browse first or set spaMode: true.");

        var mapper = new AttackSurfaceMapper();
        var result = mapper.Analyze(
            entries.Count == 0 ? [] : entries.ToList(),
            options.IncludeParameters,
            options.IncludeAuth,
            options.IncludeResponsePatterns,
            options.HostFilter,
            options.IncludeDataUrls);

        result.NetworkLogEmpty = entries.Count == 0;
        var navUrl = await ctx.GetCurrentUrl().ConfigureAwait(false);

        if (options.SpaMode)
        {
            var interactive = await ctx.GetInteractiveElements().ConfigureAwait(false);
            var formCount = await ctx.GetHtmlFormCountAsync().ConfigureAwait(false);
            var pageTitle = await ctx.GetTitle().ConfigureAwait(false);
            result.SpaRuntime = AttackSurfaceMapper.BuildSpaRuntimeSurface(
                interactive, formCount, navUrl, pageTitle);
            result.Source = result.NetworkLogEmpty ? "dom-only" : "network-log+dom";
        }
        else
        {
            result.Source = "network-log";
        }

        if (options.IncludeApiEnrichment)
        {
            await AttackSurfaceEnrichment.RunAsync(
                result,
                ctx,
                entries.Count == 0 ? [] : entries.ToList(),
                navUrl,
                new AttackSurfaceEnrichment.Options(
                    IncludeOpenApiFromNetwork: options.IncludeOpenApiFromNetwork,
                    IncludeOpenApiProbes: options.IncludeOpenApiProbes,
                    IncludeJsBundleHints: options.IncludeJsBundleHints,
                    IncludeDevArtifactProbes: options.IncludeDevArtifactProbes,
                    MaxProbeOrigins: Math.Clamp(options.MaxProbeOrigins, 1, 20),
                    MaxScripts: Math.Clamp(options.MaxJsScripts, 1, 80),
                    MaxBytesPerScript: Math.Clamp(options.MaxJsBundleBytesPerFile, 8192, 2_000_000),
                    MaxJsHintPaths: Math.Clamp(options.MaxJsHintPaths, 16, 2000),
                    HttpTimeoutMs: Math.Clamp(options.EnrichmentHttpTimeoutMs, 3_000, 60_000),
                    MaxWordPressRestRoutes: Math.Clamp(options.MaxWordPressRestRoutes, 64, 50_000)),
                ct).ConfigureAwait(false);

            if (result.Enrichment is { Enabled: true })
                result.Source += "+api-discovery";
        }

        if (options.CheckSecurityTxt)
        {
            result.SecurityTxt = await SecurityTxtProbe.CheckCurrentDocumentHostAsync(
                entries.Count == 0 ? [] : entries.ToList(),
                navUrl).ConfigureAwait(false);
        }

        return result;
    }
}
