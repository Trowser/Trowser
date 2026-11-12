using Trowser.Automation;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Helpers for playbook runs scoped to a single endpoint (<see cref="PlaybookScope.TargetUrl"/>).
/// </summary>
public static class EndpointScopeHelper
{
    public static bool IsEndpointScoped(PlaybookScope scope) =>
        !string.IsNullOrWhiteSpace(scope.TargetUrl);

    public static int CapEndpoints(PlaybookScope scope, int value) =>
        IsEndpointScoped(scope) ? 1 : value;

    /// <summary>
    /// Endpoint cap for probe-heavy scanners (injection, IDOR, SSRF). Site-wide runs default to
    /// 1–2 highest-priority endpoints unless <paramref name="depth"/> is <see cref="PlaybookDepth.Deep"/>.
    /// Set <see cref="PlaybookScope.TargetUrl"/> to scan one explicit endpoint.
    /// </summary>
    public static int CapProbeEndpoints(PlaybookScope scope, PlaybookDepthProfile depth) =>
        IsEndpointScoped(scope) ? 1 : depth.Depth switch
        {
            PlaybookDepth.Quick => 1,
            PlaybookDepth.Llm => 1,
            PlaybookDepth.Deep => depth.MaxEndpointsPerScanner,
            _ => 2
        };

    /// <summary>
    /// Open-redirect / SSRF redirect candidates need a higher floor than generic probe caps —
    /// at <see cref="PlaybookDepth.Llm"/> a cap of 1 starves <c>/api/goto?url=</c> scaffolds
    /// behind alphabetically-earlier redirect-like params.
    /// </summary>
    public static int CapRedirectCandidates(PlaybookScope scope, PlaybookDepthProfile depth) =>
        IsEndpointScoped(scope) ? Math.Max(3, CapProbeEndpoints(scope, depth)) : depth.Depth switch
        {
            PlaybookDepth.Quick => 4,
            PlaybookDepth.Llm => 8,
            PlaybookDepth.Deep => Math.Max(12, depth.MaxEndpointsPerScanner),
            _ => 12
        };

    public static bool IsProbeHeavyPlaybook(string playbookId) =>
        playbookId.Equals("a05-injection", StringComparison.OrdinalIgnoreCase)
        || playbookId.StartsWith("a05a-", StringComparison.OrdinalIgnoreCase)
        || playbookId.StartsWith("a05b-", StringComparison.OrdinalIgnoreCase)
        || playbookId.StartsWith("a05c-", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("a01-access", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("a06-design", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("a11-ssrf", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("a12-availability", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("a14-other", StringComparison.OrdinalIgnoreCase)
        || playbookId.Equals("full", StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<string>? ScopedUrlList(PlaybookScope scope, IReadOnlyList<string>? fallback = null)
    {
        if (IsEndpointScoped(scope))
            return [scope.TargetUrl!.Trim()];

        if (fallback == null)
            return null;

        return fallback.Where(u => PlaybookScopeFilter.PathInScope(u, scope)).ToList();
    }

    public static List<string> PostWriteUrls(AttackSurfaceResult surface, PlaybookScope scope)
    {
        var urls = surface.Endpoints
            .Where(ep => ep.Methods.Any(m =>
                m.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
                m.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
                m.Equals("PATCH", StringComparison.OrdinalIgnoreCase)))
            .Select(ep => ep.Url)
            .Where(u => PlaybookScopeFilter.PathInScope(u, scope))
            .ToList();

        if (!IsEndpointScoped(scope))
            return urls;

        return urls
            .Where(u => PlaybookScopeFilter.UrlsMatch(u, scope.TargetUrl!))
            .Take(1)
            .ToList();
    }

    public static void ApplyToAutoScan(
        AutoScanPipeline.AutoScanOptions options,
        PlaybookScope scope,
        AttackSurfaceResult? surface = null)
    {
        if (surface != null)
            options.PreDiscoveredSurface = surface;

        if (!IsEndpointScoped(scope))
            return;

        options.TargetUrl = scope.TargetUrl;
        options.TargetMethod = scope.TargetMethod;
        options.MaxEndpointsPerScanner = Math.Min(options.MaxEndpointsPerScanner, 1);
        options.IncludeApiEnrichment = false;
        // Endpoint Probe pins one URL — do not fall back to generic REST scaffold paths on the origin.
        options.AllowGenericScaffold = false;
        options.IncludeXssDom = false;
        options.IncludeSqliLoginSweep = false;
        options.IncludePassiveNetworkRecall = false;
    }

    public static string? SiteWideSkipReason(PlaybookScope scope, string stepName) =>
        IsEndpointScoped(scope) ? $"{stepName} is site-wide — skipped for endpoint-scoped run" : null;

    public static IEnumerable<NetworkEntry> FilterNetworkEntries(
        IEnumerable<NetworkEntry> entries,
        PlaybookScope scope)
    {
        if (IsEndpointScoped(scope))
        {
            return entries.Where(e =>
                PlaybookScopeFilter.UrlsMatch(e.Url, scope.TargetUrl!)
                && (string.IsNullOrWhiteSpace(scope.TargetMethod)
                    || e.Method.Equals(scope.TargetMethod, StringComparison.OrdinalIgnoreCase)));
        }

        return entries.Where(e => PlaybookScopeFilter.PathInScope(e.Url, scope));
    }
}
