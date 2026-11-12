using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

public static class ApiInventoryPayload
{
    public static object Serialize(ApiInventoryAnalyzer.InventoryResult inv) => new
    {
        isClean = inv.IsClean,
        summary = new
        {
            inv.Summary.DocumentedCount,
            inv.Summary.ShadowCount,
            inv.Summary.ZombieCandidateCount,
            inv.Summary.ParallelVersionClusters,
            inv.Summary.AuthGatedCount,
            inv.Summary.OpenApiPathCount,
            inv.Summary.ObservedPathCount
        },
        specVsObserved = inv.SpecVsObserved.Select(e => new
        {
            pathKey = e.PathKey,
            sampleUrl = e.SampleUrl,
            tag = e.Tag,
            discoveredVia = e.DiscoveredVia,
            methods = e.Methods,
            inOpenApiSpec = e.InOpenApiSpec,
            inLiveTraffic = e.InLiveTraffic,
            inJsHints = e.InJsHints,
            requestCount = e.RequestCount,
            authType = e.AuthType
        }).ToList(),
        versionClusters = inv.VersionClusters.Select(c => new
        {
            basePath = c.BasePath,
            versions = c.Versions,
            examplePaths = c.ExamplePaths,
            parallelActive = c.ParallelActive,
            severity = c.Severity,
            note = c.Note
        }).ToList(),
        authDelta = inv.AuthDelta.Select(a => new
        {
            url = a.Url,
            anonymousStatus = a.AnonymousStatus,
            authenticatedStatus = a.AuthenticatedStatus,
            outcome = a.Outcome,
            detail = a.Detail
        }).ToList()
    };

    public static List<ChainableFinding> ToChainFindings(ApiInventoryAnalyzer.InventoryResult inv, string? pageUrl)
    {
        var findings = new List<ChainableFinding>();
        foreach (var shadow in inv.SpecVsObserved.Where(e => e.Tag == "shadow").Take(12))
        {
            findings.Add(new ChainableFinding
            {
                Id = $"shadow-api-{shadow.PathKey.GetHashCode():x8}",
                Category = "shadow-api",
                Severity = ClassifyShadowApiSeverity(shadow),
                Title = $"Shadow API: {shadow.PathKey}",
                Detail =
                    $"Path observed in traffic/JS ({string.Join(", ", shadow.DiscoveredVia)}) but not in OpenAPI/spec inventory.",
                Endpoint = shadow.SampleUrl,
                Source = "api-inventory"
            });
        }

        foreach (var zombie in inv.SpecVsObserved.Where(e => e.Tag == "zombie-candidate").Take(12))
        {
            findings.Add(new ChainableFinding
            {
                Id = $"zombie-api-{zombie.PathKey.GetHashCode():x8}",
                Category = "zombie-api",
                Severity = "high",
                Title = $"Zombie API candidate: {zombie.PathKey}",
                Detail = "Deprecated, debug, or parallel-version API path remains reachable.",
                Endpoint = zombie.SampleUrl,
                Source = "api-inventory"
            });
        }

        foreach (var gate in inv.AuthDelta.Where(a => a.Outcome == "session-only").Take(8))
        {
            findings.Add(new ChainableFinding
            {
                Id = $"auth-gated-api-{gate.Url.GetHashCode():x8}",
                Category = "auth-gated-api",
                Severity = "medium",
                Title = $"Session-only API: {gate.Url}",
                Detail = gate.Detail ?? "Endpoint requires browser session cookies.",
                Endpoint = gate.Url,
                Source = "api-inventory"
            });
        }

        return findings;
    }

    /// <summary>
    /// Shadow = undocumented vs OpenAPI. Severity reflects confirmed live API use, not wordlist noise.
    /// </summary>
    internal static string ClassifyShadowApiSeverity(ApiInventoryAnalyzer.SpecVsObservedEntry shadow)
    {
        var hasMutating = shadow.Methods.Any(m => m is "POST" or "PUT" or "PATCH" or "DELETE");

        if (shadow.InLiveTraffic && shadow.RequestCount > 0)
            return hasMutating ? "medium" : "low";

        if (!shadow.InLiveTraffic)
            return "info";

        return hasMutating ? "high" : "medium";
    }

    public static async Task<ApiInventoryAnalyzer.InventoryResult> RunForSessionAsync(
        AutomationContext ctx,
        AttackSurfaceSessionBuilder.BuildOptions surfaceOptions,
        ApiInventoryAnalyzer.AnalyzeOptions inventoryOptions,
        CancellationToken ct = default)
    {
        var surface = await AttackSurfaceSessionBuilder.BuildAsync(ctx, surfaceOptions, ct);
        return await ApiInventoryAnalyzer.AnalyzeAsync(surface, ctx, inventoryOptions, ct);
    }
}
