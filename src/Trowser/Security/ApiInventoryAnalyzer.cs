using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Compares OpenAPI/spec paths with live traffic and JS hints — shadow/zombie API inventory.
/// </summary>
public static class ApiInventoryAnalyzer
{
    private static readonly HashSet<string> OpenApiViaTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "openapi-json", "openapi-yaml", "wordpress-rest"
    };

    private static readonly HashSet<string> ObservedViaTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "network-log", "js-bundle", "dev-artifact-probe"
    };

    private static readonly Regex VersionSegment = new(
        @"(?i)(?<![a-z0-9])/(?:api/)?v(\d+)(?:/|$)",
        RegexOptions.Compiled,
        matchTimeout: TimeSpan.FromSeconds(1));

    private static readonly string[] ZombiePathTokens =
    [
        "/debug", "/__debug__", "/_debug", "/legacy", "/deprecated", "/old/",
        "/internal/", "/_internal", "/console", "/actuator/", "/staging/",
        "/beta/", "/test/", "/dev/"
    ];

    public sealed class AnalyzeOptions
    {
        public bool IncludeAuthDeltaProbes { get; set; }
        public int MaxAuthDeltaProbes { get; set; } = 16;
        public int AuthDeltaTimeoutMs { get; set; } = 12_000;
    }

    public sealed class SpecVsObservedEntry
    {
        public string PathKey { get; init; } = "";
        public string? SampleUrl { get; init; }
        public string Tag { get; init; } = "";
        public List<string> DiscoveredVia { get; init; } = [];
        public List<string> Methods { get; init; } = [];
        public bool InOpenApiSpec { get; init; }
        public bool InLiveTraffic { get; init; }
        public bool InJsHints { get; init; }
        public int RequestCount { get; init; }
        public string? AuthType { get; init; }
    }

    public sealed class VersionCluster
    {
        public string BasePath { get; init; } = "";
        public List<string> Versions { get; init; } = [];
        public List<string> ExamplePaths { get; init; } = [];
        public bool ParallelActive { get; init; }
        public string Severity { get; init; } = "medium";
        public string? Note { get; init; }
    }

    public sealed class AuthDeltaEntry
    {
        public string Url { get; init; } = "";
        public int AnonymousStatus { get; init; }
        public int AuthenticatedStatus { get; init; }
        public string Outcome { get; init; } = "";
        public string? Detail { get; init; }
    }

    public sealed class InventorySummary
    {
        public int DocumentedCount { get; init; }
        public int ShadowCount { get; init; }
        public int ZombieCandidateCount { get; init; }
        public int ParallelVersionClusters { get; init; }
        public int AuthGatedCount { get; init; }
        public int OpenApiPathCount { get; init; }
        public int ObservedPathCount { get; init; }
    }

    public sealed class InventoryResult
    {
        public List<SpecVsObservedEntry> SpecVsObserved { get; init; } = [];
        public List<VersionCluster> VersionClusters { get; init; } = [];
        public List<AuthDeltaEntry> AuthDelta { get; init; } = [];
        public InventorySummary Summary { get; init; } = new();
        public bool IsClean =>
            Summary.ShadowCount == 0 && Summary.ZombieCandidateCount == 0 && Summary.ParallelVersionClusters == 0;
    }

    public static InventoryResult Analyze(AttackSurfaceResult surface, AnalyzeOptions? options = null)
    {
        options ??= new AnalyzeOptions();
        var pathIndex = BuildPathIndex(surface.Endpoints);
        var documentRoot = SpaShellGuard.FindDocumentRootEndpoint(surface.Endpoints);
        var scopeHost = ResolveScopeHost(surface.Endpoints, documentRoot);
        var versionClusters = BuildVersionClusters(pathIndex);
        var zombieKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var cluster in versionClusters.Where(c => c.ParallelActive))
        {
            foreach (var example in cluster.ExamplePaths)
            {
                var key = NormalizePathKey(example);
                if (!string.IsNullOrEmpty(key))
                    zombieKeys.Add(key);
            }
        }

        foreach (var key in pathIndex.Keys)
        {
            if (IsZombiePathKey(key))
                zombieKeys.Add(key);
        }

        var specVsObserved = new List<SpecVsObservedEntry>();
        foreach (var (pathKey, rows) in pathIndex.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            var inSpec = rows.Any(r => r.DiscoveredVia.Any(v => OpenApiViaTags.Contains(v)));
            var inTraffic = rows.Any(r => r.RequestCount > 0 ||
                                          r.DiscoveredVia.Contains("network-log", StringComparer.OrdinalIgnoreCase));
            var inJs = rows.Any(r => r.DiscoveredVia.Contains("js-bundle", StringComparer.OrdinalIgnoreCase));
            var inObserved = rows.Any(r => r.DiscoveredVia.Any(v => ObservedViaTags.Contains(v)) || inTraffic);

            var tag = ClassifyTag(inSpec, inObserved, zombieKeys.Contains(pathKey));
            if (tag == "shadow" && ShouldSuppressShadowInventory(pathKey, rows, documentRoot, scopeHost))
                tag = "spa-fallback";

            var sample = rows.FirstOrDefault()?.Url ?? rows.FirstOrDefault()?.UrlTemplate;
            var methods = rows.SelectMany(r => r.Methods).Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(m => m).ToList();
            var via = rows.SelectMany(r => r.DiscoveredVia).Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(v => v).ToList();
            var auth = rows.FirstOrDefault(r => r.Auth.Required)?.Auth.Type
                       ?? rows.FirstOrDefault()?.Auth.Type;

            specVsObserved.Add(new SpecVsObservedEntry
            {
                PathKey = pathKey,
                SampleUrl = sample,
                Tag = tag,
                DiscoveredVia = via,
                Methods = methods,
                InOpenApiSpec = inSpec,
                InLiveTraffic = inTraffic,
                InJsHints = inJs,
                RequestCount = rows.Sum(r => r.RequestCount),
                AuthType = auth
            });
        }

        var summary = new InventorySummary
        {
            DocumentedCount = specVsObserved.Count(e => e.Tag == "documented"),
            ShadowCount = specVsObserved.Count(e => e.Tag == "shadow"),
            ZombieCandidateCount = specVsObserved.Count(e => e.Tag == "zombie-candidate"),
            ParallelVersionClusters = versionClusters.Count(c => c.ParallelActive),
            OpenApiPathCount = specVsObserved.Count(e => e.InOpenApiSpec),
            ObservedPathCount = specVsObserved.Count(e => e.InLiveTraffic || e.InJsHints)
        };

        return new InventoryResult
        {
            SpecVsObserved = specVsObserved,
            VersionClusters = versionClusters,
            Summary = summary
        };
    }

    public static async Task<InventoryResult> AnalyzeAsync(
        AttackSurfaceResult surface,
        AutomationContext ctx,
        AnalyzeOptions? options = null,
        CancellationToken ct = default)
    {
        var result = Analyze(surface, options);
        options ??= new AnalyzeOptions();

        if (!options.IncludeAuthDeltaProbes)
            return result;

        var authDelta = await ProbeAuthDeltaAsync(surface, ctx, options, ct).ConfigureAwait(false);
        var summary = new InventorySummary
        {
            DocumentedCount = result.Summary.DocumentedCount,
            ShadowCount = result.Summary.ShadowCount,
            ZombieCandidateCount = result.Summary.ZombieCandidateCount,
            ParallelVersionClusters = result.Summary.ParallelVersionClusters,
            OpenApiPathCount = result.Summary.OpenApiPathCount,
            ObservedPathCount = result.Summary.ObservedPathCount,
            AuthGatedCount = authDelta.Count(e => e.Outcome == "session-only")
        };

        return new InventoryResult
        {
            SpecVsObserved = result.SpecVsObserved,
            VersionClusters = result.VersionClusters,
            AuthDelta = authDelta,
            Summary = summary
        };
    }

    private static string ClassifyTag(bool inSpec, bool inObserved, bool zombieCandidate)
    {
        if (zombieCandidate)
            return "zombie-candidate";
        if (inObserved && !inSpec)
            return "shadow";
        if (inSpec)
            return "documented";
        return inObserved ? "shadow" : "documented";
    }

    private sealed class PathRow
    {
        public string PathKey { get; init; } = "";
        public string Url { get; init; } = "";
        public string UrlTemplate { get; init; } = "";
        public HashSet<string> DiscoveredVia { get; init; } = [];
        public HashSet<string> Methods { get; init; } = [];
        public int RequestCount { get; init; }
        public AttackSurfaceAuth Auth { get; init; } = new();
        public bool HasSuccessResponse { get; init; }
        public AttackSurfaceEndpoint? Endpoint { get; init; }
    }

    private static Dictionary<string, List<PathRow>> BuildPathIndex(IEnumerable<AttackSurfaceEndpoint> endpoints)
    {
        var index = new Dictionary<string, List<PathRow>>(StringComparer.OrdinalIgnoreCase);

        foreach (var ep in endpoints)
        {
            var key = NormalizePathKey(!string.IsNullOrWhiteSpace(ep.UrlTemplate) ? ep.UrlTemplate : ep.Url);
            if (string.IsNullOrEmpty(key))
                continue;

            if (!index.TryGetValue(key, out var list))
            {
                list = [];
                index[key] = list;
            }

            list.Add(new PathRow
            {
                PathKey = key,
                Url = ep.Url,
                UrlTemplate = ep.UrlTemplate,
                DiscoveredVia = ep.DiscoveredVia,
                Methods = ep.Methods,
                RequestCount = ep.RequestCount,
                Auth = ep.Auth,
                HasSuccessResponse = ep.ResponsePatterns.Keys.Any(k =>
                    int.TryParse(k, out var code) && code is >= 200 and < 300),
                Endpoint = ep
            });
        }

        return index;
    }

    private static string? ResolveScopeHost(
        IEnumerable<AttackSurfaceEndpoint> endpoints, AttackSurfaceEndpoint? documentRoot)
    {
        if (documentRoot != null && Uri.TryCreate(documentRoot.Url, UriKind.Absolute, out var docUri))
            return docUri.Host;

        foreach (var ep in endpoints)
        {
            if (Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
                return uri.Host;
        }

        return null;
    }

    private static bool ShouldSuppressShadowInventory(
        string pathKey,
        List<PathRow> rows,
        AttackSurfaceEndpoint? documentRoot,
        string? scopeHost)
    {
        if (pathKey is "/" or "")
            return true;

        var sampleUrl = rows.FirstOrDefault(r => !string.IsNullOrWhiteSpace(r.Url))?.Url;
        if (SpaShellGuard.IsScannerProbeArtifact(sampleUrl))
            return true;

        if (rows.All(r => r.DiscoveredVia.Contains("dev-artifact-probe"))
            && Uri.TryCreate(sampleUrl, UriKind.Absolute, out var probeUri)
            && scopeHost != null
            && !string.Equals(probeUri.Host, scopeHost, StringComparison.OrdinalIgnoreCase))
            return true;

        // Wordlist/admin probes that never returned 2xx with API-shaped data are not shadow APIs.
        if (rows.All(r => !r.HasSuccessResponse))
            return true;

        var endpoint = rows.Select(r => r.Endpoint).FirstOrDefault(e => e != null);
        if (endpoint != null)
        {
            if (SpaShellGuard.IsAttackSurfaceSpaFallback(endpoint, documentRoot))
                return true;
            if (IsHtmlErrorProbeOnly(endpoint))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Probe-only endpoints whose responses are HTML error pages (404/403 Apache, etc.), not JSON APIs.
    /// </summary>
    private static bool IsHtmlErrorProbeOnly(AttackSurfaceEndpoint ep)
    {
        if (ep.ResponsePatterns.Count == 0)
            return false;
        if (SpaShellGuard.EndpointResponsesLookApiLike(ep))
            return false;

        return ep.ResponsePatterns.Values.All(p =>
            p.Description.Contains("HTML", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("401", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("403", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("404", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("405", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("error", StringComparison.OrdinalIgnoreCase)
            || p.Description.Contains("probe", StringComparison.OrdinalIgnoreCase));
    }

    private static List<VersionCluster> BuildVersionClusters(Dictionary<string, List<PathRow>> pathIndex)
    {
        var groups = new Dictionary<string, (HashSet<string> Versions, List<string> Examples, bool Active)>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var key in pathIndex.Keys)
        {
            var match = VersionSegment.Match(key);
            if (!match.Success)
                continue;

            var version = match.Groups[1].Value;
            var basePath = VersionSegment.Replace(key, "/").Replace("//", "/");
            if (string.IsNullOrWhiteSpace(basePath))
                basePath = "/";

            if (!groups.TryGetValue(basePath, out var g))
                g = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), [], false);

            g.Versions.Add($"v{version}");
            if (g.Examples.Count < 4)
                g.Examples.Add(key);

            var active = pathIndex[key].Any(r => r.HasSuccessResponse || r.RequestCount > 0);
            if (active)
                g = (g.Versions, g.Examples, g.Active || true);
            else
                g = (g.Versions, g.Examples, g.Active);

            groups[basePath] = g;
        }

        return groups
            .Where(kv => kv.Value.Versions.Count >= 1)
            .Select(kv =>
            {
                var parallel = kv.Value.Versions.Count >= 2 && kv.Value.Active;
                return new VersionCluster
                {
                    BasePath = kv.Key,
                    Versions = kv.Value.Versions.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList(),
                    ExamplePaths = kv.Value.Examples,
                    ParallelActive = parallel,
                    Severity = parallel ? "high" : "info",
                    Note = parallel
                        ? $"Multiple API versions active under {kv.Key}: {string.Join(", ", kv.Value.Versions)}."
                        : kv.Value.Versions.Count >= 2
                            ? "Multiple version paths discovered; not all show live 2xx traffic."
                            : null
                };
            })
            .OrderByDescending(c => c.ParallelActive)
            .ThenBy(c => c.BasePath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsZombiePathKey(string pathKey)
    {
        var lower = pathKey.ToLowerInvariant();
        return ZombiePathTokens.Any(t => lower.Contains(t, StringComparison.Ordinal));
    }

    private static async Task<List<AuthDeltaEntry>> ProbeAuthDeltaAsync(
        AttackSurfaceResult surface,
        AutomationContext ctx,
        AnalyzeOptions options,
        CancellationToken ct)
    {
        var candidates = surface.Endpoints
            .Where(ep => !IsStaticPath(ep.UrlTemplate) && !IsStaticPath(ep.Url))
            .OrderByDescending(ep => ep.TestPriority switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                _ => 1
            })
            .ThenByDescending(ep => ep.DiscoveredVia.Any(v =>
                v.Equals("js-bundle", StringComparison.OrdinalIgnoreCase) ||
                v.StartsWith("openapi", StringComparison.OrdinalIgnoreCase)))
            .Select(ep => ResolveProbeUrl(ep))
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Clamp(options.MaxAuthDeltaProbes, 1, 40))
            .ToList();

        var rows = new List<AuthDeltaEntry>();
        foreach (var url in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var anon = await SecurityProbeHttp.FetchAsync(
                ctx, url!, "GET", null, null, options.AuthDeltaTimeoutMs,
                includeBrowserCookies: false, ct);
            var authed = await SecurityProbeHttp.FetchAsync(
                ctx, url!, "GET", null, null, options.AuthDeltaTimeoutMs,
                includeBrowserCookies: true, ct);

            string outcome;
            string? detail;
            if (anon.Status is >= 200 and < 300)
            {
                outcome = "public";
                detail = $"Anonymous GET returned {anon.Status}.";
            }
            else if (authed.Status is >= 200 and < 300 &&
                     anon.Status is 401 or 403 or 404)
            {
                outcome = "session-only";
                detail = $"Anonymous {anon.Status} → session cookies {authed.Status}.";
            }
            else
            {
                outcome = "unchanged";
                detail = $"Anonymous {anon.Status} → session cookies {authed.Status}.";
            }

            if (outcome == "session-only")
            {
                rows.Add(new AuthDeltaEntry
                {
                    Url = url!,
                    AnonymousStatus = anon.Status,
                    AuthenticatedStatus = authed.Status,
                    Outcome = outcome,
                    Detail = detail
                });
            }
        }

        return rows;
    }

    private static string? ResolveProbeUrl(AttackSurfaceEndpoint ep)
    {
        if (!string.IsNullOrWhiteSpace(ep.Url) &&
            Uri.TryCreate(ep.Url, UriKind.Absolute, out _))
            return ep.Url;

        return null;
    }

    private static bool IsStaticPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        return lower.EndsWith(".js") || lower.EndsWith(".css") || lower.EndsWith(".png")
               || lower.EndsWith(".jpg") || lower.EndsWith(".svg") || lower.EndsWith(".woff2");
    }

    internal static string NormalizePathKey(string urlOrTemplate)
    {
        if (string.IsNullOrWhiteSpace(urlOrTemplate))
            return "";

        var path = urlOrTemplate;
        if (Uri.TryCreate(urlOrTemplate, UriKind.Absolute, out var uri))
            path = uri.AbsolutePath;

        if (!path.StartsWith('/'))
            path = "/" + path;

        path = path.Split('?', '#')[0];
        path = Regex.Replace(path, @"/\{[^/}]+\}", "/{param}", RegexOptions.IgnoreCase);
        path = Regex.Replace(path, @"/\d+(?=/)", "/{id}", RegexOptions.None, TimeSpan.FromSeconds(1));
        path = Regex.Replace(path, @"/\d+$", "/{id}", RegexOptions.None, TimeSpan.FromSeconds(1));

        if (path.Length > 1 && path.EndsWith('/'))
            path = path.TrimEnd('/');

        return path;
    }
}
