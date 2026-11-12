using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Extracts npm package names (and versions when available) from JS bundles and source maps.
/// </summary>
public static class BundleDependencyExtractor
{
    private static readonly Regex NodeModulesPath = new(
        @"node_modules/((?:@[\w.-]+/[\w.-]+)|(?:[\w.-]+))(?:/|\\|$)",
        RegexOptions.Compiled);

    private static readonly Regex LicenseBanner = new(
        @"@license\s+((?:@[\w.-]+/)?[\w.-]+)\s+v(?:ersion)?\.?\s*([\d][\w.\-+]*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex PackageVersionPair = new(
        @"""((?:@[\w.-]+/)?[\w.-]+)""\s*:\s*""([\d][^""]*)""",
        RegexOptions.Compiled);

    public sealed class BundleDependencyResult
    {
        public int ScriptsScanned { get; init; }
        public int SourceMapsScanned { get; init; }
        public List<DeclaredDependency> Dependencies { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    public static List<DeclaredDependency> ExtractFromText(string content, string sourceFile)
    {
        var map = new Dictionary<string, DeclaredDependency>(StringComparer.OrdinalIgnoreCase);

        foreach (Match m in NodeModulesPath.Matches(content))
        {
            var name = m.Groups[1].Value.Trim();
            if (name.Length == 0 || IsNoisePackage(name)) continue;
            TryAdd(map, name, "", sourceFile);
        }

        foreach (Match m in LicenseBanner.Matches(content))
            TryAdd(map, m.Groups[1].Value.Trim(), m.Groups[2].Value.Trim(), sourceFile);

        foreach (Match m in PackageVersionPair.Matches(content))
        {
            var name = m.Groups[1].Value.Trim();
            if (IsNoisePackage(name)) continue;
            TryAdd(map, name, m.Groups[2].Value.Trim(), sourceFile);
        }

        return map.Values.ToList();
    }

    public static async Task<BundleDependencyResult> RunAsync(
        AutomationContext ctx,
        int maxScripts = 24,
        int maxBytesPerFile = 524_288,
        bool includeSourceMaps = true,
        int timeoutMs = 20_000,
        CancellationToken ct = default)
    {
        maxScripts = Math.Clamp(maxScripts, 1, 80);
        maxBytesPerFile = Math.Clamp(maxBytesPerFile, 8_192, 2_000_000);

        var listJson = await ctx.ExecuteJs(
            """
            (function(){
              var list = [];
              var seen = Object.create(null);
              try {
                document.querySelectorAll('script[src]').forEach(function(s) {
                  try {
                    var u = new URL(s.getAttribute('src'), location.href).href;
                    if (!seen[u]) { seen[u] = true; list.push(u); }
                  } catch(e) {}
                });
              } catch(e) {}
              try {
                var resources = performance.getEntriesByType('resource');
                for (var i = 0; i < resources.length; i++) {
                  if (resources[i].initiatorType === 'script' && !seen[resources[i].name]) {
                    seen[resources[i].name] = true;
                    list.push(resources[i].name);
                  }
                }
              } catch(e) {}
              return JSON.stringify({ scripts: list });
            })()
            """);
        ct.ThrowIfCancellationRequested();

        List<string> scriptUrls;
        using (var doc = JsonDocument.Parse(listJson))
        {
            scriptUrls = doc.RootElement.GetProperty("scripts").EnumerateArray()
                .Select(x => x.GetString() ?? "")
                .Where(s => s.Length > 0 && s.Contains(".js", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(maxScripts)
                .ToList();
        }

        var summary = new List<string>();
        var depMap = new Dictionary<string, DeclaredDependency>(StringComparer.OrdinalIgnoreCase);
        var mapsScanned = 0;

        if (scriptUrls.Count == 0)
        {
            summary.Add("No external script[src] assets found for bundle dependency extraction.");
            return new BundleDependencyResult { Summary = summary };
        }

        foreach (var url in scriptUrls)
        {
            ct.ThrowIfCancellationRequested();
            var body = await FetchTextAsync(ctx, url, maxBytesPerFile, timeoutMs, ct);
            if (body == null) continue;

            foreach (var dep in ExtractFromText(body, url))
                MergeDep(depMap, dep);

            if (includeSourceMaps)
            {
                var mapUrl = ResolveSourceMapUrl(url, body);
                if (mapUrl == null) continue;

                var mapBody = await FetchTextAsync(ctx, mapUrl, maxBytesPerFile, timeoutMs, ct);
                if (mapBody == null) continue;
                mapsScanned++;

                foreach (var dep in ExtractFromSourceMap(mapBody, mapUrl))
                    MergeDep(depMap, dep);
            }
        }

        var deps = depMap.Values.OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList();
        if (deps.Count > 0)
            summary.Add($"Bundle fingerprint: {deps.Count} npm package(s) from {scriptUrls.Count} script(s)" +
                        (mapsScanned > 0 ? $" and {mapsScanned} source map(s)." : "."));

        return new BundleDependencyResult
        {
            ScriptsScanned = scriptUrls.Count,
            SourceMapsScanned = mapsScanned,
            Dependencies = deps,
            Summary = summary
        };
    }

    private static List<DeclaredDependency> ExtractFromSourceMap(string mapJson, string sourceFile)
    {
        try
        {
            using var doc = JsonDocument.Parse(mapJson);
            if (!doc.RootElement.TryGetProperty("sources", out var sources) || sources.ValueKind != JsonValueKind.Array)
                return [];

            var combined = string.Join('\n', sources.EnumerateArray()
                .Select(s => s.GetString() ?? "")
                .Where(s => s.Contains("node_modules", StringComparison.OrdinalIgnoreCase)));

            return ExtractFromText(combined, sourceFile);
        }
        catch
        {
            return [];
        }
    }

    private static string? ResolveSourceMapUrl(string scriptUrl, string scriptBody)
    {
        var m = Regex.Match(scriptBody, @"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", RegexOptions.IgnoreCase);
        if (!m.Success) return scriptUrl + ".map";

        var refUrl = m.Groups[1].Value.Trim().Trim('"', '\'');
        if (refUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) return null;

        try
        {
            return new Uri(new Uri(scriptUrl), refUrl).AbsoluteUri;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string?> FetchTextAsync(
        AutomationContext ctx, string url, int maxBytes, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var fetch = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, timeoutMs, true, ct);
            if (fetch.Status != 200 || string.IsNullOrEmpty(fetch.Body)) return null;
            if (fetch.Body.Length > maxBytes)
                return fetch.Body[..maxBytes];
            return fetch.Body;
        }
        catch
        {
            return null;
        }
    }

    private static void TryAdd(Dictionary<string, DeclaredDependency> map, string name, string version, string sourceFile)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        MergeDep(map, new DeclaredDependency
        {
            Name = name,
            Version = version,
            Ecosystem = "npm",
            SourceFile = sourceFile
        });
    }

    private static void MergeDep(Dictionary<string, DeclaredDependency> map, DeclaredDependency dep)
    {
        if (map.TryGetValue(dep.Name, out var existing))
        {
            if (string.IsNullOrWhiteSpace(existing.Version) && !string.IsNullOrWhiteSpace(dep.Version))
            {
                map[dep.Name] = new DeclaredDependency
                {
                    Name = dep.Name,
                    Version = dep.Version,
                    Ecosystem = dep.Ecosystem,
                    SourceFile = existing.SourceFile
                };
            }
            return;
        }

        map[dep.Name] = dep;
    }

    private static bool IsNoisePackage(string name) =>
        name is "node_modules" or "src" or "dist" or "lib" or "es" or "cjs" or "mjs"
        || name.StartsWith(".", StringComparison.Ordinal);
}
