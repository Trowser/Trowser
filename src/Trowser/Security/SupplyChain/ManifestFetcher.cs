using System.IO;
using Trowser.Automation;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Fetches dependency manifest bodies from common leak paths.
/// </summary>
public static class ManifestFetcher
{
    public static readonly string[] DefaultManifestPaths =
    [
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/composer.json",
        "/composer.lock",
        "/requirements.txt",
        "/pyproject.toml",
        "/Gemfile",
        "/Gemfile.lock",
        "/pom.xml",
        "/ftp/package.json",
        "/ftp/package.json.bak",
        "/ftp/package.json.bak%2500.md",
        "/ftp/package-lock.json",
        "/ftp/package-lock.json.bak%2500.md",
    ];

    public static async Task<List<LeakedManifest>> FetchAsync(
        AutomationContext ctx,
        string pageUrl,
        IReadOnlyList<string>? extraPaths,
        bool includePathFilterBypass,
        int timeoutMs,
        bool includeBrowserCookies = true,
        CancellationToken ct = default)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before fetching manifests.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in DefaultManifestPaths) paths.Add(p);
        if (extraPaths != null)
            foreach (var p in extraPaths) paths.Add(p);

        var manifests = new List<LeakedManifest>();
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + (path.StartsWith('/') ? path : "/" + path);
            if (!seenUrls.Add(url)) continue;

            var fetch = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, timeoutMs, includeBrowserCookies, ct);
            if (fetch.Status != 200 || string.IsNullOrWhiteSpace(fetch.Body)) continue;
            if (!LooksLikeManifestBody(fetch.Body)) continue;

            var fileName = Path.GetFileName(path.Split('?')[0].Split('%')[0]);
            if (string.IsNullOrEmpty(fileName)) fileName = "manifest.json";
            var eco = ManifestParser.ResolveEcosystem(fileName) ?? "npm";
            var deps = ManifestParser.Parse(fetch.Body, fileName, eco);
            if (deps.Count == 0 && !fetch.Body.Contains("dependencies", StringComparison.OrdinalIgnoreCase))
                continue;

            manifests.Add(new LeakedManifest
            {
                Url = url,
                FileName = fileName,
                Ecosystem = eco,
                ByteLength = fetch.Body.Length,
                FetchMethod = path.Contains("%2500") ? "path-filter-bypass" : "direct",
                Dependencies = deps
            });
        }

        if (includePathFilterBypass)
        {
            var bypass = await PathFilterBypassChecker.RunAsync(ctx, new PathFilterBypassChecker.BypassOptions
            {
                PathBases = ["/ftp/"],
                TimeoutMs = timeoutMs
            }, ct);

            foreach (var finding in bypass.Findings.Where(f => f.Indicator == "manifest-leak"))
            {
                ct.ThrowIfCancellationRequested();
                if (!seenUrls.Add(finding.BypassUrl)) continue;

                var fetch = await SecurityProbeHttp.FetchAsync(
                    ctx, finding.BypassUrl, "GET", null, null, timeoutMs, includeBrowserCookies, ct);
                if (fetch.Status != 200 || string.IsNullOrWhiteSpace(fetch.Body)) continue;
                if (!LooksLikeManifestBody(fetch.Body)) continue;

                var fileName = ExtractFileNameFromBypass(finding.BypassUrl);
                var eco = ManifestParser.ResolveEcosystem(fileName) ?? "npm";
                var deps = ManifestParser.Parse(fetch.Body, fileName, eco);
                manifests.Add(new LeakedManifest
                {
                    Url = finding.BypassUrl,
                    FileName = fileName,
                    Ecosystem = eco,
                    ByteLength = fetch.Body.Length,
                    FetchMethod = "path-filter-bypass",
                    Dependencies = deps
                });
            }
        }

        return manifests;
    }

    public static async Task<int> ProbeManifestPathCountAsync(
        AutomationContext ctx, string pageUrl, int timeoutMs, bool includeBrowserCookies = true, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri)) return 0;
        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var count = 0;
        foreach (var path in DefaultManifestPaths.Take(8))
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + path;
            var fetch = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, timeoutMs, includeBrowserCookies, ct);
            if (fetch.Status == 200 && LooksLikeManifestBody(fetch.Body))
                count++;
        }
        return count;
    }

    private static bool LooksLikeManifestBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 8) return false;
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') && trimmed.Contains("dependencies", StringComparison.OrdinalIgnoreCase))
            return true;
        if (trimmed.StartsWith('{') && trimmed.Contains("require", StringComparison.OrdinalIgnoreCase))
            return true;
        if (body.Contains("==") && body.Split('\n').Any(l => l.Contains("==") && !l.TrimStart().StartsWith('#')))
            return true;
        return trimmed.StartsWith('{') && trimmed.Contains("\"name\"", StringComparison.Ordinal);
    }

    private static string ExtractFileNameFromBypass(string url)
    {
        try
        {
            var path = new Uri(url).AbsolutePath;
            var segment = path.Split('/').LastOrDefault(s => !string.IsNullOrEmpty(s)) ?? "package.json";
            var idx = segment.IndexOf("%2500", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0) segment = segment[..idx];
            return segment;
        }
        catch { return "package.json"; }
    }
}
