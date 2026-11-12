namespace Trowser.Security.Orchestration;

/// <summary>
/// Narrows attack-surface and auto-scan targets by <see cref="PlaybookScope.TargetUrl"/>,
/// include/exclude path globs, regexes, and optional logout denylist.
/// </summary>
public static class PlaybookScopeFilter
{
    public static AttackSurfaceResult Apply(AttackSurfaceResult surface, PlaybookScope scope)
    {
        var filtered = surface.Endpoints
            .Where(ep => EndpointInScope(ep, scope))
            .ToList();

        // Explicit targetUrl must remain probeable even when it is absent from captured traffic
        // (e.g. agent pins /api/spawn after browsing elsewhere). Prefer same-path traffic merge
        // so POST text/plain body/CT from /api/render is not dropped.
        if (filtered.Count == 0 && !string.IsNullOrWhiteSpace(scope.TargetUrl))
        {
            filtered.Add(ResolveTargetEndpoint(surface, scope.TargetUrl!, scope.TargetMethod));
        }

        if (filtered.Count == surface.Endpoints.Count
            && (surface.Endpoints.Count > 0 || string.IsNullOrWhiteSpace(scope.TargetUrl)))
            return surface;

        return new AttackSurfaceResult
        {
            Endpoints = filtered,
            Source = surface.Source,
            Summary = surface.Summary,
            SpaRuntime = surface.SpaRuntime,
            NetworkLogEmpty = surface.NetworkLogEmpty
        };
    }

    /// <summary>Build a minimal attack-surface endpoint from an explicit target URL.</summary>
    public static AttackSurfaceEndpoint SynthesizeEndpoint(string targetUrl, string? targetMethod = null)
    {
        var url = targetUrl.Trim();
        Uri.TryCreate(url, UriKind.Absolute, out var uri);
        var pathHint = uri?.AbsolutePath ?? url;
        var templateSink = InjectionParamClassifier.LooksLikeTemplateEndpoint(pathHint);

        // Template sinks (e.g. /api/render) are almost always POST body receivers — defaulting to
        // GET leaves injectableEndpoints=0 and starves a05b/SSTI under scope.targetUrl.
        var method = !string.IsNullOrWhiteSpace(targetMethod)
            ? targetMethod.Trim().ToUpperInvariant()
            : templateSink ? "POST" : "GET";

        var ep = new AttackSurfaceEndpoint
        {
            Url = url,
            UrlTemplate = url,
            Methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { method },
            TestPriority = "high",
            DiscoveredVia = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "targetUrl" }
        };

        if (uri != null && !string.IsNullOrEmpty(uri.Query))
        {
            foreach (var key in System.Web.HttpUtility.ParseQueryString(uri.Query).AllKeys)
            {
                if (!string.IsNullOrEmpty(key) && !ep.Parameters.Query.Contains(key))
                    ep.Parameters.Query.Add(key);
            }
        }

        if (templateSink)
        {
            ep.Parameters.RequestContentType = "text/plain";
            if (!ep.Parameters.Body.Contains("body", StringComparer.OrdinalIgnoreCase))
                ep.Parameters.Body.Add("body");
            ep.Parameters.RequestBodySample ??= "{{7*7}}";
        }

        return ep;
    }

    /// <summary>
    /// When <paramref name="targetUrl"/> is pinned, merge body/CT/headers from any same-path
    /// traffic endpoint before synthesizing an empty shell (preserves text/plain SSTI sinks).
    /// </summary>
    public static AttackSurfaceEndpoint ResolveTargetEndpoint(
        AttackSurfaceResult surface, string targetUrl, string? targetMethod = null)
    {
        AttackSurfaceEndpoint? best = null;
        foreach (var ep in surface.Endpoints)
        {
            if (!UrlsMatchPathOnly(ep.Url, targetUrl)) continue;
            if (!string.IsNullOrWhiteSpace(targetMethod)
                && !ep.Methods.Contains(targetMethod.Trim()))
                continue;
            best ??= ep;
            // Prefer the variant that already looks injectable.
            if (ep.Parameters.Body.Count > 0
                || ep.Parameters.Headers.Count > 0
                || !string.IsNullOrEmpty(ep.Parameters.RequestBodySample)
                || ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH"))
            {
                best = ep;
                break;
            }
        }

        if (best != null)
            return best;

        return SynthesizeEndpoint(targetUrl, targetMethod);
    }

    private static bool UrlsMatchPathOnly(string endpointUrl, string targetUrl)
    {
        if (!Uri.TryCreate(endpointUrl, UriKind.Absolute, out var a)
            || !Uri.TryCreate(targetUrl, UriKind.Absolute, out var b))
            return string.Equals(endpointUrl, targetUrl, StringComparison.OrdinalIgnoreCase);

        if (!string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase))
            return false;

        return string.Equals(NormalizePath(a.AbsolutePath), NormalizePath(b.AbsolutePath),
            StringComparison.OrdinalIgnoreCase);
    }

    public static bool EndpointInScope(AttackSurfaceEndpoint ep, PlaybookScope scope)
    {
        // Explicit targetUrl is an intentional pin — do not apply path/logout denylist on top.
        if (!string.IsNullOrWhiteSpace(scope.TargetUrl))
            return EndpointMatches(ep, scope.TargetUrl!, scope.TargetMethod);

        return PathInScope(ep.Url, scope);
    }

    public static bool PathInScope(string urlOrPath, PlaybookScope scope) =>
        SecurityPathExclusion.IsPathAllowed(
            urlOrPath,
            scope.IncludePaths,
            scope.ExcludePaths,
            scope.ExcludeUrlPatterns,
            scope.ExcludeLogout);

    public static bool EndpointMatches(AttackSurfaceEndpoint ep, string targetUrl, string? targetMethod)
    {
        if (!UrlsMatch(ep.Url, targetUrl))
            return false;

        if (string.IsNullOrWhiteSpace(targetMethod))
            return true;

        return ep.Methods.Contains(targetMethod.Trim());
    }

    public static bool UrlsMatch(string endpointUrl, string targetUrl)
    {
        if (!Uri.TryCreate(endpointUrl, UriKind.Absolute, out var a)
            || !Uri.TryCreate(targetUrl, UriKind.Absolute, out var b))
            return string.Equals(endpointUrl, targetUrl, StringComparison.OrdinalIgnoreCase);

        if (!string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase))
            return false;

        var pathA = NormalizePath(a.AbsolutePath);
        var pathB = NormalizePath(b.AbsolutePath);
        if (!string.Equals(pathA, pathB, StringComparison.OrdinalIgnoreCase))
            return false;

        return string.Equals(
            NormalizeQuery(a.Query),
            NormalizeQuery(b.Query),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path)
    {
        path = path.TrimEnd('/');
        return string.IsNullOrEmpty(path) ? "/" : path;
    }

    private static string NormalizeQuery(string? query)
    {
        if (string.IsNullOrEmpty(query)) return "";
        return query.TrimStart('?');
    }
}
