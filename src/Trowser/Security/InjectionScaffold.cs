using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Pre-browse injection URL templates (common entry points) used when captured traffic is sparse.
/// Inspired by OWASP WSTG common input surfaces; layout historically similar to pentest-ai ALWAYS_PROBED lists.
/// Scaffold URLs are candidates only — callers own detection oracles.
/// </summary>
public static class InjectionScaffold
{
    public const int DefaultSparseThreshold = 3;

    /// <summary>URL path templates with <c>{marker}</c> placeholder for injection value.</summary>
    public sealed class ScaffoldTemplate
    {
        public string PathQueryTemplate { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Kind { get; init; } = "sqli";
    }

    /// <summary>Deduplicated scaffold entries for smart routing (one pass per path×param).</summary>
    public sealed class UnifiedScaffoldEntry
    {
        public string PathQueryTemplate { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Method { get; init; } = "GET";
        public InjectionParamKind ParamKind { get; init; }
    }

    public static readonly string[] DefaultLoginPaths =
    [
        "/login",
        "/api/login",
        "/auth/login",
        "/api/auth/login",
        "/signin",
        "/api/signin",
        "/sessions",
        "/users/sign_in",
        "/rest/user/login",
        "/api/users/login"
    ];

    public static readonly string[] SqliAlwaysProbed =
    [
        "/rest/products/search?q={marker}",
        "/rest/products/search?query={marker}",
        "/api/products/search?q={marker}",
        "/api/products?query={marker}",
        "/api/products?q={marker}",
        "/search?q={marker}",
        "/search?query={marker}",
        "/api/users?email={marker}",
        "/api/Users?email={marker}",
        "/api/search?q={marker}",
        "/api/search?query={marker}",
        "/api/lookup?q={marker}",
        "/api/find?q={marker}",
        "/api/spawn?command={marker}",
        "/api/file?path={marker}"
    ];

    public static readonly string[] NosqlAlwaysProbed =
    [
        "/api/login?email={marker}",
        "/api/auth/login?email={marker}",
        "/rest/user/login?email={marker}",
        "/api/users?email={marker}",
        "/api/Users?email={marker}",
        "/api/users/find?email={marker}",
        "/api/account?id={marker}"
    ];

    public static readonly string[] NosqlQueryOperatorProbes =
    [
        "email[$ne]=null",
        "email[$gt]=",
        "email[$regex]=.*",
        "username[$ne]=null",
        "id[$ne]=null"
    ];

    public static readonly string[] SstiAlwaysProbed =
    [
        "/search?q={marker}",
        "/api/search?q={marker}",
        "/rest/track-order/{marker}",
        "/render?template={marker}",
        "/api/render?template={marker}",
        "/preview?data={marker}",
        "/api/feedback?comment={marker}",
        "/?name={marker}"
    ];

    public static readonly string[] XssAlwaysProbed =
    [
        "/rest/products/search?q={marker}",
        "/rest/products/search?query={marker}",
        "/search?q={marker}",
        "/search?query={marker}",
        "/api/search?q={marker}",
        "/api/search?query={marker}",
        "/api/feedback?comment={marker}",
        "/?q={marker}",
        "/?name={marker}",
        "/api/Users?q={marker}"
    ];

    public static bool ShouldUseScaffold(int apiLikeEndpointCount, int sparseThreshold = DefaultSparseThreshold) =>
        apiLikeEndpointCount < sparseThreshold;

    public static int CountApiLikeNetworkEntries(IReadOnlyList<NetworkEntry> entries, string? origin = null)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (origin != null && !string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var method = (entry.Method ?? "GET").ToUpperInvariant();
            var looksApi = uri.AbsolutePath.Contains("/api", StringComparison.OrdinalIgnoreCase)
                           || uri.AbsolutePath.Contains("/rest", StringComparison.OrdinalIgnoreCase)
                           || method is "POST" or "PUT" or "PATCH" or "DELETE"
                           || !string.IsNullOrEmpty(uri.Query);
            if (!looksApi) continue;

            seen.Add($"{method}|{uri.GetLeftPart(UriPartial.Path)}");
        }

        return seen.Count;
    }

    /// <summary>Directory prefix of the current page (e.g. /potion-shop for project-site SPAs).</summary>
    public static string InferAppBasePath(string? pageUrl)
    {
        if (string.IsNullOrWhiteSpace(pageUrl)
            || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("http" or "https"))
            return "";

        var path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path) || path == "/")
            return "";

        if (path.EndsWith(".html", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".htm", StringComparison.OrdinalIgnoreCase))
        {
            var slash = path.LastIndexOf('/');
            path = slash > 0 ? path[..slash] : "";
        }
        else
        {
            path = path.TrimEnd('/');
        }

        return path.Length > 0 ? path : "";
    }

    public static string ApplyAppBasePrefix(string appBasePath, string pathQueryTemplate)
    {
        if (string.IsNullOrEmpty(appBasePath)
            || !pathQueryTemplate.StartsWith('/'))
            return pathQueryTemplate;

        var baseNorm = appBasePath.TrimEnd('/');
        if (pathQueryTemplate.StartsWith(baseNorm + "/", StringComparison.OrdinalIgnoreCase)
            || pathQueryTemplate.Equals(baseNorm, StringComparison.OrdinalIgnoreCase))
            return pathQueryTemplate;

        return baseNorm + pathQueryTemplate;
    }

    public static string BuildUrl(string origin, string pathQueryTemplate, string markerValue, string? appBasePath = null)
    {
        var templated = pathQueryTemplate.Replace("{marker}", markerValue, StringComparison.Ordinal);
        if (!string.IsNullOrEmpty(appBasePath))
            templated = ApplyAppBasePrefix(appBasePath, templated);

        if (templated.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || templated.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return templated;

        var baseOrigin = origin.TrimEnd('/');
        return templated.StartsWith('/') ? baseOrigin + templated : baseOrigin + "/" + templated;
    }

    public static IEnumerable<ScaffoldTemplate> EnumerateSqliScaffold() =>
        SqliAlwaysProbed.Select(t => new ScaffoldTemplate
        {
            PathQueryTemplate = t,
            ParamName = ExtractPrimaryParam(t),
            Method = "GET",
            Kind = "sqli"
        });

    public static IEnumerable<ScaffoldTemplate> EnumerateXssScaffold() =>
        XssAlwaysProbed.Select(t => new ScaffoldTemplate
        {
            PathQueryTemplate = t,
            ParamName = ExtractPrimaryParam(t),
            Method = "GET",
            Kind = "xss"
        });

    public static IEnumerable<ScaffoldTemplate> EnumerateNosqlScaffold()
    {
        foreach (var t in NosqlAlwaysProbed)
        {
            yield return new ScaffoldTemplate
            {
                PathQueryTemplate = t,
                ParamName = ExtractPrimaryParam(t),
                Method = "GET",
                Kind = "nosql"
            };
        }

        foreach (var op in NosqlQueryOperatorProbes)
        {
            yield return new ScaffoldTemplate
            {
                PathQueryTemplate = "/api/login?" + op,
                ParamName = op.Split('=')[0],
                Method = "GET",
                Kind = "nosql"
            };
            yield return new ScaffoldTemplate
            {
                PathQueryTemplate = "/rest/user/login?" + op,
                ParamName = op.Split('=')[0],
                Method = "GET",
                Kind = "nosql"
            };
        }
    }

    public static IEnumerable<ScaffoldTemplate> EnumerateSstiScaffold() =>
        SstiAlwaysProbed.Select(t => new ScaffoldTemplate
        {
            PathQueryTemplate = t,
            ParamName = ExtractPrimaryParam(t),
            Method = "GET",
            Kind = "ssti"
        });

    /// <summary>
    /// Merges SQLi/XSS/SSTI/NoSQL ALWAYS_PROBED templates into unique path×param entries
    /// with semantic classification for routed scanner execution.
    /// </summary>
    public static IEnumerable<UnifiedScaffoldEntry> EnumerateUnifiedScaffold(int cap = 0)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;

        foreach (var template in SqliAlwaysProbed
                     .Concat(XssAlwaysProbed)
                     .Concat(SstiAlwaysProbed)
                     .Concat(NosqlAlwaysProbed))
        {
            var param = ExtractPrimaryParam(template);
            var pathKey = template.Split('?', '#')[0];
            var key = $"{pathKey}|{param}";
            if (!seen.Add(key))
                continue;

            yield return new UnifiedScaffoldEntry
            {
                PathQueryTemplate = template,
                ParamName = param,
                Method = "GET",
                ParamKind = InjectionParamClassifier.Classify(param, pathKey)
            };

            count++;
            if (cap > 0 && count >= cap)
                yield break;
        }
    }

    public static IEnumerable<string> EnumerateLoginUrls(string origin, IEnumerable<string>? extraPaths = null)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in (extraPaths ?? []).Concat(DefaultLoginPaths))
        {
            var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? path
                : origin.TrimEnd('/') + (path.StartsWith('/') ? path : "/" + path);
            if (seen.Add(url))
                yield return url;
        }
    }

    private static string ExtractPrimaryParam(string template)
    {
        // Path-segment markers like /rest/track-order/{marker}
        if (template.Contains("/{marker}", StringComparison.Ordinal)
            || template.EndsWith("{marker}", StringComparison.Ordinal))
            return "path";

        var q = template.IndexOf('?', StringComparison.Ordinal);
        if (q < 0) return "q";
        var query = template[(q + 1)..];
        var eq = query.IndexOf('=');
        if (eq <= 0) return query.Split('&')[0];
        return Uri.UnescapeDataString(query[..eq]);
    }
}
