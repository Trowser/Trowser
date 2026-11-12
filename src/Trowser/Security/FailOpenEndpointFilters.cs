using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Filters static assets and expected-public auth surfaces from fail-open probing.
/// </summary>
public static class FailOpenEndpointFilters
{
    private static readonly string[] StaticPathSegments =
    [
        "/resources/", "/static/", "/assets/", "/public/", "/dist/", "/build/",
        "/vendor/", "/node_modules/", "/fonts/", "/images/", "/img/", "/media/",
        "/css/", "/js/", "/scripts/", "/styles/", "/icons/", "/favicon"
    ];

    private static readonly string[] StaticFileExtensions =
    [
        ".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".wasm", ".txt", ".xml"
    ];

    private static readonly string[] AuthSurfacePathSegments =
    [
        "/login", "/signin", "/sign-in", "/signup", "/sign-up", "/register",
        "/registration", "/forgot-password", "/reset-password", "/password-reset",
        "/oauth/authorize", "/oauth2/authorize", "/auth/login", "/session/new"
    ];

    private static readonly HashSet<string> StaticResourceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Stylesheet", "Script", "Image", "Font", "Media", "Ping"
    };

    private static readonly Regex StaticFileNameRegex = new(
        @"\.(css|js|mjs|map|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|otf|wasm)(\?|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] PublicCatalogPathSegments =
    [
        "/languages", "/language", "/i18n", "/locale", "/locales",
        "/challenges", "/challenge",
        "/products/search", "/product/search",
        "/about", "/faq", "/help", "/privacy", "/terms",
        "/banners", "/advertisement", "/promotion", "/carousel",
    ];

    private static readonly string[] SensitiveProtectedPathSegments =
    [
        "/admin", "/configuration", "/config", "/settings",
        "/quantity", "/quantities", "/inventory", "/stock",
        "/order", "/orders", "/payment", "/wallet", "/balance",
        "/account", "/accounts", "/customer", "/customers", "/profile", "/management", "/internal", "/private",
        "/audit", "/secret", "/debug", "/actuator",
    ];

    private static readonly Regex PublicProductListRegex = new(
        @"/products/?$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PublicSearchRegex = new(
        @"/search/?$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsStaticAsset(string url, string? contentType = null, string? resourceType = null)
    {
        if (!string.IsNullOrEmpty(resourceType) && StaticResourceTypes.Contains(resourceType))
        {
            if (!resourceType.Equals("Other", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (!string.IsNullOrEmpty(contentType))
        {
            var ct = contentType.Split(';')[0].Trim().ToLowerInvariant();
            if (ct is "text/css" or "application/javascript" or "text/javascript" or "application/x-javascript")
                return true;
            if (ct.StartsWith("image/", StringComparison.Ordinal) || ct.StartsWith("font/", StringComparison.Ordinal))
                return true;
            if (ct is "application/font-woff" or "application/font-woff2" or "application/wasm")
                return true;
            if (ct is "text/plain" && LooksLikeStaticPath(url))
                return true;
        }

        return LooksLikeStaticPath(url);
    }

    public static bool IsAuthSurface(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return AuthSurfacePathSegments.Any(s => url.Contains(s, StringComparison.OrdinalIgnoreCase));

        var path = uri.AbsolutePath.TrimEnd('/');
        if (path.Length == 0) return false;

        foreach (var segment in AuthSurfacePathSegments)
        {
            if (path.Equals(segment, StringComparison.OrdinalIgnoreCase)) return true;
            if (path.EndsWith(segment, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    public static bool ShouldSkipProbe(string url, string? contentType = null, string? resourceType = null) =>
        IsStaticAsset(url, contentType, resourceType);

    public static string ClassifyUnauthenticatedSeverity(string method) =>
        method is "POST" or "PUT" or "PATCH" or "DELETE" ? "critical" : "medium";

    public static string ClassifyInvalidTokenSeverity(string method) =>
        method is "POST" or "PUT" or "PATCH" or "DELETE" ? "high" : "medium";

    public static bool IsHomepage(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        return uri.AbsolutePath.TrimEnd('/').Length == 0;
    }

    /// <summary>
    /// Catalog, UX, and marketing endpoints that are commonly public without authentication.
    /// </summary>
    public static bool IsLikelyPublicByDesign(string url, string method)
    {
        if (method != "GET") return false;
        if (IsHomepage(url)) return true;

        var path = GetPathLower(url);
        if (path.Contains("/admin", StringComparison.Ordinal)) return false;

        if (PublicCatalogPathSegments.Any(s => path.Contains(s, StringComparison.Ordinal))) return true;
        if (PublicProductListRegex.IsMatch(path)) return true;
        if (PublicSearchRegex.IsMatch(path) && !path.Contains("/admin", StringComparison.Ordinal)) return true;

        return false;
    }

    public static bool IsLikelySensitiveProtectedPath(string url)
    {
        var path = GetPathLower(url);
        if (path.Contains("/admin", StringComparison.Ordinal)) return true;
        return SensitiveProtectedPathSegments.Any(s => path.Contains(s, StringComparison.Ordinal));
    }

    /// <summary>
    /// Skip unauthenticated fail-open when the endpoint is public-by-design, or a GET with no
    /// Authorization in traffic and no sensitive path signal (catalog vs protected data).
    /// </summary>
    public static bool ShouldSkipUnauthenticatedFailOpen(string url, string method, bool hadAuthorizationHeader) =>
        IsLikelyPublicByDesign(url, method)
        || (method == "GET" && !hadAuthorizationHeader && !IsLikelySensitiveProtectedPath(url));

    private static string GetPathLower(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.ToLowerInvariant();
        return uri.AbsolutePath.ToLowerInvariant();
    }

    private static bool LooksLikeStaticPath(string url)
    {
        if (StaticFileNameRegex.IsMatch(url)) return true;

        var lower = url.ToLowerInvariant();
        return StaticPathSegments.Any(s => lower.Contains(s, StringComparison.Ordinal));
    }

    public static NetworkEntry? FindNetworkEntry(AutomationContext ctx, string url, string? method = null)
    {
        for (var i = ctx.Network.Entries.Count - 1; i >= 0; i--)
        {
            var e = ctx.Network.Entries[i];
            if (!string.Equals(e.Url, url, StringComparison.OrdinalIgnoreCase)) continue;
            if (method != null && !string.Equals(e.Method, method, StringComparison.OrdinalIgnoreCase)) continue;
            return e;
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var targetUri)) return null;
        for (var i = ctx.Network.Entries.Count - 1; i >= 0; i--)
        {
            var e = ctx.Network.Entries[i];
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var entryUri)) continue;
            if (!string.Equals(entryUri.AbsolutePath, targetUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                continue;
            if (method != null && !string.Equals(e.Method, method, StringComparison.OrdinalIgnoreCase)) continue;
            return e;
        }

        return null;
    }
}
