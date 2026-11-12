using System.IO;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Lightweight assessment of whether captured network traffic is sufficient for security scans
/// (API/XHR/fetch and traditional form POST navigations).
/// </summary>
public static class SecurityPreflight
{
    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
        ".ttf", ".eot", ".map", ".webp", ".avif", ".mp4", ".webm", ".mp3", ".ogg"
    };
    public sealed class Assessment
    {
        public string Level { get; init; } = "ok";
        public bool NavigationOnly { get; init; }
        public int TotalEntries { get; init; }
        public int ApiLikeEntries { get; init; }
        public string? Message { get; init; }
        public string? Recommendation { get; init; }
    }

    private static readonly string[] ApiPathPrefixes =
    [
        "/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/"
    ];

    public static Assessment Assess(IReadOnlyList<NetworkEntry> entries)
    {
        if (entries.Count == 0)
        {
            return new Assessment
            {
                Level = "empty",
                TotalEntries = 0,
                Message = "No network traffic captured yet.",
                Recommendation =
                    "Browse the application (log in, search, add to cart) or run POST /api/security/crawl-light, " +
                    "then call attack-surface or auto-scan."
            };
        }

        var apiLike = entries.Count(IsLikelyApiTraffic);
        if (apiLike > 0)
        {
            return new Assessment
            {
                Level = "ok",
                TotalEntries = entries.Count,
                ApiLikeEntries = apiLike
            };
        }

        return new Assessment
        {
            Level = "navigation-only",
            NavigationOnly = true,
            TotalEntries = entries.Count,
            ApiLikeEntries = 0,
            Message =
                "No meaningful interaction traffic captured. The network log looks like page loads and static assets only.",
            Recommendation =
                "Log in, submit search/contact forms, add to cart, or use flows that trigger fetch/XHR — " +
                "then re-run attack-surface / auto-scan. Optional: POST /api/security/crawl-light to follow same-origin links first."
        };
    }

    public static bool IsLikelyApiTraffic(NetworkEntry e)
    {
        if (ScannerTrafficExclusion.ShouldExcludeFromAttackSurface(e))
            return false;

        if (IsStaticResource(e))
            return false;

        if (string.Equals(e.ResourceType, "XHR", StringComparison.OrdinalIgnoreCase)
            || string.Equals(e.ResourceType, "Fetch", StringComparison.OrdinalIgnoreCase))
            return true;

        if (e.Method is "POST" or "PUT" or "PATCH" or "DELETE")
        {
            if (!string.IsNullOrWhiteSpace(e.RequestBody))
                return true;

            var reqCt = GetHeader(e.RequestHeaders, "Content-Type");
            if (reqCt.Contains("json", StringComparison.OrdinalIgnoreCase)
                || reqCt.Contains("xml", StringComparison.OrdinalIgnoreCase)
                || reqCt.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)
                || reqCt.Contains("multipart/form-data", StringComparison.OrdinalIgnoreCase))
                return true;

            // Traditional HTML form POST navigations (Document) are attack surface even without a captured body.
            if (string.Equals(e.ResourceType, "Document", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var ct = e.ContentType;
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("+json", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("application/xml", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(e.ResponseBody)
            && (ct.Contains("json", StringComparison.OrdinalIgnoreCase)
                || ct.Contains("xml", StringComparison.OrdinalIgnoreCase)))
            return true;

        var path = e.Path;
        foreach (var prefix in ApiPathPrefixes)
        {
            if (path.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsStaticResource(NetworkEntry entry)
    {
        if (string.IsNullOrEmpty(entry.Url)) return true;
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) return false;

        var ext = Path.GetExtension(uri.AbsolutePath);
        if (!string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext))
            return true;

        return entry.ResourceType is "Image" or "Stylesheet" or "Font" or "Media" or "Script";
    }

    private static string GetHeader(IReadOnlyDictionary<string, string> headers, string name)
    {
        foreach (var kv in headers)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }

        return "";
    }
}
