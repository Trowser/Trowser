using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>Picks candidate authenticated API URLs from session traffic for state generation.</summary>
internal static class ProtectedResourceOracle
{
    private static readonly string[] UnreliablePathFragments =
    [
        "socket.io",
        "/sockjs",
        "/websocket",
        "/ws/",
        "transport=polling",
        "transport=websocket",
        "/favicon",
        "/assets/",
        "/static/",
        ".js",
        ".css",
        ".woff",
        ".png",
        ".jpg",
        ".svg",
        ".ico",
        "google-analytics",
        "googletagmanager"
    ];

    private static readonly string[] PreferredPathFragments =
    [
        "/api/",
        "/rest/",
        "/graphql",
        "/v1/",
        "/v2/",
        "/user",
        "/account",
        "/basket",
        "/cart",
        "/whoami",
        "/me",
        "/profile",
        "/admin"
    ];

    public static string? SelectProtectedUrl(AutomationContext ctx, Uri pageUri)
    {
        var host = pageUri.Host;
        var candidates = ctx.Network.Entries
            .Where(e => e.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                        && Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                        && string.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase)
                        && !IsUnreliableProtectedOracle(e.Url))
            .OrderByDescending(ScoreUrl)
            .ThenByDescending(e => e.StatusCode is 200 or 401 or 403)
            .Take(40)
            .Select(e => e.Url)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return candidates.FirstOrDefault();
    }

    public static bool IsUnreliableProtectedOracle(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        var lower = url.ToLowerInvariant();
        foreach (var frag in UnreliablePathFragments)
        {
            if (lower.Contains(frag, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static int ScoreUrl(NetworkEntry e)
    {
        if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
            return 0;
        var path = u.AbsolutePath.ToLowerInvariant();
        var score = 0;
        foreach (var pref in PreferredPathFragments)
        {
            if (path.Contains(pref, StringComparison.Ordinal))
                score += 10;
        }
        if (u.Query.Length > 0)
            score += 2;
        if (e.StatusCode is 401 or 403)
            score += 5;
        return score;
    }
}
