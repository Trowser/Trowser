using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.Security;

/// <summary>
/// Selects high-confidence authenticated URLs for logout/session probes — never generic error pages.
/// </summary>
public static class ProtectedResourceOracle
{
    private static readonly string[] UnreliablePathTokens =
    [
        "/error", "/404", "/500", "/403", "/401", "/503",
        "notfound", "not-found", "page-not-found", "errorpage",
        "/health", "/ping", "/ready", "/live", "/status",
        "/favicon", "/robots.txt", "/sitemap"
    ];

    private static readonly string[] AuthFlowPathTokens =
    [
        "/login", "/signin", "/sign-in", "/logout", "/signout", "/sign-out",
        "/saml", "/oauth", "/oidc", "/auth/", "/callback", "/acs"
    ];

    private static readonly string[] ProtectedPathBoosters =
    [
        "/account", "/profile", "/dashboard", "/admin", "/user/",
        "/mina-", "/my-", "/me", "/whoami", "/bank/", "/basket",
        "/cart", "/checkout", "/orders", "/settings", "/wallet"
    ];

    public static bool IsUnreliableProtectedOracle(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return true;

        var path = Uri.TryCreate(url, UriKind.Absolute, out var u)
            ? u.AbsolutePath
            : url;

        var lower = path.ToLowerInvariant();
        return UnreliablePathTokens.Any(t => lower.Contains(t, StringComparison.Ordinal));
    }

    public static bool IsAuthFlowUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return true;

        var path = Uri.TryCreate(url, UriKind.Absolute, out var u)
            ? u.AbsolutePath
            : url;

        var lower = path.ToLowerInvariant();
        return AuthFlowPathTokens.Any(t => lower.Contains(t, StringComparison.Ordinal));
    }

    /// <summary>
    /// Best authenticated GET endpoint from attack surface + network log for session probes.
    /// </summary>
    public static string? SelectProtectedUrl(
        AutomationContext ctx,
        Uri pageUri,
        string? explicitUrl = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitUrl))
        {
            var resolved = explicitUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? explicitUrl
                : pageUri.GetLeftPart(UriPartial.Authority)
                  + (explicitUrl.StartsWith('/') ? explicitUrl : "/" + explicitUrl);
            return IsUnreliableProtectedOracle(resolved) || IsAuthFlowUrl(resolved) ? null : resolved;
        }

        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(ctx.Network.Entries.ToList(), includeAuth: true, hostFilter: pageUri.Host);
        surface = PlaybookScopeFilter.Apply(surface, new PlaybookScope { Host = pageUri.Host });

        var candidates = surface.Endpoints
            .Where(e => e.Methods.Contains("GET") || e.Methods.Contains("HEAD"))
            .Select(e => new OracleCandidate(e.Url, ScoreEndpoint(e)))
            .Where(c => c.Score > 0 && !IsUnreliableProtectedOracle(c.Url) && !IsAuthFlowUrl(c.Url))
            .OrderByDescending(c => c.Score)
            .ToList();

        if (candidates.Count > 0)
            return candidates[0].Url;

        foreach (var e in ctx.Network.Entries.OrderByDescending(x => x.Timestamp))
        {
            if (e.Method != "GET" || e.StatusCode is not (>= 200 and < 300))
                continue;
            var path = e.Url ?? "";
            if (!Uri.TryCreate(path, UriKind.Absolute, out var u)
                || !string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (IsUnreliableProtectedOracle(path) || IsAuthFlowUrl(path))
                continue;
            if (ProtectedPathBoosters.Any(b => u.AbsolutePath.Contains(b, StringComparison.OrdinalIgnoreCase)))
                return path;
        }

        if (!AuthProbeDiscovery.LooksLikePublicHomepage(pageUri)
            && !IsUnreliableProtectedOracle(pageUri.ToString())
            && !IsAuthFlowUrl(pageUri.ToString()))
            return pageUri.ToString();

        return AuthProbeDiscovery.DiscoverPaths(ctx, pageUri, AuthProbeDiscovery.ProtectedPathHints, path =>
                !IsUnreliableProtectedOracle(path) && !IsAuthFlowUrl(path), 4)
            .FirstOrDefault();
    }

    private static int ScoreEndpoint(AttackSurfaceEndpoint e)
    {
        var score = 0;
        if (e.Auth.Required) score += 50;
        if (e.TestPriority.Equals("critical", StringComparison.OrdinalIgnoreCase)) score += 40;
        if (e.TestPriority.Equals("high", StringComparison.OrdinalIgnoreCase)) score += 30;
        if (e.TestPriority.Equals("medium", StringComparison.OrdinalIgnoreCase)) score += 10;
        score += Math.Min(e.RequestCount, 10);

        var path = Uri.TryCreate(e.Url, UriKind.Absolute, out var u) ? u.AbsolutePath : e.Url;
        if (ProtectedPathBoosters.Any(b => path.Contains(b, StringComparison.OrdinalIgnoreCase)))
            score += 25;

        if (e.ResponsePatterns.Values.Any(p =>
                p.Description.Contains("HTML", StringComparison.OrdinalIgnoreCase)
                && p.BodySnippet != null
                && AuthAccessHeuristics.LooksLikeProtectedHtml(p.BodySnippet)))
            score += 20;

        return score;
    }

    private sealed record OracleCandidate(string Url, int Score);
}
