using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Correlates session cookie SameSite attributes with CSRF scenario severity.
/// </summary>
public static class CsrfSameSiteAnalyzer
{
    public sealed class SessionCookieRow
    {
        public string Name { get; init; } = "";
        public string SameSite { get; init; } = "";
        public bool Secure { get; init; }
        public bool HttpOnly { get; init; }
    }

    public sealed class SameSiteContext
    {
        public List<SessionCookieRow> SessionCookies { get; init; } = [];
        /// <summary>low | medium | high — likelihood cookies attach on cross-site forged requests.</summary>
        public string CrossSiteCookieRisk { get; init; } = "unknown";
        public string Summary { get; init; } = "";
    }

    private static readonly string[] SessionNameTokens =
    [
        "session", "sess", "sid", "token", "auth", "jwt", "jsessionid", "phpsessid",
        "connect.sid", "laravel_session", "asp.net_sessionid", "remember", "userid", "account"
    ];

    public static async Task<SameSiteContext> AnalyzeAsync(AutomationContext ctx, string? pageUrl)
    {
        var cookies = await ctx.GetCookies();
        var sessionRows = new List<SessionCookieRow>();

        foreach (var c in cookies)
        {
            var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            if (string.IsNullOrEmpty(name) || !LooksLikeSessionCookie(name))
                continue;

            var sameSite = c.TryGetValue("sameSite", out var ss) ? ss?.ToString()?.ToLowerInvariant() ?? "unspecified" : "unspecified";
            var secure = c.TryGetValue("secure", out var sec) && sec is true;
            var httpOnly = c.TryGetValue("httpOnly", out var ho) && ho is true;
            sessionRows.Add(new SessionCookieRow
            {
                Name = name,
                SameSite = sameSite,
                Secure = secure,
                HttpOnly = httpOnly
            });
        }

        if (sessionRows.Count == 0)
        {
            return new SameSiteContext
            {
                SessionCookies = sessionRows,
                CrossSiteCookieRisk = "unknown",
                Summary = "No session-like cookies observed in the browser jar — CSRF may still apply to header/token auth."
            };
        }

        var hasNone = sessionRows.Any(c =>
            c.SameSite.Equals("none", StringComparison.OrdinalIgnoreCase)
            || c.SameSite.Equals("no_restriction", StringComparison.OrdinalIgnoreCase));
        var allStrict = sessionRows.All(c =>
            c.SameSite.Equals("strict", StringComparison.OrdinalIgnoreCase));
        var allLaxOrStrict = sessionRows.All(c =>
        {
            var s = c.SameSite.ToLowerInvariant();
            return s is "strict" or "lax" or "unspecified";
        }) && !hasNone;

        string risk;
        string summary;
        if (hasNone)
        {
            risk = "high";
            summary = "Session cookie(s) use SameSite=None — cookies may be sent on cross-site requests (weaker CSRF defense).";
        }
        else if (allStrict)
        {
            risk = "low";
            summary = "All session cookies use SameSite=Strict — cross-site request cookie attachment is unlikely.";
        }
        else if (allLaxOrStrict)
        {
            risk = "medium";
            summary = "Session cookies use Lax/Strict (or unspecified) — GET-driven CSRF may still be possible; POST cross-site is often blocked.";
        }
        else
        {
            risk = "medium";
            summary = "Mixed SameSite attributes on session cookies — review per cookie.";
        }

        return new SameSiteContext
        {
            SessionCookies = sessionRows,
            CrossSiteCookieRisk = risk,
            Summary = summary
        };
    }

    /// <summary>Adjust CSRF scenario severity using SameSite context (does not clear vulnerable flag).</summary>
    public static string AdjustSeverity(string currentSeverity, SameSiteContext ctx, string method)
    {
        var rank = SeverityRank(currentSeverity);
        if (rank <= 0) return currentSeverity;

        var isGet = method.Equals("GET", StringComparison.OrdinalIgnoreCase);
        if (ctx.CrossSiteCookieRisk == "low" && !isGet)
            rank = Math.Max(1, rank - 1);
        else if (ctx.CrossSiteCookieRisk == "high")
            rank = Math.Min(4, rank + 1);

        return rank switch
        {
            4 => "critical",
            3 => "high",
            2 => "medium",
            1 => "low",
            _ => "info"
        };
    }

    /// <summary>
    /// Baseline severity for passive "no CSRF token observed" findings.
    /// Without cookie-session evidence, missing tokens are hygiene — not high-confidence CSRF.
    /// </summary>
    public static string DefaultNoTokenSeverity(SameSiteContext? ctx, string method, string testType)
    {
        var isGet = method.Equals("GET", StringComparison.OrdinalIgnoreCase);
        var isPassiveNoToken = testType.Equals("no-csrf-token", StringComparison.OrdinalIgnoreCase);

        if (!isPassiveNoToken)
            return isGet ? "medium" : "high";

        if (ctx == null || ctx.SessionCookies.Count == 0
            || ctx.CrossSiteCookieRisk is "unknown" or "low")
            return isGet ? "info" : "medium";

        if (ctx.CrossSiteCookieRisk == "high")
            return isGet ? "medium" : "high";

        return isGet ? "low" : "medium";
    }

    public static bool LooksLikeSessionCookie(string name)
    {
        var lower = name.ToLowerInvariant();
        foreach (var token in SessionNameTokens)
        {
            if (lower.Contains(token, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static int SeverityRank(string s) => s.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
