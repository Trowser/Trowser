namespace Trowser.Security;

/// <summary>
/// Shared session/auth cookie name heuristics for cookie audit and session-ID analysis.
/// </summary>
public static class SessionCookieDetector
{
    private static readonly string[] SessionCookiePatterns =
    [
        "session", "sess", "sid", "token", "auth", "jwt", "access",
        "refresh", "login", "jsessionid", "phpsessid", "asp.net_sessionid",
        "aspsessionid", "connect.sid", "laravel_session", "ci_session",
        "dvwasession", "_identity", "shibboleth", "saml"
    ];

    public static bool IsSessionCookieName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var lower = name.ToLowerInvariant();
        if (CookieAuditChecker.IsJsReadableByDesign(name) && !lower.Contains("token"))
            return false;
        return SessionCookiePatterns.Any(p => lower.Contains(p, StringComparison.Ordinal));
    }
}
