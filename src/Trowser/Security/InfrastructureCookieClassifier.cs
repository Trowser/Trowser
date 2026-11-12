using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Load-balancer, CDN, and WAF stickiness cookies — intentionally non-HttpOnly and not auth credentials.
/// </summary>
public static class InfrastructureCookieClassifier
{
    private static readonly Regex F5TsCookie = new(
        @"^ts[0-9a-f]{6,}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    /// <summary>
    /// True when the cookie is infrastructure persistence (F5, ALB, CDN, WAF) — not a session/auth token.
    /// </summary>
    public static bool IsInfrastructureCookie(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        var lower = name.ToLowerInvariant();

        if (F5TsCookie.IsMatch(lower))
            return true;

        if (lower.StartsWith("bigipserver", StringComparison.Ordinal))
            return true;

        if (lower.StartsWith("awsalb", StringComparison.Ordinal)
            || lower.StartsWith("awselb", StringComparison.Ordinal)
            || lower.StartsWith("alb_", StringComparison.Ordinal))
            return true;

        if (lower.StartsWith("incap_ses", StringComparison.Ordinal)
            || lower.StartsWith("visid_incap", StringComparison.Ordinal)
            || lower.StartsWith("nlbi_", StringComparison.Ordinal))
            return true;

        if (lower.StartsWith("__cfduid", StringComparison.Ordinal)
            || lower.Equals("cf_clearance", StringComparison.Ordinal))
            return false; // analytics/WAF challenge — handled elsewhere

        if (lower.StartsWith("pingfed", StringComparison.Ordinal))
            return true;

        return false;
    }
}
