using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>Detect OAuth authorization-code / token material in strings (not CSRF param names).</summary>
public static class PostMessageOAuthShape
{
    private static readonly string[] OAuthKeys =
    [
        "access_token", "id_token", "refresh_token", "authorization_code"
    ];

    private static readonly Regex CodePair = new(
        @"(?<![\w-])code\s*[=:]\s*['""]?([a-zA-Z0-9._~/-]{8,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool LooksLikeOAuthSecret(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        foreach (var k in OAuthKeys)
        {
            if (text.Contains($"\"{k}\"", StringComparison.OrdinalIgnoreCase)
                || text.Contains($"'{k}'", StringComparison.OrdinalIgnoreCase)
                || text.Contains($"{k}=", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return CodePair.IsMatch(text);
    }

    public static bool SessionHasOAuthTraffic(Automation.AutomationContext ctx)
    {
        foreach (var e in ctx.Network.Entries)
        {
            if (e.Url.Contains("/authorize", StringComparison.OrdinalIgnoreCase)
                || e.Url.Contains("oauth", StringComparison.OrdinalIgnoreCase)
                || e.Url.Contains("access_token", StringComparison.OrdinalIgnoreCase)
                || (e.Url.Contains("code=", StringComparison.OrdinalIgnoreCase)
                    && e.Url.Contains("redirect", StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        return false;
    }
}
