using System.Security.Cryptography;
using System.Text;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Shared response heuristics for auth probes — login shells, protected pages, content types.</summary>
public static class AuthAccessHeuristics
{
    private static readonly string[] LoginPageNeedles =
    [
        "type=\"password\"", "type='password'", "name=\"password\"", "name='password'",
        "sign in", "log in", "login", "user name", "username", "please log", "authentication required",
        "invalid credentials", "enter your password"
    ];

    private static readonly string[] ProtectedHtmlNeedles =
    [
        "sign off", "sign out", "logout", "log out", "welcome", "dashboard", "account balance",
        "my account", "hello ", "logged in", "bank main", "transfer funds"
    ];

    public static string ResolveContentType(string? explicitType, string bodyTemplate)
    {
        if (!string.IsNullOrWhiteSpace(explicitType))
            return explicitType.Trim();

        var trimmed = bodyTemplate.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return "application/json";

        if (bodyTemplate.Contains('='))
            return "application/x-www-form-urlencoded";

        return "application/json";
    }

    public static string BuildFormLoginBodyTemplate(string userField, string passField) =>
        $"{userField}=§USER§&{passField}=§PASS§";

    public static string BuildJsonLoginBodyTemplate(string userField, string passField) =>
        $"{{\"{userField}\": \"§USER§\", \"{passField}\": \"§PASS§\"}}";

    public static string DefaultEmailForHost(Uri pageUri)
    {
        var host = pageUri.Host;
        if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            host = host[4..];
        return $"admin@{host}";
    }

    public static string DefaultUsernameForHost(Uri pageUri) => DefaultEmailForHost(pageUri);

    public static bool LooksLikeLoginPage(string? body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 20) return false;
        var lower = body.ToLowerInvariant();
        var hasPasswordField = lower.Contains("type=\"password\"", StringComparison.Ordinal)
                               || lower.Contains("type='password'", StringComparison.Ordinal)
                               || lower.Contains("name=\"passw", StringComparison.Ordinal)
                               || lower.Contains("name='passw", StringComparison.Ordinal);
        if (!hasPasswordField) return false;

        return LoginPageNeedles.Any(n => lower.Contains(n, StringComparison.Ordinal));
    }

    public static bool LooksLikeProtectedHtml(string? body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 30) return false;
        if (LooksLikeLoginPage(body)) return false;
        var lower = body.ToLowerInvariant();
        return ProtectedHtmlNeedles.Any(n => lower.Contains(n, StringComparison.Ordinal));
    }

    /// <summary>True when replay after logout looks like access was denied (login shell or loss of protected markers).</summary>
    public static bool LooksLikeDeniedAccess(string? postBody, string? preAuthBody)
    {
        if (LooksLikeLoginPage(postBody))
            return true;

        if (string.IsNullOrWhiteSpace(preAuthBody) || string.IsNullOrWhiteSpace(postBody))
            return false;

        if (LooksLikeProtectedHtml(preAuthBody) && !LooksLikeProtectedHtml(postBody))
            return true;

        var preHash = ShortBodyHash(preAuthBody);
        var postHash = ShortBodyHash(postBody);
        if (preHash != postHash && postBody.Length < preAuthBody.Length * 0.7
            && LooksLikeLoginPage(postBody))
            return true;

        return false;
    }

    /// <summary>True when response still exposes authenticated content (not a login redirect shell).</summary>
    public static bool LooksLikeGrantedAccess(string? postBody, string? preAuthBody)
    {
        if (string.IsNullOrWhiteSpace(postBody) || postBody.Length < 20) return false;
        if (LooksLikeLoginPage(postBody)) return false;
        if (LooksLikeProtectedHtml(postBody)) return true;

        if (!string.IsNullOrWhiteSpace(preAuthBody)
            && ShortBodyHash(postBody) == ShortBodyHash(preAuthBody)
            && preAuthBody.Length > 80)
            return true;

        return false;
    }

    /// <summary>True when the URL or body indicates a generic public error page — unreliable session oracle.</summary>
    public static bool LooksLikeGenericErrorPage(string? body, string? url)
    {
        if (!string.IsNullOrWhiteSpace(url))
        {
            var path = Uri.TryCreate(url, UriKind.Absolute, out var u)
                ? u.AbsolutePath
                : url;
            var lowerPath = path.ToLowerInvariant();
            if (lowerPath.Contains("/error", StringComparison.Ordinal)
                || lowerPath.Contains("/404", StringComparison.Ordinal)
                || lowerPath.Contains("/500", StringComparison.Ordinal)
                || lowerPath.Contains("notfound", StringComparison.Ordinal)
                || lowerPath.Contains("not-found", StringComparison.Ordinal))
                return true;

            if (Uri.TryCreate(url, UriKind.Absolute, out var full)
                && full.Query.Contains("aspxerrorpath=", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (string.IsNullOrWhiteSpace(body) || body.Length < 20)
            return false;

        var lower = body.ToLowerInvariant();
        if (lower.Contains("<title") && (
                lower.Contains("not found", StringComparison.Ordinal)
                || lower.Contains("page not found", StringComparison.Ordinal)
                || lower.Contains("404", StringComparison.Ordinal)
                || lower.Contains("error occurred", StringComparison.Ordinal)))
            return true;

        return false;
    }

    /// <summary>
    /// False when a captured 2xx state-changing response is a scanner probe, soft 404, or generic error shell —
    /// not evidence that a mutation endpoint exists.
    /// </summary>
    public static bool CapturedMutationLooksActionable(NetworkEntry entry)
    {
        if (ScannerTrafficExclusion.ShouldIgnoreNetworkHygiene(entry))
            return false;
        if (LooksLikeGenericErrorPage(entry.ResponseBody, entry.Url))
            return false;
        return true;
    }

    public static bool LooksSensitiveApiBody(string body, string urlTemplate)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 8) return false;
        var lower = body.ToLowerInvariant();
        if (lower.Contains("error") && lower.Contains("unauthorized")) return false;
        if (LooksLikeLoginPage(body)) return false;

        var trimmed = body.TrimStart();
        if (trimmed.StartsWith("<", StringComparison.Ordinal))
        {
            if (trimmed.StartsWith("<!doctype", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("<html", StringComparison.OrdinalIgnoreCase))
                return LooksLikeProtectedHtml(body);
            return false;
        }

        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            var needles = new[] { "\"email\"", "\"role\"", "\"userid\"", "\"username\"", "\"token\"", "\"data\"" };
            return needles.Any(n => lower.Contains(n, StringComparison.Ordinal));
        }

        if (urlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase)
            || urlTemplate.Contains("account", StringComparison.OrdinalIgnoreCase))
            return body.Length > 40 && !LooksLikeLoginPage(body);

        return body.Length > 40 && !LooksLikeLoginPage(body);
    }

    public static string ShortBodyHash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body ?? ""));
        return Convert.ToHexString(bytes)[..12];
    }
}
