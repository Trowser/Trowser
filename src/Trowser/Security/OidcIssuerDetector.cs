using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Finds an OIDC issuer in captured traffic. The login-UI host is not treated as the issuer.
/// </summary>
public static class OidcIssuerDetector
{
    /// <summary>Longer hints first so issuer-path cutting prefers the specific authorize segment.</summary>
    public static readonly string[] AuthorizePathHints =
    [
        "/protocol/openid-connect/auth",
        "/oauth2/v2.0/authorize",
        "/oauth2/authorize",
        "/oauth/authorize",
        "/connect/authorize",
        "/login/oauth/authorize",
        "/o/oauth2/v2/auth",
        "/authorize"
    ];

    public static bool IsAuthorizeUrl(string url) =>
        url.Contains("client_id=", StringComparison.OrdinalIgnoreCase)
        && AuthorizePathHints.Any(h => url.Contains(h, StringComparison.OrdinalIgnoreCase));

    public static string? TryDetect(IEnumerable<NetworkEntry> entries, IReadOnlyList<OidcSessionAnalyzer.CookieInfo>? cookies = null)
    {
        foreach (var entry in entries)
        {
            var fromDiscovery = IssuerFromDiscoveryUrl(entry.Url);
            if (fromDiscovery != null) return fromDiscovery;
        }

        foreach (var entry in entries)
        {
            if (TryGetHeader(entry.RequestHeaders, "Authorization", out var auth)
                && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var iss = IssuerFromJwt(auth["Bearer ".Length..]);
                if (iss != null) return iss;
            }
        }

        if (cookies != null)
        {
            foreach (var cookie in cookies)
            {
                if (!string.IsNullOrEmpty(cookie.JwtIssuer))
                    return cookie.JwtIssuer.TrimEnd('/');
            }
        }

        foreach (var entry in entries)
        {
            if (IsStaticUrl(entry.Url)) continue;
            var fromBody = IssuerFromBody(entry.ResponseBody) ?? IssuerFromBody(entry.RequestBody);
            if (fromBody != null) return fromBody;
        }

        foreach (var entry in entries)
        {
            if (!IsAuthorizeUrl(entry.Url)) continue;
            var fromAuthorize = IssuerFromAuthorizeUrl(entry.Url);
            if (fromAuthorize != null) return fromAuthorize;
        }

        foreach (var entry in entries)
        {
            if (!TryGetHeader(entry.RequestHeaders, "Referer", out var referer)) continue;
            if (!IsAuthorizeUrl(referer)) continue;
            var fromReferer = IssuerFromAuthorizeUrl(referer);
            if (fromReferer != null) return fromReferer;
        }

        return null;
    }

    public static string? IssuerFromDiscoveryUrl(string url)
    {
        if (!url.Contains("openid-configuration", StringComparison.OrdinalIgnoreCase)
            && !url.Contains("oauth-authorization-server", StringComparison.OrdinalIgnoreCase))
            return null;
        var idx = url.IndexOf("/.well-known/", StringComparison.OrdinalIgnoreCase);
        if (idx <= 0) return null;
        return url[..idx].TrimEnd('/');
    }

    public static string? IssuerFromAuthorizeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        var path = uri.AbsolutePath;
        foreach (var hint in AuthorizePathHints)
        {
            var idx = path.IndexOf(hint, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            var prefix = path[..idx].TrimEnd('/');
            return $"{uri.Scheme}://{uri.Authority}{prefix}";
        }
        return null;
    }

    public static string? IssuerFromJwt(string token)
    {
        var iss = ReadJwtClaim(token, "iss");
        if (string.IsNullOrEmpty(iss) || !iss.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return null;
        if (iss.Contains("/claim/", StringComparison.OrdinalIgnoreCase))
            return null;
        return iss.TrimEnd('/');
    }

    public static string? IssuerFromBody(string? body)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 150_000) return null;
        if (LooksLikeStaticAsset(body)) return null;

        var fromJwt = IssuerFromEmbeddedJwts(body);
        if (fromJwt != null) return fromJwt;

        if (!body.Contains("\"iss\"", StringComparison.OrdinalIgnoreCase)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            string? found = null;
            var nodes = 0;
            Walk(doc.RootElement, 0, ref nodes, (name, value) =>
            {
                if (found != null) return;
                if (!name.Equals("iss", StringComparison.OrdinalIgnoreCase)) return;
                if (value.ValueKind != JsonValueKind.String) return;
                var candidate = value.GetString();
                if (string.IsNullOrEmpty(candidate)) return;
                if (!candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return;
                if (candidate.Contains("/claim/", StringComparison.OrdinalIgnoreCase)) return;
                found = candidate.TrimEnd('/');
            });
            return found;
        }
        catch
        {
            return null;
        }
    }

    public static string? ReadJwtClaim(string token, string claim)
    {
        try
        {
            var parts = token.Trim().Split('.');
            if (parts.Length < 2) return null;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }
            var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
            if (!doc.RootElement.TryGetProperty(claim, out var val)) return null;
            if (val.ValueKind == JsonValueKind.String) return val.GetString();
            if (val.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in val.EnumerateArray())
                    if (el.ValueKind == JsonValueKind.String) return el.GetString();
            }
        }
        catch
        {
            /* not a JWT payload */
        }
        return null;
    }

    public static bool TryGetHeader(IReadOnlyDictionary<string, string> headers, string name, out string value)
    {
        if (headers.TryGetValue(name, out value!)) return true;
        foreach (var pair in headers)
        {
            if (!pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            value = pair.Value;
            return true;
        }
        value = "";
        return false;
    }

    private static string? IssuerFromEmbeddedJwts(string body)
    {
        var start = 0;
        var found = 0;
        while (found < 6 && start < body.Length)
        {
            var idx = body.IndexOf("eyJ", start, StringComparison.Ordinal);
            if (idx < 0) return null;
            var end = idx;
            while (end < body.Length && IsJwtChar(body[end])) end++;
            var token = body[idx..end];
            if (token.Count(c => c == '.') >= 2)
            {
                var iss = IssuerFromJwt(token);
                if (iss != null) return iss;
                found++;
            }
            start = Math.Max(end, idx + 3);
        }
        return null;
    }

    private static bool IsStaticUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var path = uri.AbsolutePath;
        return path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".map", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/assets/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/fonts/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsJwtChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.';

    private static bool LooksLikeStaticAsset(string body) =>
        body.Length > 2000 && !body.TrimStart().StartsWith('{') && !body.TrimStart().StartsWith('[');

    private static void Walk(JsonElement el, int depth, ref int nodes, Action<string, JsonElement> onProperty)
    {
        if (depth > 8 || nodes > 4000) return;
        nodes++;
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    onProperty(prop.Name, prop.Value);
                    Walk(prop.Value, depth + 1, ref nodes, onProperty);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    Walk(item, depth + 1, ref nodes, onProperty);
                break;
        }
    }
}
