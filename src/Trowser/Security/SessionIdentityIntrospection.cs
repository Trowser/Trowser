using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Live session identity introspection shared by REST and MCP.
/// </summary>
public static class SessionIdentityIntrospection
{
    private static readonly HashSet<string> TokenKeyPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "token", "jwt", "access_token", "id_token", "auth_token", "refresh_token",
        "authtoken", "accesstoken", "idtoken", "refreshtoken", "bearer",
        "authorization", "auth", "session_token", "api_key", "apikey"
    };

    private static readonly HashSet<string> AuthHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "X-Api-Key", "X-Auth-Token", "X-Access-Token", "Proxy-Authorization"
    };

    public static async Task<object> BuildLivePayloadAsync(AutomationContext context, string? sessionName)
    {
        var cookies = await context.GetCookies();
        var currentUrl = await context.GetCurrentUrl();

        string? domain = null;
        if (Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
            domain = uri.Host;

        var mechanismInfo = InferMechanismFromCookies(cookies);
        var jwtCookies = CollectJwtCookies(cookies);

        var cookieMap = new Dictionary<string, string>();
        foreach (var c in cookies)
        {
            var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            var value = c.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
            if (!string.IsNullOrEmpty(name))
                cookieMap[name] = RedactPreview(value);
        }

        var inferredTokens = new List<object>();
        var sawStorageJwt = false;
        string? storageLocation = null;
        try
        {
            foreach (var storageType in new[] { "local", "session" })
            {
                var items = await context.GetAllStorage(storageType);
                foreach (var (key, value) in items)
                {
                    if (string.IsNullOrEmpty(value)) continue;
                    var tokenType = ClassifyStorageToken(key, value);
                    if (tokenType == null) continue;

                    var where = storageType == "local" ? "localStorage" : "sessionStorage";
                    if (tokenType == "jwt")
                    {
                        sawStorageJwt = true;
                        storageLocation ??= where;
                    }
                    else
                    {
                        storageLocation ??= where;
                    }

                    inferredTokens.Add(new
                    {
                        storage = where,
                        key,
                        type = tokenType,
                        preview = RedactPreview(value)
                    });
                }
            }
        }
        catch { /* storage access may fail on about:blank or restricted pages */ }

        if (sawStorageJwt || (mechanismInfo.Mechanism == null && inferredTokens.Count > 0))
            mechanismInfo = WithStorageToken(mechanismInfo);

        return new
        {
            sessionName,
            domain,
            currentUrl,
            cookieCount = cookies.Count,
            cookies = cookieMap,
            jwtCookies = jwtCookies.Count > 0 ? jwtCookies : null,
            inferredTokens = inferredTokens.Count > 0 ? inferredTokens : null,
            inferredIdentity = mechanismInfo.Mechanism != null ? new
            {
                mechanism = mechanismInfo.Mechanism,
                sessionCookie = mechanismInfo.SessionCookie,
                storage = sawStorageJwt ? storageLocation : null,
                domain
            } : null
        };
    }

    /// <summary>
    /// A JWT in localStorage or sessionStorage is the API authenticator for most SPAs, even when
    /// a framework cookie such as <c>connect.sid</c> is also present. The cookie name is kept.
    /// </summary>
    public static MechanismInfo WithStorageToken(MechanismInfo fromCookies) =>
        fromCookies with { Mechanism = "storage-token" };

    /// <summary>
    /// Infer auth mechanism from cookies. Prefers JWT-shaped values over opaque
    /// cookies whose names merely contain "token" (e.g. DataCamp <c>authentication_token</c>
    /// vs Keycloak <c>_dct</c>).
    /// </summary>
    public static MechanismInfo InferMechanismFromCookies(IReadOnlyList<Dictionary<string, object>> cookies)
    {
        string? mechanism = null;
        string? sessionCookie = null;

        // Framework session cookies are unambiguous — keep ahead of JWT heuristics.
        foreach (var cookie in cookies)
        {
            var name = cookie.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            var nameLower = name.ToLowerInvariant();

            if (nameLower.StartsWith("_shibsession"))
                return new MechanismInfo("shibboleth", name);
            if (nameLower is "jsessionid")
                return new MechanismInfo("java-session", name);
            if (nameLower is ".aspnetcore.cookies" or ".aspnet.applicationcookie" or "asp.net_sessionid")
                return new MechanismInfo("aspnet", name);
        }

        var jwtCookies = CollectJwtCookieDetails(cookies);
        if (jwtCookies.Count > 0)
        {
            var best = jwtCookies.OrderByDescending(ScoreJwtCookie).First();
            return new MechanismInfo("jwt-cookie", best.Name);
        }

        foreach (var cookie in cookies)
        {
            var name = cookie.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            var value = cookie.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
            var nameLower = name.ToLowerInvariant();

            if (nameLower.Contains("oauth") || nameLower.Contains("access_token"))
                return new MechanismInfo("oauth", name);

            // Name-only "jwt"/"token" is unreliable (CSRF tokens, opaque session tokens).
            // Only use it when the value is JWT-shaped (already handled above) or when
            // nothing better exists and the name is specifically jwt-ish — not bare "token".
            if (nameLower.Contains("jwt") && !LooksLikeJwt(value))
            {
                mechanism ??= "session-cookie";
                sessionCookie ??= name;
                continue;
            }

            if (nameLower.Contains("session") || nameLower.Contains("sid"))
            {
                mechanism ??= "session-cookie";
                sessionCookie ??= name;
            }
        }

        return new MechanismInfo(mechanism, sessionCookie);
    }

    public static List<object> CollectJwtCookies(IReadOnlyList<Dictionary<string, object>> cookies) =>
        CollectJwtCookieDetails(cookies)
            .OrderByDescending(ScoreJwtCookie)
            .Select(j => (object)new
            {
                name = j.Name,
                alg = j.Alg,
                exp = j.Exp,
                iss = j.Iss,
                preview = RedactPreview(j.Value, keep: 8)
            })
            .ToList();

    public static string? ClassifyStorageToken(string key, string value)
    {
        var keyLower = key.ToLowerInvariant();
        if (LooksLikeJwt(value))
            return "jwt";
        if (TokenKeyPatterns.Contains(key))
            return "bearer-token";
        if (keyLower.Contains("token") || keyLower.Contains("jwt") ||
            keyLower.Contains("auth") || keyLower.Contains("bearer") ||
            keyLower.Contains("access_token") || keyLower.Contains("id_token"))
        {
            if (value.Length >= 20)
                return "bearer-token";
        }

        return null;
    }

    public static List<IdentityAuthHeader> ExtractAuthHeadersFromNetwork(
        IEnumerable<Automation.NetworkEntry> entries,
        string? originHost,
        int maxAgeMinutes = 30)
    {
        if (string.IsNullOrEmpty(originHost))
            return [];

        var cutoff = DateTime.UtcNow.AddMinutes(-maxAgeMinutes);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<IdentityAuthHeader>();

        foreach (var entry in entries.OrderByDescending(e => e.Timestamp))
        {
            if (entry.Timestamp < cutoff) break;
            if (!string.Equals(entry.Host, originHost, StringComparison.OrdinalIgnoreCase))
                continue;

            // Prefer response headers (login APIs often return Authorization / tokens only in the response),
            // then fall back to request headers from subsequent authenticated calls.
            CollectAuthHeaders(entry.ResponseHeaders, entry, seen, result);
            CollectAuthHeaders(entry.RequestHeaders, entry, seen, result);

            // Some apps return Bearer tokens in custom response headers only.
            foreach (var (headerName, headerValue) in entry.ResponseHeaders)
            {
                if (string.IsNullOrWhiteSpace(headerValue)) continue;
                if (!LooksLikeBearerOrJwtHeader(headerName, headerValue)) continue;

                var dedupeKey = $"{headerName}|{headerValue}|{entry.Host}";
                if (!seen.Add(dedupeKey)) continue;

                result.Add(new IdentityAuthHeader
                {
                    Name = headerName,
                    Value = headerValue,
                    Host = entry.Host,
                    LastSeen = entry.Timestamp,
                    Url = entry.Url
                });
            }
        }

        return result;
    }

    private static void CollectAuthHeaders(
        IReadOnlyDictionary<string, string> headers,
        Automation.NetworkEntry entry,
        HashSet<string> seen,
        List<IdentityAuthHeader> result)
    {
        foreach (var (headerName, headerValue) in headers)
        {
            if (!AuthHeaderNames.Contains(headerName) || string.IsNullOrWhiteSpace(headerValue))
                continue;

            var dedupeKey = $"{headerName}|{headerValue}|{entry.Host}";
            if (!seen.Add(dedupeKey)) continue;

            result.Add(new IdentityAuthHeader
            {
                Name = headerName,
                Value = headerValue,
                Host = entry.Host,
                LastSeen = entry.Timestamp,
                Url = entry.Url
            });
        }
    }

    private static bool LooksLikeBearerOrJwtHeader(string headerName, string headerValue)
    {
        if (AuthHeaderNames.Contains(headerName)) return false;
        var v = headerValue.Trim();
        if (v.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return true;
        // Compact JWT in a token-ish header name.
        if (headerName.Contains("token", StringComparison.OrdinalIgnoreCase)
            || headerName.Contains("jwt", StringComparison.OrdinalIgnoreCase)
            || headerName.Contains("auth", StringComparison.OrdinalIgnoreCase))
        {
            return LooksLikeJwt(v);
        }

        return false;
    }

    public static string ComputeCookieFingerprint(IReadOnlyList<Dictionary<string, object>> cookies)
    {
        var parts = cookies
            .Select(c =>
            {
                var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                var value = c.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
                return $"{name}={value}";
            })
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();
        return string.Join(";", parts);
    }

    public static string RedactPreview(string value, int keep = 4)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.Length <= keep) return new string('*', value.Length);
        return value[..keep] + "...";
    }

    public static bool LooksLikeJwt(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var v = value.Trim();
        if (v.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            v = v["Bearer ".Length..].Trim();
        var parts = v.Split('.');
        return parts.Length == 3
               && parts[0].StartsWith("eyJ", StringComparison.Ordinal)
               && parts[0].Length > 10
               && parts[1].Length > 10;
    }

    private static List<JwtCookieDetail> CollectJwtCookieDetails(IReadOnlyList<Dictionary<string, object>> cookies)
    {
        var list = new List<JwtCookieDetail>();
        foreach (var cookie in cookies)
        {
            var name = cookie.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            var value = cookie.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "";
            if (string.IsNullOrEmpty(name) || !LooksLikeJwt(value)) continue;

            var (alg, exp, iss) = TryParseJwtClaims(value);
            list.Add(new JwtCookieDetail(name, value, alg, exp, iss));
        }
        return list;
    }

    /// <summary>
    /// Rank JWT cookies: prefer access-looking over refresh, asymmetric algs, and longer-lived
    /// access tokens when both look like access tokens.
    /// </summary>
    private static int ScoreJwtCookie(JwtCookieDetail jwt)
    {
        var score = 0;
        var nameLower = jwt.Name.ToLowerInvariant();

        if (nameLower.Contains("refresh")) score -= 50;
        if (nameLower.Contains("access") || nameLower is "_dct" or "dct" || nameLower.Contains("id_token")
            || nameLower.Contains("id-token"))
            score += 30;
        if (nameLower.Contains("auth") || nameLower.Contains("session") || nameLower.Contains("token"))
            score += 5;

        if (jwt.Alg != null)
        {
            if (jwt.Alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase)
                || jwt.Alg.StartsWith("ES", StringComparison.OrdinalIgnoreCase)
                || jwt.Alg.StartsWith("PS", StringComparison.OrdinalIgnoreCase))
                score += 20;
            else if (jwt.Alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
                score += 10;
        }

        if (jwt.Exp is long expUnix)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var remaining = expUnix - now;
            if (remaining > 0)
            {
                // Prefer still-valid tokens; mild preference for longer remaining life among access tokens.
                score += 15;
                if (remaining > 3600) score += 5;
                if (remaining > 86400) score += 5;
            }
            else
            {
                score -= 20; // expired
            }
        }

        // Mild length signal: real access JWTs are usually longer than tiny canaries.
        score += Math.Min(jwt.Value.Length / 100, 10);
        return score;
    }

    private static (string? Alg, long? Exp, string? Iss) TryParseJwtClaims(string token)
    {
        try
        {
            var parts = token.Trim().Split('.');
            if (parts.Length < 2) return (null, null, null);

            string? alg = null;
            long? exp = null;
            string? iss = null;

            try
            {
                var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
                using var h = JsonDocument.Parse(headerJson);
                if (h.RootElement.TryGetProperty("alg", out var algEl) && algEl.ValueKind == JsonValueKind.String)
                    alg = algEl.GetString();
            }
            catch { /* ignore */ }

            try
            {
                var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
                using var p = JsonDocument.Parse(payloadJson);
                if (p.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var expVal))
                    exp = expVal;
                if (p.RootElement.TryGetProperty("iss", out var issEl) && issEl.ValueKind == JsonValueKind.String)
                {
                    var raw = issEl.GetString();
                    if (!string.IsNullOrEmpty(raw))
                        iss = raw.Length > 80 ? raw[..80] + "…" : raw;
                }
            }
            catch { /* ignore */ }

            return (alg, exp, iss);
        }
        catch
        {
            return (null, null, null);
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public readonly record struct MechanismInfo(string? Mechanism, string? SessionCookie);

    private sealed record JwtCookieDetail(string Name, string Value, string? Alg, long? Exp, string? Iss);
}
