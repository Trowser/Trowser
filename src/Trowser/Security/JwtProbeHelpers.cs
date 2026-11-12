using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Shared JWT security probe utilities (acceptance sweep, variant sweep, header abuse).</summary>
internal static class JwtProbeHelpers
{
    internal sealed class AlgVariantDefinition
    {
        public string Name { get; init; } = "";
        public object? AlgValue { get; init; }
    }

    internal static readonly AlgVariantDefinition[] AlgVariants =
    [
        new() { Name = "None_capital_N", AlgValue = "None" },
        new() { Name = "NONE_uppercase", AlgValue = "NONE" },
        new() { Name = "none_with_whitespace", AlgValue = " none " },
        new() { Name = "none_with_newline", AlgValue = "\nnone\n" },
        new() { Name = "alg_as_array", AlgValue = new[] { "none" } },
        new() { Name = "alg_missing", AlgValue = null },
    ];

    internal static List<AttackSurfaceEndpoint> SelectCandidateEndpoints(
        AutomationContext ctx,
        string? host,
        int maxEndpoints,
        bool excludeThirdParty = true,
        string? scopeHost = null)
    {
        scopeHost ??= host;
        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(ctx.Network.Entries, includeAuth: true, hostFilter: host);
        return surface.Endpoints
            .Where(ep => ep.Methods.Contains("GET") || ep.Methods.Contains("HEAD"))
            .Where(ep => !excludeThirdParty
                || !SecurityHostScope.IsOutsideApplicationScope(TryGetHost(ep.Url), scopeHost))
            .Where(ep => !IsStaticAssetUrl(ep.Url))
            .Where(ep => !ep.ResponsePatterns.Values.Any(p => IsStaticAssetContentType(p.Description)))
            .Where(IsLikelyProtectedEndpoint)
            .OrderByDescending(ep => ep.TestPriority switch
            {
                "critical" => 4,
                "high" => 3,
                "medium" => 2,
                _ => 1
            })
            .Take(Math.Max(1, maxEndpoints))
            .ToList();
    }

    private static string? TryGetHost(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : null;

    /// <summary>
    /// Session cookies on public HTML pages are not evidence of protection — require 401/403, API shape, or bearer auth.
    /// </summary>
    internal static bool IsLikelyProtectedEndpoint(AttackSurfaceEndpoint ep)
    {
        if (ep.ResponsePatterns.ContainsKey("401") || ep.ResponsePatterns.ContainsKey("403"))
            return true;
        if (ep.UrlTemplate.Contains('{', StringComparison.Ordinal))
            return true;
        if (ep.Auth.Type.Contains("bearer", StringComparison.OrdinalIgnoreCase))
            return true;

        var path = ep.UrlTemplate.ToLowerInvariant();
        if (path.Contains("/api/", StringComparison.Ordinal)
            || path.Contains("/rest/", StringComparison.Ordinal)
            || path.Contains("/admin", StringComparison.Ordinal)
            || path.Contains("/account/", StringComparison.Ordinal))
            return ep.Auth.Required;

        // Session cookie on document GET alone (e.g. homepage while logged in) is not a protected API.
        if (ep.Auth.Type.Contains("session-cookie", StringComparison.OrdinalIgnoreCase)
            && ep.Methods.All(m => m is "GET" or "HEAD"))
            return false;

        return ep.Auth.Required;
    }

    internal static string ShortHash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body ?? ""));
        return Convert.ToHexString(bytes)[..12];
    }

    internal static bool LooksSensitive(string body, string urlTemplate) =>
        AuthAccessHeuristics.LooksSensitiveApiBody(body, urlTemplate);

    internal static readonly string[] StaticAssetExtensions =
    [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".js", ".mjs",
        ".map", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3"
    ];

    internal static bool IsStaticAssetUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        var path = uri.AbsolutePath.ToLowerInvariant();
        foreach (var ext in StaticAssetExtensions)
        {
            if (path.EndsWith(ext, StringComparison.Ordinal))
                return true;
        }
        return path.Contains("getmapimage", StringComparison.Ordinal)
               || path.Contains("/staticmap", StringComparison.Ordinal)
               || path.Contains("/maps/api/", StringComparison.Ordinal);
    }

    internal static bool IsStaticAssetContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return false;
        var ct = contentType.ToLowerInvariant();
        return ct.StartsWith("image/", StringComparison.Ordinal)
               || ct.StartsWith("font/", StringComparison.Ordinal)
               || ct.StartsWith("audio/", StringComparison.Ordinal)
               || ct.StartsWith("video/", StringComparison.Ordinal)
               || ct.StartsWith("text/css", StringComparison.Ordinal)
               || ct.Contains("javascript", StringComparison.Ordinal);
    }

    internal static bool IsStaticAsset(string? url, string? contentType) =>
        IsStaticAssetUrl(url) || IsStaticAssetContentType(contentType);

    /// <summary>Full token when present; never the truncated analyze preview (ellipsis).</summary>
    internal static string? TokenForProbe(HttpSecurityProbes.JwtTokenAnalysis? pick)
    {
        if (pick == null) return null;
        return NormalizeBearerToken(pick.FullToken ?? pick.Raw);
    }

    internal static string? NormalizeBearerToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        token = token.Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            token = token["Bearer ".Length..].Trim();
        if (token.Contains('…'))
        {
            var parts = token.Split('…');
            if (parts.Length >= 2 && parts[0].StartsWith("eyJ", StringComparison.Ordinal))
                return null;
        }
        return token;
    }

    internal static bool IsAlgNoneJwt(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2) return false;
        try
        {
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
            using var doc = JsonDocument.Parse(headerJson);
            if (doc.RootElement.TryGetProperty("alg", out var alg))
            {
                if (alg.ValueKind == JsonValueKind.String)
                    return string.Equals(alg.GetString()?.Trim(), "none", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch { /* ignore */ }
        return false;
    }

    internal static (string? token, string? note) BuildAlgNoneBearerToken(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return (null, null);
        if (IsAlgNoneJwt(raw))
            return (raw, "Used provided alg:none JWT as-is.");

        var segments = raw.Split('.');
        if (segments.Length >= 2)
        {
            try
            {
                using var mods = JsonDocument.Parse("""{"header":{"alg":"none","typ":"JWT"},"stripSignature":true}""");
                var forged = HttpSecurityProbes.ForgeJwt(raw, mods.RootElement, stripSignature: true).Token;
                return (forged, "Forged alg:none variant from baseToken.");
            }
            catch
            {
                return (raw, "Could not forge — using token as-is for Authorization header.");
            }
        }

        return (raw, "Non-JWT token string used as Bearer credential.");
    }

    internal static string CraftAlgVariantToken(object? algValue)
    {
        var payload = JsonSerializer.Serialize(new { sub = "trowser-canary", role = "admin" });
        string headerJson;
        if (algValue == null)
            headerJson = """{"typ":"JWT"}""";
        else if (algValue is string s)
            headerJson = JsonSerializer.Serialize(new { alg = s, typ = "JWT" });
        else
            headerJson = JsonSerializer.Serialize(new { alg = algValue, typ = "JWT" });

        return $"{Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson))}.{Base64UrlEncode(Encoding.UTF8.GetBytes(payload))}.";
    }

    internal static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    internal static bool LooksLikeAdminShape(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var lower = body.ToLowerInvariant();
        return lower.Contains("admin") || lower.Contains("\"role\"") || lower.Contains("isadmin")
               || lower.Contains("superuser") || lower.Contains("privilege");
    }

    internal static bool TraceExposesJwtParser(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var lower = body.ToLowerInvariant();
        return lower.Contains("kid") || lower.Contains("jku") || lower.Contains("x5u")
               || lower.Contains("jwks") || lower.Contains("jsonwebtoken");
    }
}
