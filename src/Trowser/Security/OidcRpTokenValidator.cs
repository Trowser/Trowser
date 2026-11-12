using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Validates OIDC tokens the browser actually received (relying-party checks).
/// Works without discovery metadata when JWKS can be resolved from the token or network log.
/// </summary>
public static class OidcRpTokenValidator
{
    public sealed class RpTokenFinding
    {
        public string Category { get; init; } = "rp-token";
        public string Severity { get; init; } = "info";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public string? Recommendation { get; init; }
        public string? ArtifactLocation { get; init; }
    }

    public sealed class RpTokenOptions
    {
        public string? ExpectedClientId { get; set; }
        public string? ExpectedNonce { get; set; }
        public string? ExpectedIssuer { get; set; }
        public JsonElement? DiscoveryConfiguration { get; set; }
    }

    public static async Task<List<RpTokenFinding>> ValidateSessionAsync(
        AutomationContext ctx,
        RpTokenOptions options,
        CancellationToken ct = default)
    {
        var findings = new List<RpTokenFinding>();
        var samples = await CollectTokenSamplesAsync(ctx, ct);
        if (samples.Count == 0)
        {
            findings.Add(new RpTokenFinding
            {
                Severity = "info",
                Title = "No OIDC JWT artifacts in the browser to validate",
                Description =
                    "Typical for BFF/proxy logins. Relying-party signature and audience checks need id_token or access_token visible to the client.",
                Recommendation = "Test the session cookie and API authorization instead."
            });
            return findings;
        }

        foreach (var sample in samples)
        {
            ct.ThrowIfCancellationRequested();
            findings.AddRange(await ValidateOneAsync(ctx, sample, options, ct));
        }

        return findings;
    }

    private sealed class TokenSample
    {
        public string Raw { get; init; } = "";
        public string Kind { get; init; } = "jwt";
        public string Location { get; init; } = "";
    }

    private static async Task<List<TokenSample>> CollectTokenSamplesAsync(
        AutomationContext ctx, CancellationToken ct)
    {
        var list = new List<TokenSample>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(string? raw, string kind, string location)
        {
            raw = JwtProbeHelpers.NormalizeBearerToken(raw ?? "");
            if (string.IsNullOrEmpty(raw) || !seen.Add(raw)) return;
            list.Add(new TokenSample { Raw = raw, Kind = kind, Location = location });
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (OidcIssuerDetector.TryGetHeader(entry.RequestHeaders, "Authorization", out var auth)
                && auth.StartsWith("Bearer eyJ", StringComparison.OrdinalIgnoreCase))
                Add(auth["Bearer ".Length..], "access_token", $"header:authorization ({entry.Url})");

            ExtractJwtsFromBody(entry.ResponseBody, list, seen, "network:response");
            ExtractJwtsFromBody(entry.RequestBody, list, seen, "network:request");
        }

        try
        {
            var cookies = await ctx.GetCookies();
            foreach (var c in cookies)
            {
                c.TryGetValue("name", out var n);
                c.TryGetValue("value", out var v);
                var val = v?.ToString() ?? "";
                if (val.StartsWith("eyJ", StringComparison.Ordinal))
                    Add(val, "jwt", $"cookie:{n}");
            }

            foreach (var store in new[] { "local", "session" })
            {
                ct.ThrowIfCancellationRequested();
                foreach (var kv in await ctx.GetAllStorage(store))
                {
                    if (kv.Value.StartsWith("eyJ", StringComparison.Ordinal))
                        Add(kv.Value, "jwt", $"storage:{store}:{kv.Key}");
                }
            }
        }
        catch { /* optional */ }

        return list;
    }

    private static void ExtractJwtsFromBody(
        string? body, List<TokenSample> list, HashSet<string> seen, string prefix)
    {
        if (string.IsNullOrEmpty(body) || body.Length > 200_000) return;
        foreach (var prop in new[] { "id_token", "access_token" })
        {
            var idx = body.IndexOf($"\"{prop}\"", StringComparison.OrdinalIgnoreCase);
            while (idx >= 0)
            {
                var start = body.IndexOf('"', idx + prop.Length + 2);
                if (start < 0) break;
                start++;
                var end = body.IndexOf('"', start);
                if (end <= start) break;
                var token = body[start..end];
                if (token.StartsWith("eyJ", StringComparison.Ordinal))
                {
                    var raw = JwtProbeHelpers.NormalizeBearerToken(token);
                    if (!string.IsNullOrEmpty(raw) && seen.Add(raw))
                        list.Add(new TokenSample { Raw = raw, Kind = prop, Location = prefix });
                }

                idx = body.IndexOf($"\"{prop}\"", end, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    private static async Task<List<RpTokenFinding>> ValidateOneAsync(
        AutomationContext ctx,
        TokenSample sample,
        RpTokenOptions options,
        CancellationToken ct)
    {
        var findings = new List<RpTokenFinding>();
        var parts = sample.Raw.Split('.');
        if (parts.Length < 2)
        {
            findings.Add(Info(sample, "Malformed JWT structure", "Token is not a three-part JWT."));
            return findings;
        }

        JsonElement header;
        JsonElement payload;
        try
        {
            header = JsonDocument.Parse(JwtProbeHelpers.Base64UrlDecode(parts[0])).RootElement;
            payload = JsonDocument.Parse(JwtProbeHelpers.Base64UrlDecode(parts[1])).RootElement;
        }
        catch
        {
            findings.Add(Medium(sample, "JWT is not valid JSON", "Header or payload could not be parsed."));
            return findings;
        }

        var alg = header.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
        if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(High(sample, "JWT uses alg none",
                "Unsigned tokens must be rejected by the relying party."));
        }

        if (string.IsNullOrEmpty(parts[2]) || parts[2].Length < 8)
        {
            if (!string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
                findings.Add(Medium(sample, "JWT has no signature segment",
                    "Signed algorithms require a non-empty signature."));
        }
        else if (!string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            var sigOk = await TryVerifySignatureAsync(ctx, sample.Raw, header, payload, options, ct);
            if (sigOk == false)
                findings.Add(High(sample, "JWT signature verification failed",
                    "Token signature does not match issuer JWKS (or JWKS could not be fetched)."));
            else if (sigOk == null)
                findings.Add(Info(sample, "JWT signature not verified",
                    "JWKS was unavailable; signature was not checked. Discovery document is not required if jwks_uri appears in the network log."));
        }

        CheckTimeClaims(payload, sample, findings);
        CheckIssuer(payload, options, sample, findings);
        CheckAudience(payload, options, sample, findings);

        if (!string.IsNullOrEmpty(options.ExpectedNonce)
            && payload.TryGetProperty("nonce", out var nonceEl))
        {
            var nonce = nonceEl.GetString();
            if (!string.Equals(nonce, options.ExpectedNonce, StringComparison.Ordinal))
            {
                findings.Add(High(sample, "ID token nonce mismatch",
                    "Token nonce does not match the authorize request nonce."));
            }
        }
        else if (!string.IsNullOrEmpty(options.ExpectedNonce)
                 && sample.Kind == "id_token"
                 && !payload.TryGetProperty("nonce", out _))
        {
            findings.Add(Medium(sample, "ID token missing nonce claim",
                "OpenID Connect requires nonce in id_token when nonce was sent on authorize."));
        }

        return findings;
    }

    private static void CheckTimeClaims(JsonElement payload, TokenSample sample, List<RpTokenFinding> findings)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (payload.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp) && exp < now - 60)
            findings.Add(Medium(sample, "JWT is expired", "exp is in the past."));
        else if (!payload.TryGetProperty("exp", out _))
            findings.Add(Low(sample, "JWT has no exp claim", "Tokens without expiry cannot be bounded."));

        if (payload.TryGetProperty("nbf", out var nbfEl) && nbfEl.TryGetInt64(out var nbf) && nbf > now + 60)
            findings.Add(Medium(sample, "JWT not yet valid", "nbf is in the future."));
    }

    private static void CheckIssuer(
        JsonElement payload, RpTokenOptions options, TokenSample sample, List<RpTokenFinding> findings)
    {
        var iss = payload.TryGetProperty("iss", out var issEl) ? issEl.GetString() : null;
        if (string.IsNullOrEmpty(iss))
        {
            findings.Add(Medium(sample, "JWT missing iss claim", "Issuer must be validated."));
            return;
        }

        if (!string.IsNullOrEmpty(options.ExpectedIssuer)
            && !iss.TrimEnd('/').Equals(options.ExpectedIssuer.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(High(sample, "JWT issuer mismatch",
                "Token iss does not match expected issuer from session/discovery."));
        }
    }

    private static void CheckAudience(
        JsonElement payload, RpTokenOptions options, TokenSample sample, List<RpTokenFinding> findings)
    {
        if (string.IsNullOrEmpty(options.ExpectedClientId)) return;

        var audMatch = false;
        if (payload.TryGetProperty("aud", out var audEl))
        {
            if (audEl.ValueKind == JsonValueKind.String)
                audMatch = string.Equals(audEl.GetString(), options.ExpectedClientId, StringComparison.OrdinalIgnoreCase);
            else if (audEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in audEl.EnumerateArray())
                    if (el.ValueKind == JsonValueKind.String
                        && string.Equals(el.GetString(), options.ExpectedClientId, StringComparison.OrdinalIgnoreCase))
                        audMatch = true;
            }
        }

        if (!audMatch && payload.TryGetProperty("azp", out var azpEl))
            audMatch = string.Equals(azpEl.GetString(), options.ExpectedClientId, StringComparison.OrdinalIgnoreCase);

        if (!audMatch)
        {
            findings.Add(High(sample, "JWT audience does not match client_id",
                "aud/azp should include the OAuth client_id for this login."));
        }
    }

    private static async Task<bool?> TryVerifySignatureAsync(
        AutomationContext ctx,
        string token,
        JsonElement header,
        JsonElement payload,
        RpTokenOptions options,
        CancellationToken ct)
    {
        var alg = header.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
        if (string.IsNullOrEmpty(alg) || alg.Equals("none", StringComparison.OrdinalIgnoreCase))
            return null;

        var jwksUrl = ResolveJwksUrl(ctx, payload, options);
        if (string.IsNullOrEmpty(jwksUrl)) return null;

        var jwksBody = await FetchJwksAsync(ctx, jwksUrl, ct);
        if (string.IsNullOrEmpty(jwksBody)) return null;

        try
        {
            using var jwksDoc = JsonDocument.Parse(jwksBody);
            if (!jwksDoc.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
                return null;

            var kid = header.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;
            foreach (var key in keys.EnumerateArray())
            {
                if (!string.IsNullOrEmpty(kid)
                    && key.TryGetProperty("kid", out var keyKid)
                    && !string.Equals(keyKid.GetString(), kid, StringComparison.Ordinal))
                    continue;

                if (alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase)
                    && key.TryGetProperty("kty", out var kty) && kty.GetString() == "RSA"
                    && TryVerifyRs256(token, key, alg))
                    return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static string? ResolveJwksUrl(AutomationContext ctx, JsonElement payload, RpTokenOptions options)
    {
        if (options.DiscoveryConfiguration is { } cfg)
        {
            var fromDiscovery = OidcDiscoveryFetcher.GetString(cfg, "jwks_uri");
            if (!string.IsNullOrEmpty(fromDiscovery)) return fromDiscovery;
        }

        foreach (var entry in ctx.Network.Entries.AsEnumerable().Reverse())
        {
            if (entry.Url.Contains("jwks", StringComparison.OrdinalIgnoreCase)
                && entry.StatusCode is >= 200 and < 300)
                return entry.Url;
        }

        if (payload.TryGetProperty("iss", out var issEl))
        {
            var issuer = issEl.GetString()?.TrimEnd('/');
            if (!string.IsNullOrEmpty(issuer))
                return $"{issuer}/.well-known/jwks.json|{issuer}/protocol/openid-connect/certs";
        }

        return null;
    }

    private static bool TryVerifyRs256(string token, JsonElement jwk, string? alg)
    {
        if (string.IsNullOrEmpty(alg) || !alg.StartsWith("RS", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!jwk.TryGetProperty("n", out var nEl) || !jwk.TryGetProperty("e", out var eEl))
            return false;

        var parts = token.Split('.');
        if (parts.Length != 3) return false;

        try
        {
            var n = JwtProbeHelpers.Base64UrlDecode(nEl.GetString()!);
            var e = JwtProbeHelpers.Base64UrlDecode(eEl.GetString()!);
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });

            var signingInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
            var signature = JwtProbeHelpers.Base64UrlDecode(parts[2]);
            var hashAlg = alg switch
            {
                "RS384" => HashAlgorithmName.SHA384,
                "RS512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };
            return rsa.VerifyData(signingInput, signature, hashAlg, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string?> FetchJwksAsync(AutomationContext ctx, string? jwksUrl, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(jwksUrl)) return null;

        var urls = jwksUrl.Contains('|', StringComparison.Ordinal) ? jwksUrl.Split('|') : [jwksUrl];
        foreach (var url in urls)
        {
            try
            {
                var resp = await SecurityProbeHttp.FetchAsync(
                    ctx, url, "GET", null, null, 12000, includeBrowserCookies: false, ct);
                if (resp.Status is >= 200 and < 300 && !string.IsNullOrWhiteSpace(resp.Body))
                    return resp.Body;
            }
            catch { /* try next */ }
        }

        return null;
    }

    private static RpTokenFinding Info(TokenSample s, string title, string desc) => Finding(s, "info", title, desc);
    private static RpTokenFinding Low(TokenSample s, string title, string desc) => Finding(s, "low", title, desc);
    private static RpTokenFinding Medium(TokenSample s, string title, string desc) => Finding(s, "medium", title, desc);
    private static RpTokenFinding High(TokenSample s, string title, string desc) => Finding(s, "high", title, desc);

    private static RpTokenFinding Finding(TokenSample s, string severity, string title, string desc) =>
        new()
        {
            Severity = severity,
            Title = title,
            Description = desc,
            ArtifactLocation = s.Location,
            Recommendation = severity is "high" or "critical"
                ? "Reject the token server-side; do not trust client-only checks."
                : null
        };
}
