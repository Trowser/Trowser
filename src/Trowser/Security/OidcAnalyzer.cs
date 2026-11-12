using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Analyzes OpenID Connect provider configuration for security misconfigurations.
/// Fetches .well-known/openid-configuration, probes discovered endpoints, and flags
/// dangerous grant types, weak PKCE, exposed scopes, test authenticators, and more.
/// </summary>
public static class OidcAnalyzer
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = true,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(15)
    };

    public sealed class OidcOptions
    {
        public string? Issuer { get; set; }
        public bool AutoDetect { get; set; } = true;
        public bool ProbeEndpoints { get; set; } = true;
        public bool TestDynamicRegistration { get; set; }
        public bool TestGrantTypes { get; set; }
        public bool ValidateRpTokens { get; set; } = true;
        public string? ClientId { get; set; }
        public int TimeoutMs { get; set; } = 20000;
    }

    public sealed class OidcFinding
    {
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string? Recommendation { get; set; }
        public object? Detail { get; set; }
    }

    public sealed class OidcEndpointProbe
    {
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public bool Reachable { get; set; }
        public int? StatusCode { get; set; }
        public string? Error { get; set; }
    }

    public sealed class GrantTypeProbe
    {
        public string GrantType { get; set; } = "";
        public string ClientId { get; set; } = "";
        public string TokenEndpoint { get; set; } = "";
        public int? StatusCode { get; set; }
        public string? ErrorCode { get; set; }
        public string? ErrorDescription { get; set; }
        public string Verdict { get; set; } = "";
        public string? Error { get; set; }
    }

    public sealed class OidcResult
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string Issuer { get; set; } = "";
        public string ConfigurationUrl { get; set; } = "";
        public bool ConfigurationFound { get; set; }
        public JsonElement? RawConfiguration { get; set; }
        public List<OidcFinding> Findings { get; set; } = [];
        public List<OidcEndpointProbe> EndpointProbes { get; set; } = [];
        public List<GrantTypeProbe> GrantTypeProbes { get; set; } = [];
        public OidcSummary Summary { get; set; } = new();
        public List<string> Errors { get; set; } = [];
        /// <summary>What the browser showed of the login (including a BFF/proxy session with no issuer).</summary>
        public OidcSessionAnalyzer.SessionResult? Session { get; set; }
        public OidcSessionDossier.DossierResult? Dossier { get; set; }
        public List<OidcRpTokenValidator.RpTokenFinding> RpTokenFindings { get; set; } = [];
        public int ElapsedMs { get; set; }
    }

    public sealed class OidcSummary
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Info { get; set; }
        public List<string> GrantTypesSupported { get; set; } = [];
        public List<string> ScopesSupported { get; set; } = [];
        public List<string> SigningAlgorithms { get; set; } = [];
        public List<string> EndpointsDiscovered { get; set; } = [];
    }

    public static async Task<OidcResult> RunAsync(
        AutomationContext? ctx, OidcOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new OidcResult();

        var issuer = options.Issuer?.Trim().TrimEnd('/');

        if (ctx != null)
        {
            IReadOnlyList<OidcSessionAnalyzer.CookieInfo>? cookies = null;
            try
            {
                cookies = OidcSessionAnalyzer.CookieInfo.FromDictionaries(await ctx.GetCookies());
            }
            catch
            {
                /* cookie jar unavailable — network log is still enough for many logins */
            }

            result.Session = OidcSessionAnalyzer.Analyze(ctx.Network.Entries, cookies);
            if (string.IsNullOrEmpty(issuer) && options.AutoDetect)
                issuer = result.Session.Issuer;
        }

        OidcDiscoveryFetcher.DiscoveryResult? discovery = null;
        JsonElement? config = null;

        if (ctx != null)
        {
            try
            {
                discovery = !string.IsNullOrEmpty(issuer)
                    ? await OidcDiscoveryFetcher.TryFetchAsync(issuer, options.TimeoutMs, ct)
                    : null;
                result.Dossier = await OidcSessionDossier.BuildAsync(ctx, result.Session, discovery, ct);
                if (string.IsNullOrEmpty(issuer))
                    issuer = result.Dossier.Issuer ?? result.Session?.Issuer;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Session dossier: {ex.Message}");
            }
        }

        if (string.IsNullOrEmpty(issuer))
        {
            if (options.ValidateRpTokens && ctx != null)
                await AppendRpTokenFindingsAsync(ctx, result, options, null, null, ct);

            if (result.Session is { Observed: true } session)
                result.Errors.Add(OidcSessionAnalyzer.MissingIssuerMessage(session));
            else if (result.Session is not { Observed: true })
                result.Errors.Add(
                    "No issuer URL provided and auto-detection from network log found nothing. " +
                    "Provide an issuer URL (e.g. https://login.example.com/realms/myrealm).");

            result.Summary = BuildSummary(result);
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            return result;
        }

        result.Issuer = issuer;

        discovery ??= await OidcDiscoveryFetcher.TryFetchAsync(issuer, options.TimeoutMs, ct);
        if (discovery.Found && discovery.Configuration is { } cfgEl)
        {
            config = cfgEl;
            result.ConfigurationFound = true;
            result.ConfigurationUrl = discovery.ConfigurationUrl;
            result.RawConfiguration = cfgEl;
            if (ctx != null && result.Dossier == null)
            {
                try
                {
                    result.Dossier = await OidcSessionDossier.BuildAsync(ctx, result.Session, discovery, ct);
                }
                catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
            }
            else if (result.Dossier != null)
            {
                result.Dossier.ConfigurationFound = true;
                result.Dossier.ConfigurationUrl = discovery.ConfigurationUrl;
            }

            AnalyzeConfiguration(cfgEl, issuer, result);

            if (options.ProbeEndpoints)
            {
                ct.ThrowIfCancellationRequested();
                await ProbeEndpointsAsync(cfgEl, result, ct);
            }

            if (options.TestDynamicRegistration)
            {
                ct.ThrowIfCancellationRequested();
                await TestDynamicRegistrationAsync(cfgEl, result, ct);
            }

            if (options.TestGrantTypes)
            {
                ct.ThrowIfCancellationRequested();
                var clientIds = new List<string>();
                if (!string.IsNullOrEmpty(options.ClientId))
                    clientIds.Add(options.ClientId);
                if (ctx != null)
                {
                    foreach (var detected in DetectClientIds(ctx))
                        if (!clientIds.Contains(detected, StringComparer.OrdinalIgnoreCase))
                            clientIds.Add(detected);
                }
                if (clientIds.Count > 0)
                    await TestGrantTypesAsync(cfgEl, clientIds, result, ct);
                else
                    result.Errors.Add(
                        "Grant type testing skipped: no client_id found. Provide clientId or browse the app first to capture OAuth traffic.");
            }
        }
        else
        {
            result.ConfigurationUrl = discovery?.AttemptedUrls.FirstOrDefault()
                                      ?? OidcDiscoveryFetcher.BuildDiscoveryUrls(issuer).First();
            result.Findings.Add(new OidcFinding
            {
                Category = "discovery",
                Severity = "info",
                Title = "No OIDC discovery document at standard well-known URLs",
                Description =
                    "The issuer did not return openid-configuration or oauth-authorization-server metadata. " +
                    "Many enterprise IdPs omit public discovery; session, flow, and token checks can still run.",
                Recommendation = "Pass endpoints manually if needed, or rely on network capture and JWT iss for JWKS.",
                Detail = new { attempted = discovery?.AttemptedUrls, lastError = discovery?.LastError }
            });
            if (!string.IsNullOrEmpty(discovery?.LastError))
                result.Errors.Add($"Discovery not available: {discovery.LastError}");
        }

        if (options.ValidateRpTokens && ctx != null)
        {
            var flows = OAuthFlowTester.CaptureFlowsFromNetwork(ctx.Network.Entries);
            var primary = flows.FirstOrDefault();
            await AppendRpTokenFindingsAsync(ctx, result, options, config, primary, ct);
        }

        result.Summary = BuildSummary(result);
        result.ElapsedMs = (int)sw.ElapsedMilliseconds;
        return result;
    }

    private static async Task AppendRpTokenFindingsAsync(
        AutomationContext ctx,
        OidcResult result,
        OidcOptions options,
        JsonElement? config,
        OAuthFlowTester.CapturedOAuthFlow? flow,
        CancellationToken ct)
    {
        var rpOpts = new OidcRpTokenValidator.RpTokenOptions
        {
            ExpectedClientId = options.ClientId ?? flow?.ClientId ?? result.Dossier?.ClientId,
            ExpectedIssuer = result.Issuer,
            ExpectedNonce = flow?.Nonce,
            DiscoveryConfiguration = config
        };

        var rpFindings = await OidcRpTokenValidator.ValidateSessionAsync(ctx, rpOpts, ct);
        result.RpTokenFindings = rpFindings;
        foreach (var f in rpFindings.Where(f => f.Severity is not "info"))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Title,
                Description = f.Description,
                Recommendation = f.Recommendation,
                Detail = string.IsNullOrEmpty(f.ArtifactLocation) ? null : new { artifact = f.ArtifactLocation }
            });
        }
    }

    /// <summary>
    /// Extract client_id values from the network log: authorize URLs, token request bodies, JWT aud claims.
    /// </summary>
    private static List<string> DetectClientIds(AutomationContext ctx)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = ctx.Network.Entries;

        foreach (var entry in entries)
        {
            if (entry.Url.Contains("client_id", StringComparison.OrdinalIgnoreCase)
                && Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
            {
                var query = uri.Query;
                var clientId = ExtractQueryParam(query, "client_id");
                if (!string.IsNullOrEmpty(clientId))
                    ids.Add(clientId);
            }

            if (entry.RequestBody != null
                && entry.RequestBody.Contains("client_id", StringComparison.OrdinalIgnoreCase))
            {
                var clientId = ExtractFormParam(entry.RequestBody, "client_id");
                if (!string.IsNullOrEmpty(clientId))
                    ids.Add(clientId);
            }
        }

        foreach (var entry in entries)
        {
            if (OidcIssuerDetector.TryGetHeader(entry.RequestHeaders, "Authorization", out var auth)
                && auth.StartsWith("Bearer eyJ", StringComparison.OrdinalIgnoreCase))
            {
                var aud = ExtractJwtClaim(auth[7..], "aud");
                if (!string.IsNullOrEmpty(aud) && !aud.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    ids.Add(aud);

                var azp = ExtractJwtClaim(auth[7..], "azp");
                if (!string.IsNullOrEmpty(azp))
                    ids.Add(azp);
            }
        }

        return ids.ToList();
    }

    private static string? ExtractQueryParam(string query, string name)
    {
        if (string.IsNullOrEmpty(query)) return null;
        var q = query.TrimStart('?');
        foreach (var pair in q.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(pair[..eq]);
            if (key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return null;
    }

    private static string? ExtractFormParam(string body, string name)
    {
        foreach (var pair in body.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(pair[..eq]);
            if (key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
        }
        return null;
    }

    private static string? ExtractJwtClaim(string token, string claim)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length < 2) return null;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            switch (payload.Length % 4) { case 2: payload += "=="; break; case 3: payload += "="; break; }
            var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
            if (doc.RootElement.TryGetProperty(claim, out var val))
            {
                if (val.ValueKind == JsonValueKind.String) return val.GetString();
                if (val.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in val.EnumerateArray())
                        if (el.ValueKind == JsonValueKind.String) return el.GetString();
                }
            }
        }
        catch { }
        return null;
    }

    private static void AnalyzeConfiguration(JsonElement config, string issuer, OidcResult result)
    {
        CheckIssuer(config, issuer, result);
        CheckGrantTypes(config, result);
        CheckResponseTypes(config, result);
        CheckPkce(config, result);
        CheckScopes(config, result);
        CheckSigningAlgorithms(config, result);
        CheckAcrValues(config, result);
        CheckTokenEndpointAuth(config, result);
        CheckMisconfigurationPatterns(config, result);
    }

    private static void CheckIssuer(JsonElement config, string issuer, OidcResult result)
    {
        var configIssuer = GetString(config, "issuer");
        if (string.IsNullOrEmpty(configIssuer))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "issuer",
                Severity = "medium",
                Title = "Missing issuer in configuration",
                Description = "The OIDC configuration does not include an issuer field. This violates the OIDC Discovery specification.",
                Recommendation = "Ensure the provider includes an issuer field that exactly matches the discovery URL prefix."
            });
            return;
        }

        if (!configIssuer.TrimEnd('/').Equals(issuer.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "issuer",
                Severity = "high",
                Title = "Issuer mismatch",
                Description = $"The issuer in the configuration ({configIssuer}) does not match the discovery URL prefix ({issuer}). This could indicate a misconfiguration or a token confusion attack vector.",
                Recommendation = "Ensure the issuer exactly matches the URL used to fetch the configuration."
            });
        }

        if (configIssuer.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "issuer",
                Severity = "high",
                Title = "Non-HTTPS issuer",
                Description = "The issuer uses HTTP instead of HTTPS. All OIDC communication must be over TLS.",
                Recommendation = "Configure the issuer to use HTTPS."
            });
        }
    }

    private static void CheckGrantTypes(JsonElement config, OidcResult result)
    {
        var grants = GetStringArray(config, "grant_types_supported");
        if (grants.Count == 0) return;

        if (grants.Contains("implicit", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "grant-types",
                Severity = "high",
                Title = "Implicit grant type supported",
                Description = "The implicit grant type exposes tokens in URL fragments, making them vulnerable to browser history, referrer leakage, and access token replay attacks.",
                Recommendation = "Disable the implicit grant type and use the authorization code flow with PKCE instead.",
                Detail = new { grantType = "implicit" }
            });
        }

        if (grants.Contains("password", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "grant-types",
                Severity = "high",
                Title = "Resource Owner Password Credentials (ROPC) grant supported",
                Description = "The password grant type requires clients to handle user credentials directly, bypassing the authorization server's login UI. This is deprecated in OAuth 2.1 and vulnerable to credential phishing.",
                Recommendation = "Disable the password grant type. Use authorization code flow with PKCE for user authentication.",
                Detail = new { grantType = "password" }
            });
        }

        if (grants.Contains("urn:ietf:params:oauth:grant-type:device_code", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "grant-types",
                Severity = "info",
                Title = "Device authorization grant supported",
                Description = "The device code grant is available. Ensure device verification polling intervals and code expiry are properly configured.",
                Detail = new { grantType = "device_code" }
            });
        }

        result.Summary.GrantTypesSupported = grants;
    }

    private static void CheckResponseTypes(JsonElement config, OidcResult result)
    {
        var types = GetStringArray(config, "response_types_supported");

        if (types.Any(t => t.Equals("token", StringComparison.OrdinalIgnoreCase) ||
                           t.Contains("token", StringComparison.OrdinalIgnoreCase) &&
                           !t.Contains("id_token", StringComparison.OrdinalIgnoreCase)))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "response-types",
                Severity = "medium",
                Title = "Token response type in URL fragments",
                Description = $"Response type 'token' returns access tokens in URL fragments. Supported types: {string.Join(", ", types)}",
                Recommendation = "Prefer 'code' response type with PKCE. Avoid returning tokens in URL fragments."
            });
        }
    }

    private static void CheckPkce(JsonElement config, OidcResult result)
    {
        var methods = GetStringArray(config, "code_challenge_methods_supported");

        if (methods.Count == 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "pkce",
                Severity = "medium",
                Title = "PKCE support not advertised",
                Description = "The configuration does not list code_challenge_methods_supported. PKCE (RFC 7636) is essential for public clients to prevent authorization code interception.",
                Recommendation = "Enable PKCE with S256 method and advertise it in the OIDC configuration."
            });
            return;
        }

        if (methods.Contains("plain", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "pkce",
                Severity = "high",
                Title = "PKCE plain method supported",
                Description = "The 'plain' code_challenge_method provides no security benefit — the verifier is sent in cleartext. Only S256 (SHA-256 hash) provides meaningful protection against code interception.",
                Recommendation = "Disable the 'plain' method and require S256 for all PKCE flows.",
                Detail = new { methods }
            });
        }

        if (!methods.Contains("S256", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "pkce",
                Severity = "medium",
                Title = "PKCE S256 not supported",
                Description = $"S256 is not listed in code_challenge_methods_supported ({string.Join(", ", methods)}). S256 is the recommended PKCE method.",
                Recommendation = "Enable S256 as the required PKCE method."
            });
        }
    }

    private static void CheckScopes(JsonElement config, OidcResult result)
    {
        var scopes = GetStringArray(config, "scopes_supported");
        if (scopes.Count == 0) return;

        result.Summary.ScopesSupported = scopes;

        var categorized = new Dictionary<string, List<string>>
        {
            ["admin"] = [],
            ["financial"] = [],
            ["user-data"] = [],
            ["operator"] = [],
            ["standard"] = [],
            ["other"] = []
        };

        var adminPatterns = new[] { "admin", "superuser", "root", "manage", "system", "operator" };
        var financialPatterns = new[] { "payment", "billing", "finance", "transaction", "invoice", "bank", "economy" };
        var userDataPatterns = new[] { "email", "profile", "address", "phone", "personal", "name", "birthdate" };
        var standardScopes = new[] { "openid", "offline_access", "offline" };

        foreach (var scope in scopes)
        {
            var lower = scope.ToLowerInvariant();

            if (standardScopes.Any(s => lower == s))
                categorized["standard"].Add(scope);
            else if (adminPatterns.Any(p => lower.Contains(p)))
                categorized["admin"].Add(scope);
            else if (financialPatterns.Any(p => lower.Contains(p)))
                categorized["financial"].Add(scope);
            else if (userDataPatterns.Any(p => lower.Contains(p)))
                categorized["user-data"].Add(scope);
            else
                categorized["other"].Add(scope);
        }

        if (categorized["admin"].Count > 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "scopes",
                Severity = "medium",
                Title = "Administrative scopes exposed in discovery",
                Description = $"Administrative scopes visible in OIDC configuration: {string.Join(", ", categorized["admin"])}. Attackers can request these scopes in authorization flows.",
                Recommendation = "Consider restricting scope visibility or requiring additional authorization for admin scopes.",
                Detail = new { adminScopes = categorized["admin"] }
            });
        }

        if (categorized["financial"].Count > 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "scopes",
                Severity = "medium",
                Title = "Financial/payment scopes exposed in discovery",
                Description = $"Financial scopes visible: {string.Join(", ", categorized["financial"])}.",
                Recommendation = "Ensure financial scopes require explicit admin consent and are not auto-granted.",
                Detail = new { financialScopes = categorized["financial"] }
            });
        }

        result.Findings.Add(new OidcFinding
        {
            Category = "scopes",
            Severity = "info",
            Title = $"Scope inventory: {scopes.Count} scopes discovered",
            Description = $"Categories: standard={categorized["standard"].Count}, user-data={categorized["user-data"].Count}, admin={categorized["admin"].Count}, financial={categorized["financial"].Count}, other={categorized["other"].Count}",
            Detail = categorized
        });
    }

    private static void CheckSigningAlgorithms(JsonElement config, OidcResult result)
    {
        var algs = GetStringArray(config, "id_token_signing_alg_values_supported");
        if (algs.Count == 0) return;

        result.Summary.SigningAlgorithms = algs;

        if (algs.Contains("none", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "signing",
                Severity = "critical",
                Title = "Algorithm 'none' supported for ID tokens",
                Description = "The provider advertises 'none' as a supported signing algorithm. This allows unsigned tokens to be accepted, enabling trivial token forgery.",
                Recommendation = "Remove 'none' from id_token_signing_alg_values_supported immediately.",
                Detail = new { algorithms = algs }
            });
        }

        var symmetricAlgs = algs.Where(a => a.StartsWith("HS", StringComparison.OrdinalIgnoreCase)).ToList();
        if (symmetricAlgs.Count > 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "signing",
                Severity = "medium",
                Title = "Symmetric signing algorithms supported",
                Description = $"Symmetric algorithms ({string.Join(", ", symmetricAlgs)}) use a shared secret for signing. If the client secret is compromised, tokens can be forged. Asymmetric algorithms (RS256, ES256) are preferred.",
                Recommendation = "Prefer asymmetric signing algorithms (RS256, ES256) and disable symmetric algorithms unless required.",
                Detail = new { symmetricAlgorithms = symmetricAlgs }
            });
        }

        var weakAlgs = algs.Where(a => a.Equals("RS384", StringComparison.OrdinalIgnoreCase) == false &&
                                        (a.Contains("1", StringComparison.Ordinal) &&
                                         a.StartsWith("PS", StringComparison.OrdinalIgnoreCase) == false &&
                                         a.StartsWith("RS", StringComparison.OrdinalIgnoreCase) == false &&
                                         a.StartsWith("ES", StringComparison.OrdinalIgnoreCase) == false))
            .ToList();
        // Just report algorithm inventory
        result.Findings.Add(new OidcFinding
        {
            Category = "signing",
            Severity = "info",
            Title = $"Signing algorithms: {string.Join(", ", algs)}",
            Description = $"The provider supports {algs.Count} signing algorithm(s) for ID tokens.",
            Detail = new { algorithms = algs }
        });
    }

    private static void CheckAcrValues(JsonElement config, OidcResult result)
    {
        var acrs = GetStringArray(config, "acr_values_supported");
        if (acrs.Count == 0) return;

        var testPatterns = new[] { "mock", "test", "dummy", "fake", "dev", "debug", "bypass", "noauth", "simulator" };
        var testAcrs = acrs.Where(a => testPatterns.Any(p =>
            a.Contains(p, StringComparison.OrdinalIgnoreCase))).ToList();

        if (testAcrs.Count > 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "acr-values",
                Severity = "high",
                Title = "Test/mock authenticators in ACR values",
                Description = $"Found test/mock authenticators in acr_values_supported: {string.Join(", ", testAcrs)}. These may allow authentication bypass in production.",
                Recommendation = "Remove test and mock authenticators from production OIDC configurations.",
                Detail = new { testAcrs, allAcrs = acrs }
            });
        }

        var lowAssurancePatterns = new[] { "password", "pwd", "level0", "loa1" };
        var lowAcrs = acrs.Where(a => lowAssurancePatterns.Any(p =>
            a.Contains(p, StringComparison.OrdinalIgnoreCase))).ToList();

        if (lowAcrs.Count > 0)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "acr-values",
                Severity = "low",
                Title = "Low-assurance authentication levels available",
                Description = $"Low-assurance ACR values available: {string.Join(", ", lowAcrs)}. Clients may downgrade authentication strength.",
                Detail = new { lowAcrs }
            });
        }

        result.Findings.Add(new OidcFinding
        {
            Category = "acr-values",
            Severity = "info",
            Title = $"ACR values inventory: {acrs.Count} values",
            Description = $"Supported authentication context class references: {string.Join(", ", acrs)}",
            Detail = new { acrValues = acrs }
        });
    }

    private static void CheckTokenEndpointAuth(JsonElement config, OidcResult result)
    {
        var methods = GetStringArray(config, "token_endpoint_auth_methods_supported");
        if (methods.Count == 0) return;

        if (methods.Contains("none", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "token-endpoint-auth",
                Severity = "medium",
                Title = "Unauthenticated token endpoint access allowed",
                Description = "token_endpoint_auth_methods_supported includes 'none'. Public clients may be acceptable, but ensure confidential clients are required to authenticate.",
                Recommendation = "Restrict 'none' to explicitly configured public clients only."
            });
        }

        if (methods.Contains("client_secret_post", StringComparer.OrdinalIgnoreCase) &&
            !methods.Contains("private_key_jwt", StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "token-endpoint-auth",
                Severity = "low",
                Title = "Only secret-based client authentication available",
                Description = $"Supported auth methods: {string.Join(", ", methods)}. Consider adding private_key_jwt for stronger client authentication.",
                Recommendation = "Support private_key_jwt for high-security clients."
            });
        }
    }

    private static void CheckMisconfigurationPatterns(JsonElement config, OidcResult result)
    {
        var authEndpoint = GetString(config, "authorization_endpoint");
        var tokenEndpoint = GetString(config, "token_endpoint");

        if (!string.IsNullOrEmpty(authEndpoint) && authEndpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "misconfiguration",
                Severity = "critical",
                Title = "Authorization endpoint uses HTTP",
                Description = $"The authorization endpoint ({authEndpoint}) uses plain HTTP. Authorization codes and tokens will be transmitted unencrypted.",
                Recommendation = "All OIDC endpoints must use HTTPS."
            });
        }

        if (!string.IsNullOrEmpty(tokenEndpoint) && tokenEndpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "misconfiguration",
                Severity = "critical",
                Title = "Token endpoint uses HTTP",
                Description = $"The token endpoint ({tokenEndpoint}) uses plain HTTP. Client secrets and tokens will be transmitted unencrypted.",
                Recommendation = "All OIDC endpoints must use HTTPS."
            });
        }

        if (config.TryGetProperty("request_uri_parameter_supported", out var reqUri)
            && reqUri.ValueKind == JsonValueKind.True)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "misconfiguration",
                Severity = "medium",
                Title = "Request URI parameter supported",
                Description = "request_uri_parameter_supported is true. This can be abused for SSRF attacks if the IdP fetches arbitrary URLs.",
                Recommendation = "If not needed, disable request_uri support. If enabled, restrict to pre-registered request URIs only."
            });
        }

        var claimsParamSupported = config.TryGetProperty("claims_parameter_supported", out var clp) &&
                                   clp.ValueKind == JsonValueKind.True;
        if (claimsParamSupported)
        {
            result.Findings.Add(new OidcFinding
            {
                Category = "misconfiguration",
                Severity = "info",
                Title = "Claims parameter supported",
                Description = "The provider supports the claims request parameter, allowing clients to request specific claims. This is standard but increases the attack surface for data exposure.",
            });
        }
    }

    private static async Task ProbeEndpointsAsync(JsonElement config, OidcResult result, CancellationToken ct)
    {
        var endpoints = new Dictionary<string, string>();

        void TryAdd(string name, string prop)
        {
            var url = GetString(config, prop);
            if (!string.IsNullOrEmpty(url)) endpoints[name] = url;
        }

        TryAdd("authorization", "authorization_endpoint");
        TryAdd("token", "token_endpoint");
        TryAdd("userinfo", "userinfo_endpoint");
        TryAdd("jwks", "jwks_uri");
        TryAdd("introspection", "introspection_endpoint");
        TryAdd("revocation", "revocation_endpoint");
        TryAdd("registration", "registration_endpoint");
        TryAdd("end_session", "end_session_endpoint");
        TryAdd("device_authorization", "device_authorization_endpoint");
        TryAdd("pushed_authorization_request", "pushed_authorization_request_endpoint");

        result.Summary.EndpointsDiscovered = endpoints.Keys.ToList();

        foreach (var (name, url) in endpoints)
        {
            ct.ThrowIfCancellationRequested();
            var probe = new OidcEndpointProbe { Name = name, Url = url };

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                probe.Reachable = true;
                probe.StatusCode = (int)resp.StatusCode;
            }
            catch (Exception ex)
            {
                probe.Reachable = false;
                probe.Error = ex.Message;
            }

            result.EndpointProbes.Add(probe);
        }

        // JWKS deep analysis
        if (endpoints.TryGetValue("jwks", out var jwksUrl))
        {
            try
            {
                var jwksJson = await FetchJsonAsync(jwksUrl, ct);
                if (jwksJson.HasValue)
                    AnalyzeJwks(jwksJson.Value, result);
            }
            catch { }
        }
    }

    private static void AnalyzeJwks(JsonElement jwks, OidcResult result)
    {
        if (!jwks.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
            return;

        var keyCount = keys.GetArrayLength();
        var algorithms = new List<string>();
        var keyTypes = new List<string>();

        foreach (var key in keys.EnumerateArray())
        {
            if (key.TryGetProperty("alg", out var alg)) algorithms.Add(alg.GetString() ?? "");
            if (key.TryGetProperty("kty", out var kty)) keyTypes.Add(kty.GetString() ?? "");

            if (key.TryGetProperty("kty", out var kt) && kt.GetString() == "RSA"
                && key.TryGetProperty("n", out var n))
            {
                var modulusBytes = n.GetString()?.Length ?? 0;
                var estimatedBits = modulusBytes * 6;
                if (estimatedBits < 2000)
                {
                    result.Findings.Add(new OidcFinding
                    {
                        Category = "jwks",
                        Severity = "high",
                        Title = "Weak RSA key in JWKS",
                        Description = $"RSA key with estimated ~{estimatedBits} bit modulus detected. Minimum 2048 bits recommended.",
                        Recommendation = "Use RSA keys with at least 2048-bit modulus, or switch to ECDSA (ES256)."
                    });
                }
            }
        }

        result.Findings.Add(new OidcFinding
        {
            Category = "jwks",
            Severity = "info",
            Title = $"JWKS contains {keyCount} key(s)",
            Description = $"Key types: {string.Join(", ", keyTypes.Distinct())}. Algorithms: {string.Join(", ", algorithms.Distinct())}",
            Detail = new { keyCount, keyTypes = keyTypes.Distinct(), algorithms = algorithms.Distinct() }
        });
    }

    private static async Task TestDynamicRegistrationAsync(JsonElement config, OidcResult result, CancellationToken ct)
    {
        var regEndpoint = GetString(config, "registration_endpoint");
        if (string.IsNullOrEmpty(regEndpoint)) return;

        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                redirect_uris = new[] { "https://trowser-test.example.com/callback" },
                client_name = "Trowser OIDC Security Probe",
                token_endpoint_auth_method = "none",
                grant_types = new[] { "authorization_code" },
                response_types = new[] { "code" }
            });

            using var req = new HttpRequestMessage(HttpMethod.Post, regEndpoint)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };

            using var resp = await Http.SendAsync(req, ct);

            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                result.Findings.Add(new OidcFinding
                {
                    Category = "dynamic-registration",
                    Severity = "high",
                    Title = "Open Dynamic Client Registration",
                    Description = "The registration endpoint accepted an unauthenticated client registration request. " +
                                  "Attackers can register arbitrary clients to phish users via the IdP's login page.",
                    Recommendation = "Restrict dynamic client registration to authenticated/authorized requests, or disable it in production.",
                    Detail = new { statusCode = (int)resp.StatusCode, endpoint = regEndpoint }
                });
            }
            else if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                result.Findings.Add(new OidcFinding
                {
                    Category = "dynamic-registration",
                    Severity = "info",
                    Title = "Dynamic client registration requires authentication",
                    Description = $"Registration endpoint returned {(int)resp.StatusCode}. Registration is access-controlled.",
                    Detail = new { statusCode = (int)resp.StatusCode }
                });
            }
            else
            {
                result.Findings.Add(new OidcFinding
                {
                    Category = "dynamic-registration",
                    Severity = "info",
                    Title = $"Dynamic registration returned {(int)resp.StatusCode}",
                    Description = $"Registration endpoint returned HTTP {(int)resp.StatusCode}.",
                    Detail = new { statusCode = (int)resp.StatusCode }
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Dynamic registration test failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Probe the token endpoint with dangerous grant types (password, client_credentials)
    /// using detected client IDs to determine if they are actually usable, not just advertised.
    /// </summary>
    private static async Task TestGrantTypesAsync(
        JsonElement config, List<string> clientIds, OidcResult result, CancellationToken ct)
    {
        var tokenEndpoint = GetString(config, "token_endpoint");
        if (string.IsNullOrEmpty(tokenEndpoint))
        {
            result.Errors.Add("Grant type testing skipped: no token_endpoint in configuration.");
            return;
        }

        var grants = GetStringArray(config, "grant_types_supported");
        var dangerousGrants = new List<string>();
        if (grants.Contains("password", StringComparer.OrdinalIgnoreCase))
            dangerousGrants.Add("password");
        if (grants.Contains("client_credentials", StringComparer.OrdinalIgnoreCase))
            dangerousGrants.Add("client_credentials");

        if (dangerousGrants.Count == 0 && clientIds.Count > 0)
        {
            dangerousGrants.Add("password");
            dangerousGrants.Add("client_credentials");
        }
        else if (dangerousGrants.Count == 0)
        {
            return;
        }

        foreach (var clientId in clientIds.Take(5))
        {
            foreach (var grantType in dangerousGrants)
            {
                ct.ThrowIfCancellationRequested();
                var probe = await ProbeGrantTypeAsync(tokenEndpoint, clientId, grantType, ct);
                result.GrantTypeProbes.Add(probe);

                if (probe.Verdict == "allowed")
                {
                    var severity = grantType == "password" ? "critical" : "high";
                    result.Findings.Add(new OidcFinding
                    {
                        Category = "grant-types-live",
                        Severity = severity,
                        Title = $"Grant type '{grantType}' actively usable by client '{clientId}'",
                        Description = $"Token endpoint accepted grant_type={grantType} for client_id={clientId} " +
                                      $"(HTTP {probe.StatusCode}, error={probe.ErrorCode}). The error '{probe.ErrorCode}' indicates the " +
                                      "grant type is enabled for this client — only credentials are missing. " +
                                      "An attacker with valid credentials can obtain tokens via this flow.",
                        Recommendation = grantType == "password"
                            ? $"Disable the ROPC grant for client '{clientId}'. Reconfigure to use authorization_code with PKCE."
                            : $"Review whether client_credentials grant is necessary for client '{clientId}'. Restrict if not needed.",
                        Detail = new
                        {
                            probe.GrantType,
                            probe.ClientId,
                            probe.TokenEndpoint,
                            probe.StatusCode,
                            probe.ErrorCode,
                            probe.ErrorDescription
                        }
                    });
                }
                else if (probe.Verdict == "blocked")
                {
                    result.Findings.Add(new OidcFinding
                    {
                        Category = "grant-types-live",
                        Severity = "info",
                        Title = $"Grant type '{grantType}' blocked for client '{clientId}'",
                        Description = $"Token endpoint rejected grant_type={grantType} for client_id={clientId} " +
                                      $"with error '{probe.ErrorCode}'. The client is not authorized to use this grant type.",
                        Detail = new { probe.GrantType, probe.ClientId, probe.ErrorCode }
                    });
                }
            }
        }
    }

    private static async Task<GrantTypeProbe> ProbeGrantTypeAsync(
        string tokenEndpoint, string clientId, string grantType, CancellationToken ct)
    {
        var probe = new GrantTypeProbe
        {
            GrantType = grantType,
            ClientId = clientId,
            TokenEndpoint = tokenEndpoint
        };

        try
        {
            var formData = new Dictionary<string, string>
            {
                ["grant_type"] = grantType,
                ["client_id"] = clientId,
            };

            if (grantType == "password")
            {
                formData["username"] = "trowser_oidc_probe@invalid.test";
                formData["password"] = "trowser_invalid_probe_cred";
                formData["scope"] = "openid";
            }
            else if (grantType == "client_credentials")
            {
                formData["scope"] = "openid";
            }

            using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(formData)
            };

            using var resp = await Http.SendAsync(req, ct);
            probe.StatusCode = (int)resp.StatusCode;

            var body = await resp.Content.ReadAsStringAsync(ct);
            try
            {
                var json = JsonDocument.Parse(body);
                probe.ErrorCode = GetString(json.RootElement, "error");
                probe.ErrorDescription = GetString(json.RootElement, "error_description");
            }
            catch { }

            probe.Verdict = ClassifyGrantTypeResponse(probe);
        }
        catch (Exception ex)
        {
            probe.Error = ex.Message;
            probe.Verdict = "error";
        }

        return probe;
    }

    /// <summary>
    /// Classify the token endpoint response to determine if the grant type is allowed for this client.
    /// <list type="bullet">
    ///   <item><c>unauthorized_client</c> → the client is explicitly blocked from using this grant</item>
    ///   <item><c>unsupported_grant_type</c> → the server doesn't support it at all</item>
    ///   <item><c>invalid_grant</c> / <c>invalid_client</c> / <c>invalid_request</c> → grant accepted, creds wrong</item>
    /// </list>
    /// </summary>
    private static string ClassifyGrantTypeResponse(GrantTypeProbe probe)
    {
        var error = probe.ErrorCode?.ToLowerInvariant() ?? "";

        if (error is "unauthorized_client" or "unsupported_grant_type")
            return "blocked";

        if (probe.StatusCode is >= 200 and < 300)
            return "allowed";

        if (error is "invalid_grant" or "invalid_client" or "invalid_request"
            or "invalid_scope" or "access_denied" or "interaction_required")
            return "allowed";

        if (probe.StatusCode == 404 || probe.StatusCode == 405)
            return "blocked";

        if (probe.StatusCode is 401 or 400)
            return "allowed";

        return "unknown";
    }

    private static OidcSummary BuildSummary(OidcResult result)
    {
        return new OidcSummary
        {
            Critical = result.Findings.Count(f => f.Severity == "critical"),
            High = result.Findings.Count(f => f.Severity == "high"),
            Medium = result.Findings.Count(f => f.Severity == "medium"),
            Low = result.Findings.Count(f => f.Severity == "low"),
            Info = result.Findings.Count(f => f.Severity == "info"),
            GrantTypesSupported = result.Summary.GrantTypesSupported,
            ScopesSupported = result.Summary.ScopesSupported,
            SigningAlgorithms = result.Summary.SigningAlgorithms,
            EndpointsDiscovered = result.Summary.EndpointsDiscovered
        };
    }

    private static async Task<JsonElement?> FetchJsonAsync(string url, CancellationToken ct)
    {
        using var resp = await Http.GetAsync(url, ct);
        if (!resp.IsSuccessStatusCode) return null;
        var body = await resp.Content.ReadAsStringAsync(ct);
        var doc = JsonDocument.Parse(body);
        return doc.RootElement.Clone();
    }

    private static string GetString(JsonElement el, string property)
    {
        if (el.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String)
            return prop.GetString() ?? "";
        return "";
    }

    private static List<string> GetStringArray(JsonElement el, string property)
    {
        if (!el.TryGetProperty(property, out var prop) || prop.ValueKind != JsonValueKind.Array)
            return [];
        return prop.EnumerateArray()
            .Where(e => e.ValueKind == JsonValueKind.String)
            .Select(e => e.GetString()!)
            .ToList();
    }

    public static string Format(OidcResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== OIDC Security Analysis ===");
        sb.AppendLine($"Issuer: {result.Issuer}");
        sb.AppendLine($"Configuration URL: {result.ConfigurationUrl}");
        sb.AppendLine($"Configuration found: {result.ConfigurationFound}");
        sb.AppendLine($"Elapsed: {result.ElapsedMs}ms");
        sb.AppendLine();

        if (result.Findings.Count > 0)
        {
            sb.AppendLine($"FINDINGS: {result.Findings.Count}");
            sb.AppendLine($"  Critical: {result.Summary.Critical}, High: {result.Summary.High}, " +
                         $"Medium: {result.Summary.Medium}, Low: {result.Summary.Low}, Info: {result.Summary.Info}");
            sb.AppendLine();

            foreach (var f in result.Findings.OrderByDescending(f => SeverityRank(f.Severity)))
            {
                sb.AppendLine($"[{f.Severity.ToUpper()}] [{f.Category}] {f.Title}");
                sb.AppendLine($"  {f.Description}");
                if (f.Recommendation != null)
                    sb.AppendLine($"  Recommendation: {f.Recommendation}");
                sb.AppendLine();
            }
        }

        if (result.Summary.GrantTypesSupported.Count > 0)
            sb.AppendLine($"Grant types: {string.Join(", ", result.Summary.GrantTypesSupported)}");
        if (result.Summary.ScopesSupported.Count > 0)
            sb.AppendLine($"Scopes ({result.Summary.ScopesSupported.Count}): {string.Join(", ", result.Summary.ScopesSupported.Take(20))}");
        if (result.Summary.SigningAlgorithms.Count > 0)
            sb.AppendLine($"Signing algorithms: {string.Join(", ", result.Summary.SigningAlgorithms)}");
        if (result.Summary.EndpointsDiscovered.Count > 0)
            sb.AppendLine($"Endpoints: {string.Join(", ", result.Summary.EndpointsDiscovered)}");

        if (result.EndpointProbes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("ENDPOINT PROBES:");
            foreach (var p in result.EndpointProbes)
            {
                var status = p.Reachable ? $"HTTP {p.StatusCode}" : $"UNREACHABLE ({p.Error})";
                sb.AppendLine($"  {p.Name}: {status} — {p.Url}");
            }
        }

        if (result.GrantTypeProbes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("GRANT TYPE PROBES:");
            foreach (var p in result.GrantTypeProbes)
            {
                var icon = p.Verdict == "allowed" ? "!!!" : p.Verdict == "blocked" ? "OK " : "???";
                sb.AppendLine($"  [{icon}] {p.GrantType} + client_id={p.ClientId}: {p.Verdict.ToUpper()} " +
                             $"(HTTP {p.StatusCode}, error={p.ErrorCode ?? "none"})");
                if (!string.IsNullOrEmpty(p.ErrorDescription))
                    sb.AppendLine($"        {p.ErrorDescription}");
            }
        }

        if (result.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("ERRORS:");
            foreach (var err in result.Errors)
                sb.AppendLine($"  ! {err}");
        }

        return sb.ToString().TrimEnd();
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };
}
