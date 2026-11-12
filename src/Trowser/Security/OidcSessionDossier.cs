using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Single redacted picture of the OIDC/OAuth session for humans and LLM agents.
/// Values (tokens, codes, secrets) are never included — only handles and metadata.
/// </summary>
public static class OidcSessionDossier
{
    public sealed class ArtifactHandle
    {
        public string Kind { get; init; } = "";
        public string Location { get; init; } = "";
    }

    public sealed class DossierResult
    {
        public string Binding { get; set; } = "none";
        public string? Issuer { get; set; }
        public string? ClientId { get; set; }
        public string? RedirectUri { get; set; }
        public string? ResponseType { get; set; }
        public string? Scope { get; set; }
        public string? PkceMethod { get; set; }
        public bool? NoncePresent { get; set; }
        public bool? StatePresent { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? UserinfoEndpoint { get; set; }
        public string? AuthorizationEndpoint { get; set; }
        public bool ConfigurationFound { get; set; }
        public string? ConfigurationUrl { get; set; }
        public List<ArtifactHandle> Artifacts { get; set; } = [];
        public List<string> NotTestable { get; set; } = [];
        public List<string> NextActions { get; set; } = [];
    }

    public static async Task<DossierResult> BuildAsync(
        AutomationContext ctx,
        OidcSessionAnalyzer.SessionResult? session = null,
        OidcDiscoveryFetcher.DiscoveryResult? discovery = null,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        session ??= OidcSessionAnalyzer.Analyze(
            ctx.Network.Entries,
            OidcSessionAnalyzer.CookieInfo.FromDictionaries(await ctx.GetCookies()));

        var flows = OAuthFlowTester.CaptureFlowsFromNetwork(ctx.Network.Entries);
        var primary = flows.FirstOrDefault();

        var dossier = new DossierResult
        {
            Issuer = session.Issuer,
            Binding = MapBinding(session.Binding, primary),
            ClientId = primary?.ClientId,
            RedirectUri = primary?.RedirectUri,
            ResponseType = primary?.ResponseType,
            Scope = primary?.Scope,
            PkceMethod = string.IsNullOrEmpty(primary?.CodeChallenge)
                ? null
                : (primary.CodeChallengeMethod ?? "unknown"),
            StatePresent = primary == null ? null : !string.IsNullOrEmpty(primary.State),
            NoncePresent = primary == null ? null : !string.IsNullOrEmpty(primary.Nonce),
            TokenEndpoint = primary?.TokenEndpoint,
            AuthorizationEndpoint = string.IsNullOrEmpty(primary?.AuthorizationUrl)
                ? null
                : OAuthFlowTester.RedactAuthorizeUrl(primary.AuthorizationUrl)
        };

        if (discovery is { Found: true, Configuration: not null })
        {
            dossier.ConfigurationFound = true;
            dossier.ConfigurationUrl = discovery.ConfigurationUrl;
            var cfg = discovery.Configuration.Value;
            dossier.Issuer ??= OidcDiscoveryFetcher.GetString(cfg, "issuer")?.TrimEnd('/');
            dossier.TokenEndpoint ??= OidcDiscoveryFetcher.GetString(cfg, "token_endpoint");
            dossier.UserinfoEndpoint = OidcDiscoveryFetcher.GetString(cfg, "userinfo_endpoint");
            dossier.AuthorizationEndpoint ??= OidcDiscoveryFetcher.GetString(cfg, "authorization_endpoint");
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (dossier.UserinfoEndpoint == null
                && entry.Url.Contains("userinfo", StringComparison.OrdinalIgnoreCase)
                && entry.StatusCode is >= 200 and < 400)
                dossier.UserinfoEndpoint = RedactUrl(entry.Url);
        }

        await CollectArtifactsAsync(ctx, session, flows, dossier, ct);
        BuildGuidance(session, dossier, flows.Count > 0);
        return dossier;
    }

    public static DossierResult BuildFromNetworkOnly(
        IEnumerable<NetworkEntry> entries,
        IReadOnlyList<OidcSessionAnalyzer.CookieInfo>? cookies = null)
    {
        var session = OidcSessionAnalyzer.Analyze(entries, cookies);
        var flows = OAuthFlowTester.CaptureFlowsFromNetwork(entries);
        var primary = flows.FirstOrDefault();

        var dossier = new DossierResult
        {
            Issuer = session.Issuer,
            Binding = MapBinding(session.Binding, primary),
            ClientId = primary?.ClientId,
            RedirectUri = primary?.RedirectUri,
            ResponseType = primary?.ResponseType,
            Scope = primary?.Scope,
            PkceMethod = string.IsNullOrEmpty(primary?.CodeChallenge)
                ? null
                : (primary.CodeChallengeMethod ?? "unknown"),
            StatePresent = primary == null ? null : !string.IsNullOrEmpty(primary.State),
            NoncePresent = primary == null ? null : !string.IsNullOrEmpty(primary.Nonce),
            TokenEndpoint = primary?.TokenEndpoint,
            AuthorizationEndpoint = string.IsNullOrEmpty(primary?.AuthorizationUrl)
                ? null
                : OAuthFlowTester.RedactAuthorizeUrl(primary.AuthorizationUrl)
        };

        BuildGuidance(session, dossier, flows.Count > 0);
        return dossier;
    }

    private static string MapBinding(string sessionBinding, OAuthFlowTester.CapturedOAuthFlow? flow)
    {
        return sessionBinding switch
        {
            "bff-proxy" or "claims-only" => "bff",
            "bearer" => "bearer-api",
            "front-channel" => flow?.CodeChallenge != null ? "spa" : "confidential",
            "token" or "discovery" => "spa",
            _ => sessionBinding == "none" ? "none" : sessionBinding
        };
    }

    public static async Task CollectArtifactsAsync(
        AutomationContext ctx,
        OidcSessionAnalyzer.SessionResult session,
        List<OAuthFlowTester.CapturedOAuthFlow> flows,
        DossierResult dossier,
        CancellationToken ct = default)
    {
        if (!string.IsNullOrEmpty(session.SessionCookieName))
        {
            dossier.Artifacts.Add(new ArtifactHandle
            {
                Kind = "session_cookie",
                Location = $"cookie:{session.SessionCookieName}"
            });
        }

        foreach (var flow in flows)
        {
            foreach (var cb in flow.CallbackUrls)
            {
                if (cb.Contains("code=", StringComparison.OrdinalIgnoreCase))
                {
                    dossier.Artifacts.Add(new ArtifactHandle
                    {
                        Kind = "authorization_code",
                        Location = "url:query (callback)"
                    });
                }

                if (cb.Contains("id_token=", StringComparison.OrdinalIgnoreCase)
                    || cb.Contains("#id_token", StringComparison.OrdinalIgnoreCase))
                {
                    dossier.Artifacts.Add(new ArtifactHandle
                    {
                        Kind = "id_token",
                        Location = "url:fragment (callback)"
                    });
                }

                if (cb.Contains("access_token=", StringComparison.OrdinalIgnoreCase))
                {
                    dossier.Artifacts.Add(new ArtifactHandle
                    {
                        Kind = "access_token",
                        Location = cb.Contains('#') ? "url:fragment (callback)" : "url:query (callback)"
                    });
                }
            }

            foreach (var code in flow.ExchangedAuthorizationCodes)
            {
                dossier.Artifacts.Add(new ArtifactHandle
                {
                    Kind = "authorization_code",
                    Location = "network:token-endpoint (exchanged)"
                });
                _ = code;
            }
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (OidcIssuerDetector.TryGetHeader(entry.RequestHeaders, "Authorization", out var auth)
                && auth.StartsWith("Bearer eyJ", StringComparison.OrdinalIgnoreCase))
            {
                dossier.Artifacts.Add(new ArtifactHandle
                {
                    Kind = "access_token",
                    Location = $"header:authorization ({RedactUrl(entry.Url)})"
                });
            }
        }

        try
        {
            var cookies = await ctx.GetCookies();
            foreach (var c in cookies)
            {
                c.TryGetValue("name", out var nameObj);
                c.TryGetValue("value", out var valueObj);
                var name = nameObj?.ToString() ?? "";
                var value = valueObj?.ToString() ?? "";
                if (value.StartsWith("eyJ", StringComparison.Ordinal) && value.Count(ch => ch == '.') >= 2)
                {
                    dossier.Artifacts.Add(new ArtifactHandle
                    {
                        Kind = InferJwtKind(value),
                        Location = $"cookie:{name}"
                    });
                }
            }

            foreach (var store in new[] { "local", "session" })
            {
                ct.ThrowIfCancellationRequested();
                var items = await ctx.GetAllStorage(store);
                foreach (var kv in items)
                {
                    if (kv.Value.StartsWith("eyJ", StringComparison.Ordinal) && kv.Value.Count(ch => ch == '.') >= 2)
                    {
                        dossier.Artifacts.Add(new ArtifactHandle
                        {
                            Kind = InferJwtKind(kv.Value),
                            Location = $"storage:{store}:{kv.Key}"
                        });
                    }
                    else if (kv.Key.Contains("refresh", StringComparison.OrdinalIgnoreCase)
                             && kv.Value.Length >= 20)
                    {
                        dossier.Artifacts.Add(new ArtifactHandle
                        {
                            Kind = "refresh_token",
                            Location = $"storage:{store}:{kv.Key}"
                        });
                    }
                }
            }
        }
        catch
        {
            /* storage/cookies optional */
        }

        dossier.Artifacts = dossier.Artifacts
            .GroupBy(a => $"{a.Kind}|{a.Location}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
    }

    private static string InferJwtKind(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return "jwt";
            var payload = JwtProbeHelpers.Base64UrlDecode(parts[1]);
            var json = System.Text.Encoding.UTF8.GetString(payload);
            if (json.Contains("\"at_hash\"", StringComparison.Ordinal)) return "id_token";
            if (json.Contains("\"nonce\"", StringComparison.Ordinal)) return "id_token";
        }
        catch { /* ignore */ }

        return "jwt";
    }

    private static void BuildGuidance(
        OidcSessionAnalyzer.SessionResult session,
        DossierResult dossier,
        bool oauthFlowCaptured)
    {
        if (!session.Observed && !oauthFlowCaptured)
        {
            dossier.NextActions.Add(
                "Browse through login, then POST /api/wait-for-final-navigation; re-run oidc-analyze or oauth-flow-test.");
            return;
        }

        dossier.NextActions.Add(
            "browser_security_oidc_analyze — provider metadata when issuer is known (discovery may be absent).");

        if (dossier.Binding == "bff")
        {
            dossier.NotTestable.Add("Front-channel authorize probes — tokens and codes stayed on the server.");
            dossier.NextActions.Add(
                "Test session cookie flags, claim exposure, logout; use identity capture + peer for two-user API tests.");
        }
        else if (oauthFlowCaptured)
        {
            dossier.NextActions.Add(
                "browser_security_oauth_flow_test with passiveOnly true — state, PKCE, fragment leaks.");
            dossier.NextActions.Add(
                "browser_security_oauth_flow_test with safetyMode active — redirect_uri, code replay (after passive).");
        }

        if (dossier.Artifacts.Any(a => a.Kind is "id_token" or "jwt" or "access_token"))
        {
            dossier.NextActions.Add(
                "oidc-analyze includes relying-party token checks when JWTs were visible in the browser.");
            dossier.NextActions.Add("browser_security_jwt_analyze and jwt-acceptance-sweep on API endpoints.");
        }

        if (string.IsNullOrEmpty(dossier.Issuer))
        {
            dossier.NotTestable.Add("Provider discovery — pass issuer explicitly; login UI host is not the issuer.");
            dossier.NextActions.Add(
                "Set issuer on oidc-analyze (scripts: top of 3 OidcFromNetwork.csx).");
        }
        else if (!dossier.ConfigurationFound)
        {
            dossier.NotTestable.Add(
                "Provider grant/PKCE metadata — no discovery document at standard well-known URLs.");
            dossier.NextActions.Add(
                "Session and token checks still apply; infer jwks_uri from network log or token iss claim.");
        }
    }

    private static string RedactUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return url;
        return $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}";
    }
}
