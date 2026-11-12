using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Active and passive OAuth2/OIDC authorization-flow security testing.
/// Parses captured authorize/callback traffic from the network log, flags front-channel
/// weaknesses (state, PKCE, fragment tokens, mix-up indicators), and optionally probes
/// the authorization and token endpoints with manipulated parameters.
/// </summary>
public static class OAuthFlowTester
{
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(15)
    };

    private static readonly string[] EscalationScopes =
    [
        "admin", "offline_access", "write", "delete", "user:admin", "api:admin", "full_access"
    ];

    public sealed class OAuthFlowOptions
    {
        public string? AuthorizationUrl { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? ClientId { get; set; }
        public string? RedirectUri { get; set; }
        public string? Issuer { get; set; }
        public bool AutoDetect { get; set; } = true;
        /// <summary>Only analyze network log and current page; no authorize/token probes.</summary>
        public bool PassiveOnly { get; set; }
        public bool CheckBrowserLeaks { get; set; } = true;
        public bool SkipRedirectUriTests { get; set; }
        public bool SkipStateTests { get; set; }
        public bool SkipPkceTests { get; set; }
        public bool SkipScopeTests { get; set; }
        public bool SkipResponseTypeTests { get; set; }
        public bool SkipTokenExchange { get; set; }
        /// <summary>When no captured authorization code exists, POST a forged code (legacy canary).</summary>
        public bool UseCanaryTokenExchange { get; set; }
        /// <summary>Active: pause callback handling and run binding probes (consumes the authorization code).</summary>
        public bool HoldCallback { get; set; }
        public int TimeoutMs { get; set; } = 15000;
        /// <summary>After HTTP probes, confirm flagged mutations in the browser (consumes auth codes).</summary>
        public bool FlowBreaker { get; set; }
        public int MaxBrowserSteps { get; set; } = 2;
        public IReadOnlyList<string>? FlowBreakerMutations { get; set; }
    }

    public sealed class OAuthFlowFinding
    {
        public string Category { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string? Recommendation { get; set; }
        public object? Detail { get; set; }
    }

    public sealed class FlowProbe
    {
        public string Test { get; set; } = "";
        public string Url { get; set; } = "";
        public int? StatusCode { get; set; }
        public string? Location { get; set; }
        public string Verdict { get; set; } = "";
        public string? Notes { get; set; }
    }

    public sealed class CapturedOAuthFlow
    {
        public string AuthorizationUrl { get; set; } = "";
        public string? TokenEndpoint { get; set; }
        public string ClientId { get; set; } = "";
        public string? RedirectUri { get; set; }
        public string? State { get; set; }
        public string? Nonce { get; set; }
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Scope { get; set; }
        public string? ResponseType { get; set; }
        public string? IssuerHost { get; set; }
        public List<string> CallbackUrls { get; set; } = [];
        /// <summary>Authorization codes observed on callbacks (for active replay only; not exported in API).</summary>
        internal List<string> CapturedAuthorizationCodes { get; set; } = [];
        /// <summary>Codes that appeared in a token-endpoint exchange (best candidate for replay probe).</summary>
        internal List<string> ExchangedAuthorizationCodes { get; set; } = [];
    }

    public sealed class OAuthFlowSummary
    {
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int Info { get; set; }
        public int FlowsCaptured { get; set; }
        public int ProbesRun { get; set; }
    }

    public sealed class OAuthFlowResult
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public List<CapturedOAuthFlow> CapturedFlows { get; set; } = [];
        public List<OAuthFlowFinding> Findings { get; set; } = [];
        public List<FlowProbe> Probes { get; set; } = [];
        public OAuthFlowSummary Summary { get; set; } = new();
        public List<string> Errors { get; set; } = [];
        /// <summary>SAML, OIDC discovery, or other federation hints when OAuth capture is empty or alongside OAuth.</summary>
        public List<FederatedAuthSignals.AuthSignal> AuthSignals { get; set; } = [];
        public List<string> NextActions { get; set; } = [];
        public OidcSessionDossier.DossierResult? Dossier { get; set; }
        public int ElapsedMs { get; set; }
    }

    public static async Task<OAuthFlowResult> RunAsync(
        AutomationContext? ctx, OAuthFlowOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new OAuthFlowResult();

        if (ctx != null && options.AutoDetect)
            result.CapturedFlows = CaptureFlowsFromNetwork(ctx.Network.Entries, result);

        if (ctx != null)
        {
            result.AuthSignals = FederatedAuthSignals.ScanNetwork(ctx.Network);
            try
            {
                result.Dossier = await OidcSessionDossier.BuildAsync(ctx, ct: ct);
            }
            catch
            {
                /* dossier is best-effort */
            }
        }

        if (!string.IsNullOrEmpty(options.AuthorizationUrl))
        {
            var flow = ParseAuthorizeUrl(options.AuthorizationUrl);
            if (flow != null)
            {
                if (!string.IsNullOrEmpty(options.ClientId)) flow.ClientId = options.ClientId;
                if (!string.IsNullOrEmpty(options.RedirectUri)) flow.RedirectUri = options.RedirectUri;
                if (!string.IsNullOrEmpty(options.TokenEndpoint)) flow.TokenEndpoint = options.TokenEndpoint;
                MergeFlow(result.CapturedFlows, flow);
            }
        }

        if (result.CapturedFlows.Count == 0 && !string.IsNullOrEmpty(options.Issuer))
        {
            var fromDiscovery = await TryBuildFlowFromDiscoveryAsync(options.Issuer, options, ct);
            if (fromDiscovery != null)
                result.CapturedFlows.Add(fromDiscovery);
        }

        if (result.CapturedFlows.Count == 0)
        {
            if (result.AuthSignals.Any(s => s.Protocol.Equals("saml", StringComparison.OrdinalIgnoreCase)))
            {
                var modern = result.AuthSignals.Any(s =>
                    s.Binding.Equals("idp-api-bridge", StringComparison.OrdinalIgnoreCase));
                result.Errors.Add(modern
                    ? "No OAuth authorize flow captured. Modern SAML IdP API traffic is present (e.g. identity-response) — " +
                      "classic SAMLRequest/Response may not appear in the log; arm saml-capture before the next login."
                    : "No OAuth authorize flow captured. SAML SSO traffic is present — use SAML decode/replay tools " +
                      "(oauth-flow-test is OAuth/OIDC-specific; flowBreaker applies to authorize URLs only).");
            }
            else if (result.AuthSignals.Any(s =>
                         s.Protocol.Equals("oidc", StringComparison.OrdinalIgnoreCase)
                         && s.Binding is "bff-proxy" or "claims-only"))
            {
                result.Errors.Add(
                    "No OAuth authorize request in the log. An OIDC reverse-proxy login is present — " +
                    "the browser did not send /authorize. Pass issuer to oidc-analyze for the provider audit. " +
                    "Front-channel probes need an authorizationUrl.");
            }
            else
            {
                result.Errors.Add(
                    "No OAuth authorize flow found. Browse through login first (OAuth, SAML, or local — see authSignals), " +
                    "or provide authorizationUrl, clientId, and redirectUri.");
            }

            result.NextActions = FederatedAuthSignals.BuildNextActions(result.AuthSignals, oauthFlowsCaptured: false);
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            return result;
        }

        RunPassiveAnalysis(result);

        if (options.CheckBrowserLeaks && ctx != null)
        {
            ct.ThrowIfCancellationRequested();
            await RunBrowserLeakChecksAsync(ctx, result, options.TimeoutMs);
        }

        if (!options.PassiveOnly)
        {
            ct.ThrowIfCancellationRequested();
            await RunActiveProbesAsync(ctx, result, options, ct);
        }

        if (options.FlowBreaker && ctx != null && result.CapturedFlows.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            await OAuthFlowBreaker.RunAsync(ctx, result, result.CapturedFlows[0],
                new OAuthFlowBreaker.BreakerOptions
                {
                    MaxBrowserSteps = options.MaxBrowserSteps,
                    TimeoutMs = options.TimeoutMs,
                    Mutations = options.FlowBreakerMutations
                }, ct);
        }

        result.NextActions = FederatedAuthSignals.BuildNextActions(result.AuthSignals, oauthFlowsCaptured: true);
        if (result.CapturedFlows.Count > 0)
        {
            result.NextActions.Add(
                "browser_postmessage_audit on callback/SPA pages — token landing via postMessage is common");
            if (result.Probes.Any(p => p.Verdict is "vulnerable" or "suspicious"))
                result.NextActions.Add(
                    "browser_security_oauth_flow_test with flowBreaker true and safetyMode active to confirm browser landing");
        }

        if (result.AuthSignals.Any(s => s.Protocol.Equals("saml", StringComparison.OrdinalIgnoreCase)))
        {
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = "federation",
                Severity = "info",
                Title = "SAML traffic observed in the same session as OAuth",
                Description =
                    "Session includes SAML bindings. Run saml-decode on the network log for assertion analysis; " +
                    "OAuth flowBreaker does not replace SAML replay tests.",
                Recommendation = "browser_saml_decode with findAll; postMessage audit on ACS/callback pages if applicable."
            });
        }

        result.Summary = BuildSummary(result);
        result.ElapsedMs = (int)sw.ElapsedMilliseconds;
        return result;
    }

    public static List<CapturedOAuthFlow> CaptureFlowsFromNetwork(
        IEnumerable<NetworkEntry> entries, OAuthFlowResult? result = null)
    {
        var flows = new List<CapturedOAuthFlow>();
        result ??= new OAuthFlowResult();
        var callbacksByClient = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (IsAuthorizeUrl(entry.Url))
            {
                var flow = ParseAuthorizeUrl(entry.Url);
                if (flow != null)
                    MergeFlow(flows, flow);
            }

            if (IsOAuthCallback(entry.Url))
            {
                var code = ExtractQueryParamFromUrl(entry.Url, "code");
                var clientId = ExtractQueryParamFromUrl(entry.Url, "client_id")
                               ?? GuessClientFromCallback(entry.Url, flows);
                if (clientId != null)
                {
                    if (!callbacksByClient.ContainsKey(clientId))
                        callbacksByClient[clientId] = [];
                    callbacksByClient[clientId].Add(entry.Url);
                }
                else
                {
                    foreach (var f in flows)
                        f.CallbackUrls.Add(entry.Url);
                }

                if (!string.IsNullOrEmpty(code))
                {
                    var flow = clientId != null
                        ? flows.FirstOrDefault(f => f.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase))
                        : flows.LastOrDefault();
                    flow?.CapturedAuthorizationCodes.Add(code);
                }
            }

            if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && entry.RequestBody != null
                && entry.RequestBody.Contains("grant_type=", StringComparison.OrdinalIgnoreCase)
                && entry.Url.Contains("token", StringComparison.OrdinalIgnoreCase))
            {
                var clientId = ExtractFormParam(entry.RequestBody, "client_id");
                var code = ExtractFormParam(entry.RequestBody, "code");
                if (!string.IsNullOrEmpty(clientId))
                {
                    var existing = flows.FirstOrDefault(f =>
                        f.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase));
                    if (existing != null)
                        existing.TokenEndpoint = entry.Url;
                    else
                        flows.Add(new CapturedOAuthFlow
                        {
                            ClientId = clientId,
                            TokenEndpoint = entry.Url
                        });

                    if (!string.IsNullOrEmpty(code))
                    {
                        var target = flows.FirstOrDefault(f =>
                            f.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase));
                        target?.ExchangedAuthorizationCodes.Add(code);
                    }
                }
            }

            CheckReferrerLeakage(entry, result);
        }

        foreach (var flow in flows)
        {
            if (callbacksByClient.TryGetValue(flow.ClientId, out var cbs))
                flow.CallbackUrls.AddRange(cbs.Where(u => !flow.CallbackUrls.Contains(u)));
        }

        return flows;
    }

    private static void CheckReferrerLeakage(NetworkEntry entry, OAuthFlowResult result)
    {
        if (!entry.RequestHeaders.TryGetValue("Referer", out var referer)
            && !entry.RequestHeaders.TryGetValue("referer", out referer))
            return;

        var sensitive = new[] { "code_challenge", "state=", "client_secret", "access_token", "id_token" };
        foreach (var s in sensitive)
        {
            if (!referer.Contains(s, StringComparison.OrdinalIgnoreCase)) continue;
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = "referrer-leakage",
                Severity = "high",
                Title = "OAuth parameters leaked via Referer header",
                Description = $"Request to {entry.Url} sent Referer containing '{s}'. Sensitive OAuth values may leak to third parties.",
                Recommendation = "Use Referrer-Policy: no-referrer on OAuth pages; avoid putting secrets in URL query strings.",
                Detail = new { entry.Url, refererSnippet = referer.Length > 200 ? referer[..200] + "…" : referer }
            });
            break;
        }
    }

    private static void RunPassiveAnalysis(OAuthFlowResult result)
    {
        var flows = result.CapturedFlows;
        var issuers = flows.Select(f => f.IssuerHost).Where(h => h != null).Distinct().ToList();
        if (issuers.Count > 1)
        {
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = "mix-up",
                Severity = "medium",
                Title = "Multiple OAuth authorization servers in session",
                Description = $"Network log shows authorize traffic to {issuers.Count} distinct hosts: {string.Join(", ", issuers)}. " +
                              "Clients binding tokens to the wrong issuer (mix-up attack) may be possible if redirect_uri validation is weak.",
                Recommendation = "Bind tokens to issuer (aud/iss), use distinct redirect URIs per IdP, and validate issuer on callback."
            });
        }

        var clientIds = flows.Select(f => f.ClientId).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (clientIds.Count > 1 && flows.Count > 1)
        {
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = "mix-up",
                Severity = "low",
                Title = "Multiple OAuth client_ids observed",
                Description = $"Captured flows for client_ids: {string.Join(", ", clientIds)}. Cross-client code substitution may be testable if redirect_uri checks are client-agnostic.",
                Recommendation = "Ensure authorization codes are bound to client_id and redirect_uri at the token endpoint."
            });
        }

        foreach (var flow in flows)
        {
            if (string.IsNullOrEmpty(flow.State))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "state",
                    Severity = "high",
                    Title = "Authorize request missing state parameter",
                    Description = $"Captured authorize URL for client '{flow.ClientId}' has no state. CSRF on OAuth login initiation may be possible.",
                    Recommendation = "Require cryptographically random state; validate on callback.",
                    Detail = new { flow.AuthorizationUrl }
                });
            }
            else if (flow.State.Length < 16 || IsPredictableState(flow.State))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "state",
                    Severity = "medium",
                    Title = "Weak OAuth state parameter",
                    Description = $"State value '{flow.State}' appears short or predictable for client '{flow.ClientId}'.",
                    Recommendation = "Use at least 128 bits of entropy (e.g. 32+ char random string)."
                });
            }

            var rt = flow.ResponseType ?? "";
            if (rt.Contains("token", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "implicit-flow",
                    Severity = "high",
                    Title = "Implicit flow (response_type=token) in use",
                    Description = "Access tokens may be exposed in the browser history, Referer, and fragment.",
                    Recommendation = "Use authorization code flow with PKCE instead of implicit flow."
                });
            }

            if (string.IsNullOrEmpty(flow.CodeChallenge)
                && (rt.Contains("code", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(rt)))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "pkce",
                    Severity = "medium",
                    Title = "Authorization code flow without PKCE",
                    Description = $"Authorize URL for '{flow.ClientId}' has no code_challenge. Authorization codes may be interceptable on mobile/public clients.",
                    Recommendation = "Require PKCE (S256) for all public clients and native apps."
                });
            }

            if (flow.CodeChallengeMethod?.Equals("plain", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "pkce",
                    Severity = "high",
                    Title = "PKCE plain method used",
                    Description = "code_challenge_method=plain is vulnerable to interception; use S256.",
                    Recommendation = "Set code_challenge_method=S256 only."
                });
            }

            foreach (var cb in flow.CallbackUrls)
            {
                if (cb.Contains('#') && (
                        cb.Contains("access_token=", StringComparison.OrdinalIgnoreCase)
                        || cb.Contains("id_token=", StringComparison.OrdinalIgnoreCase)))
                {
                    result.Findings.Add(new OAuthFlowFinding
                    {
                        Category = "fragment-exposure",
                        Severity = "high",
                        Title = "Token exposed in URL fragment",
                        Description = $"Callback URL contains tokens in the fragment: {Truncate(cb, 120)}. Fragments are visible to scripts and may leak via Referer on subresource loads.",
                        Recommendation = "Avoid implicit/hybrid flows; return codes in query string only and exchange server-side.",
                        Detail = new { callback = cb }
                    });
                }

                if (cb.Contains("code=", StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrEmpty(flow.State))
                {
                    result.Findings.Add(new OAuthFlowFinding
                    {
                        Category = "state",
                        Severity = "medium",
                        Title = "Authorization code returned without state in original request",
                        Description = "Callback received a code but the authorize request had no state to validate.",
                        Recommendation = "Always send and verify state on callback."
                    });
                }
            }
        }
    }

    private static async Task RunBrowserLeakChecksAsync(
        AutomationContext ctx, OAuthFlowResult result, int timeoutMs)
    {
        const string script = """
            (function(){
              var out = { hasOpener: !!window.opener, referrer: document.referrer || '',
                hash: location.hash || '', search: location.search || '' };
              try { out.openerOrigin = window.opener ? window.opener.location.origin : null; } catch(e) { out.openerOrigin = 'blocked'; }
              return JSON.stringify(out);
            })()
            """;

        try
        {
            var json = await ctx.ExecuteJs(script);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("hasOpener", out var ho) && ho.GetBoolean())
            {
                var origin = root.TryGetProperty("openerOrigin", out var oo) ? oo.GetString() : "?";
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "window-opener",
                    Severity = "medium",
                    Title = "OAuth callback page has window.opener",
                    Description = $"Current page was opened as a popup and retains opener ({origin}). Malicious opener pages can read location or navigate this window (tab-nabbing).",
                    Recommendation = "Use COOP/opener isolation: rel=noopener on links, or window.open with noopener; prefer same-tab redirect flow."
                });
            }

            var hash = root.TryGetProperty("hash", out var h) ? h.GetString() ?? "" : "";
            if (hash.Contains("access_token=", StringComparison.OrdinalIgnoreCase)
                || hash.Contains("id_token=", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "fragment-exposure",
                    Severity = "high",
                    Title = "Live page has tokens in location.hash",
                    Description = "Current URL fragment contains OAuth tokens visible to page scripts.",
                    Recommendation = "Exchange code server-side; clear hash immediately after read if unavoidable."
                });
            }

            var referrer = root.TryGetProperty("referrer", out var r) ? r.GetString() ?? "" : "";
            if (referrer.Contains("code=", StringComparison.OrdinalIgnoreCase)
                || referrer.Contains("access_token", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "referrer-leakage",
                    Severity = "high",
                    Title = "document.referrer contains OAuth credentials",
                    Description = $"document.referrer includes OAuth parameters: {Truncate(referrer, 100)}",
                    Recommendation = "Set Referrer-Policy: no-referrer on OAuth callback pages."
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Browser leak check failed: {ex.Message}");
        }
    }

    private static async Task RunActiveProbesAsync(
        AutomationContext? ctx, OAuthFlowResult result, OAuthFlowOptions options, CancellationToken ct)
    {
        var primary = result.CapturedFlows[0];

        if (!options.SkipRedirectUriTests)
            await ProbeRedirectUriAsync(ctx, primary, result, options, ct);

        if (!options.SkipStateTests)
        {
            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "state-removed",
                url => RemoveQueryParam(url, "state"),
                (loc, _) => loc != null,
                "high", "Authorization endpoint accepted request with state removed",
                "IdP proceeded without state — CSRF protection may be absent.");

            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "state-fixed",
                url => SetQueryParam(url, "state", "fixedstate00000000000001"),
                (loc, _) => loc != null,
                "medium", "Authorization endpoint accepted fixed state value",
                "Predictable/fixed state was not rejected at authorize step.");
        }

        if (!options.SkipPkceTests)
        {
            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "pkce-stripped",
                url =>
                {
                    url = RemoveQueryParam(url, "code_challenge");
                    return RemoveQueryParam(url, "code_challenge_method");
                },
                (loc, body) => CodeInRedirect(loc, body, primary.RedirectUri),
                "high", "PKCE parameters stripped but flow may still proceed",
                "Authorize request without code_challenge was not rejected.");

            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "pkce-plain",
                url =>
                {
                    url = SetQueryParam(url, "code_challenge", "testchallenge");
                    return SetQueryParam(url, "code_challenge_method", "plain");
                },
                (loc, body) => CodeInRedirect(loc, body, primary.RedirectUri),
                "high", "PKCE plain method accepted",
                "Server allows code_challenge_method=plain.");
        }

        if (!options.SkipScopeTests)
        {
            var escalated = string.Join(" ", EscalationScopes);
            if (!string.IsNullOrEmpty(primary.Scope))
                escalated = primary.Scope + " " + escalated;

            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "scope-escalation",
                url => SetQueryParam(url, "scope", escalated),
                (loc, body) => CodeInRedirect(loc, body, primary.RedirectUri),
                "high", "Elevated scopes accepted at authorize endpoint",
                "Additional privileged scopes were not rejected in authorize request.");
        }

        if (!options.SkipResponseTypeTests)
        {
            await ProbeAuthorizeMutationAsync(ctx, primary, result, options, "implicit-downgrade",
                url => SetQueryParam(url, "response_type", "token"),
                (loc, body) =>
                    (loc != null && loc.Contains("access_token", StringComparison.OrdinalIgnoreCase))
                    || (body != null && body.Contains("access_token", StringComparison.OrdinalIgnoreCase)),
                "critical", "Implicit flow (response_type=token) accepted",
                "Server allows implicit grant via response_type manipulation.");
        }

        if (!options.SkipTokenExchange)
            await ProbeTokenExchangeAsync(ctx, primary, result, options, ct);

        if (options.HoldCallback)
            result.Errors.Add(
                "holdCallback is reserved for a future callback-intercept flow; use code replay (default) after login completes.");
    }

    private static async Task ProbeRedirectUriAsync(
        AutomationContext? ctx, CapturedOAuthFlow flow, OAuthFlowResult result,
        OAuthFlowOptions options, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(flow.AuthorizationUrl)) return;

        var evilUris = new[]
        {
            ("https://evil.com/callback", "arbitrary-origin"),
            ("https://attacker.example/oauth/callback", "attacker-domain"),
        };

        if (!string.IsNullOrEmpty(flow.RedirectUri) && Uri.TryCreate(flow.RedirectUri, UriKind.Absolute, out var legit))
        {
            var portSuffix = legit is { Scheme: "https", Port: > 0 and not 80 and not 443 }
                ? $":{legit.Port}"
                : "";
            var httpDowngrade = $"http://{legit.Host}{portSuffix}{legit.PathAndQuery}";
            evilUris = evilUris.Concat([
                ($"{legit.Scheme}://evil.{legit.Host}{legit.PathAndQuery}", "subdomain-attack"),
                ($"{legit.Scheme}://{legit.Host}.evil.com{legit.PathAndQuery}", "suffix-attack"),
                (legit.Scheme == "https" ? httpDowngrade : legit.ToString(), "scheme-downgrade"),
                ($"{legit.Scheme}://{legit.Host}{legit.AbsolutePath}/../{legit.AbsolutePath.Trim('/')}?next=https://evil.com", "path-traversal"),
                ($"{legit.Scheme}://{legit.Host}{legit.AbsolutePath}?redirect=https://evil.com", "callback-query-redirect")
            ]).ToArray();
        }

        foreach (var (evilUri, label) in evilUris)
        {
            ct.ThrowIfCancellationRequested();
            var testUrl = SetQueryParam(flow.AuthorizationUrl, "redirect_uri", evilUri);
            var probe = await SendAuthorizeProbeAsync(ctx, testUrl, options.TimeoutMs);
            probe.Test = $"redirect-uri-{label}";
            result.Probes.Add(probe);

            if (probe.Verdict is "vulnerable" or "suspicious")
            {
                result.Findings.Add(new OAuthFlowFinding
                {
                    Category = "redirect-uri",
                    Severity = probe.Verdict == "vulnerable" ? "critical" : "high",
                    Title = $"redirect_uri manipulation ({label})",
                    Description = $"Authorize request with redirect_uri={evilUri} returned: {probe.Notes}",
                    Recommendation = "Enforce exact redirect_uri match against client registration; reject open redirects.",
                    Detail = new { evilUri, probe.Location, probe.StatusCode }
                });
            }
        }
    }

    private static async Task ProbeAuthorizeMutationAsync(
        AutomationContext? ctx, CapturedOAuthFlow flow, OAuthFlowResult result,
        OAuthFlowOptions options, string testName, Func<string, string> mutateUrl,
        Func<string?, string?, bool> isVulnerable, string severity, string title, string description)
    {
        if (string.IsNullOrEmpty(flow.AuthorizationUrl)) return;

        var testUrl = mutateUrl(flow.AuthorizationUrl);
        var probe = await SendAuthorizeProbeAsync(ctx, testUrl, options.TimeoutMs);
        probe.Test = testName;
        result.Probes.Add(probe);

        if (isVulnerable(probe.Location, null))
        {
            probe.Verdict = "vulnerable";
            probe.Notes = description;
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = testName.Split('-')[0],
                Severity = severity,
                Title = title,
                Description = description + $" Location: {Truncate(probe.Location ?? "", 150)}",
                Recommendation = "Reject malformed or policy-violating authorize requests.",
                Detail = new { testUrl, probe.StatusCode, probe.Location }
            });
        }
        else if (probe.StatusCode is >= 200 and < 400)
        {
            probe.Verdict = "inconclusive";
        }
        else
        {
            probe.Verdict = "rejected";
        }
    }

    private static async Task ProbeTokenExchangeAsync(
        AutomationContext? ctx, CapturedOAuthFlow flow, OAuthFlowResult result,
        OAuthFlowOptions options, CancellationToken ct)
    {
        var tokenEndpoint = flow.TokenEndpoint ?? options.TokenEndpoint;
        if (string.IsNullOrEmpty(tokenEndpoint))
        {
            result.Errors.Add("Token exchange probe skipped: no token_endpoint in network log or request.");
            return;
        }

        ct.ThrowIfCancellationRequested();

        var replayCode = flow.ExchangedAuthorizationCodes.LastOrDefault()
                         ?? flow.CapturedAuthorizationCodes.LastOrDefault();
        if (string.IsNullOrEmpty(replayCode))
        {
            if (!options.UseCanaryTokenExchange)
            {
                result.Errors.Add(
                    "Token replay skipped: no authorization code in the network log. Complete login first, or set useCanaryTokenExchange true for a forged-code canary.");
                return;
            }

            replayCode = "stolen_or_replayed_code_00000000000000000000";
        }

        var body = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = replayCode,
            ["client_id"] = flow.ClientId,
        };
        if (!string.IsNullOrEmpty(flow.RedirectUri))
            body["redirect_uri"] = flow.RedirectUri;

        var form = string.Join("&", body.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

        string responseJson;
        try
        {
            if (ctx != null)
            {
                var headers = new Dictionary<string, string>
                {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                };
                responseJson = await ctx.Fetch(tokenEndpoint, "POST", headers, form, options.TimeoutMs);
            }
            else
            {
                responseJson = await HttpPostFormAsync(tokenEndpoint, form, options.TimeoutMs, ct);
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Token exchange probe failed: {ex.Message}");
            return;
        }

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;
        var status = root.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        var respBody = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";

        var probe = new FlowProbe
        {
            Test = options.UseCanaryTokenExchange && replayCode.StartsWith("stolen_", StringComparison.Ordinal)
                ? "token-exchange-canary-code"
                : "token-exchange-code-replay",
            Url = tokenEndpoint,
            StatusCode = status,
            Notes = Truncate(respBody, 200)
        };

        if (status == 200 && (respBody.Contains("access_token", StringComparison.OrdinalIgnoreCase)
                              || respBody.Contains("id_token", StringComparison.OrdinalIgnoreCase)))
        {
            probe.Verdict = "vulnerable";
            var replay = probe.Test == "token-exchange-code-replay";
            result.Findings.Add(new OAuthFlowFinding
            {
                Category = "token-exchange",
                Severity = "critical",
                Title = replay
                    ? "Token endpoint accepted replay of an authorization code"
                    : "Token endpoint issued tokens for invalid authorization code",
                Description = replay
                    ? "The same authorization code from the network log was accepted again at the token endpoint (single-use violation)."
                    : "POST with a forged authorization code returned access_token/id_token.",
                Recommendation = "Validate code, client_id, redirect_uri, PKCE verifier, and single-use before issuing tokens."
            });
        }
        else if (respBody.Contains("invalid_grant", StringComparison.OrdinalIgnoreCase)
                 || respBody.Contains("invalid_code", StringComparison.OrdinalIgnoreCase)
                 || status is 400 or 401)
        {
            probe.Verdict = "rejected";
        }
        else
        {
            probe.Verdict = "inconclusive";
        }

        result.Probes.Add(probe);
    }

    private static async Task<FlowProbe> SendAuthorizeProbeAsync(
        AutomationContext? ctx, string url, int timeoutMs)
    {
        var probe = new FlowProbe { Url = url };

        try
        {
            string json;
            if (ctx != null)
                json = await ctx.Fetch(url, "GET", null, null, timeoutMs, "manual");
            else
                json = await HttpGetManualAsync(url, timeoutMs);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            probe.StatusCode = root.TryGetProperty("status", out var st) ? st.GetInt32() : null;

            if (root.TryGetProperty("headers", out var hdrs))
            {
                foreach (var prop in hdrs.EnumerateObject())
                {
                    if (prop.Name.Equals("Location", StringComparison.OrdinalIgnoreCase))
                    {
                        probe.Location = prop.Value.GetString();
                        break;
                    }
                }
            }

            var body = root.TryGetProperty("body", out var b) ? b.GetString() : null;

            if (probe.Location != null)
            {
                if (probe.Location.Contains("evil.com", StringComparison.OrdinalIgnoreCase)
                    || probe.Location.Contains("attacker.", StringComparison.OrdinalIgnoreCase))
                {
                    probe.Verdict = "vulnerable";
                    probe.Notes = "Redirect to attacker-controlled redirect_uri";
                }
                else if (probe.Location.Contains("code=", StringComparison.OrdinalIgnoreCase)
                         || probe.Location.Contains("access_token", StringComparison.OrdinalIgnoreCase))
                {
                    probe.Verdict = "suspicious";
                    probe.Notes = "Redirect contains authorization code or token";
                }
                else
                {
                    probe.Verdict = "inconclusive";
                    probe.Notes = Truncate(probe.Location, 120);
                }
            }
            else if (probe.StatusCode is >= 300 and < 400)
            {
                probe.Verdict = "inconclusive";
                probe.Notes = "Redirect without Location header captured";
            }
            else if (probe.StatusCode == 200 && body != null
                     && (body.Contains("login", StringComparison.OrdinalIgnoreCase)
                         || body.Contains("sign in", StringComparison.OrdinalIgnoreCase)))
            {
                probe.Verdict = "rejected";
                probe.Notes = "Login page (unauthenticated probe)";
            }
            else
            {
                probe.Verdict = "rejected";
                probe.Notes = $"HTTP {probe.StatusCode}";
            }
        }
        catch (Exception ex)
        {
            probe.Verdict = "error";
            probe.Notes = ex.Message;
        }

        return probe;
    }

    private static async Task<string> HttpGetManualAsync(string url, int timeoutMs)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        var resp = await Http.SendAsync(req, cts.Token);
        var body = await resp.Content.ReadAsStringAsync(cts.Token);
        var headers = new Dictionary<string, string>();
        foreach (var h in resp.Headers)
            headers[h.Key] = string.Join(", ", h.Value);
        return JsonSerializer.Serialize(new
        {
            ok = resp.IsSuccessStatusCode,
            status = (int)resp.StatusCode,
            headers,
            body
        });
    }

    private static async Task<string> HttpPostFormAsync(
        string url, string form, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var content = new StringContent(form, Encoding.UTF8, "application/x-www-form-urlencoded");
        var resp = await Http.PostAsync(url, content, cts.Token);
        var body = await resp.Content.ReadAsStringAsync(cts.Token);
        return JsonSerializer.Serialize(new { status = (int)resp.StatusCode, body });
    }

    private static async Task<CapturedOAuthFlow?> TryBuildFlowFromDiscoveryAsync(
        string issuer, OAuthFlowOptions options, CancellationToken ct)
    {
        try
        {
            var discovery = await OidcDiscoveryFetcher.TryFetchAsync(issuer, options.TimeoutMs, ct);
            if (!discovery.Found || discovery.Configuration is not { } root)
                return null;
            var authEp = root.TryGetProperty("authorization_endpoint", out var ae) ? ae.GetString() : null;
            if (string.IsNullOrEmpty(authEp)) return null;

            var clientId = options.ClientId ?? "test-client";
            var redirect = options.RedirectUri ?? "https://localhost/callback";
            var url = $"{authEp}?client_id={Uri.EscapeDataString(clientId)}" +
                      $"&redirect_uri={Uri.EscapeDataString(redirect)}" +
                      "&response_type=code&scope=openid";

            var flow = ParseAuthorizeUrl(url);
            if (flow == null) return null;
            if (root.TryGetProperty("token_endpoint", out var te))
                flow.TokenEndpoint = te.GetString();
            return flow;
        }
        catch
        {
            return null;
        }
    }

    private static CapturedOAuthFlow? ParseAuthorizeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        if (!IsAuthorizeUrl(url)) return null;

        var clientId = ExtractQueryParamFromUrl(url, "client_id");
        if (string.IsNullOrEmpty(clientId)) return null;

        return new CapturedOAuthFlow
        {
            AuthorizationUrl = url,
            ClientId = clientId,
            RedirectUri = ExtractQueryParamFromUrl(url, "redirect_uri"),
            State = ExtractQueryParamFromUrl(url, "state"),
            Nonce = ExtractQueryParamFromUrl(url, "nonce"),
            CodeChallenge = ExtractQueryParamFromUrl(url, "code_challenge"),
            CodeChallengeMethod = ExtractQueryParamFromUrl(url, "code_challenge_method"),
            Scope = ExtractQueryParamFromUrl(url, "scope"),
            ResponseType = ExtractQueryParamFromUrl(url, "response_type"),
            IssuerHost = uri.Host
        };
    }

    internal static bool IsAuthorizeUrl(string url) =>
        OidcIssuerDetector.IsAuthorizeUrl(url);

    private static bool IsOAuthCallback(string url) =>
        (url.Contains("code=", StringComparison.OrdinalIgnoreCase)
         || url.Contains("access_token=", StringComparison.OrdinalIgnoreCase)
         || url.Contains("#access_token", StringComparison.OrdinalIgnoreCase))
        && (url.Contains("callback", StringComparison.OrdinalIgnoreCase)
            || url.Contains("redirect", StringComparison.OrdinalIgnoreCase)
            || url.Contains("/oauth", StringComparison.OrdinalIgnoreCase)
            || url.Contains("signin", StringComparison.OrdinalIgnoreCase));

    private static bool CodeInRedirect(string? location, string? body, string? legitRedirect)
    {
        if (location == null) return false;
        if (location.Contains("code=", StringComparison.OrdinalIgnoreCase))
        {
            if (legitRedirect != null && location.StartsWith(legitRedirect, StringComparison.OrdinalIgnoreCase))
                return true;
            return true;
        }
        return body != null && body.Contains("authorization code", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPredictableState(string state) =>
        Regex.IsMatch(state, @"^(test|123|abc|state|fixed)", RegexOptions.IgnoreCase)
        || state.All(c => c == state[0]);

    private static string? GuessClientFromCallback(string callbackUrl, List<CapturedOAuthFlow> flows)
    {
        if (!Uri.TryCreate(callbackUrl, UriKind.Absolute, out var cb)) return null;
        foreach (var f in flows)
        {
            if (string.IsNullOrEmpty(f.RedirectUri)) continue;
            if (!Uri.TryCreate(f.RedirectUri, UriKind.Absolute, out var r)) continue;
            if (string.Equals(r.Host, cb.Host, StringComparison.OrdinalIgnoreCase)
                && r.AbsolutePath.Equals(cb.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                return f.ClientId;
        }
        return flows.Count == 1 ? flows[0].ClientId : null;
    }

    private static void MergeFlow(List<CapturedOAuthFlow> flows, CapturedOAuthFlow incoming)
    {
        var existing = flows.FirstOrDefault(f =>
            f.ClientId.Equals(incoming.ClientId, StringComparison.OrdinalIgnoreCase)
            && f.AuthorizationUrl == incoming.AuthorizationUrl);
        if (existing != null)
        {
            if (string.IsNullOrEmpty(existing.TokenEndpoint) && incoming.TokenEndpoint != null)
                existing.TokenEndpoint = incoming.TokenEndpoint;
            return;
        }
        flows.Add(incoming);
    }

    private static string SetQueryParam(string url, string name, string value)
    {
        var uri = new UriBuilder(url);
        var query = ParseQuery(uri.Query);
        query[name] = value;
        uri.Query = string.Join("&", query.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return uri.Uri.ToString();
    }

    private static string RemoveQueryParam(string url, string name)
    {
        var uri = new UriBuilder(url);
        var query = ParseQuery(uri.Query);
        query.Remove(name);
        uri.Query = query.Count == 0
            ? ""
            : string.Join("&", query.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return uri.Uri.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var q = query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return dict;
        foreach (var pair in q.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(pair[..eq]);
            var val = Uri.UnescapeDataString(pair[(eq + 1)..]);
            dict[key] = val;
        }
        return dict;
    }

    private static string? ExtractQueryParamFromUrl(string url, string name)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        return ExtractQueryParam(uri.Query, name);
    }

    private static string? ExtractQueryParam(string query, string name)
    {
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

    private static OAuthFlowSummary BuildSummary(OAuthFlowResult result)
    {
        var s = new OAuthFlowSummary { FlowsCaptured = result.CapturedFlows.Count, ProbesRun = result.Probes.Count };
        foreach (var f in result.Findings)
        {
            switch (f.Severity.ToLowerInvariant())
            {
                case "critical": s.Critical++; break;
                case "high": s.High++; break;
                case "medium": s.Medium++; break;
                case "low": s.Low++; break;
                default: s.Info++; break;
            }
        }
        return s;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    public static string RedactAuthorizeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return url;
        var sensitive = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "state", "nonce", "code_challenge", "code", "code_challenge_method" };
        var kept = uri.Query.TrimStart('?').Split('&')
            .Where(p =>
            {
                var eq = p.IndexOf('=');
                var key = eq < 0 ? p : p[..eq];
                return !sensitive.Contains(key);
            });
        var path = uri.GetLeftPart(UriPartial.Path);
        var qb = string.Join("&", kept);
        return string.IsNullOrEmpty(qb) ? path : $"{path}?{qb}";
    }

    public static string Format(OAuthFlowResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== OAuth/OIDC Flow Security Test ===");
        sb.AppendLine($"Flows captured: {result.CapturedFlows.Count}");
        sb.AppendLine($"Probes run: {result.Probes.Count}");
        sb.AppendLine($"Elapsed: {result.ElapsedMs}ms");
        sb.AppendLine();

        if (result.CapturedFlows.Count > 0)
        {
            sb.AppendLine("CAPTURED FLOWS:");
            foreach (var f in result.CapturedFlows)
            {
                sb.AppendLine($"  client_id={f.ClientId} redirect_uri={f.RedirectUri ?? "(none)"}");
                sb.AppendLine($"    authorize: {Truncate(f.AuthorizationUrl, 100)}");
                if (f.TokenEndpoint != null)
                    sb.AppendLine($"    token: {f.TokenEndpoint}");
            }
            sb.AppendLine();
        }

        if (result.Findings.Count > 0)
        {
            sb.AppendLine($"FINDINGS: {result.Findings.Count}");
            sb.AppendLine($"  Critical: {result.Summary.Critical}, High: {result.Summary.High}, " +
                           $"Medium: {result.Summary.Medium}, Low: {result.Summary.Low}, Info: {result.Summary.Info}");
            sb.AppendLine();
            foreach (var f in result.Findings.OrderByDescending(x => SeverityRank(x.Severity)))
            {
                sb.AppendLine($"[{f.Severity.ToUpper()}] [{f.Category}] {f.Title}");
                sb.AppendLine($"  {f.Description}");
                if (f.Recommendation != null)
                    sb.AppendLine($"  Recommendation: {f.Recommendation}");
                sb.AppendLine();
            }
        }
        else
        {
            sb.AppendLine("No findings.");
        }

        if (result.Probes.Count > 0)
        {
            sb.AppendLine("PROBES:");
            foreach (var p in result.Probes)
                sb.AppendLine($"  [{p.Verdict}] {p.Test} HTTP {p.StatusCode} {Truncate(p.Notes ?? "", 80)}");
        }

        if (result.Errors.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("ERRORS:");
            foreach (var e in result.Errors)
                sb.AppendLine($"  - {e}");
        }

        return sb.ToString().TrimEnd();
    }

    private static int SeverityRank(string s) => s.ToLowerInvariant() switch
    {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1
    };
}
