using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Protocol-agnostic hints from the network log when OAuth authorize capture is empty or incomplete.
/// Routes testers to SAML, OIDC discovery, or OAuth-specific tools without guessing the stack.
/// </summary>
public static class FederatedAuthSignals
{
    public sealed class AuthSignal
    {
        public string Protocol { get; set; } = "";
        public string Binding { get; set; } = "";
        public string Evidence { get; set; } = "";
        public string? SampleUrl { get; set; }
        public List<string> RecommendedTools { get; set; } = [];
    }

    public static List<AuthSignal> ScanNetwork(NetworkLog network) =>
        ScanEntries(network.Entries);

    public static List<AuthSignal> ScanEntries(IEnumerable<NetworkEntry> entries)
    {
        var signals = new List<AuthSignal>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var list = entries as IReadOnlyList<NetworkEntry> ?? entries.ToList();
        foreach (var entry in list)
        {
            if (TrySaml(entry, out var saml))
            {
                var key = "saml:" + saml.Binding + ":" + saml.Evidence;
                if (seen.Add(key))
                    signals.Add(saml);
            }

            if (TryOidcDiscovery(entry, out var oidc) && seen.Add("oidc:" + oidc.Evidence))
                signals.Add(oidc);

            if (TryOAuthHint(entry, out var oauthHint) && seen.Add("oauth-hint:" + oauthHint.Evidence))
                signals.Add(oauthHint);
        }

        AugmentOidcSession(list, signals, seen);
        return signals;
    }

    private static void AugmentOidcSession(
        IReadOnlyList<NetworkEntry> entries, List<AuthSignal> signals, HashSet<string> seen)
    {
        var session = OidcSessionAnalyzer.Analyze(entries);
        if (session.Binding is not ("bff-proxy" or "claims-only")) return;
        if (!seen.Add("oidc:" + session.Binding)) return;

        signals.Add(new AuthSignal
        {
            Protocol = "oidc",
            Binding = session.Binding,
            Evidence = session.Binding == "bff-proxy"
                ? "OIDC reverse-proxy login (claims and/or session cookie, no authorize request in the browser)"
                : "OIDC claims in an application response; authorize request was not captured",
            SampleUrl = session.LoginUi,
            RecommendedTools =
            [
                "Pass issuer to browser_security_oidc_analyze — the login UI host is not the issuer",
                "3 OidcFromNetwork prints the session posture (claim types, cookie flags) without an issuer",
                "Front-channel oauth-flow-test needs an /authorize URL; test the session cookie, claim exposure, and logout instead"
            ]
        });
    }

    public static List<string> BuildNextActions(IReadOnlyList<AuthSignal> signals, bool oauthFlowsCaptured)
    {
        var actions = new List<string>();
        var brokeredOidc = signals.Any(s =>
            s.Protocol.Equals("oidc", StringComparison.OrdinalIgnoreCase)
            && s.Binding is "bff-proxy" or "claims-only");
        if (!oauthFlowsCaptured && !brokeredOidc)
        {
            actions.Add(
                "Browse the real login path (OAuth redirect, SAML SSO POST/redirect, or local form), then re-run oauth-flow-test passiveOnly.");
        }

        foreach (var s in signals)
            actions.AddRange(s.RecommendedTools);

        if (signals.Count == 0 && !oauthFlowsCaptured)
        {
            actions.Add("SAML: after IdP login use browser_saml_decode with source network and findAll true.");
            actions.Add("OIDC: browser_security_oidc_analyze when .well-known was fetched or issuer is known.");
        }

        return actions.Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToList();
    }

    private static bool TrySaml(NetworkEntry entry, out AuthSignal signal)
    {
        signal = null!;
        if (ContainsSamlParam(entry.Url, out var param))
        {
            signal = new AuthSignal
            {
                Protocol = "saml",
                Binding = "HTTP-Redirect",
                Evidence = param + " in redirect URL",
                SampleUrl = TruncateUrl(entry.Url),
                RecommendedTools =
                [
                    "browser_saml_decode with source network and findAll true",
                    "browser_saml_capture mode next-login before IdP navigation",
                    "For active tests: browser_saml_replay (requires captured assertion)"
                ]
            };
            return true;
        }

        if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
            && entry.RequestBody != null
            && ContainsSamlParam(entry.RequestBody, out param))
        {
            signal = new AuthSignal
            {
                Protocol = "saml",
                Binding = "HTTP-POST",
                Evidence = param + " in POST body (ACS)",
                SampleUrl = TruncateUrl(entry.Url),
                RecommendedTools =
                [
                    "browser_saml_decode with source network and findAll true",
                    "Check assertion audience, NotOnOrAfter, and signature via decode output",
                    "browser_saml_replay for signature/audience variants (active, lab only)"
                ]
            };
            return true;
        }

        if (SamlNetworkExtract.LooksLikeModernIdpSamlTraffic(entry.Url))
        {
            signal = new AuthSignal
            {
                Protocol = "saml",
                Binding = "idp-api-bridge",
                Evidence = "IdP SAML API or identity-response (no SAMLRequest/Response param in log URL/body)",
                SampleUrl = TruncateUrl(entry.Url),
                RecommendedTools =
                [
                    "Before the next login: browser_saml_capture mode next-login with captureRequests true",
                    "browser_saml_decode / saml_capture mode network after login (JSON/XML response bodies if captured)",
                    "Classic saml-replay needs a captured assertion — arm capture before SSO if the IdP uses API bridges"
                ]
            };
            return true;
        }

        if (!string.IsNullOrEmpty(entry.ResponseBody)
            && SamlNetworkExtract.TryExtractSamlResponsePayload(entry, out _, out var kind))
        {
            signal = new AuthSignal
            {
                Protocol = "saml",
                Binding = kind,
                Evidence = "SAML material in captured response body",
                SampleUrl = TruncateUrl(entry.Url),
                RecommendedTools =
                [
                    "browser_saml_decode with source network and findAll true",
                    "browser_saml_capture mode network"
                ]
            };
            return true;
        }

        return false;
    }

    private static bool TryOidcDiscovery(NetworkEntry entry, out AuthSignal signal)
    {
        signal = null!;
        if (!entry.Url.Contains("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)
            && !entry.Url.Contains("/.well-known/oauth-authorization-server", StringComparison.OrdinalIgnoreCase))
            return false;

        signal = new AuthSignal
        {
            Protocol = "oidc",
            Binding = "discovery",
            Evidence = "OpenID/OAuth metadata document fetched",
            SampleUrl = TruncateUrl(entry.Url),
            RecommendedTools =
            [
                "browser_security_oidc_analyze (issuer auto-detect from traffic)",
                "Complete OAuth login to capture /authorize, then oauth-flow-test passiveOnly"
            ]
        };
        return true;
    }

    private static bool TryOAuthHint(NetworkEntry entry, out AuthSignal signal)
    {
        signal = null!;
        if (OAuthFlowTester.IsAuthorizeUrl(entry.Url))
            return false;

        var url = entry.Url;
        if (!url.Contains("/oauth", StringComparison.OrdinalIgnoreCase)
            && !url.Contains("openid", StringComparison.OrdinalIgnoreCase)
            && !url.Contains("/authorize", StringComparison.OrdinalIgnoreCase))
            return false;

        signal = new AuthSignal
        {
            Protocol = "oauth-partial",
            Binding = "traffic",
            Evidence = "OAuth/OIDC-related URL without a parseable authorize request",
            SampleUrl = TruncateUrl(url),
            RecommendedTools =
            [
                "Finish the browser login redirect chain (WaitForFinalNavigation), then re-run passive oauth-flow-test",
                "Or pass authorizationUrl + clientId + redirectUri explicitly"
            ]
        };
        return true;
    }

    private static bool ContainsSamlParam(string text, out string param)
    {
        if (text.Contains("SAMLResponse=", StringComparison.OrdinalIgnoreCase))
        {
            param = "SAMLResponse";
            return true;
        }

        if (text.Contains("SAMLRequest=", StringComparison.OrdinalIgnoreCase))
        {
            param = "SAMLRequest";
            return true;
        }

        param = "";
        return false;
    }

    private static string TruncateUrl(string url) =>
        url.Length <= 160 ? url : url[..160] + "…";
}
