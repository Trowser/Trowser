using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive read of an OIDC login as the browser saw it.
/// Covers a front-channel <c>/authorize</c> redirect, a bearer token, and a reverse-proxy
/// (BFF) login where the app holds the tokens and the browser only sees a session cookie,
/// a login-UI hop, and claim JSON.
/// </summary>
public static class OidcSessionAnalyzer
{
    private static readonly string[] StrongClaimNames = ["at_hash", "c_hash"];

    private static readonly string[] LoginPathHints =
    [
        "/authn", "bank-id", "bankid", "freja", "/citizen", "/login", "/signin",
        "/sso", "openid-connect", "/oauth", "/authorize", "/saml", "/protocol/"
    ];

    public sealed class CookieInfo
    {
        public string Name { get; init; } = "";
        public string Domain { get; init; } = "";
        public bool Secure { get; init; }
        public bool HttpOnly { get; init; }
        public string SameSite { get; init; } = "";
        /// <summary>Set when the cookie value is a JWT. The value itself is not kept.</summary>
        public string? JwtIssuer { get; init; }
        public bool ValueIsJwt { get; init; }

        public static CookieInfo FromDictionary(IReadOnlyDictionary<string, object> cookie)
        {
            cookie.TryGetValue("name", out var nameObj);
            cookie.TryGetValue("domain", out var domainObj);
            cookie.TryGetValue("value", out var valueObj);
            cookie.TryGetValue("secure", out var secureObj);
            cookie.TryGetValue("httpOnly", out var httpOnlyObj);
            cookie.TryGetValue("sameSite", out var sameSiteObj);
            var value = valueObj?.ToString() ?? "";
            var jwt = value.StartsWith("eyJ", StringComparison.Ordinal)
                      && value.Count(c => c == '.') >= 2;
            return new CookieInfo
            {
                Name = nameObj?.ToString() ?? "",
                Domain = domainObj?.ToString() ?? "",
                Secure = AsBool(secureObj),
                HttpOnly = AsBool(httpOnlyObj),
                SameSite = sameSiteObj?.ToString() ?? "",
                ValueIsJwt = jwt,
                JwtIssuer = jwt ? OidcIssuerDetector.IssuerFromJwt(value) : null
            };
        }

        public static List<CookieInfo> FromDictionaries(IEnumerable<Dictionary<string, object>> cookies) =>
            cookies.Select(c => FromDictionary(c)).Where(c => !string.IsNullOrEmpty(c.Name)).ToList();

        private static bool AsBool(object? value) =>
            value is bool b ? b : bool.TryParse(value?.ToString(), out var parsed) && parsed;
    }

    public sealed class SessionFinding
    {
        public string Severity { get; init; } = "info";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public string? Recommendation { get; init; }
    }

    public sealed class SessionResult
    {
        public bool Observed { get; set; }
        /// <summary><c>front-channel</c>, <c>bearer</c>, <c>token</c>, <c>bff-proxy</c>, <c>claims-only</c>, <c>discovery</c>, or <c>none</c>.</summary>
        public string Binding { get; set; } = "none";
        public string? Issuer { get; set; }
        public string? LoginUi { get; set; }
        public string? AppHost { get; set; }
        public string? SessionCookieName { get; set; }
        public bool TokensVisibleInBrowser { get; set; }
        public List<string> Evidence { get; set; } = [];
        public List<string> ClaimTypes { get; set; } = [];
        public List<SessionFinding> Findings { get; set; } = [];
        public List<string> NotTestable { get; set; } = [];
        public List<string> NextActions { get; set; } = [];
    }

    public static SessionResult Analyze(IEnumerable<NetworkEntry> entries, IReadOnlyList<CookieInfo>? cookies = null)
    {
        var list = entries.ToList();
        var result = new SessionResult
        {
            Issuer = OidcIssuerDetector.TryDetect(list, cookies)
        };

        var authorize = list.FirstOrDefault(e => OidcIssuerDetector.IsAuthorizeUrl(e.Url));
        var discovery = list.FirstOrDefault(e => OidcIssuerDetector.IssuerFromDiscoveryUrl(e.Url) != null);
        var bearer = list.Any(e =>
            OidcIssuerDetector.TryGetHeader(e.RequestHeaders, "Authorization", out var auth)
            && auth.StartsWith("Bearer eyJ", StringComparison.OrdinalIgnoreCase));

        var proxyCookie = cookies?.FirstOrDefault(c => IsProxyCookie(c.Name));
        if (proxyCookie == null)
            proxyCookie = ProxyCookieFromSetCookie(list);

        var claims = CollectClaims(list);
        var hop = FindLoginHop(list);
        var tokens = FindVisibleTokens(list, cookies);

        result.ClaimTypes = claims.Types;
        result.TokensVisibleInBrowser = tokens.Visible;
        if (hop is { LoginShaped: true })
        {
            result.LoginUi = hop.LoginUi;
            result.AppHost = hop.AppHost;
        }
        result.SessionCookieName = proxyCookie?.Name;

        if (authorize != null)
            result.Binding = "front-channel";
        else if (bearer)
            result.Binding = "bearer";
        else if (proxyCookie != null || (claims.Strong && hop is { LoginShaped: true }))
            result.Binding = "bff-proxy";
        else if (claims.Strong)
            result.Binding = "claims-only";
        else if (discovery != null)
            result.Binding = "discovery";
        else if (result.Issuer != null)
            result.Binding = "token";
        else
            result.Binding = "none";

        result.Observed = result.Binding != "none";
        if (!result.Observed)
            return result;

        if (authorize != null)
            result.Evidence.Add("Authorize request " + PathOnly(authorize.Url));
        if (discovery != null)
            result.Evidence.Add("Discovery document " + PathOnly(discovery.Url));
        if (bearer)
            result.Evidence.Add("Bearer JWT on an API request");
        if (proxyCookie != null)
            result.Evidence.Add(DescribeCookie(proxyCookie));
        if (hop is { LoginShaped: true })
            result.Evidence.Add($"Login UI {hop.LoginUi} (app host {hop.AppHost})");
        if (claims.Types.Count > 0)
            result.Evidence.Add($"OIDC claims on {claims.Where} ({string.Join(", ", claims.Types.Take(12))})");
        if (!string.IsNullOrEmpty(result.Issuer))
            result.Evidence.Add("Issuer " + result.Issuer);

        AddFindings(result, proxyCookie, claims, tokens);
        AddGaps(result);
        return result;
    }

    public static string MissingIssuerMessage(SessionResult session)
    {
        var how = session.Binding switch
        {
            "bff-proxy" =>
                "This login is an OIDC reverse proxy (BFF): the browser saw the login UI and app claims, not the authorize request. ",
            "claims-only" =>
                "OIDC claims were returned to the browser, but not the issuer. ",
            _ =>
                "OIDC traffic was captured, but not an issuer. "
        };
        return "No issuer URL in the network log. " + how +
               "Pass issuer (for example https://login.example.com/realms/myrealm) to run the provider audit. " +
               "The login UI host is not the issuer.";
    }

    public static string Format(SessionResult result)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== OIDC session (what the browser saw) ===");
        if (!result.Observed)
        {
            sb.AppendLine("No OIDC session recognized in the network log or cookies.");
            sb.AppendLine("Auto-detect still looks for a discovery document, a JWT iss, or an authorize URL.");
            sb.AppendLine("A reverse-proxy login shows up here when the app returns OIDC claims or sets an oidc-proxy cookie.");
            return sb.ToString().TrimEnd();
        }

        sb.AppendLine($"Binding: {result.Binding}");
        sb.AppendLine($"Issuer: {(string.IsNullOrEmpty(result.Issuer) ? "(not in the browser)" : result.Issuer)}");
        if (!string.IsNullOrEmpty(result.AppHost))
            sb.AppendLine($"App host: {result.AppHost}");
        if (!string.IsNullOrEmpty(result.LoginUi))
            sb.AppendLine($"Login UI: {result.LoginUi}");
        if (!string.IsNullOrEmpty(result.SessionCookieName))
            sb.AppendLine($"Session cookie: {result.SessionCookieName}");
        sb.AppendLine($"Tokens visible in the browser: {(result.TokensVisibleInBrowser ? "yes" : "no")}");
        if (result.ClaimTypes.Count > 0)
            sb.AppendLine("Claim types: " + string.Join(", ", result.ClaimTypes));

        if (result.Evidence.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("EVIDENCE:");
            foreach (var line in result.Evidence)
                sb.AppendLine("  " + line);
        }

        if (result.Findings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"FINDINGS: {result.Findings.Count}");
            foreach (var f in result.Findings.OrderByDescending(f => Rank(f.Severity)))
            {
                sb.AppendLine($"[{f.Severity.ToUpperInvariant()}] {f.Title}");
                sb.AppendLine($"  {f.Description}");
                if (!string.IsNullOrEmpty(f.Recommendation))
                    sb.AppendLine($"  Recommendation: {f.Recommendation}");
            }
        }

        if (result.NotTestable.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("NOT TESTABLE FROM THIS LOG:");
            foreach (var line in result.NotTestable)
                sb.AppendLine("  - " + line);
        }

        if (result.NextActions.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("NEXT:");
            foreach (var line in result.NextActions)
                sb.AppendLine("  - " + line);
        }

        return sb.ToString().TrimEnd();
    }

    private static void AddFindings(SessionResult result, CookieInfo? proxyCookie, ClaimScan claims, TokenScan tokens)
    {
        if (result.Binding is "bff-proxy" or "claims-only")
        {
            result.Findings.Add(new SessionFinding
            {
                Severity = "info",
                Title = "OIDC login is brokered outside the browser",
                Description = result.Binding == "bff-proxy"
                    ? "The app completed the code flow on the server. The browser did not send /authorize and did not receive the access or ID token."
                    : "An application response contains OIDC claims, and the authorize request was not in the network log.",
                Recommendation = "Pass the issuer URL to audit the provider. Use the session cookie and claim list to test the app side of the login."
            });
        }

        if (proxyCookie != null)
        {
            if (!proxyCookie.HttpOnly)
            {
                result.Findings.Add(new SessionFinding
                {
                    Severity = "medium",
                    Title = $"OIDC session cookie {proxyCookie.Name} is readable by page script",
                    Description = "The proxy session cookie is not HttpOnly, so any script on the page can copy it.",
                    Recommendation = "Mark the session cookie HttpOnly."
                });
            }
            if (!proxyCookie.Secure)
            {
                result.Findings.Add(new SessionFinding
                {
                    Severity = "medium",
                    Title = $"OIDC session cookie {proxyCookie.Name} is not marked Secure",
                    Description = "The cookie can be sent on a non-HTTPS request.",
                    Recommendation = "Mark the session cookie Secure."
                });
            }
            if (proxyCookie.SameSite.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(new SessionFinding
                {
                    Severity = "low",
                    Title = $"OIDC session cookie {proxyCookie.Name} is SameSite=None",
                    Description = "The browser will send this cookie on cross-site requests.",
                    Recommendation = "Use Lax or Strict unless a cross-site embedding flow requires None."
                });
            }
        }

        foreach (var type in claims.NationalIdTypes)
        {
            result.Findings.Add(new SessionFinding
            {
                Severity = "low",
                Title = "National-identifier claim is visible to the browser",
                Description = $"Response {claims.Where} includes claim type {type}. The value is not stored in this report. Page script that can call this endpoint can read it.",
                Recommendation = "Keep the identifier on the server when the page does not need to display it."
            });
        }

        if (tokens.InUrl.Count > 0)
        {
            var kinds = string.Join(", ", tokens.InUrl);
            var tokenInUrl = tokens.InUrl.Any(k => k is "access_token" or "id_token");
            result.Findings.Add(new SessionFinding
            {
                Severity = tokenInUrl ? "high" : "info",
                Title = tokenInUrl ? "OIDC token in a browser URL" : "Authorization code in a browser URL",
                Description = tokenInUrl
                    ? $"Query or fragment contained {kinds}. Tokens in URLs leak via history, logs, and Referer."
                    : $"Query contained {kinds}. Normal for a front-channel code flow; the code should be single-use and bound to PKCE.",
                Recommendation = tokenInUrl
                    ? "Use authorization-code + PKCE and keep tokens in the response body or a server session."
                    : "Confirm the proxy or client exchanges the code immediately and the redirect URI is registered exactly."
            });
        }
        else if (!result.TokensVisibleInBrowser && result.Binding is "bff-proxy" or "claims-only")
        {
            result.Findings.Add(new SessionFinding
            {
                Severity = "info",
                Title = "Access token, ID token, and authorization code were not visible",
                Description = "Nothing captured in URLs, Authorization headers, cookie values, or response bodies was an access token, ID token, or authorization code.",
                Recommendation = "Test the session cookie and the claims the app chose to expose. Provider checks still need the issuer."
            });
        }
    }

    private static void AddGaps(SessionResult result)
    {
        if (string.IsNullOrEmpty(result.Issuer))
        {
            result.NotTestable.Add("Provider metadata (grants, PKCE advertisement, signing algorithms, JWKS) — pass an issuer URL.");
            result.NextActions.Add("Set issuer in 3 OidcFromNetwork.csx, or pass \"issuer\" to POST /api/security/oidc-analyze.");
        }

        if (result.Binding is "bff-proxy" or "claims-only")
        {
            result.NotTestable.Add("Authorize parameters (state, nonce, PKCE, redirect_uri) — the browser did not send /authorize.");
            result.NotTestable.Add("Token audience and expiry — the tokens stayed on the proxy.");
            result.NextActions.Add("oauth-flow-test front-channel probes need an authorizationUrl. For this login, test the session cookie, claim exposure, and logout.");
        }

        if (!string.IsNullOrEmpty(result.LoginUi) && string.IsNullOrEmpty(result.Issuer))
            result.NextActions.Add("Do not use the login UI host as the issuer. Discovery is often on a different URL, and this host may not publish /.well-known/openid-configuration.");
    }

    private static ClaimScan CollectClaims(IReadOnlyList<NetworkEntry> entries)
    {
        var scan = new ClaimScan();
        foreach (var entry in entries)
        {
            if (string.IsNullOrEmpty(entry.ResponseBody)) continue;
            if (IsStaticPath(entry.Url)) continue;
            if (entry.ResponseBody.Length > 150_000) continue;
            if (!entry.ResponseBody.Contains("at_hash", StringComparison.Ordinal)
                && !entry.ResponseBody.Contains("c_hash", StringComparison.Ordinal)
                && !entry.ResponseBody.Contains("openid", StringComparison.OrdinalIgnoreCase)
                && !entry.ResponseBody.Contains("/claim/", StringComparison.OrdinalIgnoreCase)
                && !entry.ResponseBody.Contains("\"iss\"", StringComparison.OrdinalIgnoreCase)
                && !entry.ResponseBody.Contains("\"claims\"", StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                using var doc = JsonDocument.Parse(entry.ResponseBody);
                var local = new List<string>();
                var nodes = 0;
                WalkClaims(doc.RootElement, 0, ref nodes, local);
                if (local.Count == 0) continue;
                foreach (var type in local)
                    if (!scan.Types.Contains(type, StringComparer.OrdinalIgnoreCase))
                        scan.Types.Add(type);
                scan.Where ??= $"{entry.Method} {PathOnly(entry.Url)}";
            }
            catch
            {
                /* not JSON */
            }
        }

        scan.Strong = scan.Types.Any(t =>
            StrongClaimNames.Contains(t, StringComparer.OrdinalIgnoreCase)
            || t.Contains("openid", StringComparison.OrdinalIgnoreCase)
            || t.Contains("/claim/", StringComparison.OrdinalIgnoreCase)
            || t.Contains("oidc", StringComparison.OrdinalIgnoreCase));
        scan.NationalIdTypes = scan.Types.Where(IsNationalIdClaim).ToList();
        return scan;
    }

    private static void WalkClaims(JsonElement el, int depth, ref int nodes, List<string> types)
    {
        if (depth > 8 || nodes > 4000) return;
        nodes++;
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    if (prop.Name.Equals("type", StringComparison.OrdinalIgnoreCase)
                        && prop.Value.ValueKind == JsonValueKind.String)
                    {
                        var type = prop.Value.GetString();
                        if (!string.IsNullOrEmpty(type))
                            types.Add(type);
                    }
                    else if (StrongClaimNames.Contains(prop.Name, StringComparer.OrdinalIgnoreCase)
                             || prop.Name.Equals("acr", StringComparison.OrdinalIgnoreCase)
                             || prop.Name.Equals("amr", StringComparison.OrdinalIgnoreCase))
                    {
                        types.Add(prop.Name);
                    }
                    WalkClaims(prop.Value, depth + 1, ref nodes, types);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    WalkClaims(item, depth + 1, ref nodes, types);
                break;
        }
    }

    private static LoginHop? FindLoginHop(IReadOnlyList<NetworkEntry> entries)
    {
        LoginHop? best = null;
        foreach (var entry in entries)
        {
            if (IsStaticPath(entry.Url)) continue;
            if (!OidcIssuerDetector.TryGetHeader(entry.RequestHeaders, "Referer", out var referer)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var target)) continue;
            if (!Uri.TryCreate(referer, UriKind.Absolute, out var from)) continue;
            if (string.Equals(target.Host, from.Host, StringComparison.OrdinalIgnoreCase)) continue;
            var pathLooksLikeLogin = LoginPathHints.Any(h =>
                target.AbsolutePath.Contains(h, StringComparison.OrdinalIgnoreCase));
            var isDocument = entry.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase);
            if (!pathLooksLikeLogin && !isDocument) continue;

            var hop = new LoginHop(
                $"{target.Scheme}://{target.Authority}{target.AbsolutePath}",
                from.Host,
                pathLooksLikeLogin);
            if (best == null || (pathLooksLikeLogin && !best.LoginShaped))
                best = hop;
            if (pathLooksLikeLogin && isDocument)
                return hop;
        }
        return best;
    }

    private static TokenScan FindVisibleTokens(IReadOnlyList<NetworkEntry> entries, IReadOnlyList<CookieInfo>? cookies)
    {
        var scan = new TokenScan();
        foreach (var entry in entries)
        {
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            foreach (var key in new[] { "code", "access_token", "id_token" })
            {
                if (HasQueryKey(uri.Query, key) || HasQueryKey(uri.Fragment, key))
                    scan.InUrl.Add(key);
            }

            if (!string.IsNullOrEmpty(entry.ResponseBody)
                && !IsStaticPath(entry.Url)
                && (entry.ResponseBody.Contains("\"id_token\"", StringComparison.OrdinalIgnoreCase)
                    || entry.ResponseBody.Contains("\"access_token\"", StringComparison.OrdinalIgnoreCase)))
            {
                if (entry.ResponseBody.Contains("eyJ", StringComparison.Ordinal))
                    scan.Visible = true;
            }
        }

        if (cookies != null && cookies.Any(c => c.ValueIsJwt))
            scan.Visible = true;
        if (scan.InUrl.Count > 0)
            scan.Visible = true;
        if (entries.Any(e =>
                OidcIssuerDetector.TryGetHeader(e.RequestHeaders, "Authorization", out var auth)
                && auth.StartsWith("Bearer eyJ", StringComparison.OrdinalIgnoreCase)))
            scan.Visible = true;
        return scan;
    }

    private static bool HasQueryKey(string queryOrFragment, string name)
    {
        var q = queryOrFragment.TrimStart('?', '#');
        if (string.IsNullOrEmpty(q)) return false;
        foreach (var pair in q.Split('&'))
        {
            var eq = pair.IndexOf('=');
            var key = eq >= 0 ? pair[..eq] : pair;
            if (Uri.UnescapeDataString(key).Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static CookieInfo? ProxyCookieFromSetCookie(IReadOnlyList<NetworkEntry> entries)
    {
        foreach (var entry in entries)
        {
            if (!OidcIssuerDetector.TryGetHeader(entry.ResponseHeaders, "Set-Cookie", out var setCookie))
                continue;
            var name = setCookie.Split('=', 2)[0].Trim();
            if (!IsProxyCookie(name)) continue;
            return new CookieInfo
            {
                Name = name,
                Domain = entry.Host,
                Secure = setCookie.Contains("Secure", StringComparison.OrdinalIgnoreCase),
                HttpOnly = setCookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase),
                SameSite = ReadSameSite(setCookie)
            };
        }
        return null;
    }

    private static string ReadSameSite(string setCookie)
    {
        var idx = setCookie.IndexOf("samesite=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "";
        var rest = setCookie[(idx + "samesite=".Length)..];
        var end = rest.IndexOf(';');
        return (end >= 0 ? rest[..end] : rest).Trim();
    }

    private static bool IsProxyCookie(string name)
    {
        var n = name.ToLowerInvariant();
        return n.Contains("oidcproxy")
               || n.Contains("oidc-proxy")
               || n.Contains("oidc_proxy")
               || n.Contains("oauth2-proxy")
               || n.Contains("oauth2_proxy")
               || n.Contains("oidc.session")
               || n.Contains("oidc_session")
               || n.Contains("oidc-session");
    }

    private static bool IsNationalIdClaim(string type)
    {
        var t = type.ToLowerInvariant();
        return t.Contains("personalidentity")
               || t.Contains("personal_identity")
               || t.Contains("personnummer")
               || t.Contains("nationalid")
               || t.Contains("national_id")
               || t.Contains("national-id")
               || t.Contains("socialsecurity")
               || t.Contains("/ssn")
               || t.EndsWith("ssn", StringComparison.Ordinal);
    }

    private static bool IsStaticPath(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var path = uri.AbsolutePath;
        return path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".css", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".map", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".svg", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith(".woff2", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/assets/", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/fonts/", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/media/", StringComparison.OrdinalIgnoreCase);
    }

    private static string PathOnly(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Length <= 120 ? url : url[..120];
        return $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}";
    }

    private static string DescribeCookie(CookieInfo cookie)
    {
        var flags = new List<string>();
        flags.Add(cookie.HttpOnly ? "HttpOnly" : "not HttpOnly");
        flags.Add(cookie.Secure ? "Secure" : "not Secure");
        if (!string.IsNullOrEmpty(cookie.SameSite))
            flags.Add("SameSite=" + cookie.SameSite);
        var domain = string.IsNullOrEmpty(cookie.Domain) ? "" : " on " + cookie.Domain;
        return $"Session cookie {cookie.Name}{domain} ({string.Join(", ", flags)})";
    }

    private static int Rank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private sealed class ClaimScan
    {
        public List<string> Types { get; } = [];
        public List<string> NationalIdTypes { get; set; } = [];
        public bool Strong { get; set; }
        public string? Where { get; set; }
    }

    private sealed class TokenScan
    {
        public bool Visible { get; set; }
        public HashSet<string> InUrl { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed record LoginHop(string LoginUi, string AppHost, bool LoginShaped);
}
