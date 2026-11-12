using System.Text;
using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public sealed class OidcSessionAnalyzerTests
{
    const string Secret = "SECRET-VALUE-MUST-NOT-LEAK";

    [Fact]
    public void Bff_login_is_recognized_without_treating_the_login_ui_as_issuer()
    {
        var session = OidcSessionAnalyzer.Analyze(BffEntries(), [ProxyCookie(httpOnly: true, secure: true)]);

        Assert.True(session.Observed);
        Assert.Equal("bff-proxy", session.Binding);
        Assert.Null(session.Issuer);
        Assert.Equal("https://idp.example/Citizen", session.LoginUi);
        Assert.Equal("app.example", session.AppHost);
        Assert.Equal("oidcproxy.cookie", session.SessionCookieName);
        Assert.False(session.TokensVisibleInBrowser);
        Assert.Contains(session.ClaimTypes, t => t == "at_hash");
        Assert.Contains(session.ClaimTypes, t => t.Contains("personalIdentityNumber", StringComparison.Ordinal));
        Assert.Contains(session.Findings, f => f.Title.Contains("National-identifier", StringComparison.Ordinal));
        Assert.DoesNotContain(session.Evidence, e => e.Contains(Secret, StringComparison.Ordinal));
        Assert.DoesNotContain(OidcSessionAnalyzer.Format(session), Secret, StringComparison.Ordinal);
        Assert.Contains("issuer", OidcSessionAnalyzer.MissingIssuerMessage(session), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Proxy_cookie_without_httponly_is_medium()
    {
        var session = OidcSessionAnalyzer.Analyze(BffEntries(), [ProxyCookie(httpOnly: false, secure: true)]);
        Assert.Contains(session.Findings, f => f.Severity == "medium" && f.Title.Contains("page script", StringComparison.Ordinal));
    }

    [Fact]
    public void Keycloak_authorize_url_yields_realm_issuer()
    {
        var url = "https://login.example/realms/myrealm/protocol/openid-connect/auth?client_id=app&state=abc";
        var session = OidcSessionAnalyzer.Analyze([
            new NetworkEntry { Method = "GET", Url = url, ResourceType = "Document", StatusCode = 302 }
        ]);

        Assert.Equal("front-channel", session.Binding);
        Assert.Equal("https://login.example/realms/myrealm", session.Issuer);
        Assert.True(OidcIssuerDetector.IsAuthorizeUrl(url));
    }

    [Fact]
    public void Google_style_authorize_url_yields_host_issuer()
    {
        var url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb";
        Assert.Equal("https://accounts.google.com", OidcIssuerDetector.IssuerFromAuthorizeUrl(url));
    }

    [Fact]
    public void Jwt_iss_in_a_response_body_is_the_issuer()
    {
        var token = Jwt("{\"iss\":\"https://login.example/realms/myrealm\",\"aud\":\"app\"}");
        var session = OidcSessionAnalyzer.Analyze([
            new NetworkEntry
            {
                Method = "POST",
                Url = "https://app.example/oauth/token",
                StatusCode = 200,
                ResponseBody = "{\"id_token\":\"" + token + "\"}"
            }
        ]);

        Assert.Equal("https://login.example/realms/myrealm", session.Issuer);
        Assert.True(session.TokensVisibleInBrowser);
        Assert.DoesNotContain(OidcSessionAnalyzer.Format(session), token, StringComparison.Ordinal);
    }

    [Fact]
    public void Ordinary_json_is_not_an_oidc_session()
    {
        var session = OidcSessionAnalyzer.Analyze([
            new NetworkEntry
            {
                Method = "GET",
                Url = "https://app.example/api/items",
                StatusCode = 200,
                ResponseBody = "{\"name\":\"notebook\"}"
            }
        ]);
        Assert.False(session.Observed);
    }

    [Fact]
    public void Oauth_flow_signals_point_at_the_proxy_login_instead_of_asking_to_browse_again()
    {
        var signals = FederatedAuthSignals.ScanEntries(BffEntries());
        Assert.Contains(signals, s => s.Protocol == "oidc" && s.Binding == "bff-proxy");
        var actions = FederatedAuthSignals.BuildNextActions(signals, oauthFlowsCaptured: false);
        Assert.DoesNotContain(actions, a => a.Contains("Browse the real login path", StringComparison.Ordinal));
        Assert.Contains(actions, a => a.Contains("issuer", StringComparison.OrdinalIgnoreCase));
    }

    static List<NetworkEntry> BffEntries() =>
    [
        new NetworkEntry
        {
            Method = "GET",
            Url = "https://idp.example/Citizen?sign=1&id=" + Secret,
            ResourceType = "Document",
            StatusCode = 200,
            RequestHeaders = new Dictionary<string, string> { ["Referer"] = "https://app.example/" }
        },
        new NetworkEntry
        {
            Method = "GET",
            Url = "https://app.example/api/user-info",
            ResourceType = "Fetch",
            StatusCode = 200,
            RequestHeaders = new Dictionary<string, string> { ["Referer"] = "https://app.example/home" },
            ResponseBody =
                "{\"claims\":[" +
                "{\"type\":\"at_hash\",\"value\":\"" + Secret + "\"}," +
                "{\"type\":\"https://id.oidc.se/claim/personalIdentityNumber\",\"value\":\"" + Secret + "\"}" +
                "]}"
        }
    ];

    static OidcSessionAnalyzer.CookieInfo ProxyCookie(bool httpOnly, bool secure) =>
        new()
        {
            Name = "oidcproxy.cookie",
            Domain = "app.example",
            HttpOnly = httpOnly,
            Secure = secure,
            SameSite = "lax"
        };

    static string Jwt(string payloadJson)
    {
        static string B64(string value) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return B64("{\"alg\":\"RS256\"}") + "." + B64(payloadJson) + ".sig";
    }
}
