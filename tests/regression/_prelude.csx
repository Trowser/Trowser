// Shared fixture helpers for the offline Trowser regression suite.
// Concatenated ahead of each test by run-regression.ps1 (ScriptEngine has no #load resolver).
// Helpers are top-level locals on the generated script class — available to the whole test.

const string FixtureHost = "https://trowser-regression.test";
const string FixtureOrigin = "https://trowser-regression.test";

string FixtureUrl(string path = "/")
{
    if (string.IsNullOrEmpty(path)) path = "/";
    if (!path.StartsWith("/")) path = "/" + path;
    return FixtureHost + path;
}

Dictionary<string, string> HtmlHeaders(Dictionary<string, string>? extra = null)
{
    var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Content-Type"] = "text/html; charset=utf-8",
        ["Cache-Control"] = "no-store"
    };
    if (extra != null)
        foreach (var kv in extra) h[kv.Key] = kv.Value;
    return h;
}

Dictionary<string, string> JsonHeaders(Dictionary<string, string>? extra = null)
{
    var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Content-Type"] = "application/json; charset=utf-8",
        ["Cache-Control"] = "no-store"
    };
    if (extra != null)
        foreach (var kv in extra) h[kv.Key] = kv.Value;
    return h;
}

/// <summary>Missing CSP / HSTS / XFO / Referrer-Policy / Permissions-Policy — should produce findings.</summary>
Dictionary<string, string> VulnerableHeaders()
{
    return HtmlHeaders(new Dictionary<string, string>
    {
        ["Server"] = "Apache/2.4.49",
        ["X-Powered-By"] = "PHP/7.4.0"
    });
}

/// <summary>Sensible security header set — clean twin for header audits.</summary>
Dictionary<string, string> SecureHeaders()
{
    return HtmlHeaders(new Dictionary<string, string>
    {
        ["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains",
        ["X-Content-Type-Options"] = "nosniff",
        ["X-Frame-Options"] = "DENY",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    });
}

/// <summary>
/// Like SecureHeaders but allows inline scripts (script-src unsafe-inline).
/// Use for fixture pages that need setTimeout/console/fetch handlers in the HTML.
/// </summary>
Dictionary<string, string> ScriptableHeaders()
{
    return HtmlHeaders(new Dictionary<string, string>
    {
        ["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'",
        ["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains",
        ["X-Content-Type-Options"] = "nosniff",
        ["X-Frame-Options"] = "DENY",
        ["Referrer-Policy"] = "strict-origin-when-cross-origin",
        ["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    });
}

/// <summary>Strip JSON string quotes returned by GetStorageItem / ExecuteJs.</summary>
string UnquoteJson(string? value)
{
    if (value == null) return "";
    var s = value.Trim();
    if (s.Length >= 2 && s[0] == '"' && s[^1] == '"')
        s = s.Substring(1, s.Length - 2);
    return s.Replace("\\\"", "\"");
}

string InsecureCookie(string name = "sessionid", string value = "abc123")
    => $"{name}={value}; Path=/";

string SecureCookie(string name = "sessionid", string value = "abc123")
    => $"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict";

void SetupPage(string url, string html, Dictionary<string, string>? headers = null, int statusCode = 200)
{
    ClearMocks();
    MockResponse(url, statusCode: statusCode, body: html, headers: headers ?? HtmlHeaders());
}

void SetupApi(string urlPattern, int statusCode = 200, string? body = null,
    Dictionary<string, string>? headers = null, string? method = null, int delayMs = 0)
{
    MockResponse(urlPattern, statusCode: statusCode, body: body ?? "{}",
        method: method, headers: headers ?? JsonHeaders(), delayMs: delayMs);
}

string MinimalHtml(string title, string bodyInner, string? headExtra = null)
{
    return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""utf-8"">
<title>{title}</title>
{headExtra ?? ""}
</head>
<body>
{bodyInner}
</body>
</html>";
}

/// <summary>Classic alg:none JWT with expired exp (1516239022).</summary>
string SeedJwtAlgNone()
{
    // {"alg":"none","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","exp":1516239022}.
    return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNTE2MjM5MDIyfQ.";
}

/// <summary>HS256-shaped JWT with a far-future exp and no sensitive claims (clean-ish twin).</summary>
string SeedJwtHs256Clean()
{
    // header alg HS256, payload sub+name+exp year 2099 — signature is fake but decode still works
    // {"alg":"HS256","typ":"JWT"}.{"sub":"user1","name":"Alice","exp":4102444800}.fakesig
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsIm5hbWUiOiJBbGljZSIsImV4cCI6NDEwMjQ0NDgwMH0.fakesig";
}

string SeedSamlResponseXml()
{
    // Minimal unsigned SAMLResponse-shaped XML (missing signature → should flag).
    return @"<?xml version=""1.0""?>
<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2020-01-01T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"" IssueInstant=""2020-01-01T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"">user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore=""2020-01-01T00:00:00Z"" NotOnOrAfter=""2020-01-01T01:00:00Z""/>
    <saml:AuthnStatement AuthnInstant=""2020-01-01T00:00:00Z""/>
  </saml:Assertion>
</samlp:Response>";
}

string SeedOidcDiscoveryJson(string issuer)
{
    return $@"{{
  ""issuer"": ""{issuer}"",
  ""authorization_endpoint"": ""{issuer}/authorize"",
  ""token_endpoint"": ""{issuer}/token"",
  ""userinfo_endpoint"": ""{issuer}/userinfo"",
  ""jwks_uri"": ""{issuer}/jwks"",
  ""response_types_supported"": [""code"", ""token"", ""id_token"", ""code token"", ""code id_token""],
  ""grant_types_supported"": [""authorization_code"", ""implicit"", ""password"", ""refresh_token""],
  ""code_challenge_methods_supported"": [""plain"", ""S256""],
  ""id_token_signing_alg_values_supported"": [""none"", ""HS256"", ""RS256""],
  ""scopes_supported"": [""openid"", ""profile"", ""email"", ""admin"", ""offline_access""],
  ""token_endpoint_auth_methods_supported"": [""client_secret_post"", ""none""],
  ""registration_endpoint"": ""{issuer}/register""
}}";
}

bool FindingsMention(IEnumerable<string> texts, params string[] needles)
{
    foreach (var t in texts)
    {
        if (string.IsNullOrEmpty(t)) continue;
        foreach (var n in needles)
        {
            if (t.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }
    }
    return false;
}

void NoFindings(int count, string category)
{
    Assert.Equal(0, count, $"Clean twin: no {category} findings");
}

void ExpectFindings(int count, string category)
{
    Assert.True(count > 0, $"Vulnerable fixture: expected {category} findings (got {count})");
}

async Task ResetBrowserState()
{
    ClearMocks();
    ClearInterceptRules();
    try { await ClearSession(); } catch { /* best-effort */ }
}

Trowser.Security.AutoScanPipeline.AutoScanOptions FocusedAutoScanOptions(string host, int maxEndpointsPerScanner, int timeoutMs)
{
    var o = new Trowser.Security.AutoScanPipeline.AutoScanOptions
    {
        Host = host,
        MaxEndpointsPerScanner = maxEndpointsPerScanner,
        TimeoutMs = timeoutMs,
        ConfirmBackend = true
    };
    o.DisableAllScanners();
    return o;
}

List<Dictionary<string, object?>> GetSessionVpxArtifacts() => GetVpxArtifactsSnapshot();

void SetupEvilXsLeakAttackerMocks()
{
    MockResponse("https://evil.trowser.test/", statusCode: 200,
        body: MinimalHtml("Evil origin", "<p>attacker fixture origin</p>"),
        headers: ScriptableHeaders());
}

void SetupRegressionXsLeakFixtures()
{
    MockResponse(FixtureUrl("/"), statusCode: 200,
        body: MinimalHtml("Regression root", "<p>fixture origin</p>"),
        headers: ScriptableHeaders());
    MockResponse(FixtureUrl("/trowser-xsleak-probe-miss*"), statusCode: 404,
        body: "missing", headers: HtmlHeaders());
}

Assert.Reset();
