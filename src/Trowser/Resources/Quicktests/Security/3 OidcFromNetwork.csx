// @title 3 Oidc From Network
// @shadow never
// @effects mutates
// OIDC from the network log, in two steps.
//
// 1. Session posture. What this browser actually saw: an authorize redirect, a bearer
//    token, or a reverse-proxy / BFF login (session cookie such as oidcproxy.cookie,
//    a hop to the login UI, OIDC claims on an app API, and no /authorize request).
//    Claim values are not printed.
//
// 2. Provider audit when discovery exists (grants, PKCE, signing, endpoints). Many IdPs
//    do not publish /.well-known/openid-configuration — session, dossier, and JWT checks
//    still run. Auto-detect uses discovery traffic, JWT iss, or an authorize URL.
//    A BFF login does not reveal the issuer, and the login UI host is not a substitute.
//    Set it yourself, then run again:
//
//        string? issuer = "https://login.example.com/realms/myrealm";
//
//    Leave the line below as null to auto-detect. The same value is the `issuer` field
//    on POST /api/security/oidc-analyze and on the MCP tool browser_security_oidc_analyze.
//    Grant-type probes stay off (testGrantTypes: false).

string? issuer = null;

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"OIDC analysis (from network): {title}");
Log($"URL: {url}");
Log("");

Assert.Section("OIDC session visible to the browser");
var session = await PrintOidcSessionReport();
await AssertOidcSessionClean(minSeverity: "medium");

Assert.Section("OpenID Connect discovery document & provider checks");
var resolved = string.IsNullOrWhiteSpace(issuer) ? session.Issuer : issuer.Trim();
if (!string.IsNullOrWhiteSpace(resolved))
{
    await AssertOidcAnalysisClean(minSeverity: "medium", issuer: resolved, testGrantTypes: false);
    await PrintOidcAnalysisReport(includeDetails: false, issuer: resolved, testGrantTypes: false);
}
else if (session.Observed)
{
    Log("Provider audit skipped. Set issuer at the top of this script (see the header comment) and run again.");
    Assert.Pass("Provider audit skipped — issuer was not in the browser");
}
else
{
    await AssertOidcAnalysisClean(minSeverity: "medium", testGrantTypes: false);
    await PrintOidcAnalysisReport(includeDetails: false, testGrantTypes: false);
}
