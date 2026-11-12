// @title 4 OAuth Flow From Network
// @shadow never
// @effects mutates
// OAuth/OIDC front-channel flow from the network log (passive by default).
//
// 1. Complete login in the browser first (or use a front-channel SPA — not a BFF-only login).
// 2. This reads captured /authorize and callback traffic: state, PKCE, fragment leaks, mix-up hints.
// 3. Active probes (redirect_uri, authorization-code replay) need safetyMode active on the API;
//    from scripts, call RunOAuthFlowTest(passiveOnly: false) only on lab targets.
//
// Pair with 3 OidcFromNetwork.csx for provider metadata (when discovery exists) and session dossier.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"OAuth flow test (from network): {title}");
Log($"URL: {url}");
Log("");

Assert.Section("OAuth session dossier and passive flow analysis");
await PrintOAuthFlowReport(passiveOnly: true, includeDetails: true);
await AssertOAuthFlowClean(minSeverity: "medium", passiveOnly: true);
