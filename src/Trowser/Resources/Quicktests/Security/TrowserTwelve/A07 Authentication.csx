// @title A07 Authentication
// @shadow never
// @effects mutates
// A07 Authentication & Session Management (OWASP A07:2025)
// Tests: JWT analysis + algorithm confusion, OIDC/OAuth flow testing,
// session fixation, password reset weakness, account enumeration,
// logout invalidation, default credentials, brute-force detection.
// Browse and log in to the target application first.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A07 Authentication: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a07-authn", safetyMode: "safe", depth: "standard");
