// @title A11 SSRF
// @shadow never
// @effects mutates
// A11 Server-Side Request Forgery (formerly OWASP A10:2021)
// Tests: URL parameter discovery, internal IP injection, cloud metadata probes,
// DNS rebinding, webhook callbacks, protocol handlers.
// Browse the target application first so the network log is populated.
// NOTE: Active SSRF probes require active mode.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A11 SSRF: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a11-ssrf", safetyMode: "safe", depth: "standard");
