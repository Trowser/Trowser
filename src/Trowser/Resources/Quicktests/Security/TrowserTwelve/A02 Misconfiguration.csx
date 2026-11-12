// @title A02 Misconfiguration
// @shadow never
// @effects mutates
// A02 Security Misconfiguration (OWASP A02:2025)
// Tests: HTTP headers, cookies, storage, source maps, CORS sweep, HTTP methods,
// endpoint discovery, clickjacking, subdomain takeover, forced-error disclosure.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A02 Misconfiguration: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a02-misconfig", safetyMode: "safe", depth: "standard");
