// @title A04 Crypto and Secrets
// @shadow never
// @effects mutates
// A04 Cryptographic Failures & Secrets (OWASP A04:2025)
// Tests: TLS introspection, HSTS, secrets harvest, token entropy,
// cookie audit (Secure/HttpOnly), JWT, IndexedDB/web storage, source maps.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A04 Crypto & Secrets: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a04-crypto", safetyMode: "safe", depth: "standard");
