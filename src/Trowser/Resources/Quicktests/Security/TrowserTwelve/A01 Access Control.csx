// @title A01 Access Control
// @shadow never
// @effects mutates
// A01 Access Control & Authorization (OWASP A01:2025)
// Tests: IDOR, privilege escalation, CSRF, mass assignment, BFLA, CSWSH, role matrix.
// Multi-identity probes (anon vs user vs admin) run when identities are configured.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A01 Access Control: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a01-access", safetyMode: "safe", depth: "standard");
