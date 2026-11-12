// @title A05 Injection
// @shadow never
// @effects mutates
// A05 Injection (OWASP A05:2025)
// Tests: SQLi, NoSQL, LDAP, XSS (stored/reflected/DOM), SSTI, XXE,
// prototype pollution, CSTI, command canary, parser probe — per sink,
// plus DOM XSS flow graph (runtime sensor).
// Browse the target application first so the network log is populated.
// NOTE: In safe mode, only passive/read-only checks run. Set active for injection probes.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A05 Injection: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a05-injection", safetyMode: "safe", depth: "standard");
