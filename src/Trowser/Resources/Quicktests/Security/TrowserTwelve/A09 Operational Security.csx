// @title A09 Operational Security
// @shadow never
// @effects mutates
// A09 Operational Security (OWASP A09+A10:2025)
// Tests: forced-error disclosure, fail-open behavior, exception condition discovery,
// log-leak probes, console/network error harvest, stack trace exposure.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A09 Operational Security: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a09-opsec", safetyMode: "safe", depth: "standard");
