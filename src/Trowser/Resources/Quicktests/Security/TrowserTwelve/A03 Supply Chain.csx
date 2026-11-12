// @title A03 Supply Chain
// @shadow never
// @effects mutates
// A03 Supply Chain & Software Integrity (OWASP A03+A08:2025)
// Tests: Retire.js CVEs, third-party/SRI inventory, manifest fetch + OSV.dev,
// CI/CD exposure, JS bundle fingerprinting, deserialization, file upload.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A03 Supply Chain: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a03-supplychain", safetyMode: "safe", depth: "standard");
