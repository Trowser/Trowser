// @title A06 Insecure Design
// @shadow never
// @effects mutates
// A06 Insecure Design & Business Logic (OWASP A06:2025)
// Tests: workflow capture + skip, race conditions, mass assignment (price/role),
// captcha replay, numeric tampering, step-skipping.
// Browse the target application first so the network log is populated.
// NOTE: Most tests require active mode to detect workflow flaws.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A06 Insecure Design: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a06-design", safetyMode: "safe", depth: "standard");
