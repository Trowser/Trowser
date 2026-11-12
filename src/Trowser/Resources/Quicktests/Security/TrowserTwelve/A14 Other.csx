// @title A14 Other
// @shadow never
// @effects mutates
// A14 Other (protocol-layer and niche attacks)
// Tests: cache identification, cache-map, pollution, poisoning, cache deception,
// HTTP request smuggling, host header injection, open redirect, WebSocket injection,
// XS-Leaks (current page vs a miss URL).
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A14 Other: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a14-other", safetyMode: "safe", depth: "standard");
