// @title A12 Availability
// @shadow never
// @effects mutates
// A12 Availability & Resource Management
// Tests: rate-limit audit, body-size limits, ReDoS scan,
// GraphQL query-cost analysis, load testing on hot endpoints.
// Browse the target application first so the network log is populated.
// NOTE: Load testing and stress probes require aggressive mode.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A12 Availability: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a12-availability", safetyMode: "safe", depth: "standard");
