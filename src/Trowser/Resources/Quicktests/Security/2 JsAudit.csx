// @title 2 Js Audit
// @shadow never
// @effects mutates
// JavaScript static audit: GETs external script[src] bundles from the current page and scans content for
// credential-like assignments, internal/private URLs, and debug/test markers (complements Secrets Harvest).
// Active fetch of third-party JS — only run on targets you are permitted to test.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"JavaScript static audit: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("External JS bundles (hardcoded patterns)");
await AssertJavaScriptStaticAuditClean(minSeverity: "medium");
await PrintJavaScriptStaticAuditReport(includeDetails: true);
