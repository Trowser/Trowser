// @title Link Check
// @shadow light
// @effects none
// Link check: verify all links on the page resolve correctly
// Redirects are reported as observations, not errors
// Lower concurrency if you hit rate limiting (HTTP 429).

var concurrency = 5;

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Link check: {title}");
Log($"URL: {url}");
Log($"Concurrency: {concurrency}");
Log("");

Assert.Section("Anchor Links");
await AssertLinksValid(scope: "anchors", concurrency: concurrency);
await PrintLinkCheckReport(scope: "anchors", includeDetails: true, concurrency: concurrency);
