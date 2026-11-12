// @title GUI Audit
// @shadow light
// @effects none
// GUI audit: visual consistency + image optimization
// Checks fonts, colors, sizing, spacing, and image best practices

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"GUI audit: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Visual Consistency & Image Optimization");
await AssertConsistent();
await PrintConsistencyReport(includeDetails: true);
