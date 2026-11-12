// @title Performance Check
// @shadow light
// @effects none
// Web Vitals performance check on the current page

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Performance check: {title}");
Log($"URL: {url}");
Log("");

await AssertPerformance();
await PrintPerformanceReport();
