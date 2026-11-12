// @title 2 JavaScript Vulnerabilities
// @shadow never
// @effects mutates
// Retire.js scan: known vulnerable JavaScript libraries on the current page.
// Also included as the first section of Security.SecurityScan.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"JavaScript library vulnerabilities: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("JavaScript Libraries (Retire.js)");
await AssertSecure();
await PrintSecurityReport(includeDetails: true, checkForUpdates: true);
