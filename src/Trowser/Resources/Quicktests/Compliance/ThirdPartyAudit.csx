// @title Third Party Audit
// @shadow light
// @effects none
// Third-party resource inventory: external scripts, stylesheets, iframes, fonts
// Domains, sizes, SRI coverage — missing SRI is low/informative in the printed assessment.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Third-party audit: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Third-Party Resources");
await AssertThirdPartySecure();
await PrintThirdPartyReport(includeDetails: true);
