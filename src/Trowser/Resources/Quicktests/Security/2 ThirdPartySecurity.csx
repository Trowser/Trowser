// @title 2 Third Party Security
// @shadow never
// @effects mutates
// Third-party resource security: external scripts, stylesheets, iframes, fonts.
// Reports domains, transfer sizes, and Subresource Integrity (SRI) coverage.
// Missing SRI is noted as low/informative — it is uncommon on real sites; see assessment text.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Third-party security: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Third-Party Resources & SRI Coverage");
await AssertThirdPartySecure();
await PrintThirdPartyReport(includeDetails: true);
