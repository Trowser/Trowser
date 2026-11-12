// @title 3 Saml From Network
// @shadow never
// @effects mutates
// Decode the latest SAMLRequest/SAMLResponse from the network log and print a security-oriented report.
// Complete an SSO flow (or replay traffic) so the log contains SAML parameters, then run this quicktest.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"SAML decode (network log): {title}");
Log($"URL: {url}");
Log("");

Assert.Section("SAML message (network log)");
await PrintSamlFromNetworkReport(includeXml: false);
await AssertSamlSecurity(minSeverity: Severity.Medium);
