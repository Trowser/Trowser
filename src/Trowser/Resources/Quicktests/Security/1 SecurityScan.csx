// @title 1 Security Scan
// @shadow never
// @effects mutates
// Security scan: tech stack, JS CVEs, headers, CORS, XSS, mixed content, cookies, source maps,
// web storage, HTTP method exposure (TRACE / PUT / DELETE), and path discovery. Active tests
// (firewall, CSRF replay, fuzz, interrupter) are separate — see scripting-reference.md and
// api-reference-small.md (security APIs).

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Security scan: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Tech Stack Detection");
var stack = await PrintTechStackReport();
if (stack.Cache.Detected)
    Assert.Pass($"Caching layer: {stack.Cache.DocumentStatus} ({string.Join(", ", stack.Cache.Vendors.DefaultIfEmpty("HTTP cache"))})");
else
    Assert.Pass("No caching layer detected");

Log("");
Assert.Section("JavaScript Libraries (Retire.js)");
await AssertSecure();
await PrintSecurityReport(includeDetails: true, checkForUpdates: true);

Log("");
Assert.Section("HTTP Security Headers");
await AssertSecurityHeaders(minSeverity: Severity.Medium);
await PrintSecurityHeadersReport();

Log("");
Assert.Section("CORS Configuration");
await AssertCors(minSeverity: Severity.Medium);
await PrintCorsReport();

Log("");
Assert.Section("DOM XSS Patterns");
await AssertXssClean(minSeverity: XssSeverity.Medium);
await PrintXssReport(includeDetails: true);

Log("");
Assert.Section("Mixed Content");
await AssertNoMixedContent();
await PrintMixedContentReport();

Log("");
Assert.Section("Cookie Security");
await AssertCookieSecurity(minSeverity: Severity.Medium);
await PrintCookieSecurityReport();

Log("");
Assert.Section("Source Maps & Debug Exposure");
await AssertNoSourceMaps(minSeverity: Severity.Medium);
await PrintSourceMapReport(includeDetails: true);

Log("");
Assert.Section("Web Storage (tokens, PII, stored XSS risk)");
await AssertStorageSecurity(minSeverity: Severity.Medium);
await PrintStorageSecurityReport();

Log("");
Assert.Section("HTTP Methods on Document URL");
await AssertHttpMethodsClean();
await PrintHttpMethodsReport(includeDetails: true);

Log("");
Assert.Section("Endpoint Discovery");
await AssertDiscover(delayMs: 0);
await PrintDiscoverReport(wordlist: "common", delayMs: 0);
