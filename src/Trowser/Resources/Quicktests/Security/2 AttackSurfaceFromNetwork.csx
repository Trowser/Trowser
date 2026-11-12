// @title 2 Attack Surface From Network
// @shadow never
// @effects mutates
// Attack surface map from captured network traffic (same analysis as POST /api/security/attack-surface).
// At the top of the report: RFC 9116 security.txt for the current tab host only (/.well-known/security.txt then /security.txt).
// Browse the application first so the network log is populated, then run this quicktest.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Attack surface (network log): {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Attack surface from network log");
await PrintAttackSurfaceReport(includeDetails: true);
