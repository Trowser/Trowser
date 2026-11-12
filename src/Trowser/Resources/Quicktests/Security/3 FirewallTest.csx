// @title 3 Firewall Test
// @shadow never
// @effects mutates
// Client-side firewall test: injects real bypass attempts in the live page (CSP, SRI, iframe sandbox,
// Permissions-Policy). Verifies whether defenses actually block — not just header presence.
// May modify the DOM briefly; only run on targets you are permitted to test.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Firewall test (CSP / SRI / sandbox / Permissions-Policy): {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Active client-side defense verification");
await AssertFirewallTestClean();
await PrintFirewallTestReport(includeDetails: false);
