// Security: cookie flags — insecure vs secure.

await ResetBrowserState();

Assert.Section("Insecure cookie → findings");
var badHeaders = SecureHeaders();
badHeaders["Set-Cookie"] = InsecureCookie("sessionid", "insecure-session");
SetupPage(FixtureUrl("/cookie-bad"), MinimalHtml("Cookie Bad", "<h1>Cookies</h1>"), badHeaders);
await Navigate(FixtureUrl("/cookie-bad"));
await WaitForIdle();
// Also set via API in case Set-Cookie on mock isn't applied to jar
await SetCookie("sessionid", "insecure-session", domain: "trowser-regression.test",
    path: "/", secure: false, httpOnly: false, sameSite: null);

var bad = await CheckCookieSecurity();
Log($"Insecure cookie findings: {bad.FindingCount}");
foreach (var f in bad.Findings.Take(8))
    Log($"  [{f.Severity}] {f.CookieName}: {f.Category} — {f.Description}");
ExpectFindings(bad.FindingCount, "cookie-security");

Assert.Section("Secure cookie → cleaner");
await ClearCookies();
ClearMocks();
var goodHeaders = SecureHeaders();
goodHeaders["Set-Cookie"] = SecureCookie("sessionid", "secure-session");
SetupPage(FixtureUrl("/cookie-good"), MinimalHtml("Cookie Good", "<h1>Cookies</h1>"), goodHeaders);
await Navigate(FixtureUrl("/cookie-good"));
await WaitForIdle();
await SetCookie("sessionid", "secure-session", domain: "trowser-regression.test",
    path: "/", secure: true, httpOnly: true, sameSite: "Strict");

var good = await CheckCookieSecurity();
Log($"Secure cookie findings: {bad.FindingCount} → {good.FindingCount}");
foreach (var f in good.Findings.Take(6))
    Log($"  [{f.Severity}] {f.CookieName}: {f.Category}");
Assert.True(good.FindingCount <= bad.FindingCount,
    "Secure twin has fewer-or-equal cookie findings");
