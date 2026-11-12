// Security: HTTP security headers — vulnerable vs clean twin.

await ResetBrowserState();

Assert.Section("Vulnerable headers → findings");
SetupPage(FixtureUrl("/hdr-bad"), MinimalHtml("Hdr Bad", "<h1>Bad Headers</h1>"), VulnerableHeaders());
await Navigate(FixtureUrl("/hdr-bad"));
await WaitForIdle();
var bad = await CheckSecurityHeaders();
Log($"Vulnerable findings: {bad.FindingCount}; error={bad.FetchError}");
foreach (var f in bad.Findings.Take(10))
    Log($"  [{f.Severity}] {f.Header}: {f.Description}");
Assert.True(string.IsNullOrEmpty(bad.FetchError), "Headers fetch succeeded against mock");
ExpectFindings(bad.FindingCount, "security-headers");
Assert.True(
    FindingsMention(bad.Findings.Select(f => f.Header + " " + f.Description),
        "Content-Security-Policy", "CSP", "Strict-Transport-Security", "HSTS",
        "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "X-Powered-By", "Server"),
    "Findings mention expected missing/weak headers");

Assert.Section("Secure headers → fewer/no high findings");
ClearMocks();
SetupPage(FixtureUrl("/hdr-good"), MinimalHtml("Hdr Good", "<h1>Good Headers</h1>"), SecureHeaders());
await Navigate(FixtureUrl("/hdr-good"));
await WaitForIdle();
var good = await CheckSecurityHeaders();
Log($"Secure findings: {good.FindingCount}");
foreach (var f in good.Findings.Take(8))
    Log($"  [{f.Severity}] {f.Header}: {f.Description}");
Assert.True(string.IsNullOrEmpty(good.FetchError), "Secure headers fetch succeeded");
Assert.True(good.FindingCount < bad.FindingCount,
    $"Clean twin has fewer findings ({good.FindingCount} < {bad.FindingCount})");
var highGood = good.Findings.Count(f =>
    f.Severity.ToString().Contains("High", StringComparison.OrdinalIgnoreCase)
    || f.Severity.ToString().Contains("Critical", StringComparison.OrdinalIgnoreCase));
Assert.Equal(0, highGood, "Clean twin has no high/critical header findings");
