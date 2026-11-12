// @title Site Health
// @shadow light
// @effects none
// === Full Site Health ===
// Comprehensive health check: runs all audits on the current page.
// Covers: basics, errors, accessibility, performance, security, HTML, links, GUI.

await WaitForIdle(100, 5000);
await WaitForElement("body", 15000);

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Full Site Health: {title}");
Log($"URL: {url}");
Log("");

// --- Page basics ---
Assert.Section("Page Basics");
Assert.NotEmpty(url, "Page has a URL");
Assert.NotEmpty(title, "Page has a title");

var headings = await GetHeadings();
Assert.True(headings.Any(h => h["level"] == "h1"), "Page has an h1 heading");
Log($"  Headings: {headings.Count}, Links: {(await GetLinks()).Count}, Images: {(await GetImages()).Count}");

// --- Console & Network errors ---
Log("");
Assert.Section("Console & Network Errors");
var consoleErrors = GetPageConsoleErrors();
Assert.Equal(0, consoleErrors.Count, $"No JavaScript console errors ({consoleErrors.Count} found)");
foreach (var e in consoleErrors.Take(3))
    Log($"    [{e.Level}] {e.Message.Substring(0, Math.Min(e.Message.Length, 100))}");

var netErrors = Network.FindPageErrors();
Assert.Equal(0, netErrors.Count, $"No HTTP errors ({netErrors.Count} found)");
foreach (var e in netErrors.Take(3))
    Log($"    {e.StatusCode} {e.Method} {e.Path}");

// --- Accessibility ---
Log("");
Assert.Section("Accessibility (WCAG AA)");
await AssertAccessible("AA");

// --- Performance ---
Log("");
Assert.Section("Performance (Web Vitals)");
await AssertPerformance();

// --- Security ---
Log("");
Assert.Section("Security: JS Libraries");
await AssertSecure();

Log("");
Assert.Section("Security: HTTP Headers");
await AssertSecurityHeaders(minSeverity: Severity.Medium);

Log("");
Assert.Section("Security: DOM XSS");
await AssertXssClean(minSeverity: XssSeverity.Medium);

Log("");
Assert.Section("Security: Mixed Content");
await AssertNoMixedContent();

// --- Third-Party Audit ---
Log("");
Assert.Section("Third-Party Resources");
await AssertThirdPartySecure();

// --- Link Check ---
Log("");
Assert.Section("Link Check");
await AssertLinksValid(scope: "anchors", delayMs: 100);

// --- GUI Audit ---
Log("");
Assert.Section("GUI Consistency & Images");
await AssertConsistent();
