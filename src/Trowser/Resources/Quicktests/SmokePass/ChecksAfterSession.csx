// @title Checks After Session
// @shadow light
// @effects none
// === Smoke Test ===
// Basic health check for any web page: structure, errors, accessibility.

//await WaitForIdle(300, 5000);
//await WaitForElement("body", 15000);

// --- Specific asserts ---
//await AssertPageContains("user_name");

// --- Page basics ---
Log("=== Page Basics ===");
var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"  URL: {url}");
Log($"  Title: {title}");

Assert.NotEmpty(url, "Page has a URL");
Assert.NotEmpty(title, "Page has a title");

// --- Heading structure ---
Log("\n=== Heading Structure ===");
var headings = await GetHeadings();
Log($"  Total headings: {headings.Count}");
foreach (var h in headings.Take(10))
    Log($"  {h["level"]}: {h["text"]}");

Assert.True(headings.Any(h => h["level"] == "h1"), "Page has an h1 heading");

// --- Images: alt text check ---
Log("\n=== Images ===");
var images = await GetImages();
var missingAlt = images.Where(i => !bool.TryParse(i.GetValueOrDefault("hasAlt"), out var hasAlt) || !hasAlt).ToList();
Log($"  Total images: {images.Count}");
Log($"  Missing alt text: {missingAlt.Count}");
foreach (var img in missingAlt.Take(5))
    Log($"    Missing alt: {img["src"]}");

Assert.Equal(0, missingAlt.Count, "All images should have alt text");

// --- Links ---
Log("\n=== Links ===");
var links = await GetLinks();
Log($"  Total links: {links.Count}");
var emptyLinks = links.Where(l => string.IsNullOrWhiteSpace(l["href"]) || l["href"] == "#").ToList();
Log($"  Empty/anchor-only links: {emptyLinks.Count}");

// --- Console errors (entire session) ---
Log("\n=== Console Errors (entire session) ===");
var consoleErrors = GetConsoleErrors();
Log($"  Console errors (all pages): {consoleErrors.Count}");
foreach (var e in consoleErrors.Take(5))
    Log($"    [{e.Level}] {e.Message.Substring(0, Math.Min(e.Message.Length, 120))}");

Assert.Equal(0, consoleErrors.Count, "No JavaScript console errors across session");

// --- Network errors (entire session) ---
Log("\n=== Network Errors (entire session) ===");
var netErrors = Network.FindErrors();
Log($"  HTTP errors (all pages): {netErrors.Count}");
foreach (var e in netErrors.Take(5))
    Log($"    {e.StatusCode} {e.Method} {e.Path}");

Assert.Equal(0, netErrors.Count, "No HTTP errors across session");

// --- WCAG Accessibility ---
Log("\n=== Accessibility (WCAG AA) ===");
await AssertAccessible("AA");

// --- Screenshot ---
await Screenshot("smoke-test-result.png");
Log("\nScreenshot saved: smoke-test-result.png");
