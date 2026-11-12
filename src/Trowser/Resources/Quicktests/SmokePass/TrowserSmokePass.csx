// @title Trowser Smoke Pass
// @shadow never
// @effects mutates
// Trowser scripting smoke — offline fixture (no live example.com).
//
// Run from the app (Quicktests) or:
//   Trowser.exe --run path\to\TrowserSmokePass.csx --timeout 120

const string SmokeHost = "https://trowser-smoke.test";
const string SmokeOrigin = "https://trowser-smoke.test";

string SmokeUrl(string path = "/")
{
    if (string.IsNullOrEmpty(path)) path = "/";
    if (!path.StartsWith("/")) path = "/" + path;
    return SmokeHost + path;
}

Dictionary<string, string> SmokeHtmlHeaders()
{
    return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Content-Type"] = "text/html; charset=utf-8",
        ["Cache-Control"] = "no-store",
        ["Content-Security-Policy"] =
            "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
    };
}

string MinimalHtml(string title, string bodyInner) =>
    $@"<!DOCTYPE html>
<html lang=""en"">
<head><meta charset=""utf-8""><title>{title}</title></head>
<body>{bodyInner}</body>
</html>";

void SetupSmokePage(string url, string html, int statusCode = 200)
{
    ClearMocks();
    MockResponse(url, statusCode: statusCode, body: html, headers: SmokeHtmlHeaders());
}

var homeUrl = SmokeUrl("/");
var homeHtml = MinimalHtml("Example Domain",
    "<h1>Example Domain</h1><p>This domain is for use in illustrative examples in documents.</p>" +
    $"<p><a href=\"{SmokeUrl("/more")}\">Learn more</a></p>");
SetupSmokePage(homeUrl, homeHtml);

// ============================================================
// SECTION 1: Navigation & Page State
// ============================================================
await Navigate(homeUrl);
Assert.Section("Navigation & Page State");
Log("=== 1. Navigation & Page State ===");

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"  URL: {url}");
Log($"  Title: {title}");

Assert.Contains("trowser-smoke.test", url, "URL contains fixture host");
Assert.Equal("Example Domain", title, "Page title is 'Example Domain'");

var pageText = await GetPageText();
Assert.Contains("illustrative examples", pageText, "Page text contains fixture copy");
Assert.True(pageText.Length > 50, "Page text has substantial length");

var pageSource = await GetPageSource();
Assert.Contains("<h1>", pageSource, "Page source contains <h1> tag");
Assert.Contains("</html>", pageSource, "Page source contains closing </html>");

// ============================================================
// SECTION 2: Headings & Links
// ============================================================
Assert.Section("Headings & Links");
Log("\n=== 2. Headings & Links ===");

var headings = await GetHeadings();
Assert.True(headings.Count >= 1, "Page has at least one heading");
Assert.Equal("h1", headings[0]["level"], "First heading is h1");
Assert.Equal("Example Domain", headings[0]["text"], "h1 text is 'Example Domain'");

var links = await GetLinks();
Assert.True(links.Count >= 1, "Page has at least one link");
var learnMore = links.FirstOrDefault(l => (l["text"] ?? "").Contains("Learn more"));
Assert.NotNull(learnMore, "'Learn more' link exists");
Assert.Contains("Learn more", learnMore?["text"] ?? "", "Learn more link text");

// ============================================================
// SECTION 3: Interactive Elements & Snapshot
// ============================================================
Assert.Section("Interactive Elements");
Log("\n=== 3. Interactive Elements & Snapshot ===");

var elements = await GetInteractiveElements();
Assert.True(elements.Count >= 1, "Has interactive elements");

var firstEl = elements[0];
Assert.Equal("a", firstEl["tag"]?.ToString(), "First interactive element is <a>");
Assert.Contains("Learn more", firstEl["label"]?.ToString() ?? "", "Element label is 'Learn more'");

var snapshot = await GetSnapshot();
Assert.NotNull(snapshot, "GetSnapshot returns data");
Assert.Contains("trowser-smoke.test", snapshot["url"]?.ToString() ?? "", "Snapshot contains URL");

// ============================================================
// SECTION 4: Semantic Locators
// ============================================================
Assert.Section("Semantic Locators");
Log("\n=== 4. Semantic Locators ===");

var h1Text = await GetText(ByRole("heading"));
Assert.Equal("Example Domain", h1Text, "ByRole('heading') finds h1");

var linkText = await GetText(ByRole("link", "Learn more"));
Assert.Contains("Learn more", linkText, "ByRole('link', 'Learn more') finds the link");

var byTextResult = await GetText(ByText("Learn more"));
Assert.Contains("Learn more", byTextResult, "ByText('Learn more') finds element");

// ============================================================
// SECTION 5: Click (same-origin mock target)
// ============================================================
Assert.Section("Click & Navigation");
Log("\n=== 5. Click ===");

ClearMocks();
MockResponse(SmokeUrl("/more"), statusCode: 200, body: MinimalHtml("More", "<h1>More info</h1>"), headers: SmokeHtmlHeaders());
MockResponse(homeUrl, statusCode: 200, body: homeHtml, headers: SmokeHtmlHeaders());
await Navigate(homeUrl);
await WaitForElement("h1", 10000);

var sw = System.Diagnostics.Stopwatch.StartNew();
await Click(ByRole("link", "Learn more"));
sw.Stop();
Log($"  Click completed in {sw.ElapsedMilliseconds}ms");
Assert.Pass("Click on link did not throw");

// ============================================================
// SECTION 6: Navigate Back
// ============================================================
Assert.Section("Navigate Back");
Log("\n=== 6. Navigate Back ===");

SetupSmokePage(homeUrl, homeHtml);
await Navigate(homeUrl);
await WaitForElement("h1", 10000);

url = await GetCurrentUrl();
title = await GetTitle();
Assert.Contains("trowser-smoke.test", url, "Navigated back to fixture host");
Assert.Equal("Example Domain", title, "Title restored after navigation");

// ============================================================
// SECTION 7: Inject Test Form
// ============================================================
Assert.Section("Inject Test Form");
Log("\n=== 7. Inject Test Form ===");

var formHtml = @"<form id=""tf""><label for=""ti"">Name</label>" +
    @"<input id=""ti"" type=""text"" placeholder=""Enter name"">" +
    @"<select id=""ts""><option value=""a"">Alpha</option><option value=""b"">Beta</option></select>" +
    @"<button id=""tb"" type=""button"">Go</button></form>";

var injectJs = $"(function(){{ document.body.insertAdjacentHTML('beforeend', '{formHtml}'); return document.getElementById('ti') ? 'ok' : 'no'; }})()";
var jsResult = await ExecuteJs(injectJs);
Assert.Equal("ok", jsResult, "Form injection succeeded");

var exists = await Exists("#ti");
Assert.True(exists, "Injected input #ti exists");

var existsSelect = await Exists("#ts");
Assert.True(existsSelect, "Injected select #ts exists");

// ============================================================
// SECTION 8: Type
// ============================================================
Assert.Section("Type");
Log("\n=== 8. Type ===");

await Type(ByLabel("Name"), "Hello Trowser");
var inputVal = await ExecuteJs("document.getElementById('ti').value");
Assert.Equal("Hello Trowser", inputVal, "Type by ByLabel wrote correct value");

await Type(ByPlaceholder("Enter name"), "Placeholder test");
inputVal = await ExecuteJs("document.getElementById('ti').value");
Assert.Equal("Placeholder test", inputVal, "Type by ByPlaceholder overwrote value");

// ============================================================
// SECTION 9: Select
// ============================================================
Assert.Section("Select");
Log("\n=== 9. Select ===");

await Select("#ts", "b");
var selectVal = await ExecuteJs("document.getElementById('ts').value");
Assert.Equal("b", selectVal, "Select set value to 'b'");

// ============================================================
// SECTION 10: GetText & GetAttribute
// ============================================================
Assert.Section("GetText & GetAttribute");
Log("\n=== 10. GetText & GetAttribute ===");

var headingText = await GetText("h1");
Assert.Equal("Example Domain", headingText, "GetText on h1");

var href = await GetAttribute("a", "href");
Assert.Contains("/more", href, "GetAttribute returns href");

// ============================================================
// SECTION 11: Hover
// ============================================================
Assert.Section("Hover");
Log("\n=== 11. Hover ===");

await Hover("a");
Assert.Pass("Hover on link did not throw");

// ============================================================
// SECTION 12: Scroll
// ============================================================
Assert.Section("Scroll");
Log("\n=== 12. Scroll ===");

await Scroll(direction: "down");
Assert.Pass("Scroll down succeeded");

await Scroll(direction: "up");
Assert.Pass("Scroll up succeeded");

await Scroll("#tf", scrollIntoView: true);
Assert.Pass("ScrollIntoView succeeded");

// ============================================================
// SECTION 13: PressKey
// ============================================================
Assert.Section("PressKey");
Log("\n=== 13. PressKey ===");

await PressKey("Tab");
Assert.Pass("PressKey Tab succeeded");

await PressKey("Escape");
Assert.Pass("PressKey Escape succeeded");

// ============================================================
// SECTION 14: WaitForElement
// ============================================================
Assert.Section("WaitForElement");
Log("\n=== 14. WaitForElement ===");

sw.Restart();
await WaitForElement("h1", 3000);
sw.Stop();
Assert.True(sw.ElapsedMilliseconds < 1000, $"WaitForElement resolved quickly ({sw.ElapsedMilliseconds}ms)");

var timedOut = false;
try { await WaitForElement("#nonexistent", 500); }
catch (TimeoutException) { timedOut = true; }
Assert.True(timedOut, "WaitForElement times out for missing element");

// ============================================================
// SECTION 15: WaitForIdle
// ============================================================
Assert.Section("WaitForIdle");
Log("\n=== 15. WaitForIdle ===");

var idleResult = await WaitForIdle(300, 5000);
Assert.True(idleResult, "WaitForIdle returns true on a static page");

// ============================================================
// SECTION 16: JavaScript
// ============================================================
Assert.Section("JavaScript Execution");
Log("\n=== 16. JavaScript ===");

var jsReturn = await ExecuteJs("(2 + 3).toString()");
Assert.Equal("5", jsReturn, "ExecuteJs returns computed result");

var jsTitle = await ExecuteJs("document.title");
Assert.Equal("Example Domain", jsTitle, "ExecuteJs can read document.title");

// ============================================================
// SECTION 17: Accessibility
// ============================================================
Assert.Section("Accessibility");
Log("\n=== 17. Accessibility ===");

var a11y = await CheckAccessibility("AA");
Assert.True(a11y.PassCount > 0, $"Accessibility audit has {a11y.PassCount} passing rules");
Log($"  Violations: {a11y.ViolationCount}, Passes: {a11y.PassCount}");

// ============================================================
// SECTION 18: Page Assertions
// ============================================================
Assert.Section("Page Assertions");
Log("\n=== 18. Page Assertions ===");

await AssertPageContains("Example Domain");
await AssertPageNotContains("ZZZZNOTHERE");

// ============================================================
// SECTION 19: Console & Network
// ============================================================
Assert.Section("Console & Network");
Log("\n=== 19. Console & Network ===");

var consoleErrors = GetConsoleErrors();
Log($"  Console errors: {consoleErrors.Count}");

var networkLog = GetNetworkLog();
Assert.True(networkLog.Count > 0, $"Network log has {networkLog.Count} entries");

// ============================================================
// SECTION 20: Auto-Wait Timing
// ============================================================
Assert.Section("Auto-Wait Timing");
Log("\n=== 20. Auto-Wait Timing ===");

sw.Restart();
var autoText = await GetText(ByRole("heading"));
sw.Stop();
Assert.Equal("Example Domain", autoText, "Auto-waited GetText returns heading");
Assert.True(sw.ElapsedMilliseconds < 500, $"Auto-wait resolved in {sw.ElapsedMilliseconds}ms (< 500ms)");
Log($"  GetText(ByRole('heading')) completed in {sw.ElapsedMilliseconds}ms");

// ============================================================
// SECTION 21: UTF-8 Output
// ============================================================
Assert.Section("UTF-8 Output");
Log("\n=== 21. UTF-8 Output ===");

Log("  Swedish: åäö ÅÄÖ");
Log("  French: é è ê ë");
Log("  Symbols: » « — –");
Assert.Pass("UTF-8 characters logged without error");

// ============================================================
// SECTION 22: Extract (Structured Data)
// ============================================================
Assert.Section("Extract");
Log("\n=== 22. Extract ===");

var tableHtml = @"<table id=""et""><thead><tr><th>Item</th><th>Qty</th></tr></thead>" +
    @"<tbody><tr><td>Apples</td><td>5</td></tr><tr><td>Bananas</td><td>12</td></tr></tbody></table>" +
    @"<div class=""ec"" data-id=""1""><b>Alpha</b><a href=""/a"">link</a></div>" +
    @"<div class=""ec"" data-id=""2""><b>Beta</b><a href=""/b"">link</a></div>";
var injectTableJs = $"(function(){{ document.body.insertAdjacentHTML('beforeend', '{tableHtml}'); return document.getElementById('et') ? 'ok' : 'no'; }})()";
var tableInject = await ExecuteJs(injectTableJs);
Assert.Equal("ok", tableInject, "Extract fixture injection succeeded");

var rows = await Extract("#et");
Assert.Equal(2, rows.Count, "Table extract row count");
Assert.Equal("Apples", rows[0]["Item"], "Table extract first row");
Assert.Equal("12", rows[1]["Qty"], "Table extract second row qty");

var cards = await Extract(".ec", ("name", "b"), ("url", "a@href"), ("id", "@data-id"));
Assert.Equal(2, cards.Count, "Field mapping card count");
Assert.Equal("Alpha", cards[0]["name"], "Field mapping name");
Assert.Contains("/a", cards[0]["url"], "Field mapping @href");
Assert.Equal("1", cards[0]["id"], "Field mapping @data-id");

var texts = await Extract(".ec");
Assert.Equal(2, texts.Count, "Simple list count");
Assert.Contains("Alpha", texts[0]["text"], "Simple list text");

Log($"  Table: {rows.Count} rows, Cards: {cards.Count} items, List: {texts.Count} texts");

Log("\n=== Smoke pass complete ===");
