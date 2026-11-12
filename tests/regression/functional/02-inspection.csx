// Functional: snapshot / headings / links / interactive elements with exact oracles.

await ResetBrowserState();

var url = FixtureUrl("/inspect");
var html = MinimalHtml("Inspect Me",
    @"<h1>Main Heading</h1>
      <h2>Sub Heading</h2>
      <a href=""/about"" id=""about-link"">About Us</a>
      <a href=""https://example.com/ext"">External</a>
      <button type=""button"" id=""go"">Go</button>
      <input type=""text"" id=""q"" name=""q"" aria-label=""Search query"">
      <select id=""color"" aria-label=""Color"">
        <option value=""red"">Red</option>
        <option value=""blue"" selected>Blue</option>
      </select>");

SetupPage(url, html, SecureHeaders());
await Navigate(url);
await WaitForIdle();

Assert.Section("Headings");
var headings = await GetHeadings();
Assert.True(headings.Count >= 2, "At least two headings");
Assert.Equal("h1", headings[0]["level"]?.ToString(), "First heading is h1");
Assert.Equal("Main Heading", headings[0]["text"]?.ToString(), "h1 text");
Assert.Equal("Sub Heading", headings[1]["text"]?.ToString(), "h2 text");

Assert.Section("Links");
var links = await GetLinks();
Assert.True(links.Count >= 2, "At least two links");
var about = links.FirstOrDefault(l => (l["text"]?.ToString() ?? "").Contains("About Us"));
Assert.NotNull(about, "About Us link present");
Assert.Contains("/about", about?["href"]?.ToString() ?? "", "About href");

Assert.Section("Interactive elements");
var els = await GetInteractiveElements();
Assert.True(els.Count >= 4, $"Expected >=4 interactive elements, got {els.Count}");
Assert.True(els.Any(e => (e["tag"]?.ToString() ?? "") == "button"), "Has button");
Assert.True(els.Any(e => (e["tag"]?.ToString() ?? "") == "input"), "Has input");

Assert.Section("Snapshot");
var snap = await GetSnapshot();
Assert.NotNull(snap, "Snapshot returned");
Assert.Contains("trowser-regression.test", snap["url"]?.ToString() ?? "", "Snapshot URL");
Assert.Contains("Inspect Me", snap["title"]?.ToString() ?? "", "Snapshot title");

Assert.Section("Unicode / emoji in text extraction");
var unicodeUrl = FixtureUrl("/inspect-unicode");
var unicodeHtml = MinimalHtml("Unicode Page",
    @"<h1>Hello © emoji 😀</h1>
      <button type=""button"" id=""emoji-btn"">Save © 😀</button>
      <p id=""copy"">Copyright © 2026 — café</p>");
SetupPage(unicodeUrl, unicodeHtml, SecureHeaders());
await Navigate(unicodeUrl);
await WaitForIdle();

var pageText = await GetPageText();
Assert.Contains("©", pageText, "pageText preserves copyright sign");
Assert.Contains("😀", pageText, "pageText preserves emoji");
Assert.Contains("café", pageText, "pageText preserves accented Latin");

var unicodeEls = await GetInteractiveElements();
var emojiBtn = unicodeEls.FirstOrDefault(e => (e["id"]?.ToString() ?? "") == "emoji-btn");
Assert.NotNull(emojiBtn, "Emoji button found");
var btnText = emojiBtn?["text"]?.ToString() ?? emojiBtn?["label"]?.ToString() ?? "";
Assert.Contains("©", btnText, "interactive text preserves ©");
Assert.Contains("😀", btnText, "interactive text preserves emoji");

var jsResult = await ExecuteJs("'©😀café'");
Assert.Contains("©", jsResult ?? "", "ExecuteJs preserves ©");
Assert.Contains("😀", jsResult ?? "", "ExecuteJs preserves emoji");
Assert.Contains("café", jsResult ?? "", "ExecuteJs preserves accented Latin");
