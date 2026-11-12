// Functional: accessibility / HTML / links / consistency audits with oracles.

await ResetBrowserState();

Assert.Section("Accessibility — unlabeled input flagged");
var badA11y = MinimalHtml("Bad A11y",
    @"<h1>Form</h1>
      <input type=""text"" id=""nolabel"">
      <img src=""/x.png"">
      <button>ok</button>");
SetupPage(FixtureUrl("/a11y-bad"), badA11y, SecureHeaders());
MockResponse("*/x.png", statusCode: 200, body: "x",
    headers: new Dictionary<string, string> { ["Content-Type"] = "image/png" });
await Navigate(FixtureUrl("/a11y-bad"));
await WaitForIdle();
var a11yBad = await CheckAccessibility("AA");
Log($"A11y bad violations: {a11yBad.ViolationCount}");
foreach (var v in a11yBad.Violations.Take(8))
    Log($"  [{v.Impact}] {v.RuleId}: {v.Help}");
ExpectFindings(a11yBad.ViolationCount, "accessibility");

Assert.Section("Accessibility — clean twin");
var goodA11y = MinimalHtml("Good A11y",
    @"<h1>Form</h1>
      <label for=""email"">Email</label>
      <input type=""email"" id=""email"" name=""email"">
      <img src=""/y.png"" alt=""Logo"">
      <button type=""submit"">Save</button>");
ClearMocks();
SetupPage(FixtureUrl("/a11y-good"), goodA11y, SecureHeaders());
MockResponse("*/y.png", statusCode: 200, body: "y",
    headers: new Dictionary<string, string> { ["Content-Type"] = "image/png" });
await Navigate(FixtureUrl("/a11y-good"));
await WaitForIdle();
var a11yGood = await CheckAccessibility("AA");
Log($"A11y good violations: {a11yGood.ViolationCount}");
foreach (var v in a11yGood.Violations.Take(5))
    Log($"  [{v.Impact}] {v.RuleId}: {v.Help}");
// Allow minor noise but unlabeled-input style issues should be gone
Assert.False(
    a11yGood.Violations.Any(v => v.RuleId != null &&
        (v.RuleId.Contains("label", StringComparison.OrdinalIgnoreCase)
         || v.RuleId.Contains("image-alt", StringComparison.OrdinalIgnoreCase))),
    "Clean twin has no label/image-alt violations");

Assert.Section("HTML validation — invalid markup");
ClearMocks();
var badHtml = "<html><head><title>Bad</title></head><body><div><p>Unclosed div<span>x</div></body>";
SetupPage(FixtureUrl("/html-bad"), badHtml, SecureHeaders());
await Navigate(FixtureUrl("/html-bad"));
await WaitForIdle();
var htmlBad = await CheckHtml();
Log($"HTML errors={htmlBad.ErrorCount} warnings={htmlBad.WarningCount}");
ExpectFindings(htmlBad.TotalCount, "html-validation");

Assert.Section("HTML validation — clean twin");
ClearMocks();
SetupPage(FixtureUrl("/html-good"), MinimalHtml("Good", "<h1>OK</h1><p>Valid enough.</p>"), SecureHeaders());
await Navigate(FixtureUrl("/html-good"));
await WaitForIdle();
var htmlGood = await CheckHtml();
Log($"HTML good errors={htmlGood.ErrorCount}");
Assert.True(htmlGood.ErrorCount <= htmlBad.ErrorCount, "Clean twin has fewer-or-equal HTML errors");

Assert.Section("Link check — broken .invalid host (offline DNS fail)");
ClearMocks();
SetupPage(FixtureUrl("/links"),
    MinimalHtml("Links",
        @"<h1>Links</h1>
          <a href=""#local"">Local</a>
          <a href=""https://no-such-host-trowser-regression.invalid/missing"">Broken</a>"),
    SecureHeaders());
await Navigate(FixtureUrl("/links"));
await WaitForIdle();
var links = await CheckLinks(scope: "anchors", external: true, timeoutMs: 3000, concurrency: 2);
Log($"Links checked={links.CheckedCount} broken={links.BrokenCount}");
ExpectFindings(links.BrokenCount, "broken-links");

Assert.Section("Consistency check runs");
var consistency = await CheckConsistency();
Log($"Consistency result type={consistency.GetType().Name}");
Assert.Pass("CheckConsistency completed");
