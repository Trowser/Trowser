// Security: DOM XSS patterns — vulnerable vs clean twin.

await ResetBrowserState();

Assert.Section("XSS patterns present → findings");
var badHtml = MinimalHtml("XSS Bad",
    @"<h1>XSS</h1>
      <a href=""javascript:alert(1)"">Click</a>
      <div onclick=""doEvil()"">handler</div>
      <script>
        var x = location.hash;
        document.write(x);
        eval(x);
      </script>");
SetupPage(FixtureUrl("/xss-bad"), badHtml, SecureHeaders());
await Navigate(FixtureUrl("/xss-bad"));
await WaitForIdle();
var bad = await CheckXss();
Log($"XSS bad findings: {bad.FindingCount}");
foreach (var kv in bad.FindingsByCategory)
    Log($"  {kv.Key}: {kv.Value}");
ExpectFindings(bad.FindingCount, "dom-xss");
Assert.True(
    bad.FindingsByCategory.Keys.Any(k =>
        k.Contains("javascript", StringComparison.OrdinalIgnoreCase)
        || k.Contains("inline", StringComparison.OrdinalIgnoreCase)
        || k.Contains("sink", StringComparison.OrdinalIgnoreCase)
        || k.Contains("handler", StringComparison.OrdinalIgnoreCase)),
    "Findings include expected XSS categories");

Assert.Section("Clean twin → fewer findings");
ClearMocks();
var goodHtml = MinimalHtml("XSS Good",
    @"<h1>Safe</h1>
      <a href=""/about"">About</a>
      <button type=""button"" id=""b"">Go</button>
      <script>
        document.getElementById('b').addEventListener('click', function() {
          document.getElementById('b').textContent = 'clicked';
        });
      </script>");
SetupPage(FixtureUrl("/xss-good"), goodHtml, SecureHeaders());
await Navigate(FixtureUrl("/xss-good"));
await WaitForIdle();
var good = await CheckXss();
Log($"XSS good findings: {good.FindingCount}");
Assert.True(good.FindingCount < bad.FindingCount,
    $"Clean twin has fewer XSS findings ({good.FindingCount} < {bad.FindingCount})");
var highGood = good.GetByMinSeverity(XssSeverity.High);
Assert.Equal(0, highGood.Count, "Clean twin has no high XSS findings");
