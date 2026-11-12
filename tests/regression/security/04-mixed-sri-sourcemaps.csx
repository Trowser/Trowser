// Security: mixed content, third-party SRI, source maps.

await ResetBrowserState();

Assert.Section("Mixed content - HTTP script on HTTPS page");
var mixedHtml = MinimalHtml("Mixed",
    @"<h1>Mixed</h1>
      <script src=""http://cdn.trowser-regression.test/evil.js""></script>
      <img src=""http://cdn.trowser-regression.test/x.png"">");
SetupPage(FixtureUrl("/mixed"), mixedHtml, SecureHeaders());
await Navigate(FixtureUrl("/mixed"));
await WaitForIdle();
var mixed = await CheckMixedContent();
Log($"Mixed content: https={mixed.IsHttps} findings={mixed.FindingCount} high={mixed.HighCount}");
Assert.True(mixed.IsHttps, "Fixture page is HTTPS");
ExpectFindings(mixed.FindingCount, "mixed-content");

Assert.Section("Mixed content clean twin");
ClearMocks();
SetupPage(FixtureUrl("/mixed-good"),
    MinimalHtml("No Mixed", "<h1>Safe</h1><script src=\"/local.js\"></script>"),
    SecureHeaders());
MockResponse("*/local.js", statusCode: 200, body: "console.log('ok');",
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/mixed-good"));
await WaitForIdle();
var mixedGood = await CheckMixedContent();
NoFindings(mixedGood.FindingCount, "mixed-content");

Assert.Section("Third-party script without SRI");
ClearMocks();
var sriHtml = MinimalHtml("SRI",
    @"<h1>SRI</h1>
      <script src=""https://cdn.example.com/lib.js""></script>");
SetupPage(FixtureUrl("/sri"), sriHtml, SecureHeaders());
await Navigate(FixtureUrl("/sri"));
await WaitForIdle();
var third = await CheckThirdParty();
Log($"Third-party: count={third.TotalCount} sri={third.SriCount} domains={third.DomainCount}");
Assert.True(third.TotalCount >= 1, "Inventoried at least one third-party resource");
Assert.True(third.Resources.Any(r => r.Type == "script" && !r.HasSri),
    "External script without SRI detected");

Assert.Section("Third-party with SRI (cleaner)");
ClearMocks();
var sriGood = MinimalHtml("SRI Good",
    @"<h1>SRI Good</h1>
      <script src=""https://cdn.example.com/lib.js""
              integrity=""sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC""
              crossorigin=""anonymous""></script>");
SetupPage(FixtureUrl("/sri-good"), sriGood, SecureHeaders());
await Navigate(FixtureUrl("/sri-good"));
await WaitForIdle();
var thirdGood = await CheckThirdParty();
Assert.True(thirdGood.SriCount >= 1 || thirdGood.Resources.Any(r => r.HasSri),
    "SRI attribute recognized on external script");

Assert.Section("Source map reference in inline script");
// SourceMapChecker scans HTML for sourceMappingURL; .map file probing uses HttpClient
// (bypasses WebView mocks) so we assert on the inline reference oracle only.
ClearMocks();
var mapHtml = MinimalHtml("Maps",
    @"<h1>Maps</h1>
      <script>
        console.log('app');
        //# sourceMappingURL=app.js.map
      </script>",
    headExtra: null);
SetupPage(FixtureUrl("/maps"), mapHtml, ScriptableHeaders());
await Navigate(FixtureUrl("/maps"));
await WaitForIdle();
var maps = await CheckSourceMaps();
Log($"Source map findings: {maps.FindingCount}");
foreach (var f in maps.Findings.Take(6))
    Log($"  [{f.Severity}] {f.Category}: {f.Description}");
ExpectFindings(maps.FindingCount, "source-maps");
Assert.True(
    maps.Findings.Any(f => (f.Category ?? "").Contains("SourceMap", StringComparison.OrdinalIgnoreCase)
                        || (f.Description ?? "").Contains("source map", StringComparison.OrdinalIgnoreCase)
                        || (f.Description ?? "").Contains("sourceMappingURL", StringComparison.OrdinalIgnoreCase)),
    "Finding mentions source map reference");
