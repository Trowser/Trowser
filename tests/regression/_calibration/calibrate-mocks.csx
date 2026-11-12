// Calibration: probe which scanners produce true-positives against WebView mocks.
// Run: .\tests\regression\run-regression.ps1 -Filter "_calibration*"
// (or invoke this file via CLI after concatenating prelude).
// This file lives under _calibration/ and is NOT part of the default suite.

await ResetBrowserState();
Assert.Section("Calibration — mock document + headers");

var pageUrl = FixtureUrl("/cal");
var html = MinimalHtml("Cal", "<h1>Calibration</h1><p id='ready'>ok</p>");
SetupPage(pageUrl, html, VulnerableHeaders());
await Navigate(pageUrl);
await WaitForIdle();

Assert.Contains("trowser-regression.test", await GetCurrentUrl(), "Navigate hits mocked HTTPS host");
Assert.Equal("Cal", await GetTitle(), "Title from mocked HTML");

Assert.Section("Calibration — CheckSecurityHeaders via in-page fetch");
var headers = await CheckSecurityHeaders();
Log($"Header findings: {headers.FindingCount}; fetchError={headers.FetchError}");
foreach (var f in headers.Findings.Take(8))
    Log($"  [{f.Severity}] {f.Header}: {f.Description}");
Assert.True(headers.FindingCount > 0 || !string.IsNullOrEmpty(headers.FetchError),
    "Headers checker ran (findings or reported fetch error)");

Assert.Section("Calibration — CheckXss DOM patterns");
ClearMocks();
var xssHtml = MinimalHtml("XSS",
    @"<a href=""javascript:alert(1)"">bad</a>
      <img src=x onerror=""alert(1)"">
      <script>eval('1'); document.write('x');</script>");
SetupPage(FixtureUrl("/xss"), xssHtml, SecureHeaders());
await Navigate(FixtureUrl("/xss"));
await WaitForIdle();
var xss = await CheckXss();
Log($"XSS findings: {xss.FindingCount}");
foreach (var kv in xss.FindingsByCategory)
    Log($"  {kv.Key}: {kv.Value}");
Assert.True(xss.FindingCount > 0, "DOM XSS patterns detected on planted page");

Assert.Section("Calibration — CheckCors with static ACAO mock");
ClearMocks();
var corsHeaders = HtmlHeaders(new Dictionary<string, string>
{
    ["Access-Control-Allow-Origin"] = "https://evil.com",
    ["Access-Control-Allow-Credentials"] = "true"
});
SetupPage(FixtureUrl("/cors"), MinimalHtml("CORS", "<h1>cors</h1>"), corsHeaders);
// Also mock the document URL for subsequent CORS probe fetches
MockResponse(FixtureUrl("/cors"), statusCode: 200, body: "{}", headers: corsHeaders);
await Navigate(FixtureUrl("/cors"));
await WaitForIdle();
try
{
    var cors = await CheckCors();
    Log($"CORS issues: {cors.IssueCount}");
    foreach (var f in cors.Issues.Take(6))
        Log($"  [{f.Severity}] {f.Description}");
    Assert.Pass($"CheckCors completed (issues={cors.IssueCount})");
}
catch (Exception ex)
{
    Log($"CheckCors threw: {ex.Message}");
    Assert.Pass("CheckCors threw — note for README (may need dynamic Origin echo)");
}

Assert.Section("Calibration — RunSqliScan against error-echo mock");
ClearMocks();
SetupPage(FixtureUrl("/"), MinimalHtml("Home", "<h1>home</h1>"), SecureHeaders());
await Navigate(FixtureUrl("/"));
// Mock that returns SQL error signatures for any query to /api/search
SetupApi("*/api/search*", statusCode: 500,
    body: "{\"error\":\"You have an error in your SQL syntax; check the manual near '''\"}");
try
{
    var sqli = await RunSqliScan(
        urlTemplate: FixtureUrl("/api/search?q={{PAYLOAD}}"),
        method: "GET",
        baselineValue: "1",
        includeTimeBased: false,
        timeoutMs: 8000);
    Log($"SQLi HasFindings={sqli.HasFindings} rows={sqli.Rows.Count} findings={sqli.Findings.Count}");
    foreach (var f in sqli.Findings.Take(5))
        Log($"  [{f.Severity}] {f.Title ?? f.Evidence}");
    Assert.Pass($"RunSqliScan completed (findings={sqli.Findings.Count})");
}
catch (Exception ex)
{
    Log($"RunSqliScan threw: {ex.Message}");
    Assert.Pass("RunSqliScan threw — structural-only for active scanners");
}

Assert.Section("Calibration — Retire.js with known-vulnerable jQuery ref");
ClearMocks();
// jQuery 1.6.0 is in Retire.js DB. Serve a tiny stub that identifies as jQuery 1.6.0.
var jqStub = "/*! jQuery v1.6.0 */\nvar jQuery = function(){}; jQuery.fn = jQuery.prototype = {}; jQuery.fn.jquery = '1.6.0'; window.jQuery = window.$ = jQuery;\n";
SetupPage(FixtureUrl("/jq"),
    MinimalHtml("JQ", "<h1>jq</h1><script src=\"/vendor/jquery-1.6.0.js\"></script>"),
    SecureHeaders());
MockResponse("*/vendor/jquery-1.6.0.js", statusCode: 200, body: jqStub,
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/jq"));
await WaitForIdle();
await Sleep(500);
var sec = await CheckSecurity();
Log($"Libraries={sec.LibraryCount} Vulnerable={sec.VulnerableCount}");
foreach (var lib in sec.Libraries)
    Log($"  {lib.Name} {lib.Version} vuln={lib.IsVulnerable}");
Assert.Pass($"Retire.js scan completed (vulnerable={sec.VulnerableCount})");

Assert.Section("Calibration — secrets harvest from localStorage");
await SetStorageItem("local", "authToken", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.");
var harvest = await RunSecretsHarvest(includeJsBundles: false, includeNetworkResponses: false,
    includePageText: false, includeSourceMaps: false);
Log($"Secrets findings: {harvest.TotalFindings}");
foreach (var f in harvest.Findings.Take(6))
    Log($"  [{f.Severity}] [{f.Source}] {f.Description}");
Assert.True(harvest.TotalFindings > 0, "Secrets harvest sees JWT in localStorage");

Log("\n=== Calibration complete — review output for README known-gaps ===");
