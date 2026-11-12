// Security: Retire.js, secrets harvest, JWT analysis.

await ResetBrowserState();

Assert.Section("Retire.js - vulnerable jQuery 1.6.0");
var jqStub = "/*! jQuery v1.6.0 jquery.com | jquery.org/license */\n" +
             "var jQuery = function(){}; jQuery.fn = jQuery.prototype = {};\n" +
             "jQuery.fn.jquery = '1.6.0'; window.jQuery = window.$ = jQuery;\n";
SetupPage(FixtureUrl("/retire-bad"),
    MinimalHtml("Retire Bad", "<h1>JQ</h1><script src=\"/vendor/jquery-1.6.0.js\"></script>"),
    SecureHeaders());
MockResponse("*/vendor/jquery-1.6.0.js", statusCode: 200, body: jqStub,
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/retire-bad"));
await WaitForIdle();
await Sleep(400);
var bad = await CheckSecurity();
Log($"Retire bad: libs={bad.LibraryCount} vulnerable={bad.VulnerableCount}");
foreach (var lib in bad.Libraries)
    Log($"  {lib.Name} {lib.Version} vuln={lib.IsVulnerable}");
Assert.True(bad.VulnerableCount > 0 || bad.Libraries.Any(l => l.IsVulnerable),
    "Retire.js flags jQuery 1.6.0 (or detects library)");

Assert.Section("Retire.js - Bootstrap 3.4.1 + jQuery UI in one minified bundle (no standalone filename)");
ClearMocks();
var bundledJs =
    "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n" +
    "var jQuery=function(){};jQuery.fn=jQuery.prototype={};jQuery.fn.jquery='3.6.0';\n" +
    "window.jQuery=window.$=jQuery;\n" +
    "jQuery.ui={version:'1.10.4'};\n" +
    "/*! Bootstrap v3.4.1 (https://getbootstrap.com/) */\n" +
    "var Modal=function(){};Modal.VERSION='3.4.1';jQuery.fn.modal=function(){};jQuery.fn.modal.Constructor=Modal;\n" +
    "var Tooltip=function(){};Tooltip.VERSION='3.4.1';jQuery.fn.tooltip=function(){};jQuery.fn.tooltip.Constructor=Tooltip;\n";
SetupPage(FixtureUrl("/retire-bundled"),
    MinimalHtml("Retire Bundled", "<h1>App</h1><script src=\"/js/app.bundle.min.js\"></script>"),
    SecureHeaders());
MockResponse("*/js/app.bundle.min.js", statusCode: 200, body: bundledJs,
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/retire-bundled"));
await WaitForIdle();
await Sleep(400);
var bundled = await CheckSecurity();
Log($"Retire bundled: libs={bundled.LibraryCount} vulnerable={bundled.VulnerableCount} caveats={bundled.Caveats.Count} fileContent={bundled.FileContentScanned}");
foreach (var lib in bundled.Libraries)
    Log($"  {lib.Name} {lib.Version} via={lib.DetectionMethod} vuln={lib.IsVulnerable}");
foreach (var c in bundled.Caveats)
    Log("  caveat: " + c);
Assert.True(bundled.Libraries.Any(l => l.Name.Equals("bootstrap", StringComparison.OrdinalIgnoreCase) && l.Version.StartsWith("3.4.1")),
    "Detects Bootstrap 3.4.1 inside app.bundle.min.js");
Assert.True(bundled.Libraries.Any(l => l.Name.Equals("jquery-ui", StringComparison.OrdinalIgnoreCase)),
    "Detects jQuery UI in the same bundle via func");
Assert.True(
    bundled.Libraries.Where(l => l.Name.Equals("bootstrap", StringComparison.OrdinalIgnoreCase))
        .Any(l => l.IsVulnerable),
    "Bootstrap 3.4.1 is reported as vulnerable");
Assert.True(bundled.HasBundledScripts || bundled.Caveats.Count > 0,
    "Surfaces a bundled-JS caveat so testers do not treat a clean result as complete");

Assert.Section("Retire.js - Bootstrap in bundle via func only (banner stripped)");
ClearMocks();
var funcOnlyJs =
    "var jQuery=function(){};jQuery.fn={};window.jQuery=window.$=jQuery;\n" +
    "var Modal=function(){};Modal.VERSION='3.4.1';jQuery.fn.modal=function(){};jQuery.fn.modal.Constructor=Modal;\n";
SetupPage(FixtureUrl("/retire-bs-func"),
    MinimalHtml("Retire BS func", "<h1>App</h1><script src=\"/js/app.bundle.min.js\"></script>"),
    SecureHeaders());
MockResponse("*/js/app.bundle.min.js", statusCode: 200, body: funcOnlyJs,
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/retire-bs-func"));
await WaitForIdle();
await Sleep(400);
var funcOnly = await CheckSecurity();
var bsFunc = funcOnly.Libraries.FirstOrDefault(l => l.Name.Equals("bootstrap", StringComparison.OrdinalIgnoreCase));
Log($"Retire func-only bootstrap: {(bsFunc == null ? "MISSING" : bsFunc.Version + " via=" + bsFunc.DetectionMethod)}");
Assert.True(bsFunc != null && bsFunc.Version.StartsWith("3.4.1"),
    "Bootstrap 3.4.1 detected from $.fn.modal.Constructor.VERSION without a license banner");
Assert.Equal("func", bsFunc!.DetectionMethod, "Prefers live-DOM func fingerprint when the plugin API is present");

Assert.Section("Retire.js - Bootstrap in bundle via filecontent only (no runtime VERSION)");
ClearMocks();
var contentOnlyJs =
    "/*! Bootstrap v3.4.1 (https://getbootstrap.com/) */\n" +
    "function bootModal(){this.close=function(){}};\n";
SetupPage(FixtureUrl("/retire-bs-content"),
    MinimalHtml("Retire BS content", "<h1>App</h1><script src=\"/js/app.bundle.min.js\"></script>"),
    SecureHeaders());
MockResponse("*/js/app.bundle.min.js", statusCode: 200, body: contentOnlyJs,
    headers: new Dictionary<string, string> { ["Content-Type"] = "application/javascript" });
await Navigate(FixtureUrl("/retire-bs-content"));
await WaitForIdle();
await Sleep(400);
var contentOnly = await CheckSecurity();
var bsContent = contentOnly.Libraries.FirstOrDefault(l => l.Name.Equals("bootstrap", StringComparison.OrdinalIgnoreCase));
Log($"Retire filecontent bootstrap: {(bsContent == null ? "MISSING" : bsContent.Version + " via=" + bsContent.DetectionMethod)} fileContentScanned={contentOnly.FileContentScanned}");
Assert.True(bsContent != null && bsContent.Version.StartsWith("3.4.1"),
    "Bootstrap 3.4.1 detected from bundled filecontent banner when no runtime API exists");
Assert.Equal("filecontent", bsContent!.DetectionMethod, "Uses filecontent when func/uri/filename cannot see Bootstrap");

Assert.Section("Retire.js - clean page with no libs");
ClearMocks();
SetupPage(FixtureUrl("/retire-good"),
    MinimalHtml("Retire Good", "<h1>Clean</h1><script>window.__app=1;</script>"),
    ScriptableHeaders());
await Navigate(FixtureUrl("/retire-good"));
await WaitForIdle();
var good = await CheckSecurity();
Log($"Retire good: vulnerable={good.VulnerableCount}");
NoFindings(good.VulnerableCount, "retire.js");

Assert.Section("Secrets harvest - JWT in localStorage");
ClearMocks();
SetupPage(FixtureUrl("/secrets"), MinimalHtml("Secrets", "<h1>S</h1>"), SecureHeaders());
await Navigate(FixtureUrl("/secrets"));
await WaitForIdle();
await SetStorageItem("local", "access_token", SeedJwtAlgNone());
await SetStorageItem("local", "api_key", "AKIAiosfaketestKEYEXAMPLE");
var harvest = await RunSecretsHarvest(
    includeJsBundles: false,
    includeNetworkResponses: false,
    includePageText: false,
    includeSourceMaps: false);
Log($"Secrets findings: {harvest.TotalFindings}");
foreach (var f in harvest.Findings.Take(8))
    Log($"  [{f.Severity}] [{f.Source}] {f.Description}");
ExpectFindings(harvest.TotalFindings, "secrets-harvest");

Assert.Section("Secrets clean twin");
await ClearStorage("local");
await ClearStorage("session");
var harvestGood = await RunSecretsHarvest(
    includeJsBundles: false,
    includeNetworkResponses: false,
    includePageText: false,
    includeSourceMaps: false);
Log($"Secrets clean: {harvestGood.TotalFindings}");
Assert.True(harvestGood.TotalFindings < harvest.TotalFindings,
    "Clean storage yields fewer secret findings");

Assert.Section("JWT analysis - alg none + expired");
await SetStorageItem("local", "token", SeedJwtAlgNone());
var jwtBad = await RunJwtAnalysis();
Log($"JWT tokens found: {jwtBad.Tokens.Count}");
foreach (var t in jwtBad.Tokens)
{
    Log($"  alg={t.HeaderAlg} issues={t.Issues.Count} source={t.Source}");
    foreach (var i in t.Issues) Log("    ! " + i);
}
Assert.True(jwtBad.Tokens.Count >= 1, "JWT discovered in storage");
var hasNoneOrExpiry = jwtBad.Tokens.Any(t =>
{
    var alg = t.HeaderAlg ?? "";
    if (alg.Equals("none", StringComparison.OrdinalIgnoreCase)) return true;
    return t.Issues.Any(i =>
        i.IndexOf("none", StringComparison.OrdinalIgnoreCase) >= 0
        || i.IndexOf("expir", StringComparison.OrdinalIgnoreCase) >= 0);
});
Assert.True(hasNoneOrExpiry, "alg none or expiry issue flagged");

Assert.Section("JWT analysis - cleaner HS256 token");
await ClearStorage("local");
await SetStorageItem("local", "token", SeedJwtHs256Clean());
var jwtGood = await RunJwtAnalysis();
Log($"JWT clean tokens: {jwtGood.Tokens.Count}");
foreach (var t in jwtGood.Tokens)
    Log($"  alg={t.HeaderAlg} issues={string.Join("; ", t.Issues)}");
Assert.True(jwtGood.Tokens.Count >= 1, "Clean JWT still discovered");
Assert.False(
    jwtGood.Tokens.Any(t => (t.HeaderAlg ?? "").Equals("none", StringComparison.OrdinalIgnoreCase)),
    "Clean twin is not alg none");
