// Security: XS-Leaks differential scanner — structural oracle + posture + existence tier.

await ResetBrowserState();
SetupEvilXsLeakAttackerMocks();
SetupRegressionXsLeakFixtures();

const string AttackerVictimHit = "https://evil.trowser.test/xs-victim/hit.svg";
const string AttackerVictimMiss = "https://evil.trowser.test/xs-victim/miss.svg";
var svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"10\" height=\"10\"><rect width=\"10\" height=\"10\" fill=\"red\"/></svg>";

Assert.Section("existence-only pair → informational tier when differential");
ClearMocks();
SetupEvilXsLeakAttackerMocks();
MockResponse(AttackerVictimHit, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
MockResponse(AttackerVictimMiss, statusCode: 404, body: "missing", headers: HtmlHeaders());
var existence = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "current", Url = AttackerVictimHit },
        new() { Label = "miss", Url = AttackerVictimMiss }
    ],
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var existScan = await RunXsLeaksAsync(existence, "safe");
var existTech = existScan.Techniques.First(t => t.Technique == "img-error");
Log($"existence tier={existTech.Tier} verdict={existTech.Verdict}");
if (existTech.Verdict is "distinguishable" or "probable")
{
    Assert.True(existTech.Tier == Trowser.Security.SecurityFindingTier.Informational,
        "Public hit vs miss should not be exploitable-tier when differential");
}

Assert.Section("posture block present");
Assert.True(existScan.Posture != null && existScan.Posture.Controls.Count > 0,
    "Posture analyzer returned controls");

Assert.Section("performance-timing identical victims → not distinguishable");
ClearMocks();
MockResponse(AttackerVictimHit, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
MockResponse(AttackerVictimMiss, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
var timingOpts = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = AttackerVictimHit },
        new() { Label = "b", Url = AttackerVictimMiss }
    ],
    Techniques = ["performance-timing"],
    Trials = 4,
    SkipWarmup = true
};
var timingScan = await RunXsLeaksAsync(timingOpts, "safe");
var perfTech = timingScan.Techniques.FirstOrDefault(t => t.Technique == "performance-timing");
Assert.True(perfTech != null, "performance-timing ran");
Assert.True(perfTech!.Verdict == "indistinguishable",
    $"Identical victim URLs should not produce timing distinguishable verdict, got {perfTech.Verdict}: {perfTech.Detail}");

Assert.Section("search hit/miss autoStates requires traffic delta");
await ResetBrowserState();
SetupRegressionXsLeakFixtures();
var searchHit = FixtureUrl("/rest/products/search?q=regression-hit");
var searchMiss = FixtureUrl("/rest/products/search?q=regression-miss-zz");
ClearMocks();
MockResponse(searchHit, statusCode: 200,
    body: "{\"products\":[" + new string('x', 120) + "]}",
    headers: JsonHeaders());
MockResponse(searchMiss, statusCode: 200,
    body: "{\"products\":[]}",
    headers: JsonHeaders());
var seedHtml = MinimalHtml("Search seed",
    "<script>fetch('" + searchHit + "'); fetch('" + searchMiss + "');</script>",
    headExtra: null);
MockResponse(FixtureUrl("/search-seed"), statusCode: 200, body: seedHtml, headers: ScriptableHeaders());
await Navigate(FixtureUrl("/search-seed"));
await WaitForIdle(600, 10000);

var autoSearch = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    AutoStates = true,
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var searchScan = await RunXsLeaksAsync(autoSearch, "safe");
Log($"autoStates strategy={searchScan.StateGenerationStrategy} detail={searchScan.StateGenerationDetail}");
Assert.True(searchScan.StateGenerationStrategy == "search-hit-miss",
    $"Expected search-hit-miss from traffic delta, got {searchScan.StateGenerationStrategy}: {searchScan.StateGenerationDetail}");
Assert.True(searchScan.StateGenerationDetail != null
    && searchScan.StateGenerationDetail.Contains("session traffic", StringComparison.OrdinalIgnoreCase)
    && searchScan.StateGenerationDetail.Contains("Observed", StringComparison.OrdinalIgnoreCase),
    "Detail should cite observed traffic delta (not synthetic canary tokens)");
Assert.True(searchScan.States.Count == 2, "two search states");
Assert.True(
    searchScan.States.Any(s => s.Url.Contains("regression-hit", StringComparison.Ordinal))
    && searchScan.States.Any(s => s.Url.Contains("regression-miss", StringComparison.Ordinal)),
    "States should use observed search URLs from traffic");

Assert.Section("search autoStates skipped when no length/status delta");
await ResetBrowserState();
var sameA = FixtureUrl("/rest/products/search?q=same");
var sameB = FixtureUrl("/rest/products/search?q=other");
ClearMocks();
SetupRegressionXsLeakFixtures();
MockResponse(sameA, statusCode: 200, body: "{\"products\":[]}", headers: JsonHeaders());
MockResponse(sameB, statusCode: 200, body: "{\"products\":[]}", headers: JsonHeaders());
var flatHtml = MinimalHtml("Flat",
    "<script>fetch('" + sameA + "'); fetch('" + sameB + "');</script>");
MockResponse(FixtureUrl("/search-flat"), statusCode: 200, body: flatHtml, headers: ScriptableHeaders());
await Navigate(FixtureUrl("/search-flat"));
await WaitForIdle(400, 8000);
var flatScan = await RunXsLeaksAsync(autoSearch, "safe");
Assert.True(flatScan.StateGenerationStrategy != "search-hit-miss",
    "Identical response bodies should not produce search-hit-miss pair");

Assert.Section("active-only techniques excluded in safe mode");
SetupEvilXsLeakAttackerMocks();
MockResponse(AttackerVictimHit, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
MockResponse(AttackerVictimMiss, statusCode: 404, body: "missing", headers: HtmlHeaders());
var safeAll = await RunXsLeaksAsync(new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = AttackerVictimHit },
        new() { Label = "b", Url = AttackerVictimMiss }
    ],
    Techniques =
    [
        "img-error", "status-bucket-oracle", "cache-prime-probe", "connection-pool-exhaustion",
        "event-loop-blocking", "cache-timing", "history-length-delta", "named-window-reuse"
    ],
    Trials = 2,
    SkipWarmup = true
}, "safe");
var safeIds = safeAll.Techniques.Select(t => t.Technique).ToHashSet(StringComparer.OrdinalIgnoreCase);
Assert.True(!safeIds.Contains("cache-prime-probe"), "cache-prime-probe requires active");
Assert.True(!safeIds.Contains("connection-pool-exhaustion"), "connection-pool-exhaustion requires active");
Assert.True(!safeIds.Contains("event-loop-blocking"), "event-loop-blocking requires active");
Assert.True(!safeIds.Contains("cache-timing"), "cache-timing requires active");
Assert.True(!safeIds.Contains("history-length-delta"), "history-length-delta requires active");
Assert.True(!safeIds.Contains("named-window-reuse"), "named-window-reuse requires active");
Assert.True(safeIds.Contains("img-error"), "safe mode allows img-error when explicitly requested");
Assert.True(safeIds.Contains("status-bucket-oracle"), "safe mode allows status-bucket-oracle when explicitly requested");

Assert.Section("CORS chain upgrades exploitable finding when ACAO * in traffic");
await ResetBrowserState();
ClearMocks();
var corsVictim = FixtureUrl("/api/xsleak-cors-victim?q=1");
MockResponse(corsVictim, statusCode: 200,
    body: "{\"ok\":true,\"data\":\"" + new string('y', 80) + "\"}",
    headers: JsonHeaders(new Dictionary<string, string> { ["Access-Control-Allow-Origin"] = "*" }));
MockResponse(FixtureUrl("/api/xsleak-cors-victim?q=0"), statusCode: 200,
    body: "{\"ok\":false}",
    headers: JsonHeaders(new Dictionary<string, string> { ["Access-Control-Allow-Origin"] = "*" }));
var seedCors = MinimalHtml("cors", "<script>fetch('" + corsVictim + "');</script>");
MockResponse(FixtureUrl("/cors-seed"), statusCode: 200, body: seedCors, headers: ScriptableHeaders());
await Navigate(FixtureUrl("/cors-seed"));
await WaitForIdle(500, 8000);
var corsStates = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "hit", Url = corsVictim },
        new() { Label = "miss", Url = FixtureUrl("/api/xsleak-cors-victim?q=0") }
    ],
    Techniques = ["script-error"],
    Trials = 2,
    SkipWarmup = true
};
MockResponse(corsVictim, statusCode: 200, body: "not-js", headers: JsonHeaders(new Dictionary<string, string> { ["Access-Control-Allow-Origin"] = "*" }));
MockResponse(FixtureUrl("/api/xsleak-cors-victim?q=0"), statusCode: 404, body: "missing", headers: JsonHeaders(new Dictionary<string, string> { ["Access-Control-Allow-Origin"] = "*" }));
var corsScan = await RunXsLeaksAsync(corsStates, "safe");
if (corsScan.Findings.Any(f => f.Tier == Trowser.Security.SecurityFindingTier.Exploitable))
{
    Assert.True(corsScan.ChainFindings.Any(c => c.Category == "xs-leaks+cors"),
        "Exploitable XS-Leak with wildcard CORS in traffic should emit cors chain finding");
}
else
    Log("No exploitable xs-leak on cors fixture (skip chain assert)");

Assert.Section("status-bucket-oracle: attacker observables (img load vs error)");
ClearMocks();
MockResponse(AttackerVictimHit, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
MockResponse(AttackerVictimMiss, statusCode: 404, body: "missing", headers: HtmlHeaders());
var bucketScan = await RunXsLeaksAsync(new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "hit", Url = AttackerVictimHit },
        new() { Label = "miss", Url = AttackerVictimMiss }
    ],
    Techniques = ["status-bucket-oracle"],
    Trials = 2,
    SkipWarmup = true
}, "safe");
var bucketTech = bucketScan.Techniques.First(t => t.Technique == "status-bucket-oracle");
Log($"status-bucket verdict={bucketTech.Verdict} detail={bucketTech.Detail}");
Assert.True(bucketTech.Verdict is "distinguishable" or "probable",
    $"Expected status bucket differential from cross-site observables, got {bucketTech.Verdict}");
Assert.True(bucketScan.Findings.Any(f => f.Category == "xs-leaks"),
    "Unified xs-leaks finding emitted");
Assert.True(!string.IsNullOrEmpty(bucketTech.PocHtml) && bucketTech.PocHtml.Contains("Trowser XS-Leak PoC evidence"),
    "Watermarked PoC HTML attached");
Assert.True(GetSessionVpxArtifacts().Any(a => a.TryGetValue("kind", out var k) && k?.ToString() == "xs-leak-poc"),
    "VPX artifact feed includes xs-leak PoC HTML");

Assert.Section("iframe-framecount distinguishes embedded frame count");
ClearMocks();
const string HtmlWithFrame = "https://evil.trowser.test/xs-html/with-frame";
const string HtmlNoFrame = "https://evil.trowser.test/xs-html/no-frame";
const string HtmlChild = "https://evil.trowser.test/xs-html/child";
var htmlHeaders = HtmlHeaders(new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
MockResponse(HtmlWithFrame, statusCode: 200,
    body: "<!DOCTYPE html><html><body><iframe src=\"" + HtmlChild + "\"></iframe></body></html>",
    headers: htmlHeaders);
MockResponse(HtmlNoFrame, statusCode: 200,
    body: "<!DOCTYPE html><html><body><p>plain</p></body></html>",
    headers: htmlHeaders);
MockResponse(HtmlChild, statusCode: 200,
    body: "<!DOCTYPE html><html><body>child</body></html>",
    headers: htmlHeaders);
var frameScan = await RunXsLeaksAsync(new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "member", Url = HtmlWithFrame },
        new() { Label = "guest", Url = HtmlNoFrame }
    ],
    Techniques = ["iframe-framecount"],
    Trials = 2,
    SkipWarmup = true
}, "safe");
var frameTech = frameScan.Techniques.First(t => t.Technique == "iframe-framecount");
Log($"iframe-framecount values: {string.Join(" | ", frameTech.ValuesByState.Select(kv => kv.Key + "=" + string.Join(",", kv.Value)))}");
Assert.True(frameTech.Verdict is "distinguishable" or "probable",
    $"Expected frame-count differential, got {frameTech.Verdict}: {frameTech.Detail}");

Assert.Section("same URL identity-pair skips timing techniques");
var sameUrl = FixtureUrl("/same-url-xs");
ClearMocks();
MockResponse(sameUrl, statusCode: 200,
    body: MinimalHtml("Same", "<p>same</p>"),
    headers: ScriptableHeaders());
var sameOpts = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = sameUrl, Identity = "anonymous" },
        new() { Label = "b", Url = sameUrl, Identity = "anonymous" }
    ],
    Techniques = ["img-error", "performance-timing"],
    Trials = 2,
    SkipWarmup = true
};
var sameScan = await RunXsLeaksAsync(sameOpts, "safe");
Log($"same-url warnings={string.Join("; ", sameScan.Warnings)} summary={sameScan.Summary}");
Assert.True(sameScan.SameUrlStates, "SameUrlStates flag set");
Assert.True(sameScan.Warnings.Count > 0, "warnings emitted for same URL pair");
Assert.True(!sameScan.Techniques.Any(t => t.Technique == "performance-timing"),
    "performance-timing skipped when all states share one URL");
Assert.True(sameScan.ProbableCount == 0 && sameScan.DistinguishableCount == 0,
    "no exploitable timing noise on identical URL");

Assert.Section("CORP header does not downgrade when img-error still distinguishes");
ClearMocks();
var corpHit = FixtureUrl("/corp/hit.svg");
var corpMiss = FixtureUrl("/corp/miss.svg");
var corpHeaders = HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml",
    ["Cross-Origin-Resource-Policy"] = "same-origin"
});
MockResponse(corpHit, statusCode: 200, body: svg, headers: corpHeaders);
MockResponse(corpMiss, statusCode: 404, body: "missing", headers: corpHeaders);
var corpScan = await RunXsLeaksAsync(new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = corpHit },
        new() { Label = "b", Url = corpMiss }
    ],
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
}, "safe");
var corpTech = corpScan.Techniques.First(t => t.Technique == "img-error");
if (corpTech.Verdict is "distinguishable" or "probable")
{
    Assert.True(corpTech.Tier == Trowser.Security.SecurityFindingTier.Exploitable,
        "CORP on mocks must not claim mitigation while cross-site img oracle still works");
    Assert.True(!corpTech.Mitigated, "Mitigated flag should be false when observables still leak");
}

Assert.Section("hypothesis control miss downgrades confirmed finding");
ClearMocks();
const string ControlMissSvg = "https://evil.trowser.test/xs-victim/control-miss.svg";
MockResponse(AttackerVictimHit, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
MockResponse(AttackerVictimMiss, statusCode: 404, body: "missing", headers: HtmlHeaders());
MockResponse(ControlMissSvg, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml"
}));
var controlHyp = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "hit", Url = AttackerVictimHit, Role = "hit" },
        new() { Label = "miss-0", Url = AttackerVictimMiss, Role = "miss" },
        new() { Label = "miss-1", Url = ControlMissSvg, Role = "miss" }
    ],
    Hypothesis = new Trowser.Security.XsLeaks.XsLeakHypothesis.HypothesisSpec
    {
        Secret = "fixture",
        Kind = "value",
        HitValues = ["hit"],
        MissValues = ["miss-0", "miss-1"]
    },
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var controlScan = await RunXsLeaksAsync(controlHyp, "safe");
var controlTech = controlScan.Techniques.First(t => t.Technique == "img-error");
Log($"control hypothesis confirmationStatus={controlTech.ConfirmationStatus} verdict={controlTech.Verdict}");
Assert.True(controlTech.ConfirmationStatus == "candidate-control-failed",
    $"Expected control failure downgrade, got {controlTech.ConfirmationStatus}");
Assert.True(!controlScan.Findings.Any(f => f.Tier == Trowser.Security.SecurityFindingTier.Exploitable),
    "Control failure must not emit exploitable finding");

Assert.Section("hypothesis urlTemplate expands and returns diagnostics");
var templHit = FixtureUrl("/rest/hypothesis/search?q=regression-secret-hit");
var templMiss = FixtureUrl("/rest/hypothesis/search?q=regression-secret-miss");
ClearMocks();
MockResponse(templHit, statusCode: 200,
    body: "{\"items\":[" + new string('h', 100) + "]}",
    headers: JsonHeaders());
MockResponse(templMiss, statusCode: 200, body: "{\"items\":[]}", headers: JsonHeaders());
var templScan = await RunXsLeaksAsync(new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    Hypothesis = new Trowser.Security.XsLeaks.XsLeakHypothesis.HypothesisSpec
    {
        Secret = "regression-secret",
        UrlTemplate = FixtureUrl("/rest/hypothesis/search?q={value}"),
        HitValues = ["regression-secret-hit"],
        MissValues = ["regression-secret-miss"]
    },
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true,
    MaxSeconds = 60
}, "safe");
Assert.True(templScan.HypothesisExpanded, "hypothesis should expand into states");
Assert.True(templScan.States.Count >= 2, "expanded states");
Assert.True(templScan.StateValidation != null, "stateValidation populated");

