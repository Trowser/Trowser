// Calibration: CORP on mocked victim — img-error oracle should not claim cross-origin resource read.
// If this fails after a WebView2 upgrade, isolation may not apply to WebResourceRequested mocks (use HttpListener).

await ResetBrowserState();
const string corpVictim = "https://evil.trowser.test/xsleak-calibration/corp-asset.svg";
const string corpMiss = "https://evil.trowser.test/xsleak-calibration/corp-miss.svg";
var svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"8\" height=\"8\"><rect width=\"8\" height=\"8\"/></svg>";
ClearMocks();
MockResponse(corpVictim, statusCode: 200, body: svg, headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "image/svg+xml",
    ["Cross-Origin-Resource-Policy"] = "same-origin"
}));
MockResponse(corpMiss, statusCode: 404, body: "missing", headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Cross-Origin-Resource-Policy"] = "same-origin"
}));

var opts = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "hit", Url = corpVictim },
        new() { Label = "miss", Url = corpMiss }
    ],
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var scan = await RunXsLeaksAsync(opts, "safe");
var img = scan.Techniques.First(t => t.Technique == "img-error");
Log($"img-error verdict={img.Verdict} tier={img.Tier} mitigated={img.Mitigated} detail={img.Detail}");
Assert.True(img.Mitigated || img.Tier != Trowser.Security.SecurityFindingTier.Exploitable,
    "CORP same-origin should block or downgrade exploitable img-error differential on cross-site attacker page");
