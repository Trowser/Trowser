// Calibration: record assumptions for XS-Leaks browserModel (re-run after WebView2 upgrades).

await ResetBrowserState();
Navigate("https://evil.trowser.test/xsleak-calibration/ping");
await WaitForIdle(300, 5000);

const string pingUrl = "https://evil.trowser.test/xsleak-calibration/ping";
MockResponse(pingUrl, statusCode: 200, body: "ok", headers: HtmlHeaders(new Dictionary<string, string>
{
    ["Content-Type"] = "text/plain",
    ["Cross-Origin-Resource-Policy"] = "same-origin"
}));

var options = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = pingUrl },
        new() { Label = "b", Url = pingUrl + "?miss=1" }
    ],
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var scan = await RunXsLeaksAsync(options, "safe");
Log($"browserModel engine: {scan.BrowserModel.Engine}");
Log($"attackerOrigin: {scan.BrowserModel.AttackerOrigin}");
Log($"summary: {scan.Summary}");
Assert.True(scan.BrowserModel.AttackerOrigin.Contains("evil.trowser.test"),
    "Attacker fixture origin expected for cross-site XS-Leaks calibration");
