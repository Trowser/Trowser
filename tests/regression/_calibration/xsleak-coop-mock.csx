// Calibration: COOP on mocked HTML — popup/window oracles may still run; record for WebView2 upgrades.

await ResetBrowserState();
const string victim = "https://evil.trowser.test/xsleak-calibration/coop-page";
ClearMocks();
MockResponse(victim, statusCode: 200,
    body: MinimalHtml("coop", "<p>coop probe</p>"),
    headers: HtmlHeaders(new Dictionary<string, string>
    {
        ["Cross-Origin-Opener-Policy"] = "same-origin"
    }));

var opts = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "a", Url = victim },
        new() { Label = "b", Url = victim + "?b=1" }
    ],
    Techniques = ["popup-closed"],
    Trials = 2,
    SkipWarmup = true
};
var scan = await RunXsLeaksAsync(opts, "active");
var pop = scan.Techniques.FirstOrDefault(t => t.Technique == "popup-closed");
Log($"popup-closed verdict={pop?.Verdict} mitigated={pop?.Mitigated} mitigatedBy={string.Join(",", pop?.MitigatedBy ?? [])}");
Log($"browserModel isolation={scan.BrowserModel.IsolationEnforcement}");
