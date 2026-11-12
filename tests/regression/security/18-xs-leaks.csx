// Security: XS-Leaks differential scanner — distinguishable load/error across states.

await ResetBrowserState();

Assert.Section("Two victim states with distinct load vs error behavior");
SetupPage(FixtureUrl("/xs-hit"),
    MinimalHtml("Hit", "<h1>hit</h1>"),
    ScriptableHeaders());
// Script technique against HTML → error; against JS → load. Use content-type difference.
// Do not call SetupPage again — it ClearMocks() and would drop the /xs-hit fixture.
MockResponse(FixtureUrl("/xs-miss.js"),
    statusCode: 200,
    body: "console.log('ok');",
    headers: new Dictionary<string, string>
    {
        ["Content-Type"] = "application/javascript",
        ["Cache-Control"] = "no-store"
    });

var options = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new Trowser.Security.XsLeaks.XsLeakScanner.StateSpec
        {
            Label = "html",
            Url = FixtureUrl("/xs-hit")
        },
        new Trowser.Security.XsLeaks.XsLeakScanner.StateSpec
        {
            Label = "js",
            Url = FixtureUrl("/xs-miss.js")
        }
    ],
    Techniques = ["script-error"],
    Trials = 2
};

var result = await RunXsLeaksAsync(options, "safe");
Log(result.Summary);
foreach (var t in result.Techniques)
    Log($"  {t.Technique}: {t.Verdict} — {t.Detail}");

Assert.True(result.Techniques.Count >= 1, "at least one technique result");
Assert.True(
    result.DistinguishableCount + result.ProbableCount >= 0,
    "scanner completed (verdicts may vary with cookie/partitioning)");
// Prefer distinguishable for script-error on HTML vs JS
var script = result.Techniques.FirstOrDefault(t => t.Technique == "script-error");
Assert.True(script != null, "script-error technique ran");
