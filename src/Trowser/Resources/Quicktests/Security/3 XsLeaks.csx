// @title 3 Xs Leaks
// @shadow never
// @effects mutates
// XS-Leaks: can a cross-site attacker distinguish two victim states?
// Uses a mocked attacker origin (https://evil.trowser.test). Blocked in --safe.
// Browse authenticated APIs or search traffic first so autoStates can derive secret-dependent pairs.

var hitUrl = await GetCurrentUrl();
Log("XS-Leaks differential scan");
Log($"  page: {hitUrl}");
Log("Browse search/API traffic or capture identities before running for autoStates.");
Log("Manual current-vs-404 pairs are informational tier when distinguishable (not secret-dependent).");
Log("");

Assert.Section("Attacker-observable differentials");
Trowser.Security.XsLeaks.XsLeakScanner.XsLeakResult result;
var autoOptions = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    AutoStates = true,
    Trials = 2,
    SkipWarmup = true
};

try
{
    result = await PrintXsLeaksReport(autoOptions, "safe");
}
catch (Exception ex)
{
    Log($"Auto-states unavailable: {ex.Message}");
    Log("Falling back to current URL vs synthetic miss (informational tier if differential).");
    var missUrl = hitUrl;
    if (Uri.TryCreate(hitUrl, UriKind.Absolute, out var u))
        missUrl = u.GetLeftPart(UriPartial.Authority) + "/trowser-xsleak-miss-404";

    var manualOptions = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
    {
        States =
        [
            new Trowser.Security.XsLeaks.XsLeakScanner.StateSpec { Label = "current", Url = hitUrl },
            new Trowser.Security.XsLeaks.XsLeakScanner.StateSpec { Label = "synthetic-miss", Url = missUrl }
        ],
        Techniques = ["iframe-load", "script-error", "img-error", "iframe-framecount", "status-bucket-oracle"],
        Trials = 2,
        SkipWarmup = true
    };
    result = await PrintXsLeaksReport(manualOptions, "safe");
}

if (!string.IsNullOrEmpty(result.StateGenerationStrategy))
    Log($"stateGeneration: {result.StateGenerationStrategy} — {result.StateGenerationDetail}");

var exploitable = result.Techniques.Count(t =>
    t.Verdict is "distinguishable" or "probable"
    && t.Tier == Trowser.Security.SecurityFindingTier.Exploitable);
if (exploitable > 0)
    Log($"Review {exploitable} exploitable technique(s) in the report above.");
else if (result.InformationalCount > 0)
    Log("Only informational differentials — try identity pairs or search hit/miss from session traffic.");

Assert.Pass(result.Summary);
