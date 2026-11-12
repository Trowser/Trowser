// @title Monkey Test
// @shadow never
// @effects mutates
// Robustness: gremlins.js monkey test + Monkey Trowser smart test

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Robustness test: {title}");
Log($"URL: {url}");
Log("");

// --- Part 1: Gremlins (random chaos) ---

Log("=== Part 1: Gremlins.js ===");
Log("");

var preErrors = GetConsoleErrors();
if (preErrors.Count > 0)
    Log($"Note: {preErrors.Count} console error(s) already present before test");

Log("");
await AssertRobust();
await PrintMonkeyTestReport();

var postErrors = GetConsoleErrors();
var newErrors = postErrors.Count - preErrors.Count;
if (newErrors > 0)
    Assert.Fail($"{newErrors} new console error(s) appeared during monkey testing");
else
    Assert.Pass("No new console errors from gremlins monkey testing");

Log("");

// --- Part 2: Monkey Trowser (smart robustness) ---

Log("=== Part 2: Monkey Trowser ===");
Log("");

// Reload the page to get a clean state after gremlins
Log("Reloading page to reset state after gremlins...");
await Navigate(url);
await WaitForIdle();
Log("");

var smartResult = await RunSmartMonkey();
PrintSmartMonkeyReport(smartResult);
AssertSmartMonkey(smartResult);
