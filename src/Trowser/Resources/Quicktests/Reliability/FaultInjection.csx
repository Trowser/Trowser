// @title Fault Injection
// @shadow never
// @effects mutates
// Fault injection: test how the current page handles API failures
// Auto-discovers endpoints, injects faults (500, 404, empty, invalid JSON),
// tests parameter tampering (missing/invalid IDs via fetch), then checks for
// crashes, blank pages, content changes, and error pages.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Fault Injection Test: {title}");
Log($"URL: {url}");
Log("");

// Wait for any in-flight requests to settle before discovery
await WaitForIdle(1000, 10000);

var networkEntries = GetNetworkLog();
Log($"Network log: {networkEntries.Count} request(s) captured");
Log("");

if (networkEntries.Count == 0)
{
    Log("No network traffic captured yet.");
    Log("Tip: browse the site first to populate the network log, then re-run this test.");
    Assert.Fail("No network traffic — cannot discover endpoints");
    return;
}

// Phase 1: Fault injection + parameter tampering (skip slow-response for speed)
Log("=== Phase 1: Fault Injection & Parameter Tampering ===");
Log("");

var result = await RunInterrupterTest(new InterrupterOptions
{
    WaitForIdle = true,
    MaxEndpoints = 5,
    CooldownMs = 200,
    Faults = new List<string> { "server-error", "not-found", "empty-body", "invalid-json" },
    TestParameters = true,
});

Log("");
PrintInterrupterReport(result);
Log("");

if (result.EndpointsTested == 0)
{
    Log("No API endpoints were discovered.");
    Log("The network log may only contain static assets (images, CSS, JS).");
    Log("Tip: interact with the page (submit forms, click buttons) to generate API traffic.");
    Assert.Fail("No API endpoints discovered for fault injection");
    return;
}

// Phase 2: If there are endpoints with JSON responses, also test mutate-response
var jsonEndpoints = result.DiscoveredEndpoints
    .Where(e => e.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase)
             && !string.IsNullOrEmpty(e.ResponseBody))
    .ToList();

if (jsonEndpoints.Count > 0)
{
    Log($"=== Phase 2: Response Mutation ({jsonEndpoints.Count} JSON endpoint(s)) ===");
    Log("");

    var mutationResult = await RunInterrupterTest(new InterrupterOptions
    {
        Url = jsonEndpoints[0].UrlPattern,
        Method = jsonEndpoints[0].Method,
        Faults = new List<string> { "mutate-response" },
    });

    PrintInterrupterReport(mutationResult);
    Log("");
}

// Summary
Log("=== Summary ===", "#569CD6");
Log($"  Endpoints tested:    {result.EndpointsTested}");
Log($"  Fault scenarios:     {result.ScenarioCount} ({result.Passed} passed, {result.Failed} failed, {result.Warnings} warning(s))");
if (result.ParameterScenarios.Count > 0)
{
    var ptOk = result.ParameterScenarios.Count - result.ParameterFailed - result.ParameterWarnings;
    Log($"  Parameter tampering: {result.ParameterScenarios.Count} ({ptOk} OK, {result.ParameterFailed} failed, {result.ParameterWarnings} warning(s))");
}
Log($"  Duration:            {result.DurationSeconds:F1}s");

// List each failure individually
var failedFaults = result.Scenarios.Where(s => !s.Passed).ToList();
var failedParams = result.ParameterScenarios.Where(s => !s.Passed).ToList();
var totalFailed = failedFaults.Count + failedParams.Count;

if (totalFailed > 0)
{
    Log("");
    foreach (var s in failedFaults)
    {
        var errors = s.Signals.Where(sig => sig.Severity == SignalSeverity.Error).ToList();
        Log($"  FAIL: {s.Method} {s.OriginalUrl} + {s.FaultName}", "#F44747");
        foreach (var sig in errors.Take(2))
        {
            var msg = sig.Message.Length > 100 ? sig.Message.Substring(0, 97) + "..." : sig.Message;
            Log($"        [{sig.Type.ToUpper()}] {msg}", "#F44747");
        }
    }
    foreach (var s in failedParams)
    {
        Log($"  FAIL: {s.Method} {s.TamperedUrl} -> {s.ResponseStatus} {s.ResponseStatusText}", "#F44747");
        Log($"        {s.Description}", "#F44747");
    }

    Log("");
    foreach (var s in failedFaults)
        Assert.Fail($"{s.Method} {s.OriginalUrl} + {s.FaultName}: {s.Signals.Count} signal(s)");
    foreach (var s in failedParams)
        Assert.Fail($"Parameter tamper {s.TamperType}: {s.Method} {s.TamperedUrl} -> {s.ResponseStatus}");
}
else
{
    Log("");
    var totalTests = result.ScenarioCount + result.ParameterScenarios.Count;
    Assert.Pass($"All {totalTests} test(s) handled gracefully");
}
