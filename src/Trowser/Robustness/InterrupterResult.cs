namespace Trowser.Robustness;

/// <summary>
/// Configuration for a TrowserInterrupter fault-injection test.
/// </summary>
public class InterrupterOptions
{
    /// <summary>Target a specific URL pattern (skips auto-discovery). Null = auto-discover from network log.</summary>
    public string? Url { get; init; }

    /// <summary>Filter by HTTP method (e.g. "GET", "POST"). Null = any method.</summary>
    public string? Method { get; init; }

    /// <summary>Subset of fault preset names to test. Null = all presets.</summary>
    public List<string>? Faults { get; init; }

    /// <summary>Maximum number of endpoints to test when auto-discovering (default 20).</summary>
    public int MaxEndpoints { get; init; } = 20;

    /// <summary>
    /// Minimum relevance score (0-100) for an endpoint to be included after ranking.
    /// Default 0 = no floor. Raise to trim noisy low-ranked traffic when discovery is too broad.
    /// </summary>
    public int MinRelevanceScore { get; init; }

    /// <summary>
    /// When true (default), merge endpoint templates from attack-surface analysis of the network log
    /// so grouped or deduped traffic still contributes candidates alongside raw entries.
    /// </summary>
    public bool MergeAttackSurface { get; init; } = true;

    /// <summary>Wait for network idle before reading the network log for discovery (default false).</summary>
    public bool WaitForIdle { get; init; }

    /// <summary>
    /// Custom fault definitions to test in addition to (or instead of) built-in presets.
    /// Each entry needs at minimum: name, status. Optional: body, headers, delayMs.
    /// </summary>
    public List<CustomFault>? CustomFaults { get; init; }

    /// <summary>
    /// Actions to replay after each page reload (for user-triggered endpoints).
    /// Same format as POST /api/batch actions: [{action, ref/selector/byText/placeholder, ...}].
    /// Without actions, the interrupter only tests endpoints that fire on page load.
    /// </summary>
    public List<InterrupterAction>? Actions { get; init; }

    /// <summary>
    /// Additional hosts to allow during auto-discovery, beyond the current page's origin.
    /// By default, only same-origin endpoints are discovered. Use this to include specific
    /// third-party API domains (e.g. ["api.stripe.com", "auth.example.com"]).
    /// </summary>
    public List<string>? AllowedHosts { get; init; }

    /// <summary>
    /// Delay in milliseconds between scenarios to avoid rate limits and give the app
    /// time to recover between fault injections (default 0 = no cooldown).
    /// </summary>
    public int CooldownMs { get; init; }

    /// <summary>
    /// When true, also test discovered endpoints with tampered URL parameters
    /// (missing IDs, invalid values) via browser fetch. Fast — no page reload needed.
    /// </summary>
    public bool TestParameters { get; init; }

    /// <summary>
    /// When true (default), navigate back to the original URL after testing and detect
    /// login redirects that indicate session disruption.
    /// </summary>
    public bool RestoreUrl { get; init; } = true;
}

/// <summary>
/// A user-defined fault preset for custom status codes and response bodies.
/// </summary>
public class CustomFault
{
    public string Name { get; init; } = "";
    public int Status { get; init; }
    public string? Body { get; init; }
    public Dictionary<string, string>? Headers { get; init; }
    public int DelayMs { get; init; }
}

/// <summary>
/// An action to replay after each page reload during interrupter testing.
/// Supports the same targeting as the batch API: ref, selector, byText, placeholder, role+name, label, testId.
/// </summary>
public class InterrupterAction
{
    public string Action { get; init; } = "";
    public int? Ref { get; init; }
    public string? Selector { get; init; }
    public string? ByText { get; init; }
    public string? Placeholder { get; init; }
    public string? Role { get; init; }
    public string? Name { get; init; }
    public string? Label { get; init; }
    public string? TestId { get; init; }
    public string? Text { get; init; }
    public string? Value { get; init; }
    public string? Key { get; init; }
    public int DelayMs { get; init; }
}

/// <summary>
/// Severity level for an interrupter signal.
/// Error = genuine failure the app should fix.
/// Warning = expected or tolerable degradation given the injected fault.
/// </summary>
public enum SignalSeverity
{
    Error,
    Warning,
}

/// <summary>
/// A signal detected after injecting a fault — may indicate a real problem (Error) or expected degradation (Warning).
/// </summary>
public class InterrupterSignal
{
    /// <summary>Signal category: console-error, uncaught-exception, blank-page, network-error, content-changed, error-page.</summary>
    public string Type { get; init; } = "";

    /// <summary>Human-readable description of what was detected.</summary>
    public string Message { get; init; } = "";

    /// <summary>Source file or URL, if applicable.</summary>
    public string? Source { get; init; }

    /// <summary>Error = real failure, Warning = expected/tolerable degradation.</summary>
    public SignalSeverity Severity { get; set; } = SignalSeverity.Error;

    public override string ToString()
    {
        var prefix = Severity == SignalSeverity.Warning ? "WARN" : "FAIL";
        return Source != null
            ? $"[{prefix}:{Type.ToUpper()}] {Message} ({Source})"
            : $"[{prefix}:{Type.ToUpper()}] {Message}";
    }
}

/// <summary>
/// Result of testing one endpoint with one fault preset.
/// </summary>
public class InterrupterScenario
{
    /// <summary>The API endpoint URL pattern that was mocked.</summary>
    public string Endpoint { get; init; } = "";

    /// <summary>Full original URL from the network log (for reproducibility).</summary>
    public string OriginalUrl { get; init; } = "";

    /// <summary>HTTP method of the endpoint.</summary>
    public string Method { get; init; } = "";

    /// <summary>Name of the fault preset applied (e.g. "server-error", "empty-body").</summary>
    public string FaultName { get; init; } = "";

    /// <summary>Human-readable description of the fault.</summary>
    public string FaultDescription { get; init; } = "";

    /// <summary>True if no Error-severity signals were detected (warnings are tolerated).</summary>
    public bool Passed => !Signals.Any(s => s.Severity == SignalSeverity.Error);

    /// <summary>True if there are Warning-severity signals (passed but with caveats).</summary>
    public bool HasWarnings => Signals.Any(s => s.Severity == SignalSeverity.Warning);

    /// <summary>Signals detected after injecting this fault.</summary>
    public List<InterrupterSignal> Signals { get; init; } = new();
}

/// <summary>
/// Result of testing one endpoint with a tampered URL parameter via browser fetch.
/// </summary>
public class ParameterTamperScenario
{
    /// <summary>Original URL before tampering.</summary>
    public string OriginalUrl { get; init; } = "";

    /// <summary>URL after tampering (missing/invalid ID).</summary>
    public string TamperedUrl { get; init; } = "";

    /// <summary>HTTP method used for the fetch.</summary>
    public string Method { get; init; } = "";

    /// <summary>What was tampered: missing-id, invalid-id, missing-param, invalid-param.</summary>
    public string TamperType { get; init; } = "";

    /// <summary>Human-readable description of the tampering applied.</summary>
    public string Description { get; init; } = "";

    /// <summary>HTTP status code returned by the server.</summary>
    public int ResponseStatus { get; init; }

    /// <summary>HTTP status text returned by the server.</summary>
    public string? ResponseStatusText { get; init; }

    public bool Passed => !Signals.Any(s => s.Severity == SignalSeverity.Error);
    public bool HasWarnings => Signals.Any(s => s.Severity == SignalSeverity.Warning);
    public List<InterrupterSignal> Signals { get; init; } = new();
}

/// <summary>
/// A discovered API endpoint from the network log.
/// </summary>
public class DiscoveredEndpoint
{
    /// <summary>URL path (without query string) used as the mock pattern.</summary>
    public string UrlPattern { get; init; } = "";

    /// <summary>HTTP method.</summary>
    public string Method { get; init; } = "";

    /// <summary>Original full URL from the network log.</summary>
    public string OriginalUrl { get; init; } = "";

    /// <summary>Last known good response body (for fault presets that need the original).</summary>
    public string? ResponseBody { get; init; }

    /// <summary>Response Content-Type header value.</summary>
    public string ContentType { get; init; } = "";

    /// <summary>CDP resource type (Fetch, XHR, Document, Other, etc.).</summary>
    public string ResourceType { get; init; } = "";

    /// <summary>Relevance score (0-100) used to rank endpoints during discovery. Higher = more likely an important API.</summary>
    public int RelevanceScore { get; init; }
}

/// <summary>
/// Results from a TrowserInterrupter fault-injection test run.
/// </summary>
public class InterrupterResult
{
    /// <summary>URL of the page when the test started.</summary>
    public string StartUrl { get; init; } = "";

    /// <summary>Timestamp when the test started.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Total duration in seconds.</summary>
    public double DurationSeconds { get; init; }

    /// <summary>Number of distinct API endpoints tested.</summary>
    public int EndpointsTested { get; init; }

    /// <summary>Total number of endpoint x fault scenarios run.</summary>
    public int ScenarioCount => Scenarios.Count;

    /// <summary>Number of scenarios that passed (no failure signals).</summary>
    public int Passed => Scenarios.Count(s => s.Passed);

    /// <summary>Number of scenarios that failed (Error-severity signals detected).</summary>
    public int Failed => Scenarios.Count(s => !s.Passed);

    /// <summary>Number of scenarios that passed but had Warning-severity signals.</summary>
    public int Warnings => Scenarios.Count(s => s.Passed && s.HasWarnings);

    /// <summary>All endpoints that were discovered (before applying maxEndpoints cap).</summary>
    public List<DiscoveredEndpoint> DiscoveredEndpoints { get; init; } = new();

    /// <summary>Per-scenario results.</summary>
    public List<InterrupterScenario> Scenarios { get; init; } = new();

    /// <summary>Options used for this run.</summary>
    public InterrupterOptions Options { get; init; } = new();

    /// <summary>Results from parameter tampering phase (tampered IDs via fetch).</summary>
    public List<ParameterTamperScenario> ParameterScenarios { get; init; } = new();

    /// <summary>Number of parameter tamper scenarios that failed (500 errors).</summary>
    public int ParameterFailed => ParameterScenarios.Count(s => !s.Passed);

    /// <summary>Number of parameter tamper scenarios that passed with warnings.</summary>
    public int ParameterWarnings => ParameterScenarios.Count(s => s.Passed && s.HasWarnings);

    /// <summary>URL of the page after restoration attempt (null if restoreUrl was false).</summary>
    public string? FinalUrl { get; init; }

    /// <summary>True if the page redirected to a login/auth page after restoration, indicating session disruption.</summary>
    public bool LoginRedirectDetected { get; init; }

    /// <summary>Error message if the page restoration failed (null if successful).</summary>
    public string? RestoreError { get; init; }

    /// <summary>
    /// Format a human-readable interrupter report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== TrowserInterrupter Fault-Injection Report ===");
        lines.Add($"URL: {StartUrl}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Duration: {DurationSeconds:F1}s | Endpoints: {EndpointsTested} | Scenarios: {ScenarioCount}");
        lines.Add("");

        if (DiscoveredEndpoints.Count > 0 && includeDetails)
        {
            lines.Add($"DISCOVERED ENDPOINTS ({DiscoveredEndpoints.Count}):");
            foreach (var ep in DiscoveredEndpoints)
            {
                var score = ep.RelevanceScore > 0 ? $" (score: {ep.RelevanceScore})" : "";
                lines.Add($"  {ep.Method} {ep.UrlPattern}{score}");
            }
            lines.Add("");
        }

        if (ScenarioCount == 0)
        {
            lines.Add("NO SCENARIOS RUN -- No API endpoints were found in the network log.");
            lines.Add("Tip: interact with the page to generate API requests, then run the interrupter again.");
        }
        else if (Failed == 0 && Warnings == 0)
        {
            lines.Add($"RESULT: ALL PASSED -- {Passed}/{ScenarioCount} scenario(s) handled faults gracefully.");
        }
        else
        {
            if (Failed == 0)
            {
                lines.Add($"RESULT: ALL PASSED ({Warnings} with warnings) -- {Passed}/{ScenarioCount} scenario(s) handled faults gracefully.");
            }
            else
            {
                var warnNote = Warnings > 0 ? $", {Warnings} WARNING(S)" : "";
                lines.Add($"RESULT: {Failed} FAILED, {Passed} PASSED{warnNote} out of {ScenarioCount} scenario(s).");
            }
            lines.Add("");

            if (includeDetails)
            {
                var failedScenarios = Scenarios.Where(s => !s.Passed).ToList();
                foreach (var scenario in failedScenarios)
                {
                    lines.Add($"  FAIL: {scenario.Method} {scenario.Endpoint} + {scenario.FaultName}");
                    lines.Add($"        Fault: {scenario.FaultDescription}");
                    foreach (var signal in scenario.Signals.Take(5))
                    {
                        var sev = signal.Severity == SignalSeverity.Warning ? " (warning)" : "";
                        var truncMsg = signal.Message.Length > 120
                            ? signal.Message[..117] + "..."
                            : signal.Message;
                        var src = signal.Source != null ? $" ({signal.Source})" : "";
                        lines.Add($"        [{signal.Type.ToUpper()}{sev}] {truncMsg}{src}");
                    }
                    if (scenario.Signals.Count > 5)
                        lines.Add($"        ... and {scenario.Signals.Count - 5} more signal(s)");
                    lines.Add("");
                }

                var warnScenarios = Scenarios.Where(s => s.Passed && s.HasWarnings).ToList();
                if (warnScenarios.Count > 0)
                {
                    lines.Add($"  WARNINGS ({warnScenarios.Count}):");
                    foreach (var scenario in warnScenarios)
                    {
                        lines.Add($"    WARN: {scenario.Method} {scenario.Endpoint} + {scenario.FaultName}");
                        foreach (var signal in scenario.Signals.Take(3))
                        {
                            var truncMsg = signal.Message.Length > 100
                                ? signal.Message[..97] + "..."
                                : signal.Message;
                            lines.Add($"          [{signal.Type.ToUpper()}] {truncMsg}");
                        }
                    }
                    lines.Add("");
                }

                var cleanPassed = Scenarios.Where(s => s.Passed && !s.HasWarnings).ToList();
                if (cleanPassed.Count > 0)
                {
                    lines.Add($"  PASSED ({cleanPassed.Count}):");
                    foreach (var scenario in cleanPassed)
                        lines.Add($"    OK: {scenario.Method} {scenario.Endpoint} + {scenario.FaultName}");
                    lines.Add("");
                }
            }
        }

        if (ParameterScenarios.Count > 0)
        {
            lines.Add("--- Parameter Tampering ---");
            var ptFailed = ParameterScenarios.Where(s => !s.Passed).ToList();
            var ptWarned = ParameterScenarios.Where(s => s.Passed && s.HasWarnings).ToList();
            var ptClean = ParameterScenarios.Where(s => s.Passed && !s.HasWarnings).ToList();

            if (ptFailed.Count == 0 && ptWarned.Count == 0)
            {
                lines.Add($"  All {ParameterScenarios.Count} tampered request(s) handled correctly.");
            }
            else
            {
                lines.Add($"  {ptFailed.Count} error(s), {ptWarned.Count} warning(s), {ptClean.Count} OK out of {ParameterScenarios.Count} variant(s).");
            }

            if (includeDetails)
            {
                foreach (var s in ptFailed)
                {
                    var path = s.TamperedUrl;
                    try { path = new Uri(s.TamperedUrl).PathAndQuery; } catch { }
                    lines.Add($"  FAIL: {s.Method} {path} -> {s.ResponseStatus}");
                    lines.Add($"        {s.Description}");
                    foreach (var sig in s.Signals.Where(sig => sig.Severity == SignalSeverity.Error).Take(3))
                        lines.Add($"        [{sig.Type.ToUpper()}] {sig.Message}");
                }

                foreach (var s in ptWarned)
                {
                    var path = s.TamperedUrl;
                    try { path = new Uri(s.TamperedUrl).PathAndQuery; } catch { }
                    lines.Add($"  WARN: {s.Method} {path} -> {s.ResponseStatus}");
                    lines.Add($"        {s.Description}");
                }

                if (ptClean.Count > 0)
                {
                    lines.Add($"  OK ({ptClean.Count}):");
                    foreach (var s in ptClean)
                    {
                        var path = s.TamperedUrl;
                        try { path = new Uri(s.TamperedUrl).PathAndQuery; } catch { }
                        lines.Add($"    {s.Method} {path} -> {s.ResponseStatus}");
                    }
                }
            }

            lines.Add("");
        }

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }
}
