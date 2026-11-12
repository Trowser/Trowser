namespace Trowser.Robustness;

/// <summary>
/// Which gremlin species to include in the monkey test.
/// </summary>
[Flags]
public enum MonkeySpecies
{
    None = 0,
    Clicker = 1,
    Toucher = 2,
    FormFiller = 4,
    Scroller = 8,
    Typer = 16,
    All = Clicker | Toucher | FormFiller | Scroller | Typer
}

/// <summary>
/// Configuration for a monkey test run.
/// </summary>
public class MonkeyTestOptions
{
    /// <summary>Number of random actions to perform (default 500).</summary>
    public int Actions { get; init; } = 500;

    /// <summary>Delay in ms between actions (default 20).</summary>
    public int Delay { get; init; } = 20;

    /// <summary>Random seed for reproducibility. Null = random.</summary>
    public int? Seed { get; init; }

    /// <summary>Which gremlin species to use (default All).</summary>
    public MonkeySpecies Species { get; init; } = MonkeySpecies.All;

    /// <summary>
    /// Maximum number of errors before the test stops automatically (Gizmo mogwai).
    /// Set to 0 to disable the error limit. Default 50.
    /// </summary>
    public int MaxErrors { get; init; } = 50;

    /// <summary>Estimated duration in seconds (computed from Actions * Delay).</summary>
    public double EstimatedDuration => Actions * Delay / 1000.0;
}

/// <summary>
/// An error that occurred during monkey testing.
/// </summary>
public class MonkeyTestError
{
    /// <summary>Error type: "error", "unhandledrejection", "gremlin", "console", "http-error", or "http-5xx".</summary>
    public string Type { get; init; } = "";

    /// <summary>Error message.</summary>
    public string Message { get; init; } = "";

    /// <summary>Source file (for window.onerror).</summary>
    public string? Source { get; init; }

    /// <summary>Line number (for window.onerror).</summary>
    public int? Line { get; init; }
}

/// <summary>
/// A navigation that gremlins attempted during testing (blocked to keep the test running).
/// </summary>
public class NavigationAttempt
{
    /// <summary>How the navigation was triggered: "link", "form", "window.open", or "location".</summary>
    public string Type { get; init; } = "";

    /// <summary>Target URL or form action.</summary>
    public string Url { get; init; } = "";
}

/// <summary>
/// Results from a monkey test run.
/// </summary>
public class MonkeyTestResult
{
    /// <summary>URL when the test started.</summary>
    public string StartUrl { get; init; } = "";

    /// <summary>URL when the test finished (should be the same since navigation is blocked).</summary>
    public string EndUrl { get; init; } = "";

    /// <summary>Whether the page navigated away during testing (should not happen with navigation blocking).</summary>
    public bool Navigated { get; init; }

    /// <summary>Timestamp when the test started.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Actual duration in seconds.</summary>
    public double DurationSeconds { get; init; }

    /// <summary>Number of gremlin actions performed.</summary>
    public int ActionsPerformed { get; init; }

    /// <summary>Random seed used (for reproducibility).</summary>
    public int Seed { get; init; }

    /// <summary>Options that were used.</summary>
    public MonkeyTestOptions Options { get; init; } = new();

    /// <summary>Errors that occurred during testing.</summary>
    public List<MonkeyTestError> Errors { get; init; } = new();

    /// <summary>Navigations that gremlins attempted (blocked by the test harness).</summary>
    public List<NavigationAttempt> NavigationAttempts { get; init; } = new();

    /// <summary>Number of FPS drops (below 10 fps) reported by the fps mogwai.</summary>
    public int FpsDrops { get; init; }

    /// <summary>Lowest FPS recorded during the test.</summary>
    public double? LowestFps { get; init; }

    /// <summary>Whether Gizmo stopped the test early due to too many errors.</summary>
    public bool StoppedEarly { get; init; }

    /// <summary>Total number of errors.</summary>
    public int ErrorCount => Errors.Count;

    /// <summary>True if no errors occurred and the page didn't crash.</summary>
    public bool Survived => Errors.Count == 0 && !StoppedEarly;

    /// <summary>Distinct error messages (deduplicated).</summary>
    public List<string> UniqueErrors =>
        Errors.Select(e => e.Message).Distinct().ToList();

    /// <summary>
    /// Format a human-readable monkey test report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Robustness Report (powered by gremlins.js) ===");
        lines.Add($"URL: {StartUrl}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Duration: {DurationSeconds:F1}s | Actions: {ActionsPerformed} | Seed: {Seed}");

        if (Navigated)
            lines.Add($"WARNING: Page navigated during test to: {EndUrl}");
        if (StoppedEarly)
            lines.Add($"WARNING: Test stopped early by Gizmo (error limit reached)");

        lines.Add("");

        if (NavigationAttempts.Count > 0)
        {
            var uniqueNavs = NavigationAttempts
                .Select(n => n.Url)
                .Distinct()
                .ToList();
            lines.Add($"NAVIGATION: {NavigationAttempts.Count} navigation attempt(s) blocked ({uniqueNavs.Count} unique targets)");
            if (includeDetails)
            {
                foreach (var url in uniqueNavs.Take(10))
                    lines.Add($"  -> {url}");
                if (uniqueNavs.Count > 10)
                    lines.Add($"  ... and {uniqueNavs.Count - 10} more");
            }
            lines.Add("");
        }

        if (Survived)
        {
            lines.Add("RESULT: SURVIVED -- No errors during monkey testing.");
            if (FpsDrops > 0)
                lines.Add($"Note: {FpsDrops} FPS drop(s) detected (lowest: {LowestFps:F1} fps).");
        }
        else
        {
            var unique = UniqueErrors;
            lines.Add($"RESULT: ERRORS FOUND -- {ErrorCount} error(s) ({unique.Count} unique)");

            if (FpsDrops > 0)
                lines.Add($"FPS drops: {FpsDrops} (lowest: {LowestFps:F1} fps)");

            lines.Add("");

            if (includeDetails)
            {
                var grouped = Errors
                    .GroupBy(e => e.Message)
                    .OrderByDescending(g => g.Count());

                foreach (var group in grouped.Take(20))
                {
                    var count = group.Count();
                    var first = group.First();
                    var location = first.Source != null ? $" at {first.Source}:{first.Line}" : "";
                    var countLabel = count > 1 ? $" (x{count})" : "";
                    var truncMsg = first.Message.Length > 150
                        ? first.Message[..147] + "..."
                        : first.Message;
                    lines.Add($"  [{first.Type.ToUpper()}] {truncMsg}{location}{countLabel}");
                }

                if (grouped.Count() > 20)
                    lines.Add($"  ... and {grouped.Count() - 20} more unique error(s)");
            }
        }

        lines.Add("");
        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }
}
