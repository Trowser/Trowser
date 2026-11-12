namespace Trowser.Robustness;

/// <summary>
/// Configuration for the Monkey Trowser smart robustness test.
/// </summary>
public class SmartTestOptions
{
    /// <summary>Follow links to other pages within scope (default true).</summary>
    public bool FollowLinks { get; init; } = true;

    /// <summary>Fuzz form inputs with edge-case data (default true).</summary>
    public bool FuzzForms { get; init; } = true;

    /// <summary>Maximum pages to visit when crawling (default 10).</summary>
    public int MaxPages { get; init; } = 10;

    /// <summary>Maximum element interactions per page (default 100).</summary>
    public int MaxActionsPerPage { get; init; } = 100;

    /// <summary>
    /// When set, temporarily applies this navigation scope for the run only (restored afterward).
    /// Overrides auto-scope from the current page and Settings for this run only.
    /// </summary>
    public string? Scope { get; init; }
}

/// <summary>
/// A single issue found by the Monkey Trowser.
/// </summary>
public class SmartTestIssue
{
    /// <summary>URL of the page where the issue was found.</summary>
    public string Page { get; init; } = "";

    /// <summary>Description of the element involved (e.g., "Button 'Save'", "Input 'email'").</summary>
    public string Element { get; init; } = "";

    /// <summary>What was done (e.g., "click", "fuzz (empty)", "navigate").</summary>
    public string Action { get; init; } = "";

    /// <summary>The error or problem description.</summary>
    public string Issue { get; init; } = "";

    /// <summary>Category: "js-error", "network-error", "http-5xx", "navigation", "dead-link", "page-error".</summary>
    public string IssueType { get; init; } = "";

    public override string ToString() =>
        $"[{IssueType.ToUpper()}] {Element} ({Action}): {Issue}";
}

/// <summary>
/// Summary of a single page visit during the smart test.
/// </summary>
public class SmartTestPageSummary
{
    public string Url { get; init; } = "";
    public int ElementsTested { get; init; }
    public int FormsFuzzed { get; init; }
    public int IssuesFound { get; init; }
}

/// <summary>
/// Results from a Monkey Trowser smart robustness test.
/// </summary>
public class SmartTestResult
{
    /// <summary>Starting URL.</summary>
    public string StartUrl { get; init; } = "";

    /// <summary>Timestamp of the test.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Actual duration in seconds.</summary>
    public double DurationSeconds { get; init; }

    /// <summary>Total pages visited (including the starting page).</summary>
    public int PagesVisited { get; init; }

    /// <summary>Total interactive elements tested across all pages.</summary>
    public int ElementsTested { get; init; }

    /// <summary>Total forms/inputs fuzzed across all pages.</summary>
    public int FormsFuzzed { get; init; }

    /// <summary>All issues found.</summary>
    public List<SmartTestIssue> Issues { get; init; } = new();

    /// <summary>Per-page summaries.</summary>
    public List<SmartTestPageSummary> PageSummaries { get; init; } = new();

    /// <summary>Options used.</summary>
    public SmartTestOptions Options { get; init; } = new();

    /// <summary>True if no issues were found.</summary>
    public bool Passed => Issues.Count == 0;

    /// <summary>Total issue count.</summary>
    public int IssueCount => Issues.Count;

    /// <summary>Pages that had at least one issue.</summary>
    public List<string> PagesWithIssues =>
        Issues.Select(i => i.Page).Distinct().ToList();

    /// <summary>
    /// Format a human-readable report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Monkey Trowser Robustness Report ===");
        lines.Add($"URL: {StartUrl}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Duration: {DurationSeconds:F1}s | Pages: {PagesVisited} | Elements: {ElementsTested} | Fuzzed: {FormsFuzzed}");
        lines.Add("");

        if (Issues.Count == 0)
        {
            lines.Add("RESULT: ALL CLEAR -- No issues found during smart robustness testing.");
            lines.Add($"Tested {ElementsTested} element(s) across {PagesVisited} page(s).");
        }
        else
        {
            var jsErrors = Issues.Count(i => i.IssueType == "js-error");
            var netErrors = Issues.Count(i => i.IssueType == "network-error");
            var http5xx = Issues.Count(i => i.IssueType == "http-5xx");
            var navErrors = Issues.Count(i => i.IssueType == "navigation");
            var deadLinks = Issues.Count(i => i.IssueType == "dead-link");
            var pageErrors = Issues.Count(i => i.IssueType == "page-error");

            lines.Add($"RESULT: {Issues.Count} ISSUE(S) FOUND");
            if (jsErrors > 0) lines.Add($"  JavaScript errors:  {jsErrors}");
            if (http5xx > 0) lines.Add($"  HTTP 5xx:           {http5xx}");
            if (netErrors > 0) lines.Add($"  Other HTTP errors:  {netErrors}");
            if (navErrors > 0) lines.Add($"  Navigation blocked: {navErrors}");
            if (deadLinks > 0) lines.Add($"  Dead links:         {deadLinks}");
            if (pageErrors > 0) lines.Add($"  Page load errors:   {pageErrors}");
            lines.Add("");

            if (includeDetails)
            {
                var byPage = Issues.GroupBy(i => i.Page);
                foreach (var page in byPage)
                {
                    lines.Add($"--- {page.Key} ({page.Count()} issue(s)) ---");
                    foreach (var issue in page.Take(15))
                    {
                        var truncIssue = issue.Issue.Length > 120
                            ? issue.Issue[..117] + "..."
                            : issue.Issue;
                        lines.Add($"  [{issue.IssueType.ToUpper()}] {issue.Element} ({issue.Action}): {truncIssue}");
                    }
                    if (page.Count() > 15)
                        lines.Add($"  ... and {page.Count() - 15} more");
                    lines.Add("");
                }
            }
        }

        if (PageSummaries.Count > 1 && includeDetails)
        {
            lines.Add("PAGES VISITED:");
            foreach (var p in PageSummaries)
            {
                var status = p.IssuesFound > 0 ? $"{p.IssuesFound} issue(s)" : "OK";
                lines.Add($"  {p.Url} -- {p.ElementsTested} elements, {status}");
            }
            lines.Add("");
        }

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }
}
