namespace Trowser.Consistency;

/// <summary>
/// A single consistency finding.
/// </summary>
public class ConsistencyFinding
{
    /// <summary>Category: "typography", "colors", "sizing", "spacing", "images".</summary>
    public string Category { get; init; } = "";

    /// <summary>What the issue is.</summary>
    public string Description { get; init; } = "";

    /// <summary>Warning or info.</summary>
    public bool IsWarning { get; init; }

    /// <summary>The distinct values found.</summary>
    public List<string> Values { get; init; } = new();

    public override string ToString() =>
        $"[{(IsWarning ? "WARNING" : "INFO")}] {Category}: {Description}";
}

/// <summary>
/// Detailed statistics about the page's visual consistency.
/// </summary>
public class ConsistencyStats
{
    // Typography
    public List<ValueCount> FontFamilies { get; init; } = new();
    public List<ValueCount> FontSizes { get; init; } = new();

    // Colors
    public List<ValueCount> TextColors { get; init; } = new();
    public List<ValueCount> BackgroundColors { get; init; } = new();

    // Sizing
    public List<ValueCount> ButtonHeights { get; init; } = new();
    public List<ValueCount> InputHeights { get; init; } = new();

    // Spacing
    public List<ValueCount> SpacingValues { get; init; } = new();

    // Images
    public List<ImageIssue> ImageIssues { get; init; } = new();
}

/// <summary>
/// An image optimization issue.
/// </summary>
public class ImageIssue
{
    /// <summary>Image src URL.</summary>
    public string Src { get; init; } = "";

    /// <summary>Issue type: "oversized", "missing-dimensions", "missing-lazy".</summary>
    public string IssueType { get; init; } = "";

    /// <summary>Human-readable description.</summary>
    public string Description { get; init; } = "";

    /// <summary>Natural width in pixels (0 if unknown).</summary>
    public int NaturalWidth { get; init; }

    /// <summary>Natural height in pixels (0 if unknown).</summary>
    public int NaturalHeight { get; init; }

    /// <summary>Displayed width in pixels (0 if unknown).</summary>
    public int DisplayedWidth { get; init; }

    /// <summary>Displayed height in pixels (0 if unknown).</summary>
    public int DisplayedHeight { get; init; }
}

/// <summary>
/// A value with its occurrence count.
/// </summary>
public class ValueCount
{
    public string Value { get; init; } = "";
    public int Count { get; init; }
}

/// <summary>
/// Results from a GUI consistency audit.
/// </summary>
public class ConsistencyResult
{
    /// <summary>URL that was audited.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Detailed statistics.</summary>
    public ConsistencyStats Stats { get; init; } = new();

    /// <summary>Consistency findings/warnings.</summary>
    public List<ConsistencyFinding> Findings { get; init; } = new();

    /// <summary>True if no warnings found.</summary>
    public bool IsClean => Findings.All(f => !f.IsWarning);

    /// <summary>Number of warnings.</summary>
    public int WarningCount => Findings.Count(f => f.IsWarning);

    /// <summary>
    /// Format a human-readable consistency report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== GUI Consistency Audit ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        // Overview
        lines.Add("OVERVIEW:");
        lines.Add($"  Font families:      {Stats.FontFamilies.Count}");
        lines.Add($"  Font sizes:         {Stats.FontSizes.Count}");
        lines.Add($"  Text colors:        {Stats.TextColors.Count}");
        lines.Add($"  Background colors:  {Stats.BackgroundColors.Count}");
        lines.Add($"  Button heights:     {Stats.ButtonHeights.Count}");
        lines.Add($"  Input heights:      {Stats.InputHeights.Count}");
        lines.Add($"  Spacing values:     {Stats.SpacingValues.Count}");
        lines.Add($"  Image issues:       {Stats.ImageIssues.Count}");
        lines.Add("");

        if (Findings.Count == 0)
        {
            lines.Add("No consistency issues found.");
            lines.Add("=============================");
            return string.Join(Environment.NewLine, lines);
        }

        var warnings = Findings.Where(f => f.IsWarning).ToList();
        var infos = Findings.Where(f => !f.IsWarning).ToList();

        if (warnings.Count > 0)
            lines.Add($"WARNINGS: {warnings.Count}");
        if (infos.Count > 0)
            lines.Add($"INFO: {infos.Count}");
        lines.Add("");

        if (includeDetails)
        {
            foreach (var f in Findings.OrderByDescending(f => f.IsWarning))
            {
                var label = f.IsWarning ? "WARNING" : "INFO";
                lines.Add($"--- [{label}] {f.Category} ---");
                lines.Add($"  {f.Description}");
                if (f.Values.Count > 0)
                {
                    if (f.Category == "images")
                    {
                        lines.Add("  Details:");
                        foreach (var v in f.Values)
                            lines.Add($"    • {v}");
                    }
                    else
                    {
                        lines.Add($"  Values: {string.Join(", ", f.Values)}");
                    }
                }
                lines.Add("");
            }
        }

        if (warnings.Count > 0)
            lines.Add($"ASSESSMENT: {warnings.Count} consistency warning(s) found. Consider consolidating design tokens.");
        else
            lines.Add($"ASSESSMENT: Good consistency. Only informational observations.");

        lines.Add("=============================");
        return string.Join(Environment.NewLine, lines);
    }
}
