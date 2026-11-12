namespace Trowser.XssAudit;

/// <summary>
/// Severity of an XSS-related finding.
/// </summary>
public enum XssSeverity
{
    Info,
    Low,
    Medium,
    High
}

/// <summary>
/// A single DOM XSS finding.
/// </summary>
public class XssFinding
{
    /// <summary>Category of the finding (e.g., "inline-handler", "javascript-url", "cross-domain-script").</summary>
    public string Category { get; init; } = "";

    /// <summary>Severity of the finding.</summary>
    public XssSeverity Severity { get; init; }

    /// <summary>What the issue is.</summary>
    public string Description { get; init; } = "";

    /// <summary>Where in the DOM it was found (tag and selector hint).</summary>
    public string Location { get; init; } = "";

    /// <summary>The dangerous value or attribute found.</summary>
    public string? Evidence { get; init; }

    /// <summary>How to fix it.</summary>
    public string Recommendation { get; init; } = "";

    /// <summary>high | medium | low — used for dom-xss-flow findings.</summary>
    public string? Confidence { get; init; }

    /// <summary>URL/DOM source in a source→sink flow (e.g. location.hash).</summary>
    public string? Source { get; init; }

    /// <summary>Dangerous sink in a source→sink flow (e.g. document.write).</summary>
    public string? Sink { get; init; }

    public override string ToString() =>
        $"[{Severity.ToString().ToUpper()}] {Category}: {Description}";
}

/// <summary>
/// Results from a DOM XSS audit.
/// </summary>
public class XssResult
{
    /// <summary>URL that was audited.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All findings.</summary>
    public List<XssFinding> Findings { get; init; } = new();

    /// <summary>True if no XSS-related issues found.</summary>
    public bool IsClean => Findings.Count == 0;

    /// <summary>Total number of findings.</summary>
    public int FindingCount => Findings.Count;

    /// <summary>Findings by category with counts.</summary>
    public Dictionary<string, int> FindingsByCategory =>
        Findings.GroupBy(f => f.Category).ToDictionary(g => g.Key, g => g.Count());

    /// <summary>Get findings filtered by minimum severity.</summary>
    public List<XssFinding> GetByMinSeverity(XssSeverity minSeverity) =>
        Findings.Where(f => f.Severity >= minSeverity).ToList();

    /// <summary>
    /// Format a human-readable XSS audit report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== DOM XSS Audit ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Findings.Count == 0)
        {
            lines.Add("No static DOM XSS patterns detected on this page snapshot.");
            lines.Add("This is not a proof of absence — use POST /api/security/xss-scan or");
            lines.Add("trace-input for active reflected/DOM XSS probing.");
            lines.Add("=====================");
            return string.Join(Environment.NewLine, lines);
        }

        var high = Findings.Count(f => f.Severity >= XssSeverity.High);
        var medium = Findings.Count(f => f.Severity == XssSeverity.Medium);
        var low = Findings.Count(f => f.Severity == XssSeverity.Low);
        var info = Findings.Count(f => f.Severity == XssSeverity.Info);

        lines.Add($"FINDINGS: {Findings.Count}");
        if (high > 0) lines.Add($"  HIGH:   {high}");
        if (medium > 0) lines.Add($"  MEDIUM: {medium}");
        if (low > 0) lines.Add($"  LOW:    {low}");
        if (info > 0) lines.Add($"  INFO:   {info}");
        lines.Add("");

        // Summary by category
        lines.Add("BY CATEGORY:");
        foreach (var cat in FindingsByCategory.OrderByDescending(c => c.Value))
        {
            lines.Add($"  {cat.Key}: {cat.Value}");
        }
        lines.Add("");

        if (includeDetails)
        {
            var sorted = Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .ToList();

            foreach (var f in sorted)
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                lines.Add($"--- [{sevLabel}] {f.Category} ---");
                lines.Add($"  {f.Description}");
                lines.Add($"  Location: {f.Location}");

                if (f.Evidence != null)
                {
                    var displayEvidence = f.Evidence.Length > 120
                        ? f.Evidence[..117] + "..."
                        : f.Evidence;
                    lines.Add($"  Evidence: {displayEvidence}");
                }

                if (f.Source != null || f.Sink != null)
                    lines.Add($"  Flow: {f.Source ?? "?"} → {f.Sink ?? "?"}");
                if (f.Confidence != null)
                    lines.Add($"  Confidence: {f.Confidence}");

                lines.Add($"  Fix: {f.Recommendation}");
                lines.Add("");
            }
        }

        if (high > 0)
            lines.Add($"ASSESSMENT: {high} high-severity XSS risk(s) found -- immediate attention recommended.");
        else if (medium > 0)
            lines.Add($"ASSESSMENT: {medium} medium-severity XSS risk(s) found.");
        else
            lines.Add($"ASSESSMENT: Only low-severity or informational findings.");

        lines.Add("=====================");
        return string.Join(Environment.NewLine, lines);
    }
}
