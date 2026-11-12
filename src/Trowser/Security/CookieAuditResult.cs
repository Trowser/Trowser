namespace Trowser.Security;

/// <summary>
/// Severity of a cookie security finding.
/// Reuses the existing <see cref="Severity"/> enum from SecurityResult.
/// </summary>
public class CookieFinding
{
    /// <summary>Cookie name.</summary>
    public string CookieName { get; init; } = "";

    /// <summary>Finding severity.</summary>
    public Severity Severity { get; init; }

    /// <summary>Category of the issue (e.g., "MissingSecure", "MissingHttpOnly").</summary>
    public string Category { get; init; } = "";

    /// <summary>What the issue is.</summary>
    public string Description { get; init; } = "";

    /// <summary>How to fix it.</summary>
    public string Recommendation { get; init; } = "";

    public override string ToString() =>
        $"[{Severity.ToString().ToUpper()}] {CookieName}: {Description}";
}

/// <summary>
/// A single OWASP checklist item with pass/fail status and affected cookies.
/// </summary>
public class CookieChecklistItem
{
    public bool Pass { get; init; }
    /// <summary>When true, the check did not apply (e.g. Secure on HTTP) — not a pass/fail verdict.</summary>
    public bool Skipped { get; init; }
    public string? Issue { get; init; }
    public List<string> Cookies { get; init; } = new();

    /// <summary>PASS, FAIL, or SKIP. Skipped checks are not failures.</summary>
    public string StatusLabel => Skipped ? "SKIP" : Pass ? "PASS" : "FAIL";
}

/// <summary>
/// Complete results from a cookie security audit.
/// </summary>
public class CookieAuditResult
{
    /// <summary>URL of the page whose cookies were audited.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Total number of cookies inspected.</summary>
    public int CookieCount { get; init; }

    /// <summary>Security findings (issues found).</summary>
    public List<CookieFinding> Findings { get; init; } = new();

    /// <summary>OWASP checklist with pass/fail per category and affected cookies.</summary>
    public Dictionary<string, CookieChecklistItem> Checklist { get; init; } = new();

    /// <summary>How cookie metadata was sourced (jar, plus network Set-Cookie when reconciled).</summary>
    public string PrimarySource { get; init; } = "cookieJar";

    /// <summary>Cookie names whose Secure/HttpOnly/SameSite flags were corrected from network Set-Cookie headers.</summary>
    public List<string> NetworkReconciledCookies { get; init; } = new();

    /// <summary>True if no security issues found.</summary>
    public bool IsClean => Findings.Count == 0;

    /// <summary>Total number of findings.</summary>
    public int FindingCount => Findings.Count;

    /// <summary>Get findings filtered by minimum severity.</summary>
    public List<CookieFinding> GetByMinSeverity(Severity minSeverity) =>
        Findings.Where(f => f.Severity >= minSeverity).ToList();

    /// <summary>Get only high and critical severity findings.</summary>
    public List<CookieFinding> GetCritical() => GetByMinSeverity(Severity.High);

    /// <summary>
    /// Format a human-readable cookie security audit report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Cookie Security Audit ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Cookies inspected: {CookieCount}");
        lines.Add($"Source: {PrimarySource}");
        if (NetworkReconciledCookies.Count > 0)
            lines.Add($"Network-reconciled flags: {string.Join(", ", NetworkReconciledCookies)}");
        lines.Add("");

        if (CookieCount == 0)
        {
            lines.Add("No cookies found for the current page.");
            lines.Add("==============================");
            return string.Join(Environment.NewLine, lines);
        }

        // Checklist summary
        if (Checklist.Count > 0)
        {
            lines.Add("OWASP CHECKLIST:");
            foreach (var kv in Checklist)
            {
                var status = kv.Value.StatusLabel;
                var detail = kv.Value.Issue != null ? $" -- {kv.Value.Issue}" : "";
                var cookies = kv.Value.Cookies.Count > 0 ? $" [{string.Join(", ", kv.Value.Cookies)}]" : "";
                lines.Add($"  [{status}] {kv.Key}{detail}{cookies}");
            }
            lines.Add("");
        }

        if (Findings.Count == 0)
        {
            lines.Add("No cookie security issues found. All cookies are properly configured.");
            lines.Add("==============================");
            return string.Join(Environment.NewLine, lines);
        }

        var high = Findings.Count(f => f.Severity >= Severity.High);
        var medium = Findings.Count(f => f.Severity == Severity.Medium);
        var low = Findings.Count(f => f.Severity == Severity.Low);

        lines.Add($"FINDINGS: {Findings.Count}");
        if (high > 0) lines.Add($"  HIGH/CRITICAL: {high}");
        if (medium > 0) lines.Add($"  MEDIUM:        {medium}");
        if (low > 0) lines.Add($"  LOW:           {low}");
        lines.Add("");

        if (includeDetails)
        {
            var sorted = Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.CookieName)
                .ThenBy(f => f.Category)
                .ToList();

            foreach (var f in sorted)
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                lines.Add($"--- [{sevLabel}] {f.CookieName} ({f.Category}) ---");
                lines.Add($"  {f.Description}");
                lines.Add($"  Fix: {f.Recommendation}");
                lines.Add("");
            }
        }

        if (high > 0)
            lines.Add($"ASSESSMENT: {high} high-severity issue(s) found -- immediate attention recommended.");
        else if (medium > 0)
            lines.Add($"ASSESSMENT: {medium} medium-severity issue(s) found.");
        else
            lines.Add($"ASSESSMENT: Only low-severity findings. Cookies are reasonably configured.");

        lines.Add("==============================");
        return string.Join(Environment.NewLine, lines);
    }
}
