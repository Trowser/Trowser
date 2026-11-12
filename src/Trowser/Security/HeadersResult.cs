namespace Trowser.Security;

/// <summary>
/// A single security header finding (missing header, dangerous value, or information leak).
/// </summary>
public class HeaderFinding
{
    /// <summary>Header name (e.g., "Content-Security-Policy", "Server").</summary>
    public string Header { get; init; } = "";

    /// <summary>Finding severity.</summary>
    public Severity Severity { get; init; }

    /// <summary>What the issue is.</summary>
    public string Description { get; init; } = "";

    /// <summary>How to fix it.</summary>
    public string Recommendation { get; init; } = "";

    /// <summary>Current header value, or null if the header is missing.</summary>
    public string? CurrentValue { get; init; }

    /// <summary>OWASP or MDN reference URL.</summary>
    public string? Reference { get; init; }

    public override string ToString() =>
        $"[{Severity.ToString().ToUpper()}] {Header}: {Description}";
}

/// <summary>
/// Results from an HTTP security headers analysis.
/// </summary>
public class HeadersResult
{
    /// <summary>URL that was analyzed.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the analysis.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Whether the page was served over HTTPS.</summary>
    public bool IsHttps { get; init; }

    /// <summary>All response headers received (lowercase keys).</summary>
    public Dictionary<string, string> RawHeaders { get; init; } = new();

    /// <summary>Security findings (issues found).</summary>
    public List<HeaderFinding> Findings { get; init; } = new();

    /// <summary>
    /// Set when the in-page fetch could not read response headers (e.g. network error, CORS, blocked HEAD).
    /// </summary>
    public string? FetchError { get; init; }

    /// <summary>True if response headers were successfully retrieved.</summary>
    public bool FetchSucceeded => string.IsNullOrEmpty(FetchError);

    /// <summary>True if headers were fetched and no security issues found.</summary>
    public bool IsClean => FetchSucceeded && Findings.Count == 0;

    /// <summary>True when the response included a Strict-Transport-Security header (lowercase key in <see cref="RawHeaders"/>).</summary>
    public bool HasStrictTransportSecurity =>
        RawHeaders.ContainsKey("strict-transport-security");

    /// <summary>Total number of findings.</summary>
    public int FindingCount => Findings.Count;

    /// <summary>Get findings filtered by minimum severity.</summary>
    public List<HeaderFinding> GetByMinSeverity(Severity minSeverity) =>
        Findings.Where(f => f.Severity >= minSeverity).ToList();

    /// <summary>Get only high and critical severity findings.</summary>
    public List<HeaderFinding> GetCritical() => GetByMinSeverity(Severity.High);

    /// <summary>
    /// Format a human-readable security headers report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Security Headers Analysis ===");

        if (!string.IsNullOrEmpty(FetchError))
        {
            lines.Add($"Could not fetch response headers: {FetchError}");
            lines.Add("");
            lines.Add("The request may have failed (network, offline page), or the server may block HEAD/GET in a way fetch cannot read headers.");
            lines.Add("=================================");
            return string.Join(Environment.NewLine, lines);
        }

        lines.Add($"URL: {Url}");
        lines.Add($"Protocol: {(IsHttps ? "HTTPS" : "HTTP")}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Findings.Count == 0)
        {
            lines.Add("No security header issues found. All checked headers are properly configured.");
            lines.Add("=================================");
            return string.Join(Environment.NewLine, lines);
        }

        var high = Findings.Count(f => f.Severity >= Severity.High);
        var medium = Findings.Count(f => f.Severity == Severity.Medium);
        var low = Findings.Count(f => f.Severity == Severity.Low);
        var info = Findings.Count(f => f.Severity == Severity.Info);

        lines.Add($"FINDINGS: {Findings.Count}");
        if (high > 0) lines.Add($"  HIGH/CRITICAL: {high}");
        if (medium > 0) lines.Add($"  MEDIUM:        {medium}");
        if (low > 0) lines.Add($"  LOW:           {low}");
        if (info > 0) lines.Add($"  INFO:          {info}");
        lines.Add("");

        if (includeDetails)
        {
            var sorted = Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Header)
                .ToList();

            foreach (var f in sorted)
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                lines.Add($"--- [{sevLabel}] {f.Header} ---");
                lines.Add($"  {f.Description}");

                if (f.CurrentValue != null)
                {
                    var displayValue = f.CurrentValue.Length > 120
                        ? f.CurrentValue[..117] + "..."
                        : f.CurrentValue;
                    lines.Add($"  Current: {displayValue}");
                }

                lines.Add($"  Fix: {f.Recommendation}");

                if (f.Reference != null)
                    lines.Add($"  Ref: {f.Reference}");

                lines.Add("");
            }
        }

        var baselineGaps = 0;
        if (IsHttps)
            baselineGaps = Findings.Count(f => IsBaselineHardeningHeader(f.Header));

        if (high > 0)
            lines.Add($"ASSESSMENT: {high} high-severity issue(s) found -- immediate attention recommended.");
        else if (baselineGaps > 0)
            lines.Add($"ASSESSMENT: Baseline hardening incomplete ({baselineGaps} missing or weak baseline header(s) on HTTPS document).");
        else if (medium > 0)
            lines.Add($"ASSESSMENT: {medium} medium-severity issue(s) found.");
        else if (low > 0 || info > 0)
            lines.Add($"ASSESSMENT: {low + info} informational or low-severity finding(s); review optional hardening.");
        else
            lines.Add($"ASSESSMENT: No security header issues found in this pass.");

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }

    private static bool IsBaselineHardeningHeader(string header)
    {
        if (string.IsNullOrEmpty(header)) return false;
        return header.Contains("Content-Security-Policy", StringComparison.OrdinalIgnoreCase)
               || header.Contains("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase)
               || header.Contains("X-Content-Type-Options", StringComparison.OrdinalIgnoreCase)
               || header.Contains("X-Frame-Options", StringComparison.OrdinalIgnoreCase)
               || header.Contains("Content-Security-Policy", StringComparison.OrdinalIgnoreCase)
               || header.Equals("Framing", StringComparison.OrdinalIgnoreCase);
    }
}
