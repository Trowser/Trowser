namespace Trowser.Security;

/// <summary>
/// A single CORS configuration finding from probing with a specific Origin.
/// </summary>
public class CorsFinding
{
    /// <summary>The Origin value that was tested.</summary>
    public string Origin { get; init; } = "";

    /// <summary>Whether the tested origin was reflected in Access-Control-Allow-Origin.</summary>
    public bool Reflected { get; init; }

    /// <summary>Whether Access-Control-Allow-Origin is set to wildcard (*).</summary>
    public bool Wildcard { get; init; }

    /// <summary>The actual Access-Control-Allow-Origin value returned.</summary>
    public string? AllowOrigin { get; init; }

    /// <summary>Whether Access-Control-Allow-Credentials is true.</summary>
    public bool AllowCredentials { get; init; }

    /// <summary>Access-Control-Allow-Methods value, if any.</summary>
    public string? AllowMethods { get; init; }

    /// <summary>Access-Control-Allow-Headers value, if any.</summary>
    public string? AllowHeaders { get; init; }

    /// <summary>Severity of the finding (null if the configuration is safe).</summary>
    public Severity? Severity { get; init; }

    /// <summary>Description of the issue, or null if configuration is safe for this probe.</summary>
    public string? Description { get; init; }
}

/// <summary>
/// Complete results from a CORS configuration audit.
/// </summary>
public class CorsResult
{
    /// <summary>URL that was tested.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All CORS probes and their results.</summary>
    public List<CorsFinding> Findings { get; init; } = new();

    /// <summary>Only findings with security issues.</summary>
    public List<CorsFinding> Issues => Findings.Where(f => f.Severity.HasValue).ToList();

    /// <summary>True if no CORS misconfigurations were found.</summary>
    public bool IsClean => Issues.Count == 0;

    /// <summary>Number of issues found.</summary>
    public int IssueCount => Issues.Count;

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== CORS Configuration Audit ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Issues.Count == 0)
        {
            lines.Add("No CORS misconfigurations found. The server does not reflect arbitrary origins " +
                       "or use overly permissive configurations.");
            lines.Add("================================");
            return string.Join(Environment.NewLine, lines);
        }

        var high = Issues.Count(f => f.Severity >= Security.Severity.High);
        var medium = Issues.Count(f => f.Severity == Security.Severity.Medium);
        var low = Issues.Count(f => f.Severity == Security.Severity.Low);

        lines.Add($"ISSUES: {Issues.Count}");
        if (high > 0) lines.Add($"  HIGH/CRITICAL: {high}");
        if (medium > 0) lines.Add($"  MEDIUM:        {medium}");
        if (low > 0) lines.Add($"  LOW:           {low}");
        lines.Add("");

        if (includeDetails)
        {
            foreach (var f in Issues.OrderByDescending(f => f.Severity))
            {
                var sevLabel = f.Severity?.ToString().ToUpper() ?? "?";
                lines.Add($"--- [{sevLabel}] Origin: {f.Origin} ---");
                lines.Add($"  {f.Description}");
                lines.Add($"  Access-Control-Allow-Origin: {f.AllowOrigin ?? "(not set)"}");
                lines.Add($"  Access-Control-Allow-Credentials: {f.AllowCredentials}");
                if (f.AllowMethods != null)
                    lines.Add($"  Access-Control-Allow-Methods: {f.AllowMethods}");
                lines.Add("");
            }
        }

        if (high > 0)
            lines.Add("ASSESSMENT: Critical CORS misconfiguration detected -- arbitrary origins can make " +
                       "authenticated cross-origin requests. This enables CSRF and data theft attacks.");
        else if (medium > 0)
            lines.Add("ASSESSMENT: CORS configuration is overly permissive and should be tightened.");
        else
            lines.Add("ASSESSMENT: Minor CORS configuration issues found.");

        lines.Add("================================");
        return string.Join(Environment.NewLine, lines);
    }
}
