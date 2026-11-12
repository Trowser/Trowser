namespace Trowser.Security;

/// <summary>
/// Severity of a known vulnerability.
/// </summary>
public enum Severity
{
    /// <summary>Hardening / hygiene signal — not an exploitable vulnerability by itself.</summary>
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// A known vulnerability affecting a detected JavaScript library.
/// </summary>
public class LibraryVulnerability
{
    /// <summary>Severity: low, medium, high, or critical.</summary>
    public Severity Severity { get; init; }

    /// <summary>Short description of the vulnerability.</summary>
    public string Summary { get; init; } = "";

    /// <summary>CVE identifiers (e.g., "CVE-2020-11022").</summary>
    public List<string> CVEs { get; init; } = new();

    /// <summary>CWE identifiers (e.g., "CWE-79").</summary>
    public List<string> CWEs { get; init; } = new();

    /// <summary>Links to vulnerability details.</summary>
    public List<string> Info { get; init; } = new();

    /// <summary>Versions below this are vulnerable.</summary>
    public string? Below { get; init; }

    /// <summary>Only versions at or above this are checked (optional lower bound).</summary>
    public string? AtOrAbove { get; init; }

    public override string ToString()
    {
        var cves = CVEs.Count > 0 ? string.Join(", ", CVEs) : "(no CVE)";
        return $"[{Severity.ToString().ToUpper()}] {cves}: {Summary}";
    }
}

/// <summary>
/// A JavaScript library detected on the page.
/// </summary>
public class DetectedLibrary
{
    /// <summary>Library name (e.g., "jquery", "lodash").</summary>
    public string Name { get; init; } = "";

    /// <summary>Detected version string.</summary>
    public string Version { get; init; } = "";

    /// <summary>How the library was detected: "func", "uri", "filename", or "filecontent".</summary>
    public string DetectionMethod { get; init; } = "";

    /// <summary>Known vulnerabilities affecting this version. Empty if none.</summary>
    public List<LibraryVulnerability> Vulnerabilities { get; init; } = new();

    /// <summary>True if this library+version has known vulnerabilities.</summary>
    public bool IsVulnerable => Vulnerabilities.Count > 0;

    /// <summary>Highest severity among vulnerabilities, or null if none.</summary>
    public Severity? HighestSeverity =>
        Vulnerabilities.Count > 0 ? Vulnerabilities.Max(v => v.Severity) : null;

    public override string ToString()
    {
        var status = IsVulnerable ? $"VULNERABLE ({Vulnerabilities.Count} issue(s))" : "OK";
        return $"{Name} {Version} [{status}]";
    }
}

/// <summary>
/// Complete results from a Retire.js security scan.
/// </summary>
public class SecurityResult
{
    /// <summary>URL of the page that was scanned.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the scan.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All JavaScript libraries detected on the page.</summary>
    public List<DetectedLibrary> Libraries { get; init; } = new();

    /// <summary>Only libraries with known vulnerabilities.</summary>
    public List<DetectedLibrary> Vulnerable =>
        Libraries.Where(l => l.IsVulnerable).ToList();

    /// <summary>Total number of libraries detected.</summary>
    public int LibraryCount => Libraries.Count;

    /// <summary>Number of libraries with known vulnerabilities.</summary>
    public int VulnerableCount => Vulnerable.Count;

    /// <summary>Total number of individual vulnerabilities across all libraries.</summary>
    public int VulnerabilityCount => Libraries.Sum(l => l.Vulnerabilities.Count);

    /// <summary>True if no vulnerabilities were found.</summary>
    public bool IsClean => VulnerableCount == 0;

    /// <summary>
    /// Coverage warnings (e.g. few large bundled scripts that can hide libraries).
    /// Not vulnerabilities — <see cref="IsClean"/> stays true when only caveats exist.
    /// </summary>
    public List<string> Caveats { get; init; } = new();

    /// <summary>True when the page loaded bundled/minified or large JS files.</summary>
    public bool HasBundledScripts { get; init; }

    /// <summary>True when external script bodies were fetched for filecontent matching.</summary>
    public bool FileContentScanned { get; init; }

    /// <summary>Get vulnerable libraries filtered by minimum severity.</summary>
    public List<DetectedLibrary> GetByMinSeverity(Severity minSeverity) =>
        Libraries.Where(l => l.Vulnerabilities.Any(v => v.Severity >= minSeverity)).ToList();

    /// <summary>Get only libraries with critical or high severity vulnerabilities.</summary>
    public List<DetectedLibrary> GetCritical() => GetByMinSeverity(Severity.High);

    /// <summary>
    /// Format a human-readable security scan report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== JavaScript Security Scan (powered by Retire.js) ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Libraries.Count == 0)
        {
            lines.Add("No JavaScript libraries detected on this page.");
            AppendCaveats(lines);
            lines.Add("=========================================================");
            return string.Join(Environment.NewLine, lines);
        }

        // All detected libraries
        lines.Add($"DETECTED LIBRARIES: {LibraryCount}");
        foreach (var lib in Libraries.OrderBy(l => l.Name))
        {
            var status = lib.IsVulnerable ? " *** VULNERABLE ***" : "";
            lines.Add($"  {lib.Name} {lib.Version} (detected via: {lib.DetectionMethod}){status}");
        }
        lines.Add("");

        // Vulnerable libraries
        if (VulnerableCount == 0)
        {
            lines.Add("No known vulnerabilities found. All detected libraries are up to date.");
        }
        else
        {
            var critical = Vulnerable.Count(l => l.HighestSeverity >= Severity.High);
            var medium = Vulnerable.Count(l => l.HighestSeverity == Severity.Medium);
            var low = Vulnerable.Count(l => l.HighestSeverity == Severity.Low);

            lines.Add($"VULNERABLE LIBRARIES: {VulnerableCount}");
            if (critical > 0) lines.Add($"  HIGH/CRITICAL: {critical}");
            if (medium > 0) lines.Add($"  MEDIUM:        {medium}");
            if (low > 0) lines.Add($"  LOW:           {low}");
            lines.Add("");

            if (includeDetails)
            {
                var sorted = Vulnerable
                    .OrderByDescending(l => l.HighestSeverity)
                    .ThenBy(l => l.Name)
                    .ToList();

                foreach (var lib in sorted)
                {
                    var sevLabel = lib.HighestSeverity?.ToString().ToUpper() ?? "?";
                    lines.Add($"--- [{sevLabel}] {lib.Name} {lib.Version} ---");

                    foreach (var vuln in lib.Vulnerabilities.OrderByDescending(v => v.Severity))
                    {
                        var cves = vuln.CVEs.Count > 0 ? string.Join(", ", vuln.CVEs) : "(no CVE)";
                        lines.Add($"  [{vuln.Severity.ToString().ToUpper()}] {cves}");
                        if (!string.IsNullOrEmpty(vuln.Summary))
                            lines.Add($"    {vuln.Summary}");
                        if (vuln.CWEs.Count > 0)
                            lines.Add($"    CWE: {string.Join(", ", vuln.CWEs)}");
                        if (vuln.Below != null)
                        {
                            var range = vuln.AtOrAbove != null
                                ? $"versions {vuln.AtOrAbove} to < {vuln.Below}"
                                : $"versions < {vuln.Below}";
                            lines.Add($"    Affects: {range}");
                        }
                        if (vuln.Info.Count > 0)
                            lines.Add($"    Info: {vuln.Info[0]}");
                    }
                    lines.Add("");
                }
            }

            lines.Add($"ASSESSMENT: {VulnerableCount} library/libraries with {VulnerabilityCount} known vulnerability/vulnerabilities.");
        }

        AppendCaveats(lines);
        lines.Add("=========================================================");
        return string.Join(Environment.NewLine, lines);
    }

    private void AppendCaveats(List<string> lines)
    {
        if (Caveats.Count == 0)
            return;

        lines.Add("");
        lines.Add("CAVEATS:");
        foreach (var caveat in Caveats)
            lines.Add("  " + caveat);
        if (FileContentScanned)
            lines.Add("  Script bodies were scanned for Retire.js filecontent signatures.");
    }
}
