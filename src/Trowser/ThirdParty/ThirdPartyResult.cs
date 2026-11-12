namespace Trowser.ThirdParty;

/// <summary>
/// A single third-party resource loaded by the page.
/// </summary>
public class ThirdPartyResource
{
    /// <summary>Full URL of the resource.</summary>
    public string Url { get; init; } = "";

    /// <summary>Registrable domain (eTLD+1) the resource is loaded from. Same as <see cref="EtldPlus1"/>.</summary>
    public string Domain { get; init; } = "";

    /// <summary>Full hostname of the resource (e.g. <c>fonts.googleapis.com</c>).</summary>
    public string Hostname { get; init; } = "";

    /// <summary>Registrable domain / eTLD+1 (e.g. <c>googleapis.com</c>), via tldts / Public Suffix List.</summary>
    public string EtldPlus1 { get; init; } = "";

    /// <summary>Resource type: "script", "stylesheet", "iframe", "font", "other".</summary>
    public string Type { get; init; } = "";

    /// <summary>Transfer size in bytes (0 if unknown).</summary>
    public long SizeBytes { get; init; }

    /// <summary>Whether the element has a Subresource Integrity (integrity) attribute.</summary>
    public bool HasSri { get; init; }

    /// <summary>The integrity hash value, if present.</summary>
    public string? IntegrityHash { get; init; }
}

/// <summary>
/// Results from a third-party resource inventory scan.
/// </summary>
public class ThirdPartyResult
{
    /// <summary>URL that was audited.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All third-party resources found.</summary>
    public List<ThirdPartyResource> Resources { get; init; } = new();

    /// <summary>Total number of third-party resources.</summary>
    public int TotalCount => Resources.Count;

    /// <summary>Distinct third-party domains.</summary>
    public List<string> Domains => Resources.Select(r => r.Domain).Distinct().OrderBy(d => d).ToList();

    /// <summary>Number of distinct third-party domains.</summary>
    public int DomainCount => Domains.Count;

    /// <summary>Total transfer size of all third-party resources.</summary>
    public long TotalSizeBytes => Resources.Sum(r => r.SizeBytes);

    /// <summary>Number of resources with Subresource Integrity.</summary>
    public int SriCount => Resources.Count(r => r.HasSri);

    /// <summary>True if no third-party resources found.</summary>
    public bool IsClean => Resources.Count == 0;

    /// <summary>
    /// Format a human-readable third-party resource report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Third-Party Resource Inventory ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Resources.Count == 0)
        {
            lines.Add("No third-party resources found.");
            lines.Add("=============================");
            return string.Join(Environment.NewLine, lines);
        }

        // Overview
        var sriPercent = TotalCount > 0 ? (int)Math.Round(100.0 * SriCount / TotalCount) : 0;
        lines.Add("OVERVIEW:");
        lines.Add($"  Third-party resources: {TotalCount}");
        lines.Add($"  Distinct domains:     {DomainCount}");
        lines.Add($"  Total transfer size:  {FormatBytes(TotalSizeBytes)}");
        lines.Add($"  Resources with SRI:   {SriCount} / {TotalCount} ({sriPercent}%)");
        lines.Add("");

        // Domains
        lines.Add("DOMAINS:");
        var byDomain = Resources
            .GroupBy(r => r.Domain)
            .OrderByDescending(g => g.Count())
            .ToList();

        foreach (var group in byDomain)
        {
            var domainSize = group.Sum(r => r.SizeBytes);
            lines.Add($"  {group.Key} ({group.Count()} resource(s), {FormatBytes(domainSize)})");
        }
        lines.Add("");

        // Resources by type
        var scripts = Resources.Count(r => r.Type == "script");
        var stylesheets = Resources.Count(r => r.Type == "stylesheet");
        var fonts = Resources.Count(r => r.Type == "font");
        var iframes = Resources.Count(r => r.Type == "iframe");
        var other = Resources.Count(r => r.Type == "other");

        lines.Add("RESOURCES BY TYPE:");
        if (scripts > 0) lines.Add($"  Scripts:      {scripts}");
        if (stylesheets > 0) lines.Add($"  Stylesheets:  {stylesheets}");
        if (fonts > 0) lines.Add($"  Fonts:        {fonts}");
        if (iframes > 0) lines.Add($"  Iframes:      {iframes}");
        if (other > 0) lines.Add($"  Other:        {other}");
        lines.Add("");

        if (includeDetails)
        {
            lines.Add("--- DETAILS ---");
            foreach (var r in Resources.OrderBy(r => r.Domain).ThenBy(r => r.Type))
            {
                var sri = r.HasSri ? " [SRI]" : "";
                var size = r.SizeBytes > 0 ? $" ({FormatBytes(r.SizeBytes)})" : "";
                var host = !string.IsNullOrEmpty(r.Hostname) && r.Hostname != r.EtldPlus1
                    ? $" (host: {r.Hostname})"
                    : "";
                lines.Add($"  [{r.Type}] {r.Url}{size}{sri}{host}");
            }
            lines.Add("");
        }

        // Assessment — missing SRI is usually informational: most production sites omit it.
        var withoutSri = Resources.Count(r => !r.HasSri);
        var assessment = withoutSri > 0
            ? $"ASSESSMENT [LOW/informative]: {TotalCount} third-party resource(s) from {DomainCount} domain(s). " +
              $"{withoutSri} resource(s) lack Subresource Integrity (SRI). " +
              "SRI is uncommon in practice; absence is mild risk unless the third-party host could serve malicious content."
            : $"ASSESSMENT: {TotalCount} third-party resource(s) from {DomainCount} domain(s). " +
              "All sampled third-party resources declare Subresource Integrity (SRI).";

        lines.Add(assessment);
        lines.Add("=============================");

        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024} KB";
        return $"{(bytes / (1024 * 1024.0)).ToString("F1", System.Globalization.CultureInfo.InvariantCulture)} MB";
    }
}
