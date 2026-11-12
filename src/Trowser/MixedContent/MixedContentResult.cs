namespace Trowser.MixedContent;

/// <summary>
/// Severity of a mixed content finding.
/// Lower value = more severe: High &lt; Medium &lt; Low.
/// </summary>
public enum MixedContentSeverity
{
    /// <summary>Scripts, iframes, objects, embeds — can execute code.</summary>
    High = 0,
    /// <summary>Images, stylesheets, fonts, forms — visual/layout/data impact.</summary>
    Medium = 1,
    /// <summary>Other resources.</summary>
    Low = 2
}

/// <summary>
/// A single mixed content finding: an HTTP resource loaded on an HTTPS page.
/// </summary>
public class MixedContentFinding
{
    /// <summary>Element tag name (e.g. "script", "img").</summary>
    public string Tag { get; set; } = "";

    /// <summary>Attribute containing the HTTP URL (e.g. "src", "href", "action").</summary>
    public string Attribute { get; set; } = "";

    /// <summary>The http:// URL found.</summary>
    public string Url { get; set; } = "";

    /// <summary>Severity based on element type.</summary>
    public MixedContentSeverity Severity { get; set; }

    /// <summary>Optional additional context (e.g. "inline script src", "form action").</summary>
    public string? Context { get; set; }
}

/// <summary>
/// Result of a mixed content audit on a single page.
/// </summary>
public class MixedContentResult
{
    /// <summary>Page URL that was audited.</summary>
    public string Url { get; set; } = "";

    /// <summary>When the audit was performed.</summary>
    public DateTime Timestamp { get; set; }

    /// <summary>Whether the page itself was loaded over HTTPS.</summary>
    public bool IsHttps { get; set; }

    /// <summary>All mixed content findings.</summary>
    public List<MixedContentFinding> Findings { get; set; } = new();

    /// <summary>Total number of findings.</summary>
    public int FindingCount => Findings.Count;

    /// <summary>True if the page is HTTP (not applicable) or HTTPS with no findings.</summary>
    public bool IsClean => !IsHttps || Findings.Count == 0;

    public int HighCount => Findings.Count(f => f.Severity == MixedContentSeverity.High);
    public int MediumCount => Findings.Count(f => f.Severity == MixedContentSeverity.Medium);
    public int LowCount => Findings.Count(f => f.Severity == MixedContentSeverity.Low);

    /// <summary>
    /// Format a human-readable report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== Mixed Content Audit ===");
        sb.AppendLine($"URL: {Url}");

        if (!IsHttps)
        {
            sb.AppendLine("Page is HTTP — mixed content check not applicable.");
            return sb.ToString().TrimEnd();
        }

        sb.AppendLine("Page is HTTPS: Yes");
        sb.AppendLine();

        if (Findings.Count == 0)
        {
            sb.AppendLine("ASSESSMENT: No mixed content found. All resources use HTTPS.");
            return sb.ToString().TrimEnd();
        }

        sb.AppendLine($"FINDINGS: {Findings.Count} mixed content issue(s)");
        if (HighCount > 0)
            sb.AppendLine($"  High: {HighCount} (scripts/iframes)");
        if (MediumCount > 0)
            sb.AppendLine($"  Medium: {MediumCount} (images/stylesheets)");
        if (LowCount > 0)
            sb.AppendLine($"  Low: {LowCount} (other resources)");

        if (includeDetails)
        {
            sb.AppendLine();
            foreach (var f in Findings.OrderBy(f => f.Severity))
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                sb.AppendLine($"[{sevLabel}] <{f.Tag} {f.Attribute}=\"{f.Url}\">");

                var desc = f.Severity switch
                {
                    MixedContentSeverity.High =>
                        "  Active mixed content \u2014 can execute arbitrary code",
                    MixedContentSeverity.Medium =>
                        "  Passive mixed content \u2014 may not display in strict browsers",
                    _ =>
                        "  Mixed content \u2014 resource loaded over HTTP"
                };

                if (!string.IsNullOrEmpty(f.Context))
                    desc += $" ({f.Context})";

                sb.AppendLine(desc);
            }
        }

        sb.AppendLine();
        sb.AppendLine(
            $"ASSESSMENT: {Findings.Count} mixed content issue(s) found. " +
            "Modern browsers block active mixed content (scripts/iframes) entirely.");

        return sb.ToString().TrimEnd();
    }
}
