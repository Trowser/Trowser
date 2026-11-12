namespace Trowser.TextExtraction;

/// <summary>
/// A heading found on the page.
/// </summary>
public class PageHeading
{
    /// <summary>Heading level (1-6).</summary>
    public int Level { get; init; }

    /// <summary>Heading text content.</summary>
    public string Text { get; init; } = "";
}

/// <summary>
/// A link found on the page.
/// </summary>
public class PageLink
{
    /// <summary>Link display text.</summary>
    public string Text { get; init; } = "";

    /// <summary>Link URL.</summary>
    public string Url { get; init; } = "";
}

/// <summary>
/// An image found on the page.
/// </summary>
public class PageImage
{
    /// <summary>Alt text.</summary>
    public string Alt { get; init; } = "";

    /// <summary>Image source URL.</summary>
    public string Src { get; init; } = "";
}

/// <summary>
/// Structured text content extracted from a page.
/// Designed to make proofreading and text analysis easy.
/// </summary>
public class StructuredTextResult
{
    /// <summary>URL of the page.</summary>
    public string Url { get; init; } = "";

    /// <summary>Page title.</summary>
    public string Title { get; init; } = "";

    /// <summary>HTML lang attribute value.</summary>
    public string? Language { get; init; }

    /// <summary>Meta description content.</summary>
    public string? MetaDescription { get; init; }

    /// <summary>All headings with hierarchy.</summary>
    public List<PageHeading> Headings { get; init; } = new();

    /// <summary>All paragraph texts.</summary>
    public List<string> Paragraphs { get; init; } = new();

    /// <summary>All link texts with URLs.</summary>
    public List<PageLink> Links { get; init; } = new();

    /// <summary>All button labels.</summary>
    public List<string> Buttons { get; init; } = new();

    /// <summary>All form labels.</summary>
    public List<string> Labels { get; init; } = new();

    /// <summary>All image alt texts.</summary>
    public List<PageImage> Images { get; init; } = new();

    /// <summary>Total word count of visible text.</summary>
    public int WordCount { get; init; }

    /// <summary>All visible page text concatenated.</summary>
    public string AllText { get; init; } = "";

    /// <summary>
    /// Format a human-readable structured text report.
    /// </summary>
    public string Format()
    {
        var lines = new List<string>();

        lines.Add("=== Structured Page Text ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Title: {Title}");
        if (Language != null)
            lines.Add($"Language: {Language}");
        if (MetaDescription != null)
            lines.Add($"Meta description: {MetaDescription}");
        lines.Add($"Word count: {WordCount}");
        lines.Add("");

        if (Headings.Count > 0)
        {
            lines.Add($"HEADINGS ({Headings.Count}):");
            foreach (var h in Headings)
            {
                var indent = new string(' ', (h.Level - 1) * 2);
                lines.Add($"  {indent}H{h.Level}: {h.Text}");
            }
            lines.Add("");
        }

        if (Paragraphs.Count > 0)
        {
            lines.Add($"PARAGRAPHS ({Paragraphs.Count}):");
            foreach (var p in Paragraphs)
            {
                var display = p.Length > 200 ? p[..197] + "..." : p;
                lines.Add($"  {display}");
            }
            lines.Add("");
        }

        if (Links.Count > 0)
        {
            lines.Add($"LINK TEXTS ({Links.Count}):");
            foreach (var l in Links)
            {
                if (!string.IsNullOrWhiteSpace(l.Text))
                    lines.Add($"  \"{l.Text}\" -> {l.Url}");
            }
            lines.Add("");
        }

        if (Buttons.Count > 0)
        {
            lines.Add($"BUTTON LABELS ({Buttons.Count}):");
            foreach (var b in Buttons)
                lines.Add($"  {b}");
            lines.Add("");
        }

        if (Labels.Count > 0)
        {
            lines.Add($"FORM LABELS ({Labels.Count}):");
            foreach (var l in Labels)
                lines.Add($"  {l}");
            lines.Add("");
        }

        if (Images.Count > 0)
        {
            var withAlt = Images.Count(i => !string.IsNullOrWhiteSpace(i.Alt));
            var withoutAlt = Images.Count - withAlt;
            lines.Add($"IMAGES ({Images.Count}, {withAlt} with alt text, {withoutAlt} without):");
            foreach (var img in Images)
            {
                var alt = string.IsNullOrWhiteSpace(img.Alt) ? "(no alt text)" : $"\"{img.Alt}\"";
                lines.Add($"  {alt}");
            }
            lines.Add("");
        }

        lines.Add("============================");
        return string.Join(Environment.NewLine, lines);
    }
}
