namespace Trowser.LinkChecking;

public enum LinkStatus
{
    Ok,          // 2xx
    Redirect,    // 3xx (observation, not error)
    Broken,      // 4xx/5xx
    Timeout,     // Connection timeout
    Error,       // DNS failure, connection refused, etc.
    Skipped      // mailto:, tel:, javascript:, data:, #fragment-only
}

public class CheckedLink
{
    public string Url { get; init; } = "";
    public string OriginalUrl { get; init; } = "";  // before resolving relative
    public string Source { get; init; } = "";        // "anchor", "image", "script", "stylesheet", "iframe"
    public LinkStatus Status { get; init; }
    public int? StatusCode { get; init; }
    public string? RedirectUrl { get; init; }        // for 3xx
    public string? Error { get; init; }              // for timeout/error
    public string? LinkText { get; init; }           // for anchors only

    public override string ToString()
    {
        var status = StatusCode.HasValue ? $"{StatusCode}" : Status.ToString().ToUpper();
        return $"[{status}] {Url}";
    }
}

public class LinkCheckResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public int TotalLinks { get; init; }
    public int CheckedCount { get; init; }
    public int BrokenCount => Links.Count(l => l.Status is LinkStatus.Broken or LinkStatus.Timeout or LinkStatus.Error);
    public int RedirectCount => Links.Count(l => l.Status == LinkStatus.Redirect);
    public int SkippedCount => Links.Count(l => l.Status == LinkStatus.Skipped);
    public List<CheckedLink> Links { get; init; } = new();
    public List<CheckedLink> Broken => Links.Where(l => l.Status is LinkStatus.Broken or LinkStatus.Timeout or LinkStatus.Error).ToList();
    public bool IsClean => BrokenCount == 0;

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();
        lines.Add("=== Link Check ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Total links found: {TotalLinks}");
        lines.Add($"Checked: {CheckedCount}  |  Broken: {BrokenCount}  |  Redirects: {RedirectCount}  |  Skipped: {SkippedCount}");
        lines.Add("");

        if (BrokenCount == 0 && RedirectCount == 0)
        {
            lines.Add("All links are valid. No broken links found.");
            lines.Add("==================");
            return string.Join(Environment.NewLine, lines);
        }

        var broken = Links.Where(l => l.Status is LinkStatus.Broken or LinkStatus.Timeout or LinkStatus.Error).ToList();
        if (broken.Count > 0)
        {
            lines.Add($"BROKEN LINKS: {broken.Count}");
            if (includeDetails)
            {
                foreach (var link in broken)
                {
                    var statusLabel = link.Status switch
                    {
                        LinkStatus.Broken => $"[BROKEN {link.StatusCode}]",
                        LinkStatus.Timeout => "[TIMEOUT]",
                        LinkStatus.Error => "[ERROR]",
                        _ => $"[{link.Status.ToString().ToUpper()}]"
                    };
                    lines.Add($"  {statusLabel} {link.Url}");
                    if (!string.IsNullOrEmpty(link.Error))
                        lines.Add($"    Error: {link.Error}");
                    if (!string.IsNullOrEmpty(link.LinkText))
                        lines.Add($"    Text: \"{link.LinkText}\"");
                    lines.Add($"    Source: {link.Source}  Original: {link.OriginalUrl}");
                }
            }
            lines.Add("");
        }

        var redirects = Links.Where(l => l.Status == LinkStatus.Redirect).ToList();
        if (redirects.Count > 0)
        {
            lines.Add($"REDIRECTS: {redirects.Count}");
            if (includeDetails)
            {
                foreach (var link in redirects)
                {
                    lines.Add($"  [REDIRECT {link.StatusCode}] {link.Url}");
                    if (!string.IsNullOrEmpty(link.RedirectUrl))
                        lines.Add($"    → {link.RedirectUrl}");
                }
            }
            lines.Add("");
        }

        var skipped = Links.Where(l => l.Status == LinkStatus.Skipped).ToList();
        if (skipped.Count > 0 && includeDetails)
        {
            lines.Add($"SKIPPED: {skipped.Count}");
            foreach (var link in skipped.Take(20))
            {
                lines.Add($"  [SKIPPED] {link.OriginalUrl}");
            }
            if (skipped.Count > 20)
                lines.Add($"  ... and {skipped.Count - 20} more");
            lines.Add("");
        }

        if (BrokenCount > 0)
            lines.Add($"ASSESSMENT: {BrokenCount} broken link(s) found -- fix recommended.");
        else
            lines.Add("ASSESSMENT: No broken links. All checked links are valid.");

        lines.Add("==================");
        return string.Join(Environment.NewLine, lines);
    }
}
