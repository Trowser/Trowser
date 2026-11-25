namespace Trowser.Api;

/// <summary>
/// URL shaping for agent-facing payloads (journal, bookmarks, lists). Mirrors network-log defaults:
/// omit or summarize huge <c>data:</c> URLs so pollers stay usable.
/// </summary>
public static class AgentUrlPolicy
{
    public const int DefaultMaxUrlChars = 500;

    public static bool IsOmittedUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        var t = url.Trim();
        return t.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
               || t.Equals("about:blank", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsInternalDisplayUrl(string? url) =>
        !string.IsNullOrWhiteSpace(url)
        && url.StartsWith("trowser://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Skip journaling synthetic in-app navigations (HTML report tabs, etc.).</summary>
    public static bool ShouldSkipJournalNavigation(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        if (IsOmittedUrl(url)) return true;
        return IsInternalDisplayUrl(url);
    }

    public static string? ForAgent(string? url, int maxChars = DefaultMaxUrlChars)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        var t = url.Trim();
        if (t.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            var semi = t.IndexOf(',', StringComparison.Ordinal);
            var meta = semi > 0 ? t[..Math.Min(semi + 1, Math.Min(48, maxChars))] : t[..Math.Min(32, t.Length)];
            return $"{meta}…({t.Length} chars data-url omitted)";
        }

        if (t.Length <= maxChars) return t;
        return t[..maxChars] + "…";
    }

    /// <summary>
    /// Prefer a logical page URL over WebView <c>Source</c> when the bar shows a welcome/start page
    /// but the document is a huge inline <c>data:</c> URL.
    /// </summary>
    public static string? ResolveLogicalPageUrl(string? webViewSource, string? displayUrlOverride)
    {
        if (!string.IsNullOrWhiteSpace(displayUrlOverride)
            && !IsInternalDisplayUrl(displayUrlOverride))
            return displayUrlOverride!.Trim();

        if (string.IsNullOrWhiteSpace(webViewSource)) return null;
        var raw = webViewSource.Trim();
        if (raw.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return displayUrlOverride?.Trim();

        if (raw.Equals("about:blank", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(displayUrlOverride))
            return displayUrlOverride!.Trim();

        return raw;
    }
}