using Trowser.Automation;

namespace Trowser.Laws;

internal static class LawPathMatch
{
    public static bool HostMatches(string? siteFilter, string pageHost)
    {
        if (string.IsNullOrWhiteSpace(siteFilter))
            return true;

        var pattern = siteFilter.Trim();
        if (pattern.Contains('*'))
            return GlobMatch(pattern, pageHost, pathStyle: false);

        if (pageHost.Equals(pattern, StringComparison.OrdinalIgnoreCase))
            return true;

        // Bare registrable domain: also match www.domain.com, api.domain.com, etc.
        return pageHost.EndsWith("." + pattern, StringComparison.OrdinalIgnoreCase);
    }

    public static bool PagePathMatches(string? pattern, string url)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return true;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return GlobMatch(pattern, url, pathStyle: pattern.TrimStart().StartsWith('/'));

        var pathQuery = uri.PathAndQuery;
        var trimmed = pattern.Trim();
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return GlobMatch(trimmed, url, pathStyle: false);

        return GlobMatch(trimmed, pathQuery, pathStyle: true);
    }

    /// <summary>Pattern like <c>GET /api/cart*</c> or <c>/api/cart*</c>.</summary>
    public static bool ResponseMatches(string? pattern, NetworkEntry entry)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return true;

        var p = pattern.Trim();
        string? method = null;
        string pathPart = p;

        var space = p.IndexOf(' ');
        if (space > 0 && p[..space].All(char.IsLetter))
        {
            method = p[..space];
            pathPart = p[(space + 1)..].Trim();
        }

        if (method != null && !method.Equals(entry.Method, StringComparison.OrdinalIgnoreCase))
            return false;

        if (pathPart.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || pathPart.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return GlobMatch(pathPart, entry.Url, pathStyle: false);

        var entryPath = entry.Path;
        if (pathPart.StartsWith('/'))
            return GlobMatch(pathPart, entryPath, pathStyle: true);

        return GlobMatch(pathPart, entryPath, pathStyle: true);
    }

    private static bool GlobMatch(string pattern, string value, bool pathStyle)
    {
        if (string.Equals(pattern, value, StringComparison.OrdinalIgnoreCase))
            return true;

        if (pattern.Contains('*'))
        {
            var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return System.Text.RegularExpressions.Regex.IsMatch(value, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        if (pathStyle)
            return PathLiteralMatches(pattern, value);

        return string.Equals(pattern, value, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Exact path match, or prefix <c>{pattern}/…</c> (not substring).</summary>
    private static bool PathLiteralMatches(string pattern, string pathQuery)
    {
        if (pathQuery.Equals(pattern, StringComparison.OrdinalIgnoreCase))
            return true;

        if (pattern.EndsWith('/'))
            return pathQuery.StartsWith(pattern, StringComparison.OrdinalIgnoreCase);

        return pathQuery.StartsWith(pattern + "/", StringComparison.OrdinalIgnoreCase);
    }
}
