using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Shared path/URL exclusion for light crawl and playbook/probe target selection.
/// Supports include/exclude globs, optional regexes, and a default logout denylist.
/// </summary>
public static class SecurityPathExclusion
{
    /// <summary>
    /// Path-segment logout patterns (case-insensitive). Anchored so
    /// <c>/catalog/logout-history</c> is not treated as logout.
    /// </summary>
    private static readonly Regex DefaultLogoutPathRegex = new(
        @"/(?:log[-_]?out|sign[-_]?out|signoff|sign[-_]?off|endsession|end[-_]?session|slo)(?:/|$|\?|\.)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>Query-string logout indicators (e.g. <c>?action=logout</c>).</summary>
    private static readonly Regex DefaultLogoutQueryRegex = new(
        @"[?&](?:action|op|do|cmd|event|task)=(?:[^&]*log[-_]?out|[^&]*sign[-_]?out|signoff|sign[-_]?off)(?:&|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string[] LogoutLabelNeedles =
    [
        "log out", "logout", "log-out", "sign out", "sign-out", "sign off", "sign-off", "signoff"
    ];

    /// <summary>Default logout globs merged when <c>excludeLogout</c> is true (also matched via regex).</summary>
    public static IReadOnlyList<string> DefaultLogoutGlobs { get; } =
    [
        "/logout", "/logout/*", "/log-out", "/log-out/*", "/log_out", "/log_out/*",
        "/signout", "/signout/*", "/sign-out", "/sign-out/*", "/sign_out", "/sign_out/*",
        "/signoff", "/signoff/*", "/sign-off", "/sign-off/*",
        "/slo", "/slo/*", "/endsession", "/endsession/*", "/end-session", "/end-session/*",
        "*/logout", "*/logout.*", "*/signout", "*/sign-out", "*/endsession", "*/slo"
    ];

    public static bool IsPathAllowed(
        string pathOrUrl,
        IReadOnlyList<string>? includePaths = null,
        IReadOnlyList<string>? excludePaths = null,
        IReadOnlyList<string>? excludeUrlPatterns = null,
        bool excludeLogout = true)
    {
        var pathAndQuery = ExtractPathAndQuery(pathOrUrl);
        if (string.IsNullOrEmpty(pathAndQuery))
            pathAndQuery = "/";

        if (includePaths is { Count: > 0 }
            && !includePaths.Any(p => MatchesGlob(pathAndQuery, p)))
            return false;

        if (excludePaths is { Count: > 0 }
            && excludePaths.Any(p => MatchesGlob(pathAndQuery, p)))
            return false;

        if (excludeUrlPatterns is { Count: > 0 })
        {
            foreach (var pattern in excludeUrlPatterns)
            {
                if (string.IsNullOrWhiteSpace(pattern)) continue;
                try
                {
                    if (Regex.IsMatch(pathAndQuery, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                        return false;
                }
                catch (ArgumentException)
                {
                    // Invalid caller regex — ignore rather than fail the scan.
                }
            }
        }

        if (excludeLogout && MatchesDefaultLogout(pathAndQuery))
            return false;

        return true;
    }

    public static bool MatchesDefaultLogout(string pathOrUrl)
    {
        var pathAndQuery = ExtractPathAndQuery(pathOrUrl);
        if (string.IsNullOrEmpty(pathAndQuery))
            return false;

        // Ensure leading slash so ^/-anchored segment patterns work on relative paths.
        if (pathAndQuery[0] != '/')
            pathAndQuery = "/" + pathAndQuery;

        return DefaultLogoutPathRegex.IsMatch(pathAndQuery)
               || DefaultLogoutQueryRegex.IsMatch(pathAndQuery)
               || DefaultLogoutGlobs.Any(g => MatchesGlob(pathAndQuery, g));
    }

    /// <summary>True when interactive-element label/text looks like a logout control.</summary>
    public static bool LooksLikeLogoutLabel(string? labelOrText)
    {
        if (string.IsNullOrWhiteSpace(labelOrText))
            return false;

        var lower = CollapseWs(labelOrText).ToLowerInvariant();
        return LogoutLabelNeedles.Any(n => lower.Contains(n, StringComparison.Ordinal));
    }

    /// <summary>
    /// Glob match against path+query. <c>*</c> matches any characters; matching is case-insensitive.
    /// Patterns without <c>*</c> match the path exactly or as a path-prefix when they end with <c>/</c>.
    /// </summary>
    public static bool MatchesGlob(string pathAndQuery, string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return false;

        var path = ExtractPathAndQuery(pathAndQuery);
        if (string.IsNullOrEmpty(path))
            path = "/";
        if (path[0] != '/')
            path = "/" + path;

        var glob = pattern.Trim();
        if (glob.Length == 0)
            return false;

        // Absolute URL pattern → compare path+query only.
        if (glob.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || glob.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            glob = ExtractPathAndQuery(glob);

        if (string.IsNullOrEmpty(glob))
            return false;
        if (glob[0] != '/' && glob[0] != '*')
            glob = "/" + glob;

        if (!glob.Contains('*', StringComparison.Ordinal))
        {
            if (glob.EndsWith('/'))
                return path.StartsWith(glob, StringComparison.OrdinalIgnoreCase)
                       || string.Equals(path.TrimEnd('/'), glob.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

            return string.Equals(path, glob, StringComparison.OrdinalIgnoreCase)
                   || path.StartsWith(glob + "/", StringComparison.OrdinalIgnoreCase)
                   || path.StartsWith(glob + "?", StringComparison.OrdinalIgnoreCase);
        }

        var regex = "^" + Regex.Escape(glob).Replace("\\*", ".*", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(path, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static string ExtractPathAndQuery(string pathOrUrl)
    {
        if (string.IsNullOrWhiteSpace(pathOrUrl))
            return "";

        var s = pathOrUrl.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var uri)
            && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            var pq = uri.PathAndQuery;
            if (uri.Fragment.StartsWith("#/", StringComparison.Ordinal))
                pq += uri.Fragment;
            return string.IsNullOrEmpty(pq) ? "/" : pq;
        }

        var hashIdx = s.IndexOf('#');
        if (hashIdx >= 0 && !s[hashIdx..].StartsWith("#/", StringComparison.Ordinal))
            s = s[..hashIdx];

        return s;
    }

    private static string CollapseWs(string s) =>
        Regex.Replace(s.Trim(), @"\s+", " ");
}
