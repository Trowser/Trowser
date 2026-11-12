using System.Text.RegularExpressions;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Enforces URL navigation scope restrictions.
/// Converts simple wildcard patterns (like "https://*.example.com") to regex
/// and checks URLs against them.
///
/// Special pattern "*.*" means no restrictions (allow all URLs).
/// Multiple patterns can be comma-separated.
/// </summary>
public class NavigationGuard
{
    private readonly List<Regex> _patterns = new();
    private bool _allowAll;
    private string _rawScope;

    /// <summary>The raw scope string as entered by the user.</summary>
    public string Scope => _rawScope;

    /// <summary>True when navigation is restricted to specific patterns (not "*.*").</summary>
    public bool IsRestricted => !_allowAll;

    /// <summary>When false (default), <c>file://</c> URLs are blocked even under <c>*.*</c>.</summary>
    public bool AllowFileUrls { get; private set; }

    public NavigationGuard(string scope, bool allowFileUrls = false)
    {
        AllowFileUrls = allowFileUrls;
        _rawScope = scope?.Trim() ?? "*.*";
        SetScope(_rawScope);
    }

    public void SetAllowFileUrls(bool allow) => AllowFileUrls = allow;

    /// <summary>
    /// Update the allowed scope patterns.
    /// </summary>
    public void SetScope(string scope)
    {
        _rawScope = scope?.Trim() ?? "*.*";
        _patterns.Clear();
        _allowAll = false;

        var parts = _rawScope.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var part in parts)
        {
            if (part == "*.*")
            {
                _allowAll = true;
                return;
            }

            var pattern = ConvertToRegex(part);
            _patterns.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled));
        }
    }

    /// <summary>
    /// Build a temporary navigation scope for Monkey Trowser from the current page URL.
    /// Uses a naive registrable-domain heuristic (last two host labels) so subdomains stay in scope.
    /// Loopback, IP, and single-label hosts are scoped to the exact origin host.
    /// </summary>
    public static bool TryBuildTemporaryScopeFromPageUrl(string url, out string scope)
    {
        scope = "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            && !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            return false;

        var host = uri.Host;
        if (string.IsNullOrWhiteSpace(host))
            return false;

        if (SecurityHostScope.IsLoopback(host)
            || System.Net.IPAddress.TryParse(host, out _)
            || host.Contains(':', StringComparison.Ordinal)
            || !host.Contains('.'))
        {
            scope = $"{uri.Scheme}://{host}";
            return true;
        }

        var parts = host.Split('.');
        var domain = parts.Length <= 2
            ? host
            : $"{parts[^2]}.{parts[^1]}";

        scope = $"https://*.{domain},http://*.{domain},https://{domain},http://{domain}";
        return true;
    }

    /// <summary>
    /// Check if a URL is allowed under the current scope.
    /// Internal URLs (about:, data:, blob:) are always allowed.
    /// </summary>
    public bool IsAllowed(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;

        if (!AllowFileUrls && url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
            return false;

        if (_allowAll) return true;

        // Always allow internal browser URLs
        if (url.StartsWith("about:", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
            url.StartsWith("edge:", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return _patterns.Any(p => p.IsMatch(url));
    }

    /// <summary>
    /// Convert a simple wildcard pattern to a regex pattern.
    /// '*' matches any characters except '/'.
    /// A trailing path is always allowed (i.e. https://*.example.com matches https://www.example.com/any/path).
    /// </summary>
    private static string ConvertToRegex(string pattern)
    {
        // Normalize: strip trailing slashes so "https://site.com/" and "https://site.com"
        // produce the same regex. Without this, a trailing slash creates a pattern requiring
        // a double slash ("//") before any path can match, blocking all sub-page navigation.
        pattern = pattern.TrimEnd('/');

        // Escape all regex special chars, then convert \* back to [^/]* (wildcard within URL segments)
        var escaped = Regex.Escape(pattern).Replace("\\*", "[^/]*");

        // Allow any trailing path after the pattern
        if (!pattern.EndsWith("*"))
            escaped += "(/.*)?";

        return "^" + escaped + "$";
    }
}
