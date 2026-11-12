using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Host matching for security scanners — treats localhost, 127.0.0.1, and ::1 as the same origin.
/// </summary>
public static class SecurityHostScope
{
    /// <summary>Resolve scan scope host from explicit filter or current page URL.</summary>
    public static string? ResolveScopeHost(string? explicitHost, string? currentPageUrl)
    {
        if (!string.IsNullOrWhiteSpace(explicitHost))
            return NormalizeHostFilter(explicitHost);
        if (Uri.TryCreate(currentPageUrl, UriKind.Absolute, out var uri))
            return uri.Host;
        return null;
    }

    /// <summary>True when <paramref name="host"/> is outside the in-scope application origin.</summary>
    public static bool IsThirdPartyHost(string? host, string? scopeHost)
    {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(scopeHost))
            return false;
        return !Matches(host, scopeHost);
    }

    /// <summary>
    /// True when <paramref name="host"/> is a different site than <paramref name="scopeHost"/>,
    /// including well-known CDNs even when no scope host was supplied.
    /// The scope host itself is never treated as third-party.
    /// </summary>
    public static bool IsOutsideApplicationScope(string? host, string? scopeHost)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        if (!string.IsNullOrWhiteSpace(scopeHost) && Matches(host, scopeHost))
            return false;
        if (IsWellKnownThirdPartyHost(host))
            return true;
        return IsThirdPartyHost(host, scopeHost);
    }

    /// <summary>Analytics, map, and CDN hosts that are not the application under test.</summary>
    public static bool IsWellKnownThirdPartyHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        var h = host.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var suffix in WellKnownThirdPartySuffixes)
        {
            if (h.Equals(suffix, StringComparison.Ordinal) || h.EndsWith("." + suffix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static readonly string[] WellKnownThirdPartySuffixes =
    [
        "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
        "doubleclick.net", "googleusercontent.com", "facebook.net", "facebook.com",
        "fbcdn.net", "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net",
        "unpkg.com", "cdnjs.cloudflare.com", "fontawesome.com", "bootstrapcdn.com",
        "sentry.io", "hotjar.com", "segment.io", "segment.com",
        "newrelic.com", "datadoghq.com", "intercom.io", "intercomcdn.com"
    ];

    public static bool EntryInScope(NetworkEntry entry, string? hostFilter, string? scopeHost, bool excludeThirdParty)
    {
        if (!string.IsNullOrWhiteSpace(hostFilter) && !MatchesHostFilter(entry.Host, hostFilter))
            return false;
        if (excludeThirdParty && IsThirdPartyHost(entry.Host, scopeHost))
            return false;
        return true;
    }

    /// <summary>
    /// Match a network-entry host against a filter that may be a bare hostname,
    /// <c>host:port</c>, or a full origin/URL (<c>http://host:port/…</c>).
    /// Port is ignored — <see cref="NetworkEntry.Host"/> is hostname-only.
    /// </summary>
    public static bool MatchesHostFilter(string? entryHost, string? hostFilter)
    {
        if (string.IsNullOrWhiteSpace(hostFilter))
            return true;
        if (string.IsNullOrWhiteSpace(entryHost))
            return false;
        return Matches(entryHost, NormalizeHostFilter(hostFilter));
    }

    /// <summary>
    /// Normalize user-supplied host filters to a hostname comparable with <see cref="NetworkEntry.Host"/>.
    /// Accepts <c>example.com</c>, <c>example.com:8443</c>, <c>http://example.com:8443/path</c>, and IPv6 forms.
    /// </summary>
    public static string NormalizeHostFilter(string hostFilter)
    {
        var t = hostFilter.Trim();
        if (t.Length == 0) return t;

        if (t.Contains("://", StringComparison.Ordinal)
            && Uri.TryCreate(t, UriKind.Absolute, out var absolute))
            return absolute.Host;

        // [ipv6]:port
        if (t.StartsWith('[') && t.Contains(']', StringComparison.Ordinal))
        {
            var end = t.IndexOf(']');
            if (end > 1)
                return t[1..end];
        }

        // host:port (avoid treating bare IPv6 as host:port)
        var lastColon = t.LastIndexOf(':');
        if (lastColon > 0 && t.IndexOf(':') == lastColon
            && int.TryParse(t.AsSpan(lastColon + 1), out _))
            return t[..lastColon];

        return t;
    }

    public static bool Matches(string? hostA, string? hostB)
    {
        if (string.IsNullOrWhiteSpace(hostA) || string.IsNullOrWhiteSpace(hostB))
            return false;
        var a = NormalizeHostFilter(hostA);
        var b = NormalizeHostFilter(hostB);
        if (a.Equals(b, StringComparison.OrdinalIgnoreCase))
            return true;
        return IsLoopback(a) && IsLoopback(b);
    }

    public static bool IsLoopback(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (host.Equals("::1", StringComparison.OrdinalIgnoreCase)
            || host.Equals("[::1]", StringComparison.OrdinalIgnoreCase))
            return true;
        if (host.StartsWith("127.", StringComparison.Ordinal))
            return true;
        return false;
    }

    /// <summary>Stable endpoint key for dedup/suppression (loopback hosts collapse to one bucket).</summary>
    public static string LogicalEndpointKey(string method, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return $"{method}|{url}";

        var hostKey = IsLoopback(uri.Host) ? "loopback" : uri.Host.ToLowerInvariant();
        return $"{method}|{hostKey}|{uri.AbsolutePath}";
    }
}
