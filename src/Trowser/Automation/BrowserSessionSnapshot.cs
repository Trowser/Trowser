namespace Trowser.Automation;

/// <summary>
/// Scope for capturing or clearing browser session material (cookies, web storage).
/// Designed for reversible checkpoints during scans and future first-class session APIs.
/// </summary>
public enum BrowserSessionScopeKind
{
    /// <summary>Entire WebView2 profile (all cookies; storage for the active document origin only).</summary>
    Profile,

    /// <summary>Cookies and storage for one origin (scheme + host + port).</summary>
    Origin,

    /// <summary>Cookies whose domain matches the anchor host; storage for the anchor origin.</summary>
    Site
}

/// <summary>
/// Immutable snapshot of session state that can be restored after temporary mutations.
/// </summary>
public sealed class BrowserSessionSnapshot
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
    public BrowserSessionScopeKind Scope { get; init; }
    public string? AnchorUrl { get; init; }
    public string? AnchorOrigin { get; init; }
    public string? AnchorHost { get; init; }
    public List<BrowserSessionCookieRecord> Cookies { get; init; } = [];
    public Dictionary<string, string> LocalStorage { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<string, string> SessionStorage { get; init; } = new(StringComparer.Ordinal);
}

public sealed class BrowserSessionCookieRecord
{
    public string Name { get; init; } = "";
    public string Value { get; init; } = "";
    public string Domain { get; init; } = "";
    public string Path { get; init; } = "/";
    public bool Secure { get; init; }
    public bool HttpOnly { get; init; }
    public string SameSite { get; init; } = "lax";
    public bool Session { get; init; } = true;
    public string? Expires { get; init; }
}

public static class BrowserSessionCookieMatching
{
    public static bool DomainMatchesHost(string cookieDomain, string host)
    {
        if (string.IsNullOrWhiteSpace(cookieDomain) || string.IsNullOrWhiteSpace(host))
            return false;
        var d = cookieDomain.TrimStart('.');
        return host.Equals(d, StringComparison.OrdinalIgnoreCase)
               || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase);
    }
}
