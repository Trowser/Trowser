namespace Trowser.Automation;

/// <summary>
/// Cookie header material derived from the WebView2 jar for a specific request URL (no values in <see cref="Scopes"/>).
/// </summary>
public sealed record BrowserCookieSnapshot(
    string Header,
    string CookieSourceUrl,
    IReadOnlyList<BrowserCookieScope> Scopes);

/// <summary>Name/domain/path scope for one cookie included in a server-side replay (values omitted).</summary>
public sealed record BrowserCookieScope(string Name, string Domain, string Path);
