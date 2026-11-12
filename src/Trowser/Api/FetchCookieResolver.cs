using System.Text.Json;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Api;

/// <summary>
/// One-shot cookie impersonation for server-side fetch (does not mutate the browser jar).
/// </summary>
internal sealed class FetchIdentityOverride
{
    public string? Peer { get; init; }
    public string? Identity { get; init; }
}

internal sealed class FetchCookieResolution
{
    public Dictionary<string, string>? Headers { get; init; }
    public bool IncludeBrowserCookies { get; init; } = true;
    public bool ForceServerSide { get; init; }
    public string? Error { get; init; }
    public string? IdentitySource { get; init; }
}

internal static class FetchCookieResolver
{
    public static FetchIdentityOverride? ParseIdentityOverride(JsonBody body)
    {
        if (body.GetJsonElement("identityOverride") is not { ValueKind: JsonValueKind.Object } el)
            return null;

        return new FetchIdentityOverride
        {
            Peer = el.TryGetProperty("peer", out var p) ? p.GetString()?.Trim() : null,
            Identity = el.TryGetProperty("identity", out var i) ? i.GetString()?.Trim() : null
        };
    }

    public static async Task<FetchCookieResolution> ResolveAsync(
        AutomationContext context,
        PeerRegistry peers,
        IdentityStore identityStore,
        string url,
        Dictionary<string, string>? headers,
        string? cookies,
        FetchIdentityOverride? identityOverride,
        bool? includeBrowserCookies,
        bool cookiesSpecified = false)
    {
        headers = HttpHeaderDictionary.Normalize(headers);

        var hasCookies = !string.IsNullOrWhiteSpace(cookies);
        var hasPeer = !string.IsNullOrWhiteSpace(identityOverride?.Peer);
        var hasIdentity = !string.IsNullOrWhiteSpace(identityOverride?.Identity);

        if (hasCookies && (hasPeer || hasIdentity))
            return Error("Use either 'cookies' or 'identityOverride', not both.");

        if (hasPeer && hasIdentity)
            return Error("identityOverride.peer and identityOverride.identity are mutually exclusive.");

        if (!hasCookies && !hasPeer && !hasIdentity)
        {
            string? cookieHeaderValue = null;
            var cookieHeaderPresent = headers != null && headers.TryGetValue("Cookie", out cookieHeaderValue);
            if (ExplicitAnonymous(cookiesSpecified, cookies, cookieHeaderPresent, cookieHeaderValue, includeBrowserCookies))
            {
                if (cookieHeaderPresent)
                    headers!.Remove("Cookie");
                return new FetchCookieResolution
                {
                    Headers = headers,
                    IncludeBrowserCookies = false,
                    ForceServerSide = true,
                    IdentitySource = "anonymous"
                };
            }

            return new FetchCookieResolution
            {
                Headers = headers,
                IncludeBrowserCookies = includeBrowserCookies ?? true
            };
        }

        string? cookieHeader;
        string? source;

        if (hasCookies)
        {
            cookieHeader = cookies!.Trim();
            source = "cookies";
        }
        else if (hasPeer)
        {
            var peerName = identityOverride!.Peer!;
            if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                return Error("identityOverride.peer requires an absolute url.");

            var query = Uri.EscapeDataString(url);
            var resp = await peers.ForwardAsync(peerName, "GET", $"/api/session/cookie-header?url={query}", timeoutMs: 15000);
            if (!resp.Success)
                return Error(resp.Body ?? $"Could not load cookies from peer \"{peerName}\".");

            if (!TryParseCookieHeaderFromApi(resp.Body, out cookieHeader, out var parseErr))
                return Error(parseErr ?? "Invalid peer cookie-header response.");

            source = $"peer:{peerName}";
        }
        else
        {
            var name = identityOverride!.Identity!;
            if (!IdentityStore.IsValidName(name))
                return Error("identityOverride.identity is not a valid identity name.");

            var snapshot = identityStore.Load(name);
            if (snapshot == null)
                return Error($"Identity '{name}' not found. Capture it with POST /api/identity/capture.");

            cookieHeader = BuildCookieHeaderFromSnapshot(snapshot, url);
            if (string.IsNullOrEmpty(cookieHeader))
                return Error($"No cookies in identity '{name}' match the request URL.");

            source = $"identity:{name}";
        }

        headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        headers["Cookie"] = cookieHeader ?? "";

        return new FetchCookieResolution
        {
            Headers = headers,
            IncludeBrowserCookies = includeBrowserCookies ?? false,
            ForceServerSide = true,
            IdentitySource = source
        };
    }

    /// <summary>
    /// An explicit empty <c>cookies</c> field or <c>Cookie</c> header means "send no cookies",
    /// unless the caller also set <c>includeBrowserCookies: true</c>.
    /// </summary>
    internal static bool ExplicitAnonymous(
        bool cookiesSpecified,
        string? cookies,
        bool cookieHeaderPresent,
        string? cookieHeader,
        bool? includeBrowserCookies)
    {
        if (includeBrowserCookies == true)
            return false;
        if (cookiesSpecified && string.IsNullOrWhiteSpace(cookies))
            return true;
        return cookieHeaderPresent && string.IsNullOrWhiteSpace(cookieHeader);
    }

    private static FetchCookieResolution Error(string message) =>
        new() { Error = message };

    private static bool TryParseCookieHeaderFromApi(string? json, out string? cookieHeader, out string? error)
    {
        cookieHeader = null;
        error = null;
        if (string.IsNullOrWhiteSpace(json))
        {
            error = "Empty cookie-header response.";
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var data = root.TryGetProperty("data", out var d) ? d : root;
            if (data.TryGetProperty("cookieHeader", out var h) && h.ValueKind == JsonValueKind.String)
            {
                cookieHeader = h.GetString();
                return !string.IsNullOrEmpty(cookieHeader);
            }

            error = "Response missing data.cookieHeader.";
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string BuildCookieHeaderFromSnapshot(IdentitySnapshot snapshot, string requestUrl)
    {
        if (!Uri.TryCreate(requestUrl, UriKind.Absolute, out var target))
            return "";

        var pairs = new List<(string Name, string Value)>();
        foreach (var c in snapshot.Cookies)
        {
            if (string.IsNullOrWhiteSpace(c.Name) || c.Value == null)
                continue;
            if (!CookieAppliesToUrl(c.Domain, c.Path, target))
                continue;
            pairs.Add((c.Name, c.Value));
        }

        return CookieHeaderSanitizer.BuildCookieHeader(pairs);
    }

    private static bool CookieAppliesToUrl(string? domain, string? path, Uri target)
    {
        var cookieDomain = (domain ?? "").Trim();
        if (string.IsNullOrEmpty(cookieDomain))
            cookieDomain = target.Host;

        if (cookieDomain.StartsWith('.'))
            cookieDomain = cookieDomain[1..];

        var host = target.Host;
        if (!host.Equals(cookieDomain, StringComparison.OrdinalIgnoreCase)
            && !host.EndsWith("." + cookieDomain, StringComparison.OrdinalIgnoreCase))
            return false;

        var cookiePath = string.IsNullOrWhiteSpace(path) ? "/" : path;
        return target.AbsolutePath.StartsWith(cookiePath, StringComparison.OrdinalIgnoreCase);
    }
}
