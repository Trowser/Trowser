using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

public partial class AutomationContext
{
    private readonly Dictionary<string, BrowserSessionSnapshot> _browserSessionCheckpoints = new(StringComparer.Ordinal);

    /// <summary>
    /// Capture a restorable browser session checkpoint. Returns a checkpoint id for <see cref="BrowserSessionRestoreAsync"/>.
    /// </summary>
    public async Task<string> BrowserSessionCaptureAsync(
        BrowserSessionScopeKind scope = BrowserSessionScopeKind.Site,
        string? anchorUrl = null)
    {
        var snapshot = await CaptureBrowserSessionSnapshotAsync(scope, anchorUrl);
        _browserSessionCheckpoints[snapshot.Id] = snapshot;
        return snapshot.Id;
    }

    /// <summary>Restore a checkpoint captured with <see cref="BrowserSessionCaptureAsync"/>.</summary>
    public async Task BrowserSessionRestoreAsync(string checkpointId)
    {
        if (!_browserSessionCheckpoints.TryGetValue(checkpointId, out var snapshot))
            throw new ArgumentException($"Unknown browser session checkpoint '{checkpointId}'.", nameof(checkpointId));
        await RestoreBrowserSessionSnapshotAsync(snapshot);
    }

    /// <summary>Drop a checkpoint without restoring.</summary>
    public void BrowserSessionDiscardCheckpoint(string checkpointId) =>
        _browserSessionCheckpoints.Remove(checkpointId);

    internal async Task<BrowserSessionSnapshot> CaptureBrowserSessionSnapshotAsync(
        BrowserSessionScopeKind scope,
        string? anchorUrl)
    {
        var url = anchorUrl;
        if (string.IsNullOrWhiteSpace(url))
            url = await GetCurrentUrl();
        Uri? anchor = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u : null;
        var origin = anchor?.GetLeftPart(UriPartial.Authority);
        var host = anchor?.Host ?? "";

        var allCookies = await GetAllProfileCookiesViaCdpAsync();
        var cookies = scope switch
        {
            BrowserSessionScopeKind.Profile => allCookies,
            BrowserSessionScopeKind.Site => allCookies
                .Where(c => BrowserSessionCookieMatching.DomainMatchesHost(c.Domain, host))
                .ToList(),
            BrowserSessionScopeKind.Origin => allCookies
                .Where(c => BrowserSessionCookieMatching.DomainMatchesHost(c.Domain, host))
                .ToList(),
            _ => allCookies
        };

        Dictionary<string, string> local = new(StringComparer.Ordinal);
        Dictionary<string, string> session = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(origin)
            && anchor != null
            && string.Equals(await GetCurrentUrl(), url, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                local = await GetAllStorage("local");
                session = await GetAllStorage("session");
            }
            catch
            {
                /* storage readable only on matching origin */
            }
        }

        return new BrowserSessionSnapshot
        {
            Scope = scope,
            AnchorUrl = url,
            AnchorOrigin = origin,
            AnchorHost = host,
            Cookies = cookies,
            LocalStorage = local,
            SessionStorage = session
        };
    }

    internal async Task RestoreBrowserSessionSnapshotAsync(BrowserSessionSnapshot snapshot)
    {
        if (snapshot.Scope == BrowserSessionScopeKind.Profile)
        {
            await ClearCookies();
        }
        else if (!string.IsNullOrWhiteSpace(snapshot.AnchorHost))
        {
            await ClearSiteCookiesAsync(snapshot.AnchorHost);
        }

        foreach (var c in snapshot.Cookies)
        {
            await SetCookie(c.Name, c.Value, c.Domain, c.Path, c.Secure, c.HttpOnly, c.SameSite);
        }

        if (snapshot.LocalStorage.Count > 0 || snapshot.SessionStorage.Count > 0)
        {
            if (!string.IsNullOrWhiteSpace(snapshot.AnchorUrl))
            {
                try
                {
                    await ForceNavigateAsync(snapshot.AnchorUrl, terminateScripts: true);
                    await WaitForIdle(150, 5000);
                }
                catch
                {
                    /* best-effort origin for storage restore */
                }
            }

            await ClearStorage("local");
            await ClearStorage("session");
            foreach (var (k, v) in snapshot.LocalStorage)
                await SetStorageItem("local", k, v);
            foreach (var (k, v) in snapshot.SessionStorage)
                await SetStorageItem("session", k, v);
        }
    }

    /// <summary>Clear cookies for one site host (not the entire profile).</summary>
    public async Task ClearSiteCookiesAsync(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return;
        var all = await GetAllProfileCookiesViaCdpAsync();
        foreach (var c in all.Where(x => BrowserSessionCookieMatching.DomainMatchesHost(x.Domain, host)))
        {
            await DeleteCookie(c.Name, c.Domain, c.Path);
        }
    }

    /// <summary>Clear web storage for the current document origin.</summary>
    public async Task ClearOriginStorageAsync()
    {
        await ClearStorage("local");
        await ClearStorage("session");
    }

    internal async Task ApplyAnonymousSiteSessionAsync(string host, string? originUrl)
    {
        await ClearSiteCookiesAsync(host);
        if (!string.IsNullOrWhiteSpace(originUrl))
        {
            try
            {
                await ForceNavigateAsync(originUrl, terminateScripts: true);
                await WaitForIdle(150, 5000);
                await ClearOriginStorageAsync();
            }
            catch
            {
                // Cookies are cleared; skip storage when origin did not load (opaque / DNS / mock-only URLs).
            }
        }
        else
        {
            try
            {
                await ClearOriginStorageAsync();
            }
            catch
            {
                /* no readable origin on active document */
            }
        }
    }

    private async Task<List<BrowserSessionCookieRecord>> GetAllProfileCookiesViaCdpAsync()
    {
        var webView = ActiveTab.WebView;
        var resultJson = await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Network.getCookies", "{}"));

        using var doc = JsonDocument.Parse(resultJson);
        var list = new List<BrowserSessionCookieRecord>();
        if (!doc.RootElement.TryGetProperty("cookies", out var cookiesArray))
            return list;

        foreach (var c in cookiesArray.EnumerateArray())
        {
            var name = c.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(name)) continue;
            var value = c.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
            var domain = c.TryGetProperty("domain", out var d) ? d.GetString() ?? "" : "";
            var path = c.TryGetProperty("path", out var p) ? p.GetString() ?? "/" : "/";
            var secure = c.TryGetProperty("secure", out var s) && s.GetBoolean();
            var httpOnly = c.TryGetProperty("httpOnly", out var h) && h.GetBoolean();
            var sameSite = c.TryGetProperty("sameSite", out var ss) ? ss.GetString()?.ToLowerInvariant() ?? "lax" : "lax";
            var expires = c.TryGetProperty("expires", out var exp) ? exp.GetDouble() : -1;
            var isSession = expires <= 0;
            string? expiresIso = null;
            if (!isSession)
                expiresIso = DateTimeOffset.FromUnixTimeSeconds((long)expires).UtcDateTime.ToString("O");

            list.Add(new BrowserSessionCookieRecord
            {
                Name = name,
                Value = value,
                Domain = domain,
                Path = path,
                Secure = secure,
                HttpOnly = httpOnly,
                SameSite = sameSite,
                Session = isSession,
                Expires = expiresIso
            });
        }

        return list;
    }
}
