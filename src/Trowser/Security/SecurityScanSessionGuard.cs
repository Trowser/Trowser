using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Session checks for long-running security scans (home tab URL + cookies).</summary>
internal static class SecurityScanSessionGuard
{
    public static async Task<bool> IsHomeSessionIntactAsync(
        AutomationContext ctx,
        int homeTabId,
        string victimHost,
        string baselineCookieMode)
    {
        if (string.Equals(baselineCookieMode, "no-session-cookie", StringComparison.OrdinalIgnoreCase))
            return true;

        var home = ctx.GetTabById(homeTabId);
        if (home == null)
            return false;

        var url = home.Url;
        if (string.IsNullOrWhiteSpace(url))
        {
            try
            {
                url = home.WebView.CoreWebView2?.Source;
            }
            catch
            {
                /* best-effort */
            }
        }

        if (SecurityUrlPolicy.IsSessionDisruptionUrl(url, victimHost))
            return false;

        try
        {
            var cookies = await ctx.GetCookies();
            var hasSessionOnHost = cookies.Any(c =>
            {
                var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                if (!SessionCookieDetector.IsSessionCookieName(name)
                    || XsLeaks.XsLeakSessionProfile.IsLikelyCsrfCookieName(name))
                    return false;
                var domain = c.TryGetValue("domain", out var d) ? d?.ToString()?.TrimStart('.') ?? "" : "";
                return domain.Equals(victimHost, StringComparison.OrdinalIgnoreCase)
                       || victimHost.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
            });
            return hasSessionOnHost;
        }
        catch
        {
            return true;
        }
    }
}
