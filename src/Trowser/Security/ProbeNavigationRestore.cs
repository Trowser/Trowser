using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Restores the WebView URL after probes that navigate away (payload URLs, cache-bust params).
/// </summary>
internal static class ProbeNavigationRestore
{
    public static async Task<string?> CaptureBaselineUrlAsync(AutomationContext ctx)
    {
        try
        {
            var url = await ctx.GetCurrentUrl();
            return string.IsNullOrWhiteSpace(url)
                ? null
                : UrlPayloadInjector.StripToolQueryParams(url);
        }
        catch
        {
            return null;
        }
    }

    public static async Task TryRestoreAsync(AutomationContext ctx, string? baselineUrl)
    {
        if (string.IsNullOrWhiteSpace(baselineUrl)) return;
        try
        {
            var now = await ctx.GetCurrentUrl();
            if (string.IsNullOrWhiteSpace(now)) return;
            now = UrlPayloadInjector.StripToolQueryParams(now);
            if (string.Equals(now, baselineUrl, StringComparison.OrdinalIgnoreCase))
                return;
            await ctx.Navigate(baselineUrl);
            await Task.Delay(300);
        }
        catch
        {
            /* best-effort — do not fail the probe */
        }
    }
}
