using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Shared prep/teardown for active security scans (dialogs block automation after XSS proofs).
/// </summary>
public static class SecurityScanHygiene
{
    /// <summary>Auto-accept alerts/confirms/prompts before active probes.</summary>
    public static async Task PrepareActiveScanAsync(AutomationContext ctx)
    {
        try
        {
            await ctx.HandleDialog(accept: true);
        }
        catch
        {
            /* best effort */
        }
    }

    /// <summary>Clear dialog latch and dismiss a blocking native dialog if one fired.</summary>
    public static async Task TryClearBlockingDialogAsync(AutomationContext ctx)
    {
        try
        {
            var dialog = await ctx.GetDialog();
            if (dialog != null)
                await ctx.DismissDialog();
        }
        catch
        {
            /* best effort */
        }
    }
}
