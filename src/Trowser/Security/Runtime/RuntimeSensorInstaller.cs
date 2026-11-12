using Trowser.Automation;

namespace Trowser.Security.Runtime;

/// <summary>
/// Install / uninstall the shared runtime sensor on a tab.
/// Prefer document-created registration when a navigation is about to happen.
/// </summary>
public static class RuntimeSensorInstaller
{
    /// <summary>
    /// Install via ExecuteJs on the current document. Idempotent.
    /// </summary>
    public static async Task InstallOnCurrentDocumentAsync(
        AutomationContext ctx,
        RuntimeSensorProfile profile = RuntimeSensorProfile.Active)
    {
        var tab = ctx.ActiveTab;
        try
        {
            var result = await ctx.ExecuteJs(RuntimeSensorScript.Build(profile));
            tab.RuntimeEvents.Installed = true;
            // result may be JSON-quoted
            _ = result;
        }
        catch
        {
            /* best-effort */
        }
    }

    /// <summary>
    /// Register a document-created script so hooks run before page scripts on the next navigation(s).
    /// Returns the script id (or null on failure). Caller should remove it after navigation.
    /// </summary>
    public static async Task<string?> InstallDocumentCreatedAsync(
        AutomationContext ctx,
        RuntimeSensorProfile profile = RuntimeSensorProfile.Active)
    {
        var tab = ctx.ActiveTab;
        try
        {
            var id = await ctx.AddDocumentCreatedScriptAsync(RuntimeSensorScript.Build(profile));
            if (!string.IsNullOrEmpty(id))
            {
                tab.RuntimeEvents.DocumentScriptId = id;
                tab.RuntimeEvents.Installed = true;
            }
            return id;
        }
        catch
        {
            return null;
        }
    }

    public static async Task RemoveDocumentCreatedAsync(AutomationContext ctx, string? scriptId)
    {
        if (string.IsNullOrEmpty(scriptId)) return;
        try
        {
            await ctx.RemoveDocumentCreatedScriptAsync(scriptId);
            if (ctx.ActiveTab.RuntimeEvents.DocumentScriptId == scriptId)
                ctx.ActiveTab.RuntimeEvents.DocumentScriptId = null;
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Keep the sensor installed for ambient Shadow runtime audit (document-created, not removed).
    /// </summary>
    public static async Task EnsureAmbientAsync(AutomationContext ctx)
    {
        var tab = ctx.ActiveTab;
        if (string.IsNullOrEmpty(tab.RuntimeEvents.DocumentScriptId))
        {
            var id = await InstallDocumentCreatedAsync(ctx, RuntimeSensorProfile.Ambient);
            if (id == null)
                await InstallOnCurrentDocumentAsync(ctx, RuntimeSensorProfile.Ambient);
        }
        else
        {
            tab.RuntimeEvents.Installed = true;
        }

        // Document-created hooks run on the next navigation only — always patch the live document too.
        await InstallOnCurrentDocumentAsync(ctx, RuntimeSensorProfile.Ambient);
    }

    /// <summary>
    /// Register document-created sensor before navigation so page scripts run under hooks.
    /// </summary>
    public static Task PrepareForNextNavigationAsync(AutomationContext ctx) =>
        InstallDocumentCreatedAsync(ctx, RuntimeSensorProfile.Active);
}
