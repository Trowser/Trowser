using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Tracks tabs opened during a security scan and closes probe popups without touching the tester's home tab.
/// </summary>
public sealed class SecurityScanTabScope
{
    private readonly AutomationContext _ctx;
    private readonly int _homeTabId;
    private readonly HashSet<int> _baselineTabIds;

    private SecurityScanTabScope(AutomationContext ctx, int homeTabId, HashSet<int> baselineTabIds)
    {
        _ctx = ctx;
        _homeTabId = homeTabId;
        _baselineTabIds = baselineTabIds;
    }

    public static SecurityScanTabScope Begin(AutomationContext ctx)
    {
        var home = ctx.ActiveTab ?? throw new InvalidOperationException("No active tab for scan.");
        var baseline = ctx.Tabs.Select(t => t.Id).ToHashSet();
        return new SecurityScanTabScope(ctx, home.Id, baseline);
    }

    public int HomeTabId => _homeTabId;

    public int HomeTabIndex => _ctx.FindTabIndexById(_homeTabId);

    public bool TrySwitchToHome()
    {
        var idx = HomeTabIndex;
        if (idx < 0)
            return false;
        _ctx.SwitchTab(idx);
        return true;
    }

    public int CountTabsOpenedDuringScan() =>
        _ctx.Tabs.Count(t => !_baselineTabIds.Contains(t.Id));

    public async Task<int> CloseProbePopupsAsync(string? victimHost = null, string? runId = null)
    {
        TrySwitchToHome();
        var closed = 0;
        for (var i = _ctx.Tabs.Count - 1; i >= 0; i--)
        {
            if (_ctx.Tabs.Count <= 1)
                break;

            var tab = _ctx.Tabs[i];
            if (tab.Id == _homeTabId)
                continue;
            if (!ShouldCloseProbeTab(tab, victimHost, runId))
                continue;

            if (ReferenceEquals(_ctx.ActiveTab, tab))
                TrySwitchToHome();

            try
            {
                await _ctx.CloseTab(i);
                closed++;
            }
            catch
            {
                /* ignore */
            }
        }

        TrySwitchToHome();
        return closed;
    }

    public async Task<(int Opened, int Closed)> FinishAsync(string? victimHost = null, string? runId = null)
    {
        var opened = CountTabsOpenedDuringScan();
        var closed = await CloseProbePopupsAsync(victimHost, runId);
        return (opened, closed);
    }

    public Task<bool> IsHomeSessionIntactAsync(string victimHost, string baselineCookieMode) =>
        SecurityScanSessionGuard.IsHomeSessionIntactAsync(_ctx, _homeTabId, victimHost, baselineCookieMode);

    private bool ShouldCloseProbeTab(BrowserTab tab, string? victimHost, string? runId)
    {
        if (tab.OpenedByPageWindow)
            return true;

        if (!_baselineTabIds.Contains(tab.Id) && tab.Owner == TabOwners.Agent)
            return true;

        var url = tab.Url ?? "";
        if (url.Length == 0)
            return false;

        if (url.Contains("__xsleak", StringComparison.OrdinalIgnoreCase))
            return true;

        if (url.Contains("evil.trowser.test/", StringComparison.OrdinalIgnoreCase))
            return true;

        if (url.Contains("/csrf/", StringComparison.OrdinalIgnoreCase)
            && url.Contains("evil.trowser.test", StringComparison.OrdinalIgnoreCase))
            return true;

        if (url.Contains("/cswsh/", StringComparison.OrdinalIgnoreCase)
            && url.Contains("evil.trowser.test", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(runId)
            && url.Contains(runId, StringComparison.OrdinalIgnoreCase)
            && url.Contains("xsleak", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(victimHost)
            && url.Contains(victimHost, StringComparison.OrdinalIgnoreCase)
            && tab.OpenedByPageWindow)
            return true;

        return false;
    }
}
