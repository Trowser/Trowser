using Trowser.Api;
using Trowser.Security.Orchestration;
using Trowser.Security.Sse;

namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>
    /// Pull in-flight event-stream bytes from CDP for open connections (WebView2 often lacks <c>dataReceived</c>).
    /// </summary>
    public async Task RefreshOpenSseCaptureFromCdpAsync(CancellationToken ct = default)
    {
        var tab = ActiveTab;
        var dispatcher = tab.UiDispatcher;
        if (dispatcher == null) return;

        await await dispatcher.InvokeAsync(async () =>
        {
            ct.ThrowIfCancellationRequested();
            if (tab.WebView.CoreWebView2 == null) return;
            await SseCdpLiveBodySync.PollOpenStreamsAsync(tab);
        });
    }

  public async Task<SseAuditResult> RunSseAuditAsync(SseAuditor.AuditOptions? options = null, PeerRegistry? peers = null,
        CancellationToken ct = default)
    {
        options ??= new SseAuditor.AuditOptions();
        await RefreshOpenSseCaptureFromCdpAsync(ct);
        var manager = ActiveTab.Sse;
        var passive = SseAuditor.AuditPassive(this, manager, options);

        var pageSink = await SsePageHandlerAnalyzer.AnalyzeAsync(this);
        passive.Findings.AddRange(pageSink);

        var activeWanted = options.Checks.Contains("all")
            || options.Checks.Contains("unauthenticated")
            || options.Checks.Contains("cross-origin")
            || options.Checks.Contains("last-event-id")
            || options.Checks.Contains("peer");

        if (activeWanted)
        {
            var connections = options.ConnectionId > 0
                ? manager.GetConnections().Where(c => c.ConnectionId == options.ConnectionId).ToList()
                : manager.GetConnections();
            if (connections.Count == 0)
            {
                foreach (var entry in Network.Entries.Where(e => e.IsEventStream && e.IsSuccess).Take(3))
                {
                    manager.EnsureConnection(
                        $"net-{entry.Id}",
                        entry.Url,
                        entry.Method,
                        null,
                        entry.StatusCode,
                        entry.ResponseHeaders,
                        entry.RequestHeaders);
                }

                connections = manager.GetConnections();
            }

            foreach (var conn in connections.Take(5))
            {
                ct.ThrowIfCancellationRequested();
                var active = await SseActiveProbes.RunAsync(this, manager, conn, options, peers, ct);
                passive.Findings.AddRange(active);
            }
        }

        return passive;
    }
}
