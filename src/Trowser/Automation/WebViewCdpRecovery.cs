using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Automation;

/// <summary>Best-effort CDP recovery when DevTools calls time out (unblocks hung page scripts).</summary>
internal static class WebViewCdpRecovery
{
    private const int TerminateTimeoutMs = 3_000;

    /// <summary>
    /// Fire-and-forget <c>Runtime.terminateExecution</c> on the WebView dispatcher.
    /// Does not throw; safe to call from timeout handlers.
    /// </summary>
    public static void TryTerminateExecutionAsync(WebView2 webView)
    {
        try
        {
            _ = webView.Dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    var core = webView.CoreWebView2;
                    if (core == null) return;
                    using var cts = new CancellationTokenSource(TerminateTimeoutMs);
                    await core.CallDevToolsProtocolMethodAsync("Runtime.terminateExecution", "{}")
                        .WaitAsync(cts.Token);
                }
                catch
                {
                    // recovery is best-effort
                }
            });
        }
        catch
        {
            // ignore
        }
    }
}
