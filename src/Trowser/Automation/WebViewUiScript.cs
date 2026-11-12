using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Automation;

/// <summary>
/// Executes JavaScript on the WebView UI thread with per-call timeout and optional abort cancellation.
/// Used by audit checkers (axe, web-vitals, Retire.js, etc.) — same contract as <see cref="AutomationContext"/> RunJs.
/// </summary>
internal static class WebViewUiScript
{
    public const int DefaultTimeoutMs = 30_000;

    public static async Task<string> RunAsync(
        WebView2 webView,
        string script,
        CancellationToken cancellationToken = default,
        int timeoutMs = DefaultTimeoutMs,
        string? operationLabel = null)
    {
        var taskOfResult = await webView.Dispatcher.InvokeAsync(
            () => webView.CoreWebView2.ExecuteScriptAsync(script));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            var rawResult = await taskOfResult.WaitAsync(timeoutCts.Token);
            return WebViewScriptResult.UnwrapJsonString(rawResult);
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                throw;

            WebViewCdpRecovery.TryTerminateExecutionAsync(webView);
            var label = string.IsNullOrWhiteSpace(operationLabel) ? "Page script" : operationLabel;
            throw new TimeoutException(
                $"{label} timed out after {timeoutMs / 1000} seconds. " +
                "The page JavaScript context may be blocked; try POST /api/force-navigate or POST /api/abort.");
        }
    }
}
