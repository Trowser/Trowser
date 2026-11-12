using System.IO;
using System.Net;

namespace Trowser.Api;

/// <summary>
/// Best-effort cancellation when the HTTP client closes the connection while a gated operation runs.
/// HttpListener does not expose RequestAborted; we poll for a dead connection so long scans release the gate.
/// </summary>
internal static class ApiClientDisconnect
{
    public static void Link(HttpListenerContext? context, CancellationTokenSource operationCts)
    {
        if (context == null || operationCts.IsCancellationRequested)
            return;
        _ = MonitorAsync(context, operationCts);
    }

    private static async Task MonitorAsync(HttpListenerContext context, CancellationTokenSource operationCts)
    {
        try
        {
            var request = context.Request;
            while (!operationCts.IsCancellationRequested)
            {
                await Task.Delay(400).ConfigureAwait(false);
                if (operationCts.IsCancellationRequested)
                    break;

                try
                {
                    if (!request.InputStream.CanRead)
                    {
                        operationCts.Cancel();
                        break;
                    }
                }
                catch (HttpListenerException)
                {
                    operationCts.Cancel();
                    break;
                }
                catch (ObjectDisposedException)
                {
                    operationCts.Cancel();
                    break;
                }
                catch (IOException)
                {
                    operationCts.Cancel();
                    break;
                }
            }
        }
        catch
        {
            /* best-effort */
        }
    }
}
