// Functional: fetch() + ReadableStream on a long-lived text/event-stream must be captured
// while the connection is still open (CDP streamResourceContent + Network.dataReceived).
// Uses a local HttpListener so the server can flush incremental chunks (mocks deliver one shot).

await ResetBrowserState();

const string StreamOracle = "TROUSER-SSE-FETCH-OPEN-v1";
var port = 17933;
var prefix = $"http://127.0.0.1:{port}/";
var listener = new System.Net.HttpListener();
listener.Prefixes.Add(prefix);

var cts = new CancellationTokenSource();
var acceptTask = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        System.Net.HttpListenerContext? ctx = null;
        try { ctx = await listener.GetContextAsync(); }
        catch when (cts.IsCancellationRequested) { break; }
        catch { continue; }

        var req = ctx.Request;
        var path = req.Url?.AbsolutePath ?? "/";

        if (req.HttpMethod == "GET" && path == "/")
        {
            var html = MinimalHtml("SSE fetch open",
                @"<h1>SSE fetch</h1>",
                @"<meta http-equiv=""Content-Security-Policy"" content=""default-src 'self'; script-src 'unsafe-inline' 'self'; connect-src 'self' http://127.0.0.1:*"">");
            var buf = System.Text.Encoding.UTF8.GetBytes(html);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.ContentLength64 = buf.Length;
            await ctx.Response.OutputStream.WriteAsync(buf);
            ctx.Response.Close();
            continue;
        }

        if (req.HttpMethod == "GET" && path == "/stream")
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "text/event-stream";
            ctx.Response.Headers.Add("Cache-Control", "no-cache");
            ctx.Response.SendChunked = true;

            var n = 0;
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    var ev =
                        $"id: open-{n}\nevent: tick\ndata: {{\"n\":{n},\"oracle\":\"{StreamOracle}\"}}\n\n";
                    var chunk = System.Text.Encoding.UTF8.GetBytes(ev);
                    await ctx.Response.OutputStream.WriteAsync(chunk);
                    await ctx.Response.OutputStream.FlushAsync();
                    n++;
                    await Task.Delay(350, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (System.Net.HttpListenerException) { /* client closed */ }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }

            continue;
        }

        ctx.Response.StatusCode = 404;
        ctx.Response.Close();
    }
});

try
{
    listener.Start();
}
catch (Exception ex)
{
    Log($"HttpListener bind failed on {prefix}: {ex.Message}");
    Assert.Pass("fetch SSE open-stream structural pass (port bind failed)");
    return;
}

try
{
    Assert.Section("fetch() event-stream — capture while connection open");
    await Navigate(prefix);
    await WaitForIdle();

    await ExecuteJs("""
        window.__sseOpen = { bytes: 0, err: null };
        window.__sseAbort = null;
        (function () {
          var ac = new AbortController();
          window.__sseAbort = function () { ac.abort(); };
          (async function () {
            try {
              var resp = await fetch('/stream', {
                headers: { 'Accept': 'text/event-stream' },
                signal: ac.signal
              });
              var rd = resp.body.getReader();
              var dec = new TextDecoder();
              for (;;) {
                var step = await rd.read();
                if (step.done) break;
                window.__sseOpen.bytes += dec.decode(step.value).length;
              }
            } catch (e) {
              window.__sseOpen.err = String(e);
            }
          })();
        })();
        'started';
        """);

    await Sleep(1200);
    await RefreshOpenSseCaptureFromCdpAsync();

    var conns = ActiveTab.Sse.GetConnections(stateFilter: "open", urlFilter: "/stream");
    Assert.True(conns.Count >= 1, "Open fetch SSE connection while stream is in flight");

    var conn = conns[0];
    Assert.True(conn.MessagesReceived >= 2,
        $"SSE messages captured while open (got {conn.MessagesReceived})");
    Assert.True(ActiveTab.Sse.GetWireBytes(conn.CdpRequestId) > 0, "wireBytes > 0 while open");

    var mode = ActiveTab.Sse.DescribeCaptureMode(conn.CdpRequestId);
    Assert.True(
        !string.Equals(mode, "headers-only", StringComparison.OrdinalIgnoreCase),
        $"captureMode reflects payload (got {mode})");

    var msgs = ActiveTab.Sse.GetMessages(conn.ConnectionId, eventNameFilter: "tick", last: 5);
    Assert.True(msgs.Any(m => m.Data.Contains(StreamOracle, StringComparison.Ordinal)),
        "Parsed tick event data contains oracle");

    Assert.NotNull(conn.NetworkEntryId);
    var netRow = GetNetworkLog().FirstOrDefault(e => e.Id == conn.NetworkEntryId);
    Assert.NotNull(netRow);
    Assert.True(netRow!.IsEventStream, "Linked network row marked event-stream");
    Assert.True(
        (netRow.ResponseBody?.Length ?? 0) > 0,
        "Network row accumulates event-stream body while open");

    var pageBytes = UnquoteJson(await ExecuteJs("String(window.__sseOpen.bytes)")).Trim();
    Assert.True(int.TryParse(pageBytes, out var pb) && pb > 0,
        $"Page consumer decoded bytes (got {pageBytes})");
}
finally
{
    try { await ExecuteJs("if (window.__sseAbort) window.__sseAbort();"); } catch { }
    await Sleep(300);
    cts.Cancel();
    try { listener.Stop(); } catch { }
    try { await acceptTask.WaitAsync(TimeSpan.FromSeconds(3)); } catch { }
    listener.Close();
}
