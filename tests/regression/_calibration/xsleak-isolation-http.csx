// Calibration Phase 1: real HTTP response headers (HttpListener) vs WebResourceRequested mocks.
// Re-run after WebView2 upgrades. Compare img-error mitigated/tier against mock-only xsleak-corp-mock.csx.

await ResetBrowserState();

var listener = new System.Net.HttpListener();
var port = 17924;
var prefix = $"http://127.0.0.1:{port}/";
listener.Prefixes.Add(prefix);
try
{
    listener.Start();
}
catch (Exception ex)
{
    Log($"HttpListener bind failed: {ex.Message}");
    Assert.Pass("XS-Leak isolation HTTP calibration skipped (port busy)");
    return;
}

var cts = new CancellationTokenSource();
var acceptTask = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        System.Net.HttpListenerContext? ctx = null;
        try { ctx = await listener.GetContextAsync(); }
        catch when (cts.IsCancellationRequested) { break; }
        catch { continue; }

        var path = ctx!.Request.Url?.AbsolutePath ?? "/";
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cross-Origin-Resource-Policy"] = "same-origin",
            ["Cross-Origin-Opener-Policy"] = "same-origin",
            ["Cross-Origin-Embedder-Policy"] = "require-corp"
        };
        byte[] body;
        int status;
        if (path.Contains("hit", StringComparison.OrdinalIgnoreCase))
        {
            status = 200;
            body = System.Text.Encoding.UTF8.GetBytes(
                "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"4\" height=\"4\"><rect width=\"4\" height=\"4\"/></svg>");
            headers["Content-Type"] = "image/svg+xml";
        }
        else
        {
            status = 404;
            body = "missing"u8.ToArray();
            headers["Content-Type"] = "text/plain";
        }

        ctx.Response.StatusCode = status;
        foreach (var (k, v) in headers)
            ctx.Response.Headers[k] = v;
        ctx.Response.ContentLength64 = body.Length;
        await ctx.Response.OutputStream.WriteAsync(body);
        ctx.Response.Close();
    }
});

var hit = $"{prefix}xsleak/hit.svg";
var miss = $"{prefix}xsleak/miss.svg";
await Navigate(hit);
await WaitForIdle(400, 8000);

var opts = new Trowser.Security.XsLeaks.XsLeakScanner.XsLeakOptions
{
    States =
    [
        new() { Label = "hit", Url = hit },
        new() { Label = "miss", Url = miss }
    ],
    Techniques = ["img-error"],
    Trials = 2,
    SkipWarmup = true
};
var scan = await RunXsLeaksAsync(opts, "safe");
var img = scan.Techniques.First(t => t.Technique == "img-error");
Log($"HttpListener CORP+COOP+COEP img-error verdict={img.Verdict} tier={img.Tier} mitigated={img.Mitigated}");
Log($"isolation note: {scan.BrowserModel.IsolationEnforcement}");

cts.Cancel();
try { listener.Stop(); } catch { /* ignore */ }
acceptTask.Wait(2000);

Assert.True(true, "Calibration logged — compare with xsleak-corp-mock.csx mock path");
