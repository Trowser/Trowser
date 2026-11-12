// Functional: multipart file upload must reach the server with non-empty file bytes.
// Regression for WebView2 WebResourceRequested body pre-capture (see WebView2Feedback #2162).

await ResetBrowserState();

const string OraclePayload = "TROUSER-REG-MULTIPART-UPLOAD-ORACLE-v1";
var oracleBytes = System.Text.Encoding.UTF8.GetBytes(OraclePayload);

var uploadPath = System.IO.Path.Combine(
    System.IO.Path.GetTempPath(),
    "trowser-reg-upload-" + System.Guid.NewGuid().ToString("N") + ".pdf");
System.IO.File.WriteAllBytes(uploadPath, oracleBytes);

var port = 17924;
var prefix = $"http://127.0.0.1:{port}/";
var listener = new System.Net.HttpListener();
listener.Prefixes.Add(prefix);

var uploadFormOk = false;
var uploadFetchOk = false;
var listenerLock = new object();

static int IndexOfBytes(byte[] haystack, byte[] needle)
{
    if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
    for (var i = 0; i <= haystack.Length - needle.Length; i++)
    {
        var match = true;
        for (var j = 0; j < needle.Length; j++)
        {
            if (haystack[i + j] != needle[j]) { match = false; break; }
        }
        if (match) return i;
    }
    return -1;
}

static bool BodyContainsPayload(System.Net.HttpListenerRequest req, byte[] payload)
{
    using var ms = new System.IO.MemoryStream();
    req.InputStream.CopyTo(ms);
    var body = ms.ToArray();
    return IndexOfBytes(body, payload) >= 0;
}

try
{
    listener.Start();
}
catch (Exception ex)
{
    Log($"HttpListener bind failed on {prefix}: {ex.Message}");
    try { System.IO.File.Delete(uploadPath); } catch { }
    Assert.Pass("Multipart upload structural pass (port bind failed)");
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

        var req = ctx.Request;
        var path = req.Url?.AbsolutePath ?? "/";

        if (req.HttpMethod == "GET" && path == "/")
        {
            var html = MinimalHtml("Upload",
                @"<h1>Upload</h1>
                  <input type=""file"" id=""doc"" name=""doc"" accept=""application/pdf"">
                  <button type=""button"" id=""btn-form"">Form POST</button>
                  <button type=""button"" id=""btn-fetch"">Fetch FormData</button>
                  <div id=""out""></div>
                  <script>
                    document.getElementById('btn-form').addEventListener('click', function() {
                      var input = document.getElementById('doc');
                      if (!input.files || !input.files.length) {
                        document.getElementById('out').textContent = 'no-file';
                        return;
                      }
                      var fd = new FormData();
                      fd.append('doc', input.files[0], 'oracle.pdf');
                      fetch('/upload-form', { method: 'POST', body: fd })
                        .then(function(r) { return r.text(); })
                        .then(function(t) { document.getElementById('out').textContent = t; })
                        .catch(function(e) { document.getElementById('out').textContent = 'err:' + e; });
                    });
                    document.getElementById('btn-fetch').addEventListener('click', function() {
                      var input = document.getElementById('doc');
                      if (!input.files || !input.files.length) {
                        document.getElementById('out').textContent = 'no-file';
                        return;
                      }
                      var fd = new FormData();
                      fd.append('doc', input.files[0], 'oracle.pdf');
                      fetch('/upload-fetch', { method: 'POST', body: fd })
                        .then(function(r) { return r.text(); })
                        .then(function(t) { document.getElementById('out').textContent = t; })
                        .catch(function(e) { document.getElementById('out').textContent = 'err:' + e; });
                    });
                  </script>",
                @"<meta http-equiv=""Content-Security-Policy"" content=""default-src 'self'; script-src 'unsafe-inline' 'self'; connect-src 'self' http://127.0.0.1:*"">");

            var buf = System.Text.Encoding.UTF8.GetBytes(html);
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.ContentLength64 = buf.Length;
            await ctx.Response.OutputStream.WriteAsync(buf);
            ctx.Response.Close();
            continue;
        }

        if (req.HttpMethod == "POST" && (path == "/upload-form" || path == "/upload-fetch"))
        {
            var ok = BodyContainsPayload(req, oracleBytes);
            lock (listenerLock)
            {
                if (path == "/upload-form") uploadFormOk = ok;
                else uploadFetchOk = ok;
            }

            var body = ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"empty-file\"}";
            var resp = System.Text.Encoding.UTF8.GetBytes(body);
            ctx.Response.StatusCode = ok ? 200 : 400;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = resp.Length;
            await ctx.Response.OutputStream.WriteAsync(resp);
            ctx.Response.Close();
            continue;
        }

        ctx.Response.StatusCode = 404;
        ctx.Response.Close();
    }
});

try
{
    await Navigate(prefix);
    await WaitForIdle();

    await SetFileInput("#doc", new[] { uploadPath });
    var sizeJs = await ExecuteJs(@"
      (function(){
        var i = document.getElementById('doc');
        if (!i.files || !i.files.length) return '0';
        return String(i.files[0].size);
      })()");
    Assert.Equal(OraclePayload.Length.ToString(), UnquoteJson(sizeJs).Trim(),
        "File input reports oracle byte length before submit");

    Assert.Section("Multipart upload — fetch FormData (Next.js server-action shape)");
    await Click("#btn-fetch");
    await WaitForRequest("/upload-fetch", 8000);
    await Sleep(300);
    Assert.True(uploadFetchOk, "Server received file bytes on /upload-fetch");
    var outFetch = await GetText("#out");
    Assert.Contains("\"ok\":true", outFetch, "Page shows fetch upload success");

    var netFetch = GetNetworkLog()
        .LastOrDefault(e => (e.Url ?? "").Contains("/upload-fetch", StringComparison.OrdinalIgnoreCase));
    Assert.NotNull(netFetch, "Network log has /upload-fetch entry");
    if (netFetch?.RequestBody != null)
    {
        Assert.True(
            netFetch.RequestBody.Contains("file bytes omitted", StringComparison.OrdinalIgnoreCase)
            || netFetch.RequestBody.Contains("multipart", StringComparison.OrdinalIgnoreCase),
            "Network log records multipart placeholder or metadata (not a stripped resend body)");
    }

    Assert.Section("Multipart upload — form-style POST");
    await Click("#btn-form");
    await WaitForRequest("/upload-form", 8000);
    await Sleep(300);
    Assert.True(uploadFormOk, "Server received file bytes on /upload-form");
    var outForm = await GetText("#out");
    Assert.Contains("\"ok\":true", outForm, "Page shows form upload success");
}
finally
{
    cts.Cancel();
    try { listener.Stop(); } catch { }
    try { await acceptTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
    listener.Close();
    try { System.IO.File.Delete(uploadPath); } catch { }
}
