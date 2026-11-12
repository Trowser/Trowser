using System.IO;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Downloads

    /// <summary>Captured downloads for the active tab.</summary>
    public DownloadLog Downloads => ActiveTab.Downloads;

    /// <summary>Directory under the session folder where deferred downloads are saved.</summary>
    public string? DownloadDirectory { get; set; }

    /// <summary>Ensure the download directory exists; create under TEMP if unset.</summary>
    public string EnsureDownloadDirectory()
    {
        if (!string.IsNullOrEmpty(DownloadDirectory))
        {
            Directory.CreateDirectory(DownloadDirectory);
            return DownloadDirectory;
        }

        var dir = Path.Combine(Path.GetTempPath(), "trowser-downloads", ActiveTab.Id.ToString());
        Directory.CreateDirectory(dir);
        DownloadDirectory = dir;
        return dir;
    }

    public List<DownloadEntry> GetDownloads() => Downloads.Entries;

    public Task<DownloadEntry> WaitForDownload(
        string? fileNameContains = null,
        int? timeoutMs = null,
        int afterId = 0)
        => Downloads.WaitForAsync(
            fileNameContains,
            timeoutMs ?? 30000,
            afterId,
            ScriptCancellation);

    /// <summary>
    /// Assert properties of a download. When <paramref name="entry"/> is null, uses the latest matching download.
    /// Records via <see cref="Assert"/> (unlike a bare throw, failures show up in <c>/api/assertions</c>).
    /// </summary>
    public DownloadEntry AssertDownload(
        string? fileNameContains = null,
        string? mimeContains = null,
        long? minBytes = null,
        bool? exists = true,
        DownloadEntry? entry = null)
    {
        entry ??= Downloads.Entries
            .Where(e => DownloadLog.Matches(e, fileNameContains))
            .LastOrDefault();

        string Fail(string details)
        {
            var desc = string.IsNullOrEmpty(fileNameContains)
                ? "Download assert"
                : $"Download assert '{fileNameContains}'";
            Assert.Fail(desc, details);
            return details;
        }

        if (entry == null)
        {
            var msg = string.IsNullOrEmpty(fileNameContains)
                ? "No downloads captured."
                : $"No download matching '{fileNameContains}'.";
            throw new InvalidOperationException(Fail(msg));
        }

        if (!string.IsNullOrEmpty(fileNameContains) && !DownloadLog.Matches(entry, fileNameContains))
            throw new InvalidOperationException(Fail(
                $"Download filename '{entry.SuggestedFileName}' does not contain '{fileNameContains}'."));

        if (!string.IsNullOrEmpty(mimeContains) &&
            !entry.MimeType.Contains(mimeContains, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(Fail(
                $"Download mime '{entry.MimeType}' does not contain '{mimeContains}'."));

        // Prefer on-disk size when the WebView2 counter is still 0 after completion.
        var bytes = entry.BytesReceived;
        if (bytes <= 0 && !string.IsNullOrEmpty(entry.Path) && File.Exists(entry.Path))
        {
            try { bytes = new FileInfo(entry.Path).Length; }
            catch { /* ignore */ }
        }

        if (minBytes is { } min && bytes < min)
            throw new InvalidOperationException(Fail($"Download size {bytes} < minBytes {min}."));

        if (exists == true && !string.IsNullOrEmpty(entry.Path) && !File.Exists(entry.Path))
            throw new InvalidOperationException(Fail($"Download file does not exist: {entry.Path}"));

        if (exists == false && !string.IsNullOrEmpty(entry.Path) && File.Exists(entry.Path))
            throw new InvalidOperationException(Fail($"Download file unexpectedly exists: {entry.Path}"));

        if (entry.State != DownloadState.Completed)
            throw new InvalidOperationException(Fail(
                $"Download state is {entry.State}, expected Completed."));

        Assert.Pass(string.IsNullOrEmpty(fileNameContains)
            ? $"Download ok: {entry.SuggestedFileName} ({bytes} bytes)"
            : $"Download ok '{fileNameContains}': {entry.SuggestedFileName} ({bytes} bytes)");
        return entry;
    }

    public void ClearDownloads(bool deleteFiles = false) => Downloads.Clear(deleteFiles);

    /// <summary>
    /// Wire WebView2 <c>DownloadStarting</c> for a tab. Called from MainWindow tab setup.
    /// </summary>
    public void AttachDownloadHandler(BrowserTab tab, CoreWebView2 core)
    {
        core.DownloadStarting += (s, e) => OnDownloadStarting(tab, e);
    }

    /// <summary>
    /// When the user navigates directly to a file URL, WebView2 often displays the body inline and
    /// never raises <see cref="CoreWebView2.DownloadStarting"/>. Save those responses to the session
    /// download folder and log them like normal downloads.
    /// </summary>
    public async Task TryCaptureDirectDocumentDownloadAsync(
        BrowserTab tab,
        string url,
        int statusCode,
        IReadOnlyDictionary<string, string> responseHeaders,
        string? capturedTextBody)
    {
        if (statusCode is < 200 or >= 300)
            return;

        // Attachment responses should go through WebView2 DownloadStarting (same handler + UI).
        if (responseHeaders.TryGetValue("Content-Disposition", out var cd) &&
            cd.Contains("attachment", StringComparison.OrdinalIgnoreCase))
            return;

        if (!DocumentDownloadHeuristics.ShouldTreatDirectNavigationAsDownload(url, responseHeaders))
            return;

        if (HasRecentDownloadForUrl(tab, url))
            return;

        var suggested = DocumentDownloadHeuristics.ResolveSuggestedFileName(url, responseHeaders);
        var dir = EnsureDownloadDirectory();
        var dest = DocumentDownloadHeuristics.BuildDestinationPath(dir, suggested);
        var mime = "";
        if (responseHeaders.TryGetValue("Content-Type", out var ct))
            mime = ct.Split(';')[0].Trim();

        long bytes = 0;
        try
        {
            if (!string.IsNullOrEmpty(capturedTextBody) &&
                !capturedTextBody.EndsWith("...(truncated)", StringComparison.Ordinal))
            {
                await File.WriteAllTextAsync(dest, capturedTextBody);
                bytes = new FileInfo(dest).Length;
            }
            else if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                     (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                bytes = await RedownloadWithBrowserCookiesAsync(tab, uri, dest);
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Direct document download failed for {url}: {ex.Message}");
            return;
        }

        if (bytes <= 0)
            return;

        ApplyMarkOfTheWeb(dest, url);

        tab.Downloads.Add(new DownloadEntry
        {
            Url = url,
            SuggestedFileName = DocumentDownloadHeuristics.SanitizeFileName(suggested),
            Path = dest,
            State = DownloadState.Completed,
            MimeType = mime,
            BytesReceived = bytes,
            TotalBytes = bytes,
            Timestamp = DateTime.UtcNow
        });
    }

    private static bool HasRecentDownloadForUrl(BrowserTab tab, string url)
    {
        foreach (var entry in tab.Downloads.Entries)
        {
            if ((DateTime.UtcNow - entry.Timestamp).TotalSeconds > 120)
                continue;
            if (!DocumentDownloadHeuristics.UrlsEquivalent(entry.Url, url))
                continue;
            if (entry.State is DownloadState.Interrupted or DownloadState.Cancelled)
                continue;
            return true;
        }

        return false;
    }

    private void OnDownloadStarting(BrowserTab tab, CoreWebView2DownloadStartingEventArgs e)
    {
        CoreWebView2Deferral? deferral = null;
        try
        {
            // Match WebView2 sample order: touch DownloadOperation, set path, then Handled.
            deferral = e.GetDeferral();
            var op = e.DownloadOperation;

            var dir = EnsureDownloadDirectory();
            var suggested = Path.GetFileName(e.ResultFilePath);
            if (string.IsNullOrWhiteSpace(suggested))
                suggested = Path.GetFileName(new Uri(op.Uri ?? "download.bin").LocalPath);
            if (string.IsNullOrWhiteSpace(suggested))
                suggested = "download.bin";

            var safeName = DocumentDownloadHeuristics.SanitizeFileName(suggested);
            var dest = DocumentDownloadHeuristics.BuildDestinationPath(dir, safeName);
            e.ResultFilePath = dest;
            e.Handled = true;

            // Keep a strong reference for the lifetime of the download (WebView2 requirement).
            tab.RetainDownloadOperation(op);

            var entry = tab.Downloads.Add(new DownloadEntry
            {
                Url = op.Uri ?? "",
                SuggestedFileName = safeName,
                Path = dest,
                State = DownloadState.InProgress,
                MimeType = op.MimeType ?? "",
                BytesReceived = (long)op.BytesReceived,
                TotalBytes = op.TotalBytesToReceive >= 0
                    ? (long?)op.TotalBytesToReceive
                    : null,
                Timestamp = DateTime.UtcNow
            });

            var id = entry.Id;
            var downloadUrl = entry.Url;
            var finalizeStarted = 0;

            void SyncFromOperation()
            {
                var state = op.State switch
                {
                    CoreWebView2DownloadState.Completed => DownloadState.Completed,
                    CoreWebView2DownloadState.Interrupted => DownloadState.Interrupted,
                    _ => DownloadState.InProgress
                };

                long bytes = (long)op.BytesReceived;
                if (state == DownloadState.Completed && bytes <= 0)
                    bytes = TryReadFileLength(dest);

                tab.Downloads.Update(id, d => d with
                {
                    State = state,
                    BytesReceived = bytes > 0 ? bytes : d.BytesReceived,
                    TotalBytes = op.TotalBytesToReceive >= 0
                        ? (long?)op.TotalBytesToReceive
                        : d.TotalBytes,
                    InterruptReason = state == DownloadState.Interrupted
                        ? op.InterruptReason.ToString()
                        : null
                });

                if (state == DownloadState.Completed)
                {
                    if (Interlocked.Exchange(ref finalizeStarted, 1) == 0)
                        _ = FinalizeDownloadBytesAsync(tab, op, id, dest, downloadUrl);
                }
                else if (state == DownloadState.Interrupted)
                {
                    tab.ReleaseDownloadOperation(op);
                }
            }

            op.BytesReceivedChanged += (_, _) => SyncFromOperation();
            op.StateChanged += (_, _) => SyncFromOperation();
            // Catch race where the download already finished before handlers were attached.
            SyncFromOperation();

            deferral.Complete();
            deferral = null;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"DownloadStarting handler failed: {ex.Message}");
            try { e.Handled = false; } catch { /* ignore */ }
            try { deferral?.Complete(); } catch { /* ignore */ }
        }
    }

    private static long TryReadFileLength(string path)
    {
        try
        {
            if (File.Exists(path))
                return new FileInfo(path).Length;
        }
        catch { /* ignore */ }
        return 0;
    }

    /// <summary>
    /// After WebView2 reports Completed with 0 bytes, poll the file briefly and — for http(s) —
    /// re-fetch with the browser's cookies if the on-disk file stays empty.
    /// </summary>
    private async Task FinalizeDownloadBytesAsync(
        BrowserTab tab,
        CoreWebView2DownloadOperation op,
        int id,
        string dest,
        string downloadUrl)
    {
        try
        {
            long bytes = (long)op.BytesReceived;
            if (bytes <= 0)
                bytes = TryReadFileLength(dest);

            for (var i = 0; i < 15 && bytes <= 0; i++)
            {
                await Task.Delay(100);
                bytes = TryReadFileLength(dest);
                if (bytes <= 0)
                    bytes = (long)op.BytesReceived;
            }

            if (bytes <= 0 &&
                Uri.TryCreate(downloadUrl, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                try
                {
                    bytes = await RedownloadWithBrowserCookiesAsync(tab, uri, dest);
                    if (bytes > 0)
                        ApplyMarkOfTheWeb(dest, downloadUrl);
                }
                catch (Exception ex)
                {
                    TrowserLog.Warn($"Download HTTP fallback failed for {downloadUrl}: {ex.Message}");
                }
            }

            if (bytes > 0)
            {
                tab.Downloads.Update(id, d => d with
                {
                    State = DownloadState.Completed,
                    BytesReceived = bytes,
                    TotalBytes = d.TotalBytes is null or 0 ? bytes : d.TotalBytes
                });
            }
        }
        finally
        {
            tab.ReleaseDownloadOperation(op);
        }
    }

    private async Task<long> RedownloadWithBrowserCookiesAsync(BrowserTab tab, Uri uri, string dest)
    {
        var webView = tab.WebView;
        string cookieHeader = "";
        string userAgent = "Trowser";

        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = webView.CoreWebView2;
            if (core == null) return;
            try { userAgent = core.Settings.UserAgent; } catch { /* ignore */ }
            var cookies = await core.CookieManager.GetCookiesAsync(uri.GetLeftPart(UriPartial.Authority));
            if (cookies == null || cookies.Count == 0) return;
            cookieHeader = string.Join("; ", cookies.Select(c => $"{c.Name}={c.Value}"));
        });

        using var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };

        // Follow redirects by hand so the origin's cookies are never sent to another host.
        var current = uri;
        HttpResponseMessage? resp = null;
        try
        {
            for (var hop = 0; ; hop++)
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, current);
                if (!string.IsNullOrEmpty(cookieHeader) && SameAuthority(current, uri))
                    req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
                req.Headers.TryAddWithoutValidation("User-Agent", userAgent);

                resp?.Dispose();
                resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
                var status = (int)resp.StatusCode;
                if (status is < 300 or > 399 || resp.Headers.Location == null)
                    break;
                if (hop >= 5)
                    throw new HttpRequestException("Too many redirects.");
                var next = new Uri(current, resp.Headers.Location);
                if (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps)
                    throw new HttpRequestException($"Refusing redirect to {next.Scheme}: URL.");
                current = next;
            }

            resp.EnsureSuccessStatusCode();
            if (resp.Content.Headers.ContentLength > MaxRedownloadBytes)
                throw new HttpRequestException("Download exceeds the size limit.");

            await using var body = await resp.Content.ReadAsStreamAsync();
            await using var file = new FileStream(dest, FileMode.Create, FileAccess.Write);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await body.ReadAsync(buffer)) > 0)
            {
                total += read;
                if (total > MaxRedownloadBytes)
                {
                    file.Close();
                    File.Delete(dest);
                    throw new HttpRequestException("Download exceeds the size limit.");
                }
                await file.WriteAsync(buffer.AsMemory(0, read));
            }
            if (total == 0)
            {
                file.Close();
                File.Delete(dest);
            }
            return total;
        }
        finally
        {
            resp?.Dispose();
        }
    }

    private const long MaxRedownloadBytes = 512L * 1024 * 1024;

    private static bool SameAuthority(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.IdnHost, b.IdnHost, StringComparison.OrdinalIgnoreCase)
        && a.Port == b.Port;

    /// <summary>
    /// Tags a file Trowser wrote itself with the Internet zone, as WebView2's own downloads are,
    /// so SmartScreen and Office protected view still apply when the user opens it.
    /// </summary>
    private static void ApplyMarkOfTheWeb(string path, string sourceUrl)
    {
        try
        {
            var host = Uri.TryCreate(sourceUrl, UriKind.Absolute, out var u) ? u.GetLeftPart(UriPartial.Path) : "";
            File.WriteAllText(path + ":Zone.Identifier", $"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl={host}\r\n");
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Could not set Mark-of-the-Web on {path}: {ex.Message}");
        }
    }

    #endregion
}
