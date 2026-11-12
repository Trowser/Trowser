using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Trowser.Automation;

namespace Trowser.Security.Sse;

/// <summary>
/// For open <c>fetch()</c> event-streams, WebView2 often skips body capture and CDP
/// <c>Network.dataReceived</c> may not fire. CDP <c>Network.getResponseBody</c> can still
/// return bytes received so far while the stream is in flight.
/// </summary>
internal static class SseCdpLiveBodySync
{
    /// <summary>
    /// Chromium only puts payload bytes in <c>Network.dataReceived</c> after
    /// <c>Network.streamResourceContent</c> was called for that request; it also returns what was buffered so far.
    /// </summary>
    public static async Task StartStreamingAsync(BrowserTab tab, CoreWebView2 core, string cdpRequestId)
    {
        try
        {
            var param = JsonSerializer.Serialize(new { requestId = cdpRequestId });
            var raw = await core.CallDevToolsProtocolMethodAsync("Network.streamResourceContent", param)
                .ConfigureAwait(true);
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("bufferedData", out var buffered)
                && buffered.ValueKind == JsonValueKind.String
                && buffered.GetString() is { Length: > 0 } data)
            {
                tab.Sse.OnNetworkDataReceived(cdpRequestId, data, base64: true, tab);
            }
        }
        catch { /* request already finished or streaming unsupported; loadingFinished poll covers it */ }
    }

    public static Task PollRequestAsync(BrowserTab tab, string cdpRequestId)
    {
        var conn = tab.Sse.FindByCdpRequestId(cdpRequestId);
        if (conn == null) return Task.CompletedTask;
        return PollConnectionAsync(tab, conn);
    }

    public static async Task PollOpenStreamsAsync(BrowserTab tab)
    {
        var core = tab.WebView.CoreWebView2;
        if (core == null) return;

        foreach (var conn in tab.Sse.GetConnections(stateFilter: "open"))
        {
            if (string.IsNullOrEmpty(conn.CdpRequestId) || conn.CdpRequestId.StartsWith("net-", StringComparison.Ordinal))
                continue;
            try { await PollConnectionAsync(tab, conn).ConfigureAwait(true); }
            catch { /* best-effort */ }
        }
    }

    private static async Task PollConnectionAsync(BrowserTab tab, SseConnection conn)
    {
        var core = tab.WebView.CoreWebView2;
        if (core == null || string.IsNullOrEmpty(conn.CdpRequestId)) return;

        var text = await ReadResponseBodyTextAsync(core, conn.CdpRequestId).ConfigureAwait(true);
        if (string.IsNullOrEmpty(text)) return;

        if (conn.NetworkEntryId is int nid)
        {
            if (tab.Network.TryGrowResponseBody(nid, text, NetworkCaptureLimits.MaxEventStreamBodyChars))
                tab.Sse.OnNetworkEntryBodyUpdated(tab, nid);
        }
        else
        {
            var newId = EnsureNetworkRow(tab, conn, text);
            tab.Sse.OnNetworkEntryBodyUpdated(tab, newId);
        }
    }

    private static int EnsureNetworkRow(BrowserTab tab, SseConnection conn, string body)
    {
        var id = tab.LogEventStreamNetworkRow(
            conn.Method,
            conn.Url,
            conn.HttpStatus ?? 200,
            "",
            conn.RequestHeaders,
            conn.ResponseHeaders,
            conn.CdpRequestId);
        tab.Network.TryGrowResponseBody(id, body, NetworkCaptureLimits.MaxEventStreamBodyChars);
        tab.Sse.LinkNetworkEntry(conn.CdpRequestId, id);
        return id;
    }

    private static async Task<string?> ReadResponseBodyTextAsync(CoreWebView2 core, string cdpRequestId)
    {
        var param = JsonSerializer.Serialize(new { requestId = cdpRequestId });
        var raw = await core.CallDevToolsProtocolMethodAsync("Network.getResponseBody", param)
            .ConfigureAwait(true);
        using var doc = JsonDocument.Parse(raw);
        var body = doc.RootElement.GetProperty("body").GetString() ?? "";
        if (body.Length == 0) return null;

        var base64 = doc.RootElement.TryGetProperty("base64Encoded", out var b) && b.GetBoolean();
        if (!base64) return body;

        var bytes = Convert.FromBase64String(body);
        var max = NetworkCaptureLimits.MaxEventStreamBodyChars;
        if (bytes.Length <= max)
            return Encoding.UTF8.GetString(bytes);
        return Encoding.UTF8.GetString(bytes, 0, max);
    }
}
