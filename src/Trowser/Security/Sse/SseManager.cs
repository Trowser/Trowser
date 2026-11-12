using System.Text;
using Trowser.Automation;

namespace Trowser.Security.Sse;

/// <summary>Per-tab SSE tracker: EventSource CDP messages + incremental <c>Network.dataReceived</c> chunks.</summary>
public class SseManager
{
    private readonly object _lock = new();
    private readonly List<SseConnection> _connections = [];
    private readonly Dictionary<string, int> _cdpToConnection = new();

    private sealed class StreamWire
    {
        public SseParseState Parser { get; } = new();
        public bool SawEventSourceCdp;
        public bool SawNetworkChunks;
        public bool SawNetworkBodyFallback;
        public int NetworkBodySyncedChars;
    }

    private readonly Dictionary<string, StreamWire> _wireByRequest = new();

    public const int MaxConnections = 100;
    public const int MaxWireCharsPerStream = NetworkCaptureLimits.MaxEventStreamBodyChars;

    public event Action<SseConnection>? ConnectionCreated;
    public event Action<SseMessage>? MessageLogged;

    public void EnsureConnection(
        string cdpRequestId,
        string url,
        string method,
        string? origin,
        int? httpStatus,
        Dictionary<string, string>? responseHeaders,
        Dictionary<string, string>? requestHeaders)
    {
        lock (_lock)
        {
            if (_cdpToConnection.TryGetValue(cdpRequestId, out var existingId))
            {
                var existing = _connections.FirstOrDefault(c => c.ConnectionId == existingId);
                if (existing != null)
                {
                    if (httpStatus.HasValue) existing.HttpStatus = httpStatus;
                    if (responseHeaders != null && responseHeaders.Count > 0)
                        existing.ResponseHeaders = new Dictionary<string, string>(responseHeaders, StringComparer.OrdinalIgnoreCase);
                    if (requestHeaders != null && requestHeaders.Count > 0)
                        MergeHeaders(existing.RequestHeaders, requestHeaders);
                }

                return;
            }

            if (_connections.Count >= MaxConnections)
                EvictOne();

            var conn = new SseConnection
            {
                CdpRequestId = cdpRequestId,
                Url = url,
                Method = method,
                Origin = origin ?? "",
                HttpStatus = httpStatus,
                ResponseHeaders = responseHeaders != null
                    ? new Dictionary<string, string>(responseHeaders, StringComparer.OrdinalIgnoreCase)
                    : new(),
                RequestHeaders = requestHeaders != null
                    ? new Dictionary<string, string>(requestHeaders, StringComparer.OrdinalIgnoreCase)
                    : new()
            };

            _connections.Add(conn);
            _cdpToConnection[cdpRequestId] = conn.ConnectionId;
            _wireByRequest[cdpRequestId] = new StreamWire();
            ConnectionCreated?.Invoke(conn);
        }
    }

    public void OnMessageReceived(string cdpRequestId, string? eventName, string? eventId, string data)
    {
        SseConnection? conn;
        lock (_lock)
        {
            conn = FindByCdpId(cdpRequestId);
            if (conn == null) return;
            if (_wireByRequest.TryGetValue(cdpRequestId, out var wire))
                wire.SawEventSourceCdp = true;
        }

        IngestParsedEvent(conn!, eventName, eventId, data, source: "event-source-cdp");
    }

    /// <summary>Append base64 or plain chunk from <c>Network.dataReceived</c>.</summary>
    public int OnNetworkDataReceived(string cdpRequestId, string encodedData, bool base64, BrowserTab tab)
    {
        if (!TryEnsureConnectionForCdpChunk(tab, cdpRequestId))
            return 0;

        SseConnection? conn;
        StreamWire wire;
        lock (_lock)
        {
            conn = FindByCdpId(cdpRequestId);
            if (conn == null) return 0;
            if (!_wireByRequest.TryGetValue(cdpRequestId, out wire!))
            {
                wire = new StreamWire();
                _wireByRequest[cdpRequestId] = wire;
            }

            wire.SawNetworkChunks = true;
        }

        string text;
        try
        {
            text = base64
                ? Encoding.UTF8.GetString(Convert.FromBase64String(encodedData))
                : encodedData;
        }
        catch
        {
            text = encodedData;
        }

        if (string.IsNullOrEmpty(text)) return 0;

        List<SseParsedEvent> parsed;
        lock (_lock)
            parsed = SseIncrementalParser.Append(wire.Parser, text);

        if (conn.NetworkEntryId is int nid)
        {
            // Appending raises EntryBodyUpdated; mark the chunk synced first so it is not parsed twice.
            var before = tab.Network.TryGetEntry(nid, out var prior) ? prior?.ResponseBody?.Length ?? 0 : 0;
            lock (_lock)
                wire.NetworkBodySyncedChars = Math.Min(before + text.Length, MaxWireCharsPerStream);
            tab.Network.TryAppendResponseBody(nid, text, MaxWireCharsPerStream);
            if (tab.Network.TryGetEntry(nid, out var entry) && entry?.ResponseBody != null)
            {
                lock (_lock)
                {
                    if (_wireByRequest.TryGetValue(conn.CdpRequestId, out var w))
                        w.NetworkBodySyncedChars = entry.ResponseBody.Length;
                }
            }
        }

        var added = 0;
        foreach (var ev in parsed)
        {
            IngestParsedEvent(conn, ev.EventName, ev.EventId, ev.Data, source: "network-chunk");
            added++;
        }

        return added;
    }

    /// <summary>When the network log captured event-stream bytes, parse any new suffix into SSE messages.</summary>
    public void OnNetworkEntryBodyUpdated(BrowserTab tab, int networkEntryId)
    {
        if (!tab.Network.TryGetEntry(networkEntryId, out var entry) || entry == null || !entry.IsEventStream)
            return;

        var cdpId = FindCdpIdForNetworkEntry(networkEntryId);
        if (cdpId == null)
        {
            cdpId = $"net-{networkEntryId}";
            EnsureConnection(
                cdpId,
                entry.Url,
                entry.Method,
                null,
                entry.StatusCode,
                entry.ResponseHeaders,
                entry.RequestHeaders);
            LinkNetworkEntry(cdpId, networkEntryId);
        }

        var conn = FindByCdpId(cdpId);
        if (conn == null) return;
        SyncFromLinkedNetworkBody(tab, conn);
    }

    private void SyncFromLinkedNetworkBody(BrowserTab tab, SseConnection conn)
    {
        if (conn.NetworkEntryId is not int nid)
            return;
        if (!tab.Network.TryGetEntry(nid, out var entry) || entry == null)
            return;
        var body = entry.ResponseBody;
        if (string.IsNullOrEmpty(body)) return;

        StreamWire wire;
        lock (_lock)
        {
            if (!_wireByRequest.TryGetValue(conn.CdpRequestId, out wire!))
            {
                wire = new StreamWire();
                _wireByRequest[conn.CdpRequestId] = wire;
            }
        }

        var start = wire.NetworkBodySyncedChars;
        if (body.Length <= start) return;

        var delta = body[start..];
        wire.NetworkBodySyncedChars = body.Length;
        wire.SawNetworkBodyFallback = true;

        List<SseParsedEvent> parsed;
        lock (_lock)
            parsed = SseIncrementalParser.Append(wire.Parser, delta);

        foreach (var ev in parsed)
            IngestParsedEvent(conn, ev.EventName, ev.EventId, ev.Data, source: "network-body");
    }

    private bool TryEnsureConnectionForCdpChunk(BrowserTab tab, string cdpRequestId)
    {
        lock (_lock)
        {
            if (FindByCdpId(cdpRequestId) != null)
                return true;
        }

        if (!tab.TryResolveCdpRequest(cdpRequestId, out var method, out var url))
            return false;

        if (!tab.CdpBackfill.TryGetPendingForSse(cdpRequestId, out var pm, out var pu, out var st, out var rh, out var rq))
            return false;

        if (!CdpNetworkBackfillTracker.HeadersIndicateEventStream(rh))
            return false;

        EnsureConnection(cdpRequestId, pu, pm, null, st, rh, rq);
        return FindByCdpId(cdpRequestId) != null;
    }

    private string? FindCdpIdForNetworkEntry(int networkEntryId)
    {
        lock (_lock)
        {
            foreach (var c in _connections)
            {
                if (c.NetworkEntryId == networkEntryId)
                    return c.CdpRequestId;
            }
        }

        return null;
    }

    public void OnStreamFinished(string cdpRequestId, BrowserTab? tab = null)
    {
        SseConnection? conn;
        StreamWire? wire;
        lock (_lock)
        {
            conn = FindByCdpId(cdpRequestId);
            if (conn == null) return;
            if (_wireByRequest.TryGetValue(cdpRequestId, out wire))
            {
                var tail = SseIncrementalParser.Flush(wire.Parser);
                foreach (var ev in tail)
                    IngestParsedEvent(conn, ev.EventName, ev.EventId, ev.Data, source: "network-chunk");
            }

            conn.State = "closed";
            conn.ClosedAt = DateTime.UtcNow;
        }
    }

    public void NoteLastEventIdHeader(string cdpRequestId, string? lastEventId)
    {
        if (string.IsNullOrEmpty(lastEventId)) return;
        lock (_lock)
        {
            var conn = FindByCdpId(cdpRequestId);
            if (conn != null)
                conn.LastEventIdSent = lastEventId;
        }
    }

    public void LinkNetworkEntry(string cdpRequestId, int networkEntryId)
    {
        lock (_lock)
        {
            var conn = FindByCdpId(cdpRequestId);
            if (conn != null)
                conn.NetworkEntryId = networkEntryId;
        }
    }

    public long GetWireBytes(string cdpRequestId)
    {
        lock (_lock)
        {
            return _wireByRequest.TryGetValue(cdpRequestId, out var w) ? w.Parser.WireBytes : 0;
        }
    }

    public string DescribeCaptureMode(string cdpRequestId)
    {
        lock (_lock)
        {
            if (!_wireByRequest.TryGetValue(cdpRequestId, out var w))
                return "headers-only";
            if (w.SawEventSourceCdp && w.SawNetworkChunks) return "event-source-cdp+network-chunks";
            if (w.SawEventSourceCdp && w.SawNetworkBodyFallback) return "event-source-cdp+network-body";
            if (w.SawNetworkChunks && w.SawNetworkBodyFallback) return "network-chunks+network-body";
            if (w.SawEventSourceCdp) return "event-source-cdp";
            if (w.SawNetworkChunks) return "network-chunks";
            if (w.SawNetworkBodyFallback) return "network-body";
            return "headers-only";
        }
    }

    public List<SseConnection> GetConnections(string? stateFilter = null, string? urlFilter = null)
    {
        lock (_lock)
        {
            IEnumerable<SseConnection> q = _connections;
            if (stateFilter != null && !stateFilter.Equals("all", StringComparison.OrdinalIgnoreCase))
                q = q.Where(c => c.State.Equals(stateFilter, StringComparison.OrdinalIgnoreCase));
            if (urlFilter != null)
                q = q.Where(c => c.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase));
            return q.ToList();
        }
    }

    public SseConnection? GetConnection(int connectionId)
    {
        lock (_lock)
            return _connections.FirstOrDefault(c => c.ConnectionId == connectionId);
    }

    public SseConnection? FindByCdpRequestId(string cdpRequestId)
    {
        lock (_lock)
            return FindByCdpId(cdpRequestId);
    }

    public List<SseMessage> GetMessages(
        int connectionId,
        string? eventNameFilter = null,
        int? last = null,
        string? searchText = null)
    {
        var conn = GetConnection(connectionId);
        if (conn == null) return [];

        lock (conn.MessageLock)
        {
            IEnumerable<SseMessage> q = conn.Messages;
            if (eventNameFilter != null)
                q = q.Where(m => m.EventName.Equals(eventNameFilter, StringComparison.OrdinalIgnoreCase));
            if (searchText != null)
                q = q.Where(m => m.Data.Contains(searchText, StringComparison.OrdinalIgnoreCase));
            var list = q.ToList();
            if (last is > 0 && list.Count > last.Value)
                list = list.Skip(list.Count - last.Value).ToList();
            return list;
        }
    }

    public int TotalMessageCount
    {
        get
        {
            lock (_lock)
                return _connections.Sum(c => { lock (c.MessageLock) return c.Messages.Count; });
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _connections.Clear();
            _cdpToConnection.Clear();
            _wireByRequest.Clear();
        }
    }

    private void IngestParsedEvent(SseConnection conn, string? eventName, string? eventId, string data, string source)
    {
        var msg = new SseMessage
        {
            ConnectionId = conn.ConnectionId,
            EventName = string.IsNullOrEmpty(eventName) ? "message" : eventName,
            EventId = eventId,
            Data = data
        };

        lock (conn.MessageLock)
        {
            var last = conn.Messages.Count > 0 ? conn.Messages[^1] : null;
            if (last != null
                && string.Equals(last.EventId, msg.EventId, StringComparison.Ordinal)
                && string.Equals(last.Data, msg.Data, StringComparison.Ordinal)
                && string.Equals(last.EventName, msg.EventName, StringComparison.Ordinal))
                return;

            if (conn.Messages.Count >= SseConnection.MaxMessagesPerConnection)
                conn.Messages.RemoveAt(0);
            conn.Messages.Add(msg);
        }

        conn.MessagesReceived++;
        conn.BytesReceived += data.Length;
        MessageLogged?.Invoke(msg);
    }

    private void EvictOne()
    {
        var closed = _connections.FindIndex(c => c.State == "closed");
        if (closed >= 0)
        {
            var evicted = _connections[closed];
            _cdpToConnection.Remove(evicted.CdpRequestId);
            _wireByRequest.Remove(evicted.CdpRequestId);
            _connections.RemoveAt(closed);
            return;
        }

        if (_connections.Count > 0)
        {
            var evicted = _connections[0];
            _cdpToConnection.Remove(evicted.CdpRequestId);
            _wireByRequest.Remove(evicted.CdpRequestId);
            _connections.RemoveAt(0);
        }
    }

    private SseConnection? FindByCdpId(string cdpRequestId)
    {
        if (!_cdpToConnection.TryGetValue(cdpRequestId, out var connId))
            return null;
        return _connections.FirstOrDefault(c => c.ConnectionId == connId);
    }

    private static void MergeHeaders(Dictionary<string, string> into, IReadOnlyDictionary<string, string> from)
    {
        foreach (var kv in from)
        {
            if (NetworkCaptureLimits.ShouldMergeCapturedRequestHeader(kv.Key))
                into[kv.Key] = kv.Value;
        }
    }
}
