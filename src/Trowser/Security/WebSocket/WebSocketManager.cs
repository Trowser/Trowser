using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Per-tab WebSocket connection tracker. Captures connections and frames from
/// CDP Network.webSocket* events and provides query/interaction capabilities.
/// </summary>
public class WebSocketManager
{
    private readonly object _lock = new();
    private readonly List<WebSocketConnection> _connections = [];

    /// <summary>Maps CDP requestId to our ConnectionId for event correlation.</summary>
    private readonly Dictionary<string, int> _cdpToConnection = new();

    private int _nextFrameId;

    public const int MaxConnections = 100;

    /// <summary>Fired when a new connection is created.</summary>
    public event Action<WebSocketConnection>? ConnectionCreated;

    /// <summary>Fired when a new frame is logged.</summary>
    public event Action<WebSocketFrame>? FrameLogged;

    // ── CDP Event Handlers ──

    /// <summary>
    /// Handle CDP Network.webSocketCreated event.
    /// </summary>
    public void OnWebSocketCreated(string cdpRequestId, string url, string? initiatorUrl)
    {
        var conn = new WebSocketConnection
        {
            CdpRequestId = cdpRequestId,
            Url = url,
            Origin = initiatorUrl ?? ""
        };

        lock (_lock)
        {
            // Evict oldest closed connection if at capacity
            if (_connections.Count >= MaxConnections)
            {
                var closed = _connections.FindIndex(c => c.State == "closed");
                if (closed >= 0)
                {
                    var evicted = _connections[closed];
                    _cdpToConnection.Remove(evicted.CdpRequestId);
                    _connections.RemoveAt(closed);
                }
                else if (_connections.Count >= MaxConnections)
                {
                    var evicted = _connections[0];
                    _cdpToConnection.Remove(evicted.CdpRequestId);
                    _connections.RemoveAt(0);
                }
            }

            _connections.Add(conn);
            _cdpToConnection[cdpRequestId] = conn.ConnectionId;
        }

        ConnectionCreated?.Invoke(conn);
    }

    /// <summary>
    /// Handle CDP Network.webSocketHandshakeResponseReceived event.
    /// </summary>
    public void OnHandshakeResponse(string cdpRequestId, int status, Dictionary<string, string> headers)
    {
        lock (_lock)
        {
            var conn = FindByCdpId(cdpRequestId);
            if (conn == null) return;
            conn.HandshakeStatus = status;
            conn.ResponseHeaders = headers;
            conn.State = status == 101 ? "open" : "closed";
        }
    }

    /// <summary>
    /// Handle CDP Network.webSocketFrameSent event.
    /// </summary>
    public void OnFrameSent(string cdpRequestId, string data, int opcode)
    {
        AddFrame(cdpRequestId, "sent", data, opcode);
    }

    /// <summary>
    /// Handle CDP Network.webSocketFrameReceived event.
    /// </summary>
    public void OnFrameReceived(string cdpRequestId, string data, int opcode)
    {
        AddFrame(cdpRequestId, "received", data, opcode);
    }

    /// <summary>
    /// Handle CDP Network.webSocketClosed event.
    /// </summary>
    public void OnWebSocketClosed(string cdpRequestId)
    {
        lock (_lock)
        {
            var conn = FindByCdpId(cdpRequestId);
            if (conn == null) return;
            conn.State = "closed";
            conn.ClosedAt = DateTime.UtcNow;
        }
    }

    // ── Query Methods ──

    /// <summary>Get all connections, optionally filtered.</summary>
    public List<WebSocketConnection> GetConnections(string? stateFilter = null, string? urlFilter = null)
    {
        lock (_lock)
        {
            IEnumerable<WebSocketConnection> q = _connections;
            if (stateFilter != null && stateFilter != "all")
                q = q.Where(c => c.State.Equals(stateFilter, StringComparison.OrdinalIgnoreCase));
            if (urlFilter != null)
                q = q.Where(c => c.Url.Contains(urlFilter, StringComparison.OrdinalIgnoreCase));
            return q.ToList();
        }
    }

    /// <summary>Get a connection by ID.</summary>
    public WebSocketConnection? GetConnection(int connectionId)
    {
        lock (_lock)
            return _connections.FirstOrDefault(c => c.ConnectionId == connectionId);
    }

    /// <summary>Get frames for a connection with optional filtering.</summary>
    public List<WebSocketFrame> GetFrames(
        int connectionId,
        string? directionFilter = null,
        int? sinceFrameId = null,
        int? last = null,
        string? searchText = null,
        string? jsonTypeFilter = null)
    {
        var conn = GetConnection(connectionId);
        if (conn == null) return [];

        lock (conn.FrameLock)
        {
            IEnumerable<WebSocketFrame> q = conn.Frames;

            if (directionFilter != null)
                q = q.Where(f => f.Direction.Equals(directionFilter, StringComparison.OrdinalIgnoreCase));
            if (sinceFrameId.HasValue)
                q = q.Where(f => f.FrameId > sinceFrameId.Value);
            if (searchText != null)
                q = q.Where(f => f.Data.Contains(searchText, StringComparison.OrdinalIgnoreCase));
            if (jsonTypeFilter != null)
                q = q.Where(f => f.JsonType != null &&
                    f.JsonType.Equals(jsonTypeFilter, StringComparison.OrdinalIgnoreCase));

            var list = q.ToList();
            if (last.HasValue && list.Count > last.Value)
                list = list.Skip(list.Count - last.Value).ToList();

            return list;
        }
    }

    /// <summary>Get total frame count across all connections.</summary>
    public int TotalFrameCount
    {
        get
        {
            lock (_lock)
                return _connections.Sum(c => { lock (c.FrameLock) return c.Frames.Count; });
        }
    }

    /// <summary>Clear all connections and frames.</summary>
    public void Clear()
    {
        lock (_lock)
        {
            _connections.Clear();
            _cdpToConnection.Clear();
        }
    }

    // ── Internals ──

    private void AddFrame(string cdpRequestId, string direction, string data, int opcode)
    {
        WebSocketConnection? conn;
        WebSocketFrame frame;

        lock (_lock)
        {
            conn = FindByCdpId(cdpRequestId);
            if (conn == null) return;
        }

        var isText = opcode == 1;
        var (isJson, jsonType) = isText ? DetectJsonType(data) : (false, null);
        var frameId = Interlocked.Increment(ref _nextFrameId);

        frame = new WebSocketFrame
        {
            FrameId = frameId,
            ConnectionId = conn.ConnectionId,
            Direction = direction,
            DataType = isText ? "text" : "binary",
            Data = data,
            DataLength = data.Length,
            IsJson = isJson,
            JsonType = jsonType
        };

        lock (conn.FrameLock)
        {
            // Ring buffer: evict oldest if at capacity
            if (conn.Frames.Count >= WebSocketConnection.MaxFramesPerConnection)
                conn.Frames.RemoveAt(0);

            conn.Frames.Add(frame);
        }

        // Update stats
        // Stats updates (lock-free; minor races acceptable for counters)
        if (direction == "sent")
        {
            conn.FramesSent++;
            conn.BytesSent += data.Length;
        }
        else
        {
            conn.FramesReceived++;
            conn.BytesReceived += data.Length;
        }

        FrameLogged?.Invoke(frame);
    }

    private WebSocketConnection? FindByCdpId(string cdpRequestId)
    {
        if (!_cdpToConnection.TryGetValue(cdpRequestId, out var connId))
            return null;
        return _connections.FirstOrDefault(c => c.ConnectionId == connId);
    }

    /// <summary>
    /// Detect if data is JSON and extract the "type" or "action" field value.
    /// </summary>
    private static (bool IsJson, string? JsonType) DetectJsonType(string data)
    {
        if (string.IsNullOrWhiteSpace(data) || (data[0] != '{' && data[0] != '['))
            return (false, null);

        try
        {
            using var doc = JsonDocument.Parse(data);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return (true, null);

            // Try common message type fields
            foreach (var fieldName in new[] { "type", "action", "event", "method", "op", "cmd" })
            {
                if (doc.RootElement.TryGetProperty(fieldName, out var prop) &&
                    prop.ValueKind == JsonValueKind.String)
                {
                    return (true, prop.GetString());
                }
            }

            return (true, null);
        }
        catch
        {
            return (false, null);
        }
    }
}
