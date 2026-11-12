namespace Trowser.Security.WebSocket;

/// <summary>
/// A tracked WebSocket connection observed via CDP Network domain events.
/// </summary>
public sealed class WebSocketConnection
{
    private static int _nextId;

    public int ConnectionId { get; init; } = Interlocked.Increment(ref _nextId);

    /// <summary>CDP request ID for the WebSocket upgrade request.</summary>
    public string CdpRequestId { get; init; } = "";

    /// <summary>The ws:// or wss:// URL.</summary>
    public string Url { get; init; } = "";

    /// <summary>Sec-WebSocket-Protocol value from handshake, if any.</summary>
    public string? Protocol { get; init; }

    /// <summary>Origin of the page that created this connection.</summary>
    public string Origin { get; set; } = "";

    /// <summary>Connection state: "connecting", "open", "closing", "closed".</summary>
    public string State { get; set; } = "connecting";

    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime? ClosedAt { get; set; }
    public int? CloseCode { get; set; }
    public string? CloseReason { get; set; }

    /// <summary>HTTP upgrade request headers.</summary>
    public Dictionary<string, string> RequestHeaders { get; set; } = new();

    /// <summary>HTTP upgrade response headers.</summary>
    public Dictionary<string, string> ResponseHeaders { get; set; } = new();

    /// <summary>HTTP status of the handshake (should be 101).</summary>
    public int HandshakeStatus { get; set; }

    // Stats
    public int FramesSent { get; set; }
    public int FramesReceived { get; set; }
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }

    /// <summary>Frame log ring buffer.</summary>
    internal List<WebSocketFrame> Frames { get; } = [];
    internal readonly object FrameLock = new();

    /// <summary>Max frames to keep per connection.</summary>
    public static int MaxFramesPerConnection { get; set; } = 5000;
}

/// <summary>
/// A single WebSocket frame (sent or received).
/// </summary>
public sealed class WebSocketFrame
{
    public int FrameId { get; init; }
    public int ConnectionId { get; init; }

    /// <summary>"sent" or "received".</summary>
    public string Direction { get; init; } = "";

    public DateTime Timestamp { get; init; } = DateTime.UtcNow;

    /// <summary>"text" or "binary".</summary>
    public string DataType { get; init; } = "text";

    /// <summary>Frame payload (text content or base64-encoded binary).</summary>
    public string Data { get; init; } = "";

    /// <summary>Raw byte length of the payload.</summary>
    public int DataLength { get; init; }

    /// <summary>Quick check: is the payload valid JSON?</summary>
    public bool IsJson { get; init; }

    /// <summary>If JSON, the detected message type field value (from "type" or "action" fields).</summary>
    public string? JsonType { get; init; }
}

/// <summary>
/// Intercept rule for WebSocket frames — applied via the JS interception hook.
/// </summary>
public sealed class WebSocketInterceptRule
{
    private static int _nextId;

    public int RuleId { get; init; } = Interlocked.Increment(ref _nextId);

    /// <summary>Match connection URL (substring or glob).</summary>
    public string? UrlPattern { get; init; }

    /// <summary>Filter by direction: "sent", "received", or null (both).</summary>
    public string? Direction { get; init; }

    /// <summary>Regex match on frame data content.</summary>
    public string? ContentPattern { get; init; }

    /// <summary>Action: "log" (default), "drop", "modify", "hold".</summary>
    public string Action { get; init; } = "log";

    /// <summary>JS function for "modify" action: (data) => newData.</summary>
    public string? ModifyScript { get; init; }

    public bool Enabled { get; set; } = true;
}

/// <summary>
/// A WebSocket frame that has been held by an intercept rule, pending user/API decision.
/// </summary>
public sealed class HeldFrame
{
    public int HeldId { get; init; }
    public int ConnectionId { get; init; }
    public string Direction { get; init; } = "";
    public string Data { get; init; } = "";
    public DateTime HeldAt { get; init; } = DateTime.UtcNow;
    public int RuleId { get; init; }
}

/// <summary>
/// Finding from WebSocket security audit.
/// </summary>
public sealed class WebSocketAuditFinding
{
    public string Check { get; init; } = "";
    public string Severity { get; init; } = "info";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string? Evidence { get; init; }
    public string? Remediation { get; init; }
}

/// <summary>
/// WebSocket audit finding deduplicated across connections (e.g. many Socket.IO sessions to the same endpoint).
/// </summary>
public sealed class AggregatedWebSocketAuditFinding
{
    public string Check { get; init; } = "";
    public string Severity { get; init; } = "info";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string? Evidence { get; init; }
    public string? Remediation { get; init; }
    public int Occurrences { get; init; } = 1;
    public string NormalizedUrl { get; init; } = "";
    public List<string> SeenConnectionUrls { get; init; } = [];
    public List<int> ConnectionIds { get; init; } = [];
}
