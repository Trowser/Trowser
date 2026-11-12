namespace Trowser.Security.Sse;

public sealed class SseConnection
{
    private static int _nextId;

    public int ConnectionId { get; init; } = Interlocked.Increment(ref _nextId);

    public string CdpRequestId { get; init; } = "";
    public string Url { get; init; } = "";
    public string Method { get; set; } = "GET";
    public string Origin { get; set; } = "";

    /// <summary>open, closed</summary>
    public string State { get; set; } = "open";

    public int? HttpStatus { get; set; }
    public Dictionary<string, string> ResponseHeaders { get; set; } = new();
    public Dictionary<string, string> RequestHeaders { get; set; } = new();

    public string? LastEventIdSent { get; set; }

    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime? ClosedAt { get; set; }

    public int MessagesReceived { get; set; }
    public long BytesReceived { get; set; }

    internal List<SseMessage> Messages { get; } = [];
    internal readonly object MessageLock = new();

    public static int MaxMessagesPerConnection { get; set; } = 5000;

    public int? NetworkEntryId { get; set; }
}

public sealed class SseMessage
{
    private static int _nextMsgId;

    public int MessageId { get; init; } = Interlocked.Increment(ref _nextMsgId);
    public int ConnectionId { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string? EventId { get; init; }
    public string EventName { get; init; } = "message";
    public string Data { get; init; } = "";
}

public sealed class SseAuditFinding
{
    public string Check { get; init; } = "";
    public string Severity { get; init; } = "info";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";
    public string? Evidence { get; init; }
    public string? Remediation { get; init; }
    public int? ConnectionId { get; init; }
    public string? Url { get; init; }
}

public sealed class SseAuditResult
{
    public int ElapsedMs { get; init; }
    public string AuditVerdict { get; init; } = "no_traffic";
    public List<SseAuditFinding> Findings { get; init; } = [];
    public List<SseSkippedCheck> SkippedChecks { get; init; } = [];
    public SseAuditCoverage Coverage { get; init; } = new();
    public List<SseConnectionAuditSummary> Connections { get; init; } = [];
}

public sealed class SseAuditCoverage
{
    public int ConnectionsCaptured { get; init; }
    public int MessagesCaptured { get; init; }
    public int EventStreamNetworkRows { get; init; }
    public long WireBytesCaptured { get; init; }
    public bool AnyStreamPossiblyOpen { get; init; }
    public bool AnyBodyTruncated { get; init; }
    public List<string> CaptureModes { get; init; } = [];
    public string? Note { get; init; }
}

public sealed class SseConnectionAuditSummary
{
    public int ConnectionId { get; init; }
    public int? NetworkEntryId { get; init; }
    public string Url { get; init; } = "";
    public string State { get; init; } = "";
    public int MessageCount { get; init; }
    public long WireBytes { get; init; }
    public string CaptureMode { get; init; } = "";
}
