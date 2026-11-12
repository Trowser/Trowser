namespace Trowser.Security.Sse;

public enum SseAuditVerdict
{
    Complete,
    Incomplete,
    NoTraffic
}

public sealed class SseSkippedCheck
{
    public string Check { get; init; } = "";
    public string Reason { get; init; } = "";
}
