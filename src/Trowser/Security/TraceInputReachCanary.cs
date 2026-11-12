namespace Trowser.Security;

/// <summary>Phase-1 reach probes use a distinct canary prefix (not an exploit payload).</summary>
internal static class TraceInputReachCanary
{
    public const string Prefix = "trwR_";

    public static bool IsReachCanary(string? payload) =>
        !string.IsNullOrEmpty(payload)
        && payload.StartsWith(Prefix, StringComparison.Ordinal);
}
