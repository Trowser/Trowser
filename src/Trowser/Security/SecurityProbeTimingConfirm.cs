namespace Trowser.Security;

/// <summary>
/// Replays control and attack requests once after an initial timing hit to reduce one-off latency false positives.
/// </summary>
public static class SecurityProbeTimingConfirm
{
    /// <summary>
    /// After the caller detects an initial timing hit, re-fetch control and attack and require the same threshold on the replay.
    /// </summary>
    public static async Task<bool> ConfirmDeltaAsync(
        Func<CancellationToken, Task<double>> fetchControlSeconds,
        Func<CancellationToken, Task<double>> fetchAttackSeconds,
        Func<double, double, bool> meetsThreshold,
        CancellationToken ct = default)
    {
        var control = await fetchControlSeconds(ct);
        var attack = await fetchAttackSeconds(ct);
        return meetsThreshold(control, attack);
    }
}
