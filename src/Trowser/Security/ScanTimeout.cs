namespace Trowser.Security;

/// <summary>
/// Wall-clock caps that stay valid for <see cref="CancellationTokenSource.CancelAfter(TimeSpan)"/>
/// and for <c>seconds * 1000</c> millisecond conversions.
/// </summary>
public static class ScanTimeout
{
    /// <summary>
    /// <see cref="CancellationTokenSource.CancelAfter(TimeSpan)"/> throws
    /// <see cref="ArgumentOutOfRangeException"/> (parameter <c>delay</c>) when
    /// <c>TotalMilliseconds</c> is greater than <see cref="uint.MaxValue"/> (~49.7 days)
    /// or less than -1. <see cref="int.MaxValue"/> seconds overflows that range.
    /// </summary>
    public const int MaxCancelAfterSeconds = (int)(uint.MaxValue / 1000);

    /// <summary>
    /// Largest seconds value that can be multiplied by 1000 without overflowing <see cref="int"/>.
    /// Endpoint Probe historically passed <see cref="int.MaxValue"/> as an "unlimited" playbook
    /// budget, which made A05 <c>injection-scan</c> fail inside AutoScanPipeline.CancelAfter.
    /// ~24.8 days is unlimited for interactive use.
    /// </summary>
    public const int MaxSafeBudgetSeconds = int.MaxValue / 1000;

    public static int ClampBudgetSeconds(int seconds) =>
        seconds <= 0 ? seconds : Math.Min(seconds, MaxSafeBudgetSeconds);

    /// <summary>
    /// Schedule cancellation without throwing when <paramref name="seconds"/> is huge
    /// (e.g. Endpoint Probe's former <see cref="int.MaxValue"/> budget).
    /// </summary>
    public static void CancelAfterSeconds(CancellationTokenSource cts, int seconds)
    {
        if (seconds <= 0)
            return;
        var clamped = Math.Min(seconds, MaxCancelAfterSeconds);
        cts.CancelAfter(TimeSpan.FromSeconds(clamped));
    }
}
