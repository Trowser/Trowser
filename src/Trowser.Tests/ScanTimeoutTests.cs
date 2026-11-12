using Trowser.Security;
using Trowser.Security.Orchestration;
using Xunit;

namespace Trowser.Tests;

public class ScanTimeoutTests
{
    [Fact]
    public void cancel_after_int_max_seconds_throws_delay_out_of_range()
    {
        using var cts = new CancellationTokenSource();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => cts.CancelAfter(TimeSpan.FromSeconds(int.MaxValue)));
        Assert.Equal("delay", ex.ParamName);
    }

    [Fact]
    public void cancel_after_seconds_accepts_int_max_value()
    {
        using var cts = new CancellationTokenSource();
        ScanTimeout.CancelAfterSeconds(cts, int.MaxValue);
        Assert.False(cts.IsCancellationRequested);
    }

    [Fact]
    public void budget_tracker_clamps_unlimited_endpoint_probe_budget()
    {
        var budget = new BudgetTracker(maxRequests: int.MaxValue, maxSeconds: int.MaxValue);
        Assert.Equal(ScanTimeout.MaxSafeBudgetSeconds, budget.MaxSeconds);
        Assert.True(budget.RemainingSeconds > 0);
        var timeoutMs = Math.Min(budget.RemainingSeconds * 1000, 60_000);
        Assert.Equal(60_000, timeoutMs);
    }

    [Fact]
    public void a05_injection_scan_timeout_from_unlimited_budget_is_cancel_after_safe()
    {
        var budget = new BudgetTracker(maxRequests: int.MaxValue, maxSeconds: int.MaxValue);
        var reservedSeconds = Math.Clamp(budget.RemainingSeconds / 4, 15, 120);
        var maxStepSeconds = Math.Max(20, budget.RemainingSeconds - reservedSeconds);

        using var cts = new CancellationTokenSource();
        ScanTimeout.CancelAfterSeconds(cts, Math.Max(5, maxStepSeconds));
        Assert.False(cts.IsCancellationRequested);

        var timeoutMs = Math.Min(maxStepSeconds * 1000, 60_000);
        Assert.Equal(60_000, timeoutMs);
    }
}
