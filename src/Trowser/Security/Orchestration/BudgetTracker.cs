using System.Diagnostics;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Tracks request count and wall-clock time against a caller-specified budget.
/// Thread-safe — shared across playbook steps.
/// </summary>
public sealed class BudgetTracker
{
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private int _requestCount;
    private int _maxRequests;
    private int _maxSeconds;
    private int _extensionCount;

    public int OriginalMaxRequests { get; }
    public int OriginalMaxSeconds { get; }
    public bool Adaptive { get; }

    public int MaxRequests => _maxRequests;
    public int MaxSeconds => _maxSeconds;
    public int ExtensionCount => _extensionCount;
    public List<string> ExtensionReasons { get; } = [];

    public BudgetTracker(int maxRequests = 800, int maxSeconds = 120, bool adaptive = false)
    {
        OriginalMaxRequests = maxRequests > 0 ? maxRequests : 800;
        OriginalMaxSeconds = maxSeconds > 0 ? ScanTimeout.ClampBudgetSeconds(maxSeconds) : 120;
        _maxRequests = OriginalMaxRequests;
        _maxSeconds = OriginalMaxSeconds;
        Adaptive = adaptive;
    }

    public int RequestCount => _requestCount;
    public int ElapsedSeconds => (int)_stopwatch.Elapsed.TotalSeconds;
    public int ElapsedMs => (int)_stopwatch.Elapsed.TotalMilliseconds;
    public bool IsExhausted => _requestCount >= _maxRequests || _stopwatch.Elapsed.TotalSeconds >= _maxSeconds;

    /// <summary>Remaining requests before budget is hit.</summary>
    public int RemainingRequests => Math.Max(0, _maxRequests - _requestCount);

    /// <summary>Remaining seconds before time budget is hit.</summary>
    public int RemainingSeconds => Math.Max(0, _maxSeconds - ElapsedSeconds);

    public void AddRequests(int count) => Interlocked.Add(ref _requestCount, count);

    /// <summary>
    /// When <see cref="Adaptive"/> is enabled, extend caps by 25% of original (max 3 times)
    /// if the current step is making measurable progress.
    /// </summary>
    public bool TryExtendForProgress(string reason, int progressSignal = 0)
    {
        if (!Adaptive || _extensionCount >= 3)
            return false;

        if (progressSignal <= 0 && RequestCount < 3)
            return false;

        _extensionCount++;
        _maxSeconds = Math.Min(
            ScanTimeout.MaxSafeBudgetSeconds,
            _maxSeconds + Math.Max(15, OriginalMaxSeconds / 4));
        _maxRequests += Math.Max(50, OriginalMaxRequests / 4);
        ExtensionReasons.Add(reason);
        return true;
    }

    /// <summary>
    /// Checks whether the budget allows at least one more request.
    /// If exhausted, throws <see cref="BudgetExhaustedException"/>.
    /// </summary>
    public void ThrowIfExhausted(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (IsExhausted)
            throw new BudgetExhaustedException(RequestCount, _maxRequests, ElapsedSeconds, _maxSeconds);
    }

    public Dictionary<string, object?> ToSummary()
    {
        var summary = new Dictionary<string, object?>
        {
            ["requests"] = _requestCount,
            ["seconds"] = ElapsedSeconds,
            ["maxRequests"] = _maxRequests,
            ["maxSeconds"] = _maxSeconds
        };

        if (_extensionCount > 0)
        {
            summary["extensions"] = _extensionCount;
            summary["extensionReasons"] = ExtensionReasons;
        }

        return summary;
    }
}

public sealed class BudgetExhaustedException : OperationCanceledException
{
    public int Requests { get; }
    public int MaxRequests { get; }
    public int Seconds { get; }
    public int MaxSeconds { get; }

    public BudgetExhaustedException(int requests, int maxRequests, int seconds, int maxSeconds)
        : base($"Budget exhausted: {requests}/{maxRequests} requests, {seconds}/{maxSeconds}s")
    {
        Requests = requests;
        MaxRequests = maxRequests;
        Seconds = seconds;
        MaxSeconds = maxSeconds;
    }
}
