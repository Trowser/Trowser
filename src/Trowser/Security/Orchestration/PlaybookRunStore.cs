using System.Collections.Concurrent;

namespace Trowser.Security.Orchestration;

/// <summary>In-memory async playbook runs for GET /api/orchestrate/runs/{runId} polling.</summary>
public sealed class PlaybookRunStore
{
    public const int MaxRuns = 32;

    private readonly ConcurrentDictionary<string, Entry> _runs = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _order = new();

    public Entry Create(string runId, string playbookId)
    {
        EvictIfNeeded();
        var entry = new Entry(runId, playbookId);
        if (!_runs.TryAdd(runId, entry))
            throw new InvalidOperationException($"Run id '{runId}' is already in use.");
        _order.Enqueue(runId);
        return entry;
    }

    public bool TryGet(string runId, out Entry? entry) =>
        _runs.TryGetValue(runId, out entry);

    private void EvictIfNeeded()
    {
        while (_runs.Count >= MaxRuns && _order.TryDequeue(out var oldest))
            _runs.TryRemove(oldest, out _);
    }

    public sealed class Entry
    {
        private readonly object _lock = new();
        private CancellationTokenSource? _cts;

        public Entry(string runId, string playbookId)
        {
            RunId = runId;
            PlaybookId = playbookId;
            Status = "queued";
            CreatedAtUtc = DateTime.UtcNow;
        }

        public string RunId { get; }
        public string PlaybookId { get; }
        public string Status { get; private set; }
        public DateTime CreatedAtUtc { get; }
        public DateTime? StartedAtUtc { get; private set; }
        public DateTime? FinishedAtUtc { get; private set; }
        public string? Error { get; private set; }
        public string? CurrentStep { get; private set; }
        public List<PlaybookStepResult> StepsExecuted { get; } = [];
        public object? Result { get; private set; }

        public CancellationTokenSource CreateLinkedCancellation(CancellationToken outer)
        {
            lock (_lock)
            {
                _cts?.Dispose();
                _cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
                return _cts;
            }
        }

        public void Cancel()
        {
            lock (_lock)
            {
                _cts?.Cancel();
                if (Status is "queued" or "running")
                {
                    Status = "cancelled";
                    FinishedAtUtc = DateTime.UtcNow;
                    Error ??= "Cancelled.";
                }
            }
        }

        public void MarkRunning()
        {
            lock (_lock)
            {
                if (Status == "queued")
                {
                    Status = "running";
                    StartedAtUtc = DateTime.UtcNow;
                }
            }
        }

        public void SetCurrentStep(string? name)
        {
            lock (_lock)
                CurrentStep = name;
        }

        public void RecordStep(PlaybookStepResult step)
        {
            lock (_lock)
            {
                StepsExecuted.Add(step);
                CurrentStep = null;
            }
        }

        public void Complete(object serializedResult)
        {
            lock (_lock)
            {
                Status = "completed";
                Result = serializedResult;
                FinishedAtUtc = DateTime.UtcNow;
                CurrentStep = null;
            }
        }

        public void Fail(string message)
        {
            lock (_lock)
            {
                Status = "failed";
                Error = message;
                FinishedAtUtc = DateTime.UtcNow;
                CurrentStep = null;
            }
        }

        public object ToPollResponse()
        {
            lock (_lock)
            {
                var obj = new Dictionary<string, object?>
                {
                    ["runId"] = RunId,
                    ["playbookId"] = PlaybookId,
                    ["status"] = Status,
                    ["createdAt"] = CreatedAtUtc.ToString("o"),
                    ["startedAt"] = StartedAtUtc?.ToString("o"),
                    ["finishedAt"] = FinishedAtUtc?.ToString("o"),
                    ["currentStep"] = CurrentStep,
                    ["stepsExecuted"] = StepsExecuted.ToList(),
                    ["pollUrl"] = $"/api/orchestrate/runs/{RunId}"
                };
                if (Error != null)
                    obj["error"] = Error;
                if (Result != null)
                    obj["result"] = Result;
                return obj;
            }
        }
    }

    internal sealed class ProgressReporter(PlaybookRunStore store, string runId) : IPlaybookRunProgress
    {
        public void StepStarting(string name)
        {
            if (store.TryGet(runId, out var e) && e != null)
                e.SetCurrentStep(name);
        }

        public void StepCompleted(PlaybookStepResult step)
        {
            if (store.TryGet(runId, out var e) && e != null)
                e.RecordStep(step);
        }
    }
}

/// <summary>Optional hooks for async run polling.</summary>
public interface IPlaybookRunProgress
{
    void StepStarting(string name);
    void StepCompleted(PlaybookStepResult step);
}
