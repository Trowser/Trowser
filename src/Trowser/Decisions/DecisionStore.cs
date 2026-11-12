namespace Trowser.Decisions;

/// <summary>
/// In-memory store for <see cref="Decision"/>s, modelled on <see cref="Trowser.Pointers.PointerStore"/>:
/// a lock-guarded list, a monotonic revision counter, and change events raised off the lock. It adds
/// two things pointers do not need — a waiter per pending decision so the <c>gate</c> lane can block
/// the agent until the human answers.
/// </summary>
public sealed class DecisionStore
{
    private readonly object _lock = new();
    private readonly List<Decision> _decisions = new();
    private readonly Dictionary<string, TaskCompletionSource<Decision>> _waiters = new(StringComparer.Ordinal);
    private readonly string _token;
    private int _revision;
    private int _seq;

    public DecisionStore()
    {
        // Short random token keeps ids unique across sessions/instances for future peer forwarding.
        _token = Guid.NewGuid().ToString("N")[..6];
    }

    /// <summary>
    /// Raised (off the lock) when a new decision needs the human. The host shows the A/B/C/D card and
    /// asks for attention. Handlers must marshal to the UI thread themselves — this may fire from an
    /// API or worker thread.
    /// </summary>
    public event Action<Decision>? Asked;

    /// <summary>
    /// Raised (off the lock) whenever a decision leaves <c>pending</c> — answered, defaulted, expired
    /// or cancelled. The host journals it here, in one place, so every resolution path is recorded
    /// regardless of whether a human clicked, a timeout fired, or the agent withdrew the question.
    /// </summary>
    public event Action<Decision>? Resolved;

    /// <summary>Raised (off the lock) on every mutation, for pollers and live views.</summary>
    public event Action? Changed;

    /// <summary>Monotonic generation counter. Increments on every add / resolve.</summary>
    public int Revision { get { lock (_lock) return _revision; } }

    /// <summary>True while at least one decision is still waiting on the human.</summary>
    public bool HasPending
    {
        get { lock (_lock) return _decisions.Any(d => d.Status == DecisionStatuses.Pending); }
    }

    /// <summary>
    /// True while at least one pending decision should interrupt the human (gate or steer).
    /// Review-lane questions are on the record only — they must not pin attention chrome.
    /// </summary>
    public bool HasAttentionPending
    {
        get
        {
            lock (_lock)
                return _decisions.Any(d =>
                    d.Status == DecisionStatuses.Pending && d.Lane != DecisionLanes.Review);
        }
    }

    /// <summary>Pending gate/steer decisions, newest first. Empty when nothing needs attention.</summary>
    public List<Decision> GetAttentionPending()
    {
        ApplyDueDefaults();
        lock (_lock)
        {
            return _decisions
                .Where(d => d.Status == DecisionStatuses.Pending && d.Lane != DecisionLanes.Review)
                .OrderByDescending(d => d.CreatedAt)
                .ToList();
        }
    }

    // ----- Decisions -----

    /// <summary>
    /// Add a decision, assigning an id and <see cref="Decision.ExpiresAt"/> from its timeout.
    /// Raises <see cref="Asked"/> so the host can surface it.
    /// </summary>
    public Decision Add(Decision decision)
    {
        lock (_lock)
        {
            if (string.IsNullOrEmpty(decision.Id))
                decision.Id = $"{_token}-d{++_seq}";
            decision.TimeoutMs = Math.Clamp(decision.TimeoutMs, DecisionDefaults.MinTimeoutMs, DecisionDefaults.MaxTimeoutMs);
            decision.ExpiresAt = decision.CreatedAt.AddMilliseconds(decision.TimeoutMs);
            _decisions.Add(decision);
            _revision++;
        }
        RaiseAsked(decision);
        RaiseChanged();
        return decision;
    }

    /// <summary>Look up a decision by id, or null if unknown. Applies any due defaults first.</summary>
    public Decision? Get(string? id)
    {
        if (string.IsNullOrEmpty(id)) return null;
        ApplyDueDefaults();
        lock (_lock)
            return _decisions.FirstOrDefault(d => d.Id == id);
    }

    /// <summary>List decisions with optional filters. Returns a snapshot copy.</summary>
    public List<Decision> GetAll(string? status = null, string? lane = null)
    {
        ApplyDueDefaults();
        lock (_lock)
        {
            IEnumerable<Decision> query = _decisions;

            if (!string.IsNullOrEmpty(status))
                query = query.Where(d => d.Status.Equals(status, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(lane))
                query = query.Where(d => d.Lane.Equals(lane, StringComparison.OrdinalIgnoreCase));

            return query.ToList();
        }
    }

    /// <summary>
    /// Record an answer. No-op (returns the decision unchanged) if it is already resolved, so a
    /// double-click or a race between the human and the timeout cannot rewrite history.
    /// </summary>
    public Decision? Answer(string? id, string? optionKey, string answeredBy, string? note = null)
    {
        Decision? decision;
        var changed = false;
        lock (_lock)
        {
            decision = _decisions.FirstOrDefault(d => d.Id == id);
            if (decision == null) return null;
            if (decision.Status == DecisionStatuses.Pending)
            {
                if (decision.MatchesOtherKey(optionKey))
                {
                    if (string.IsNullOrWhiteSpace(note))
                        return decision;
                    var text = note.Trim();
                    decision.Status = DecisionStatuses.Answered;
                    decision.AnswerKey = decision.OtherKey!;
                    decision.AnswerLabel = text;
                    decision.AnsweredBy = answeredBy;
                    decision.AnswerNote = text;
                    decision.ResolvedAt = DateTime.Now;
                    _revision++;
                    changed = true;
                }
                else
                {
                    var option = decision.FindOption(optionKey);
                    if (option == null) return decision;
                    decision.Status = DecisionStatuses.Answered;
                    decision.AnswerKey = option.Key;
                    decision.AnswerLabel = option.Label;
                    decision.AnsweredBy = answeredBy;
                    decision.AnswerNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
                    decision.ResolvedAt = DateTime.Now;
                    _revision++;
                    changed = true;
                }
            }
        }

        if (changed)
        {
            CompleteWaiter(decision);
            RaiseResolved(decision);
            RaiseChanged();
        }
        return decision;
    }

    /// <summary>Withdraw a pending question the agent no longer needs answered.</summary>
    public Decision? Cancel(string? id, string? reason = null)
    {
        Decision? decision;
        var changed = false;
        lock (_lock)
        {
            decision = _decisions.FirstOrDefault(d => d.Id == id);
            if (decision == null) return null;
            if (decision.Status == DecisionStatuses.Pending)
            {
                decision.Status = DecisionStatuses.Cancelled;
                decision.AnsweredBy = DecisionAnswerers.Agent;
                decision.AnswerNote = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim();
                decision.ResolvedAt = DateTime.Now;
                _revision++;
                changed = true;
            }
        }

        if (changed)
        {
            CompleteWaiter(decision);
            RaiseResolved(decision);
            RaiseChanged();
        }
        return decision;
    }

    /// <summary>
    /// Apply the timeout to every pending decision that is past its expiry: the default fires if one
    /// was set, otherwise the decision expires with no answer. Called lazily on every read and by the
    /// host's one-second sweep, so the record is honest whenever anyone looks at it.
    /// </summary>
    public int ApplyDueDefaults()
    {
        List<Decision>? due = null;
        lock (_lock)
        {
            var now = DateTime.Now;
            foreach (var d in _decisions)
            {
                if (d.Status != DecisionStatuses.Pending || d.ExpiresAt > now) continue;

                var fallback = d.FindOption(d.DefaultKey);
                if (fallback != null)
                {
                    d.Status = DecisionStatuses.Defaulted;
                    d.AnswerKey = fallback.Key;
                    d.AnswerLabel = fallback.Label;
                    d.AnsweredBy = DecisionAnswerers.Default;
                }
                else
                {
                    d.Status = DecisionStatuses.Expired;
                }
                d.ResolvedAt = now;
                (due ??= new()).Add(d);
            }
            if (due != null) _revision++;
        }

        if (due == null) return 0;
        foreach (var d in due)
        {
            CompleteWaiter(d);
            RaiseResolved(d);
        }
        RaiseChanged();
        return due.Count;
    }

    /// <summary>
    /// Block until the decision leaves <c>pending</c> — a human answer, the timeout default, or a
    /// cancellation. This is what makes the <c>gate</c> lane a gate. Returns immediately if the
    /// decision is already resolved.
    /// </summary>
    public async Task<Decision> WaitForResolutionAsync(string id, CancellationToken ct = default)
    {
        var decision = Get(id) ?? throw new KeyNotFoundException($"Unknown decision: {id}");
        if (decision.Status != DecisionStatuses.Pending) return decision;

        var wait = RegisterWaiter(decision);
        if (wait.IsCompleted) return await wait;

        var remaining = decision.ExpiresAt - DateTime.Now;
        if (remaining <= TimeSpan.Zero)
        {
            ApplyDueDefaults();
            return Get(id) ?? decision;
        }

        // Linked source so the timer is torn down as soon as the answer lands — a five-minute
        // default would otherwise keep a live timer per answered question.
        using var timerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var timeout = Task.Delay(remaining, timerCts.Token);
        var winner = await Task.WhenAny(wait, timeout);
        timerCts.Cancel();

        if (winner == wait) return await wait;

        ct.ThrowIfCancellationRequested();
        ApplyDueDefaults();
        return Get(id) ?? decision;
    }

    /// <summary>
    /// Steer grace: wait up to <paramref name="graceMs"/> for a human answer without applying the
    /// default. Returns the current decision (still pending if grace expired with no answer).
    /// </summary>
    public async Task<Decision> WaitForSteerGraceAsync(string id, int graceMs, CancellationToken ct = default)
    {
        if (graceMs <= 0)
            return Get(id) ?? throw new KeyNotFoundException($"Unknown decision: {id}");

        var decision = Get(id) ?? throw new KeyNotFoundException($"Unknown decision: {id}");
        if (decision.Status != DecisionStatuses.Pending) return decision;

        var wait = RegisterWaiter(decision);
        if (wait.IsCompleted) return await wait;

        using var timerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var grace = Task.Delay(graceMs, timerCts.Token);
        var winner = await Task.WhenAny(wait, grace);
        timerCts.Cancel();

        if (winner == wait) return await wait;

        ct.ThrowIfCancellationRequested();
        return Get(id) ?? decision;
    }

    private Task<Decision> RegisterWaiter(Decision decision)
    {
        lock (_lock)
        {
            if (decision.Status != DecisionStatuses.Pending)
                return Task.FromResult(decision);
            if (!_waiters.TryGetValue(decision.Id, out var existing))
            {
                existing = new TaskCompletionSource<Decision>(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters[decision.Id] = existing;
            }
            return existing.Task;
        }
    }

    private void CompleteWaiter(Decision decision)
    {
        TaskCompletionSource<Decision>? tcs;
        lock (_lock)
        {
            if (!_waiters.Remove(decision.Id, out tcs)) return;
        }
        tcs?.TrySetResult(decision);
    }

    private void RaiseAsked(Decision decision)
    {
        try { Asked?.Invoke(decision); }
        catch (Exception ex) { TrowserLog.Warn($"DecisionStore Asked handler failed: {ex.Message}"); }
    }

    private void RaiseResolved(Decision decision)
    {
        try { Resolved?.Invoke(decision); }
        catch (Exception ex) { TrowserLog.Warn($"DecisionStore Resolved handler failed: {ex.Message}"); }
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"DecisionStore Changed handler failed: {ex.Message}"); }
    }
}
