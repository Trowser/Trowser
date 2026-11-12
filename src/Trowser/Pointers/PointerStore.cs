namespace Trowser.Pointers;

/// <summary>
/// In-memory store for <see cref="Pointer"/>s and <see cref="Checkpoint"/>s. Modelled on
/// <see cref="Trowser.SessionLog.SessionLogger"/>: a lock-guarded list, a monotonic revision
/// counter so pollers can detect mutations, and a change event so live views (the overlay
/// window) refresh without polling. Ids are session-scoped with a short random token prefix
/// so pointer/checkpoint ids can be forwarded to peers later without collisions.
/// </summary>
public sealed class PointerStore
{
    private readonly object _lock = new();
    private readonly List<Pointer> _pointers = new();
    private readonly List<Checkpoint> _checkpoints = new();
    private readonly string _token;
    private int _revision;
    private int _pointerSeq;
    private int _checkpointSeq;

    public PointerStore()
    {
        // Short random token keeps ids unique across sessions/instances for future peer forwarding.
        _token = Guid.NewGuid().ToString("N")[..6];
    }

    /// <summary>
    /// Raised (off the lock) whenever pointers or checkpoints change, so the overlay window
    /// and other live views can refresh. Handlers must marshal to the UI thread themselves —
    /// this may fire from API/worker threads.
    /// </summary>
    public event Action? Changed;

    /// <summary>Monotonic generation counter. Increments on every add / remove / status change.</summary>
    public int Revision { get { lock (_lock) return _revision; } }

    // ----- Pointers -----

    /// <summary>Add a pointer, assigning an id if one is not already set. Returns the stored pointer.</summary>
    public Pointer Add(Pointer pointer)
    {
        lock (_lock)
        {
            if (string.IsNullOrEmpty(pointer.Id))
                pointer.Id = $"{_token}-p{++_pointerSeq}";
            _pointers.Add(pointer);
            _revision++;
        }
        RaiseChanged();
        return pointer;
    }

    /// <summary>Look up a pointer by id, or null if unknown.</summary>
    public Pointer? Get(string? id)
    {
        if (string.IsNullOrEmpty(id)) return null;
        lock (_lock)
            return _pointers.FirstOrDefault(p => p.Id == id);
    }

    /// <summary>List pointers with optional filters. Returns a snapshot copy.</summary>
    public List<Pointer> GetAll(string? author = null, string? kind = null, string? status = null,
        int? tabId = null, string? checkpointId = null)
    {
        lock (_lock)
        {
            IEnumerable<Pointer> query = _pointers;

            if (!string.IsNullOrEmpty(author))
                query = query.Where(p => p.Author.Equals(author, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(kind))
                query = query.Where(p => p.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(status))
                query = query.Where(p => p.Status.Equals(status, StringComparison.OrdinalIgnoreCase));
            if (tabId.HasValue)
                query = query.Where(p => p.TabId == tabId.Value);
            if (!string.IsNullOrEmpty(checkpointId))
                query = query.Where(p => p.CheckpointId == checkpointId);

            return query.ToList();
        }
    }

    /// <summary>Remove a pointer by id. Returns false if it was already gone.</summary>
    public bool Remove(string? id)
    {
        if (string.IsNullOrEmpty(id)) return false;
        bool removed;
        lock (_lock)
        {
            var i = _pointers.FindIndex(p => p.Id == id);
            if (i < 0) return false;
            _pointers.RemoveAt(i);
            _revision++;
            removed = true;
        }
        if (removed) RaiseChanged();
        return removed;
    }

    /// <summary>Update a pointer's status and (optionally) refresh its rect. Returns the pointer or null.</summary>
    public Pointer? UpdateStatus(string? id, string status, PointerRect? rect = null)
    {
        Pointer? pointer;
        lock (_lock)
        {
            pointer = _pointers.FirstOrDefault(p => p.Id == id);
            if (pointer == null) return null;
            pointer.Status = PointerStatuses.Normalize(status);
            if (rect != null)
                pointer.Anchors.Rect = rect;
            _revision++;
        }
        RaiseChanged();
        return pointer;
    }

    /// <summary>Mark every currently-resolved pointer on a tab as stale (e.g. after a DOM change).</summary>
    public void MarkTabStale(int tabId)
    {
        var any = false;
        lock (_lock)
        {
            foreach (var p in _pointers)
            {
                if (p.TabId == tabId && p.Status == PointerStatuses.Resolved)
                {
                    p.Status = PointerStatuses.Stale;
                    any = true;
                }
            }
            if (any) _revision++;
        }
        if (any) RaiseChanged();
    }

    // ----- Checkpoints -----

    /// <summary>Create a checkpoint bounding "now". Returns the stored checkpoint.</summary>
    public Checkpoint AddCheckpoint(int journalIndex, string? label = null, string? url = null)
    {
        Checkpoint cp;
        lock (_lock)
        {
            cp = new Checkpoint
            {
                Id = $"{_token}-c{++_checkpointSeq}",
                Label = string.IsNullOrWhiteSpace(label) ? null : label.Trim(),
                JournalIndex = journalIndex,
                Url = url,
                CreatedAt = DateTime.Now
            };
            _checkpoints.Add(cp);
            _revision++;
        }
        RaiseChanged();
        return cp;
    }

    /// <summary>Look up a checkpoint by id, or null if unknown.</summary>
    public Checkpoint? GetCheckpoint(string? id)
    {
        if (string.IsNullOrEmpty(id)) return null;
        lock (_lock)
            return _checkpoints.FirstOrDefault(c => c.Id == id);
    }

    /// <summary>The most recent checkpoint, or null if none have been taken.</summary>
    public Checkpoint? LatestCheckpoint
    {
        get { lock (_lock) return _checkpoints.Count > 0 ? _checkpoints[^1] : null; }
    }

    /// <summary>List checkpoints (oldest first). Returns a snapshot copy.</summary>
    public List<Checkpoint> GetCheckpoints()
    {
        lock (_lock)
            return _checkpoints.ToList();
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"PointerStore Changed handler failed: {ex.Message}"); }
    }
}
