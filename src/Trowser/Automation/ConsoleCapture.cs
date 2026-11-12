namespace Trowser.Automation;

/// <summary>
/// Represents a single captured browser console message.
/// </summary>
public record ConsoleEntry
{
    public int Id { get; init; }
    public ConsoleLevel Level { get; init; }
    public string Message { get; init; } = "";
    public string Source { get; init; } = "";
    public int Line { get; init; }
    public DateTime Timestamp { get; init; }

    public override string ToString()
    {
        var prefix = Level switch
        {
            ConsoleLevel.Log => "log",
            ConsoleLevel.Warning => "warn",
            ConsoleLevel.Error => "error",
            ConsoleLevel.Info => "info",
            _ => "log"
        };
        return $"[console.{prefix}] {Message}";
    }
}

public enum ConsoleLevel
{
    Log,
    Info,
    Warning,
    Error
}

/// <summary>
/// Thread-safe collection of captured browser console messages with query methods.
/// </summary>
public class ConsoleLog
{
    private readonly List<ConsoleEntry> _entries = new();
    private readonly object _lock = new();
    private int _nextId;
    private int _navigationBoundaryId = -1;

    /// <summary>
    /// All captured console entries.
    /// </summary>
    public List<ConsoleEntry> Entries
    {
        get
        {
            lock (_lock)
            {
                return new List<ConsoleEntry>(_entries);
            }
        }
    }

    /// <summary>
    /// Number of captured entries.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Fired after a new entry is added. Subscribers must not block.</summary>
    public event Action<ConsoleEntry>? EntryAdded;

    /// <summary>
    /// Add a console entry.
    /// </summary>
    internal int Add(ConsoleEntry entry)
    {
        ConsoleEntry stored;
        lock (_lock)
        {
            var id = _nextId++;
            stored = entry with { Id = id };
            _entries.Add(stored);
        }
        EntryAdded?.Invoke(stored);
        return stored.Id;
    }

    /// <summary>
    /// Clear all entries.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
    }

    /// <summary>
    /// Mark the current position as a navigation boundary. Entries added after this
    /// point are considered "for the current page" by GetPageErrors/PageEntries.
    /// </summary>
    internal void MarkNavigationBoundary()
    {
        lock (_lock)
        {
            _navigationBoundaryId = _nextId - 1;
        }
    }

    /// <summary>
    /// Console entries captured since the last navigation (current page only).
    /// </summary>
    public List<ConsoleEntry> PageEntries
    {
        get
        {
            lock (_lock)
            {
                return _entries.Where(e => e.Id > _navigationBoundaryId).ToList();
            }
        }
    }

    /// <summary>
    /// Error-level messages captured since the last navigation (current page only).
    /// </summary>
    public List<ConsoleEntry> GetPageErrors()
    {
        lock (_lock)
        {
            return _entries.Where(e => e.Level == ConsoleLevel.Error && e.Id > _navigationBoundaryId).ToList();
        }
    }

    /// <summary>
    /// Get all error-level messages.
    /// </summary>
    public List<ConsoleEntry> GetErrors()
    {
        lock (_lock)
        {
            return _entries.Where(e => e.Level == ConsoleLevel.Error).ToList();
        }
    }

    /// <summary>
    /// Get all warning-level messages.
    /// </summary>
    public List<ConsoleEntry> GetWarnings()
    {
        lock (_lock)
        {
            return _entries.Where(e => e.Level == ConsoleLevel.Warning).ToList();
        }
    }

    /// <summary>
    /// Get entries whose message contains the given text.
    /// </summary>
    public List<ConsoleEntry> Find(string text)
    {
        lock (_lock)
        {
            return _entries
                .Where(e => e.Message.Contains(text, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    /// <summary>
    /// Check if any error-level messages were logged.
    /// </summary>
    public bool HasErrors
    {
        get
        {
            lock (_lock)
            {
                return _entries.Any(e => e.Level == ConsoleLevel.Error);
            }
        }
    }

    /// <summary>
    /// Format all entries as a string for display.
    /// </summary>
    public string Format(int? maxEntries = null)
    {
        List<ConsoleEntry> entries;
        lock (_lock)
        {
            entries = maxEntries.HasValue
                ? _entries.TakeLast(maxEntries.Value).ToList()
                : new List<ConsoleEntry>(_entries);
        }

        if (entries.Count == 0)
            return "No console messages captured.";

        var lines = entries.Select(e =>
        {
            var level = e.Level switch
            {
                ConsoleLevel.Log => "LOG  ",
                ConsoleLevel.Info => "INFO ",
                ConsoleLevel.Warning => "WARN ",
                ConsoleLevel.Error => "ERROR",
                _ => "LOG  "
            };
            var source = string.IsNullOrEmpty(e.Source) ? "" : $" ({e.Source}:{e.Line})";
            return $"  [{level}] {e.Message}{source}";
        }).ToList();

        lines.Insert(0, $"Console messages ({entries.Count}):");
        return string.Join(Environment.NewLine, lines);
    }
}
