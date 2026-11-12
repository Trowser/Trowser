using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser.SessionLog;

/// <summary>
/// Volatile session state for the built-in AI Assistant: focus, tasks, and compact handoff.
/// Rebuilt from the journal on demand; not persisted separately.
/// </summary>
public sealed class SessionMemory
{
    public string? Mission { get; set; }
    public string? Focus { get; set; }
    public List<SessionTask> Tasks { get; set; } = new();
    public CompactHandoff? Handoff { get; set; }
    public int CompactCount { get; set; }
    public DateTime? LastCompactAt { get; set; }

    private int _nextTaskId = 1;
    private PendingCompactRequest? _pendingCompact;

    public event Action? Changed;

    public void SetFocus(string? focus)
    {
        Focus = string.IsNullOrWhiteSpace(focus) ? null : focus.Trim();
        NotifyChanged();
    }

    public SessionTask AddTask(string text, int? journalIndex = null)
    {
        var task = new SessionTask
        {
            Id = $"t{_nextTaskId++}",
            Text = text.Trim(),
            Status = SessionTaskStatus.Open,
            JournalIndex = journalIndex
        };
        Tasks.Add(task);
        NotifyChanged();
        return task;
    }

    public SessionTask? UpdateTask(string id, string? text = null, string? status = null, int? journalIndex = null)
    {
        var task = Tasks.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (task == null) return null;

        if (text != null)
            task.Text = text.Trim();
        if (status != null && SessionTask.TryParseStatus(status, out var parsed))
            task.Status = parsed;
        if (journalIndex.HasValue)
            task.JournalIndex = journalIndex;

        NotifyChanged();
        return task;
    }

    public void QueueCompact(PendingCompactRequest request)
    {
        _pendingCompact = request;
    }

    public PendingCompactRequest? TakePendingCompact()
    {
        var pending = _pendingCompact;
        _pendingCompact = null;
        return pending;
    }

    public void ApplyHandoff(PendingCompactRequest request, int messagesBefore, int messagesAfter, int tokensBefore, int tokensAfter)
    {
        Handoff = new CompactHandoff
        {
            Summary = request.Summary,
            OpenThreads = request.OpenThreads?.ToList() ?? new List<string>(),
            Timestamp = DateTime.Now,
            MessagesBefore = messagesBefore,
            MessagesAfter = messagesAfter,
            TokensBefore = tokensBefore,
            TokensAfter = tokensAfter,
            JournalIndexes = request.JournalIndexes?.ToList() ?? new List<int>()
        };
        CompactCount++;
        LastCompactAt = Handoff.Timestamp;

        if (request.NextSteps != null)
        {
            foreach (var step in request.NextSteps)
            {
                if (string.IsNullOrWhiteSpace(step)) continue;
                AddTask(step.Trim());
            }
        }

        NotifyChanged();
    }

    public void RebuildFrom(SessionLogger logger)
    {
        var entries = logger.GetJournal();
        Mission = entries
            .Where(e => NoteKinds.Normalize(e.Kind ?? e.Type) == NoteKinds.Charter)
            .OrderByDescending(e => e.Index)
            .Select(e => e.Summary)
            .FirstOrDefault();

        if (Tasks.Count == 0)
        {
            foreach (var e in entries.Where(e =>
                         NoteKinds.Normalize(e.Kind ?? e.Type) is NoteKinds.Bug or NoteKinds.TestIdea))
            {
                AddTask(e.Summary, e.Index);
            }
        }
    }

    public object ToApiObject()
    {
        return new
        {
            mission = Mission,
            focus = Focus,
            tasks = Tasks.Select(t => t.ToApiObject()).ToArray(),
            handoff = Handoff?.ToApiObject(),
            compactCount = CompactCount,
            lastCompactAt = LastCompactAt?.ToString("yyyy-MM-dd HH:mm:ss")
        };
    }

    public string BuildDigestBlock(SessionLogger logger, IEnumerable<SessionLogger.JournalEntry>? inlineEntries = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## Session state (compact digest)");
        if (!string.IsNullOrEmpty(Mission))
            sb.AppendLine($"Mission: {Mission}");
        if (!string.IsNullOrEmpty(Focus))
            sb.AppendLine($"Focus: {Focus}");
        if (Handoff != null)
        {
            sb.AppendLine();
            sb.AppendLine("### Last segment summary");
            sb.AppendLine(Handoff.Summary);
            if (Handoff.OpenThreads.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Open threads:");
                foreach (var thread in Handoff.OpenThreads)
                    sb.AppendLine($"- {thread}");
            }
        }

        var openTasks = Tasks.Where(t => t.Status is SessionTaskStatus.Open or SessionTaskStatus.Doing).ToList();
        if (openTasks.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Open tasks:");
            foreach (var task in openTasks)
                sb.AppendLine($"- [{task.Status}] {task.Text}");
        }

        sb.AppendLine();
        sb.AppendLine("### Journal index");
        foreach (var e in logger.GetJournal())
            sb.AppendLine(JournalProjection.FormatIndexLine(e));

        if (inlineEntries != null)
        {
            sb.AppendLine();
            sb.AppendLine("### Referenced journal entries");
            foreach (var e in inlineEntries)
                sb.AppendLine(JournalProjection.FormatFullEntry(e));
        }

        return sb.ToString().TrimEnd();
    }

    private void NotifyChanged()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"SessionMemory.Changed handler failed: {ex.Message}"); }
    }
}

public enum SessionTaskStatus
{
    Open,
    Doing,
    Done,
    Dropped
}

public sealed class SessionTask
{
    public string Id { get; set; } = "";
    public string Text { get; set; } = "";
    public SessionTaskStatus Status { get; set; } = SessionTaskStatus.Open;
    public int? JournalIndex { get; set; }

    public object ToApiObject() => new
    {
        id = Id,
        text = Text,
        status = Status.ToString().ToLowerInvariant(),
        journalIndex = JournalIndex
    };

    public static bool TryParseStatus(string? raw, out SessionTaskStatus status)
    {
        status = SessionTaskStatus.Open;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        switch (raw.Trim().ToLowerInvariant())
        {
            case "open":
                status = SessionTaskStatus.Open;
                return true;
            case "doing":
                status = SessionTaskStatus.Doing;
                return true;
            case "done":
                status = SessionTaskStatus.Done;
                return true;
            case "dropped":
                status = SessionTaskStatus.Dropped;
                return true;
            default:
                return false;
        }
    }
}

public sealed class CompactHandoff
{
    public string Summary { get; set; } = "";
    public List<string> OpenThreads { get; set; } = new();
    public DateTime Timestamp { get; set; }
    public int MessagesBefore { get; set; }
    public int MessagesAfter { get; set; }
    public int TokensBefore { get; set; }
    public int TokensAfter { get; set; }
    public List<int> JournalIndexes { get; set; } = new();

    public object ToApiObject() => new
    {
        summary = Summary,
        openThreads = OpenThreads,
        timestamp = Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
        messagesBefore = MessagesBefore,
        messagesAfter = MessagesAfter,
        tokensBefore = TokensBefore,
        tokensAfter = TokensAfter,
        journalIndexes = JournalIndexes
    };
}

public sealed class PendingCompactRequest
{
    public string Summary { get; set; } = "";
    public List<string>? OpenThreads { get; set; }
    public List<string>? NextSteps { get; set; }
    public List<int>? JournalIndexes { get; set; }
    public int KeepLastTurns { get; set; } = 10;
    public bool Deterministic { get; set; }
}

/// <summary>Shared journal projection helpers for REST, MCP, and compact digest.</summary>
public static class JournalProjection
{
    public const int DefaultIndexViewThreshold = 40;

    public static object ProjectEntry(SessionLogger.JournalEntry e)
    {
        object? fieldsForResponse = e.Fields;
        if (e.Fields != null && e.StepsIsArray && e.Fields.TryGetValue("steps", out var stepsStr))
        {
            var dict = new Dictionary<string, object>(e.Fields.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var (k, v) in e.Fields)
            {
                if (k.Equals("steps", StringComparison.OrdinalIgnoreCase))
                    dict[k] = stepsStr.Split('\n');
                else
                    dict[k] = v;
            }
            fieldsForResponse = dict;
        }

        return new
        {
            index = e.Index,
            timestamp = e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            type = e.Type,
            kind = e.Kind,
            source = e.Source,
            origin = SessionLogger.GetOrigin(e.Source),
            summary = e.Summary,
            details = e.Details,
            severity = e.Severity,
            evidence = e.Evidence,
            fields = fieldsForResponse,
            tags = e.Tags,
            url = e.Url
        };
    }

    public static object ProjectEntryIndex(SessionLogger.JournalEntry e)
    {
        string? rank = e.Severity;
        if (string.IsNullOrEmpty(rank) && e.Fields != null && e.Fields.TryGetValue("priority", out var pri))
            rank = pri;

        return new
        {
            index = e.Index,
            timestamp = e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            kind = e.Kind ?? e.Type,
            evidence = e.Evidence,
            rank,
            summary = e.Summary,
            tags = e.Tags,
            origin = SessionLogger.GetOrigin(e.Source)
        };
    }

    public static string FormatIndexLine(SessionLogger.JournalEntry e)
    {
        var rank = e.Severity;
        if (string.IsNullOrEmpty(rank) && e.Fields != null && e.Fields.TryGetValue("priority", out var pri))
            rank = pri;
        var rankPart = string.IsNullOrEmpty(rank) ? "" : $" [{rank}]";
        var tagsPart = e.Tags != null && e.Tags.Count > 0 ? $" tags={string.Join(",", e.Tags)}" : "";
        return $"[{e.Index}] {e.Timestamp:HH:mm:ss} {e.Kind ?? e.Type}/{e.Evidence}{rankPart}{tagsPart}: {e.Summary}";
    }

    public static string FormatFullEntry(SessionLogger.JournalEntry e)
    {
        var sb = new StringBuilder();
        sb.AppendLine(FormatIndexLine(e));
        if (!string.IsNullOrEmpty(e.Details))
            sb.AppendLine(e.Details);
        if (e.Fields != null)
        {
            foreach (var key in NoteKinds.StructuredFieldOrder)
            {
                if (e.Fields.TryGetValue(key, out var v))
                    sb.AppendLine($"{NoteKinds.FieldLabel(key)}: {v}");
            }
        }
        return sb.ToString().TrimEnd();
    }

    public static List<int>? ParseIndexes(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var list = new List<int>();
        foreach (var part in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out var index) && index >= 0)
                list.Add(index);
        }
        return list.Count == 0 ? null : list;
    }
}
