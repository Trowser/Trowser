using System.Globalization;
using System.IO;
using Trowser.SessionLog;

namespace Trowser.Bookmarks;

/// <summary>
/// Field keys on a <c>bookmark</c> journal entry. The journal entry is the bookmark: there is no
/// second store; deleting the entry removes the bookmark and deletes its evidence files on disk
/// (unless another entry still references the same folder).
/// </summary>
public static class BookmarkFields
{
    public const string EntryType = "bookmark";

    /// <summary>
    /// Journal row for something done <em>to</em> a bookmark (Go, Verify, Export). Never carries
    /// <see cref="BookmarkId"/>, so it is not itself a bookmark and deleting it touches no files.
    /// </summary>
    public const string EventEntryType = "bookmark-event";
    /// <summary>On a <see cref="EventEntryType"/> row: <c>restore</c>, <c>verify</c>, or <c>export</c>.</summary>
    public const string EventName = "event";
    /// <summary>On a <see cref="EventEntryType"/> row: the bookmark the event is about.</summary>
    public const string EventBookmarkRef = "bookmarkRef";

    public const string BookmarkId = "bookmarkId";
    /// <summary>1-based sequence among bookmarks in this journal (not the journal entry index).</summary>
    public const string BookmarkNumber = "bookmarkNumber";
    /// <summary>Browser tab id when caught; journal <c>action</c> entries use the same key.</summary>
    public const string TabId = "tabId";
    public const string CheckpointId = "checkpointId";
  /// <summary>Narrated automation since prior checkpoint (not bug-report <c>steps</c>).</summary>
    public const string CapturedSteps = "capturedSteps";
    /// <summary>Legacy key; read for old sessions only.</summary>
    public const string Steps = CapturedSteps;
    public const string StepCount = "stepCount";
    public const string StepsOmitted = "stepsOmitted";
    public const string RequestMethod = "requestMethod";
    public const string RequestStatus = "requestStatus";
    public const string RequestUrl = "requestUrl";
    public const string Directory = "bookmarkDir";
    public const string Screenshot = "screenshot";
    public const string TrwPath = "trwPath";
    public const string StatePath = "statePath";
    public const string StateRedacted = "stateRedacted";
    public const string Imported = "importedFrom";
    /// <summary>Bookmark id this row was copied from (zip import, or a journal import that collided with a live id).</summary>
    public const string ImportedId = "importedId";
    /// <summary>Page URL where the captured steps start (the setup navigate in the <c>.trw</c>).</summary>
    public const string StartUrl = "startUrl";
    /// <summary>Bookmark the captured steps continue from (previous bookmark on the tab, or the one restored with Go).</summary>
    public const string StartsFrom = "startsFrom";

    public const string ScreenshotFile = "screenshot.png";
    public const string TrwFile = "repro.trw";
    public const string StateFile = "state.json";
    public const string EntryFile = "bookmark.json";

    /// <summary>Every file name Trowser writes into a bookmark folder. Cleanup deletes only these.</summary>
    public static readonly string[] KnownFiles = [ScreenshotFile, TrwFile, StateFile, EntryFile];

    private static readonly string[] EvidenceKeys =
    [
        BookmarkId, BookmarkNumber, TabId, CheckpointId, CapturedSteps, StepCount, StepsOmitted,
        RequestMethod, RequestStatus, RequestUrl,
        Directory, Screenshot, TrwPath, StatePath, StateRedacted, Imported, ImportedId, StartUrl, StartsFrom
    ];

    /// <summary>True when <paramref name="fields"/> carries a bookmark id (evidence may still be on disk).</summary>
    public static bool HasEvidence(IReadOnlyDictionary<string, string>? fields) =>
        fields != null && fields.TryGetValue(BookmarkId, out var id) && !string.IsNullOrWhiteSpace(id);

    public static int? TryGetTabId(IReadOnlyDictionary<string, string>? fields) =>
        fields != null && fields.TryGetValue(TabId, out var v)
        && int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id) ? id : null;

    public static bool ActionMatchesTab(SessionLogger.JournalEntry entry, int tabId)
    {
        if (TryGetTabId(entry.Fields) != tabId) return false;
        if (string.Equals(entry.Type, "action", StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(entry.Type, "error", StringComparison.OrdinalIgnoreCase)
               && entry.Fields != null
               && entry.Fields.ContainsKey(RequestMethod);
    }

    /// <summary>Next display number: max existing <see cref="BookmarkNumber"/> + 1 (stable across deletes).</summary>
    public static int NextBookmarkNumber(IEnumerable<SessionLogger.JournalEntry> entries)
    {
        var max = 0;
        foreach (var e in entries)
        {
            if (!HasEvidence(e.Fields)) continue;
            if (e.Fields!.TryGetValue(BookmarkNumber, out var v)
                && int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
                max = Math.Max(max, n);
        }
        return max + 1;
    }

    /// <summary>
    /// When a bookmark is reclassified as bug/enhancement, move narrated <c>steps</c> off the structured bug field.
    /// </summary>
    public static void MigrateCapturedStepsOffBugFields(Dictionary<string, string>? fields)
    {
        if (fields == null || !HasEvidence(fields)) return;
        if (fields.ContainsKey(CapturedSteps)) return;
        if (!fields.TryGetValue("steps", out var narrated) || string.IsNullOrWhiteSpace(narrated)) return;
        fields[CapturedSteps] = narrated;
        fields.Remove("steps");
    }

    /// <summary>Copy bookmark evidence keys from <paramref name="from"/> onto <paramref name="into"/>.</summary>
    public static void RestoreEvidenceKeys(IReadOnlyDictionary<string, string>? from, Dictionary<string, string> into)
    {
        if (from == null) return;
        foreach (var key in EvidenceKeys)
        {
            if (from.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v))
                into[key] = v;
        }
    }
}

/// <summary>API projection of a bookmark journal entry.</summary>
public sealed class BookmarkInfo
{
    public string Id { get; init; } = "";
    /// <summary>Sequential bookmark number in this session (1, 2, 3…). Distinct from <see cref="JournalIndex"/>.</summary>
    public int BookmarkNumber { get; init; }
    public int? TabId { get; init; }
    public int JournalIndex { get; init; }
    public DateTime CreatedAt { get; init; }
    public string Author { get; init; } = "";
    public string Title { get; init; } = "";
    public string? Url { get; init; }
    public string? Note { get; init; }
    public string? CheckpointId { get; init; }
    public List<string> Steps { get; init; } = [];
    public int StepCount { get; init; }
    public int StepsOmitted { get; init; }
    public BookmarkRequest? LastRequest { get; init; }
    public string? Directory { get; init; }
    public string? Screenshot { get; init; }
    public string? TrwPath { get; init; }
    public string? StatePath { get; init; }
    public bool StateRedacted { get; init; }
    public string? StartUrl { get; init; }
    public string? StartsFrom { get; init; }
    /// <summary>True when a replayable <c>.trw</c> exists with at least one supported step.</summary>
    public bool CanVerify { get; init; }
    /// <summary>True when unredacted <c>state.json</c> exists on disk.</summary>
    public bool CanRestore { get; init; }
    /// <summary>Non-fatal notes about this bookmark, e.g. evidence that will not survive a restart. Only set on Catch.</summary>
    public List<string>? Warnings { get; set; }
    /// <summary>Only set on import: true when the zip was already imported and the existing row was returned.</summary>
    public bool? AlreadyImported { get; set; }

    /// <summary>
    /// Set when the catch window had no narrated/replayable steps — the moment may not match the title/note.
    /// </summary>
    public bool EmptyStepCapture => StepCount == 0 && Steps.Count == 0 && !CanVerify;

    /// <summary>Journal row is a bookmark moment (<c>type: bookmark</c>).</summary>
    public static bool IsBookmark(SessionLogger.JournalEntry? e) =>
        e != null && string.Equals(e.Type, BookmarkFields.EntryType, StringComparison.OrdinalIgnoreCase);

    /// <summary>Entry still has on-disk bookmark evidence (Verify/Go/export) even if reclassified.</summary>
    public static bool HasBookmarkEvidence(SessionLogger.JournalEntry? e) =>
        e != null && BookmarkFields.HasEvidence(e.Fields);

    private static string? LegacyCapturedSteps(SessionLogger.JournalEntry e) =>
        e.Fields != null && e.Fields.TryGetValue("steps", out var legacy)
        && !string.Equals(e.Kind, NoteKinds.Bug, StringComparison.OrdinalIgnoreCase)
        && !string.Equals(e.Kind, NoteKinds.Enhancement, StringComparison.OrdinalIgnoreCase)
            ? legacy
            : null;

    public static BookmarkInfo FromEntry(SessionLogger.JournalEntry e)
    {
        string? F(string key) =>
            e.Fields != null && e.Fields.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

        var steps = (F(BookmarkFields.CapturedSteps) ?? LegacyCapturedSteps(e))?
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList() ?? [];

        BookmarkRequest? request = null;
        var reqUrl = F(BookmarkFields.RequestUrl);
        if (reqUrl != null)
        {
            request = new BookmarkRequest
            {
                Method = F(BookmarkFields.RequestMethod) ?? "",
                Status = int.TryParse(F(BookmarkFields.RequestStatus), out var s) ? s : 0,
                Url = reqUrl
            };
        }

        var bookmarkNumber = int.TryParse(F(BookmarkFields.BookmarkNumber), out var bn) ? bn : 0;
        var statePath = F(BookmarkFields.StatePath);
        var stateRedacted = string.Equals(F(BookmarkFields.StateRedacted), "true", StringComparison.OrdinalIgnoreCase);

        return new BookmarkInfo
        {
            Id = F(BookmarkFields.BookmarkId) ?? "",
            BookmarkNumber = bookmarkNumber,
            TabId = BookmarkFields.TryGetTabId(e.Fields),
            JournalIndex = e.Index,
            CreatedAt = e.Timestamp,
            Author = e.Source,
            Title = e.Summary,
            Url = Trowser.Api.AgentUrlPolicy.ForAgent(e.Url),
            Note = e.Details,
            CheckpointId = F(BookmarkFields.CheckpointId),
            Steps = steps,
            StepCount = int.TryParse(F(BookmarkFields.StepCount), out var c) ? c : steps.Count,
            StepsOmitted = int.TryParse(F(BookmarkFields.StepsOmitted), out var o) ? o : 0,
            LastRequest = request,
            Directory = F(BookmarkFields.Directory),
            Screenshot = F(BookmarkFields.Screenshot),
            TrwPath = F(BookmarkFields.TrwPath),
            StatePath = statePath,
            StateRedacted = stateRedacted,
            StartUrl = Trowser.Api.AgentUrlPolicy.ForAgent(F(BookmarkFields.StartUrl)),
            StartsFrom = F(BookmarkFields.StartsFrom),
            CanVerify = BookmarkEvidence.TrwPathIsVerifiable(F(BookmarkFields.TrwPath)),
            CanRestore = !stateRedacted && FileExists(statePath)
        };
    }

    private static bool FileExists(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || Trowser.Api.ExportPathGuard.IsRemoteOrDevicePath(path)) return false;
        try { return File.Exists(path); }
        catch { return false; }
    }

    /// <summary>One-line label for compact journal and bookmark lists: <c>#N title — note</c>.</summary>
    public static string IndexSummary(SessionLogger.JournalEntry e)
    {
        var number = e.Fields != null && e.Fields.TryGetValue(BookmarkFields.BookmarkNumber, out var n)
                     && !string.IsNullOrWhiteSpace(n) ? $"#{n} " : "";
        var title = string.IsNullOrWhiteSpace(e.Summary) ? "Bookmark" : e.Summary.Trim();
        var note = e.Details?.Replace('\r', ' ').Replace('\n', ' ').Trim();
        if (string.IsNullOrEmpty(note)) return number + title;
        if (note.Length > 100) note = note[..97] + "...";
        return $"{number}{title} — {note}";
    }

    /// <summary>Compact projection for <c>view=index</c> lists.</summary>
    public object ToIndex() => new
    {
        id = Id,
        bookmarkNumber = BookmarkNumber,
        journalIndex = JournalIndex,
        createdAt = CreatedAt,
        author = Author,
        title = Title,
        note = Note,
        url = Url,
        stepCount = StepCount,
        canVerify = CanVerify,
        canRestore = CanRestore
    };
}

/// <summary>Method, status, and URL of the most recent network request. No headers, no body.</summary>
public sealed class BookmarkRequest
{
    public string Method { get; init; } = "";
    public int Status { get; init; }
    public string Url { get; init; } = "";
}
