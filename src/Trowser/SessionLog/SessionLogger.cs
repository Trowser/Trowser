using System.Collections.Concurrent;
using System.IO;
using System.Reflection;
using System.Text;
using Trowser.Decisions;

namespace Trowser.SessionLog;

/// <summary>
/// Records a tester's actions, notes, script output and screenshots to a markdown file.
/// The log format is optimised for LLM consumption: each entry shows the REST API
/// equivalent of what happened so another agent can replay or vary the session.
///
/// The unified <see cref="JournalEntry"/> list is the single source of truth for all
/// session activity — browser actions, LLM notes, assertions, messages, screenshots,
/// and API usage. Exposed via <c>GET /api/journal</c>.
/// </summary>
public class SessionLogger
{
    private readonly object _lock = new();
    private StreamWriter? _writer;
    private string? _filePath;
    private DateTime _sessionStart;
    private int _nextJournalIndex;
    private int _revision;
    private readonly List<int> _deletedIndices = new();

    // Unified journal — single timeline of all session activity
    private readonly List<JournalEntry> _journal = new();

    /// <summary>
    /// When true, GUI browser action logging is suppressed because an API call
    /// is in progress that will log its own richer journal entry.
    /// </summary>
    public bool SuppressGuiActions { get; set; }

    public bool IsLogging => _writer != null;
    public string? FilePath => _filePath;
    public SessionLogSettings Settings { get; set; } = new();

    /// <summary>
    /// Raised (off the lock) whenever a new journal entry is added, so live views such as
    /// the Journal panel can refresh without polling. Handlers must marshal to the UI thread —
    /// this may fire from API/worker threads. Kept intentionally lightweight (no args); consumers
    /// re-read via <see cref="GetJournal"/>.
    /// </summary>
    public event Action? JournalChanged;

    /// <summary>Start logging. Appends to existing file content.</summary>
    public void Start(string filePath, string? currentUrl = null)
    {
        lock (_lock)
        {
            Stop();

            _filePath = Path.GetFullPath(filePath);
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            // FileShare.ReadWrite so Chronological Report can read the .md while logging is on.
            var stream = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            _writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true };
            _sessionStart = DateTime.Now;

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var versionText = version != null
                ? $"{version.Major}.{version.Minor}.{version.Build}"
                : "1.0.0";

            _writer.WriteLine();
            _writer.WriteLine("---");
            _writer.WriteLine("# Trowser Session Log");
            _writer.WriteLine($"**Started:** {_sessionStart:yyyy-MM-dd HH:mm:ss}  ");
            _writer.WriteLine($"**Trowser Version:** {versionText}  ");
            if (!string.IsNullOrEmpty(currentUrl))
                _writer.WriteLine($"**URL:** {currentUrl}  ");
            _writer.WriteLine("---");
            _writer.WriteLine();
        }
    }

    /// <summary>Stop logging and close the file.</summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (_writer == null) return;
            try
            {
                _writer.WriteLine();
                _writer.WriteLine($"---");
                _writer.WriteLine($"*Session ended: {DateTime.Now:yyyy-MM-dd HH:mm:ss}*");
                _writer.WriteLine();
                _writer.Flush();
                _writer.Dispose();
            }
            catch (Exception ex) { TrowserLog.Warn($"SessionLogger stop failed: {ex.Message}"); }
            _writer = null;
            _filePath = null;
        }
    }

    /// <summary>Log a browser action as its REST API equivalent (GUI-originated actions only).</summary>
    public void LogBrowserAction(string httpMethod, string apiPath, string? jsonBody, string? description = null)
    {
        if (!Settings.LogBrowserActions) return;
        if (SuppressGuiActions) return; // API call in progress — it will log its own entry

        var descPart = string.IsNullOrEmpty(description) ? "" : $" — {description}";
        var line = $"`{Timestamp()}` **Action** — {httpMethod} {apiPath}{descPart}";

        if (!string.IsNullOrEmpty(jsonBody))
        {
            line += Environment.NewLine + "```json" + Environment.NewLine + jsonBody + Environment.NewLine + "```";
        }

        WriteEntry(line);
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["method"] = httpMethod,
            ["path"] = apiPath
        };
        if (!string.IsNullOrEmpty(jsonBody))
            fields["body"] = jsonBody;
        AddJournal("action", "gui", $"{httpMethod} {apiPath}",
            descPart.Length > 0 ? description : null, fields: fields);
    }

    /// <summary>Log an API command from an LLM or external tool. Always stored in-memory; written to file when logging + LogApiUsage enabled.</summary>
    public void LogApiAction(string httpMethod, string apiPath, string? keyParams = null, bool isError = false, string? errorMessage = null, string? rawBody = null)
    {
        var summary = $"{httpMethod} {apiPath}";
        string? details = null;

        if (isError && !string.IsNullOrEmpty(errorMessage))
            details = errorMessage;
        else if (!string.IsNullOrEmpty(keyParams))
            details = keyParams;

        Dictionary<string, string>? fields = null;
        if (!isError)
        {
            fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["method"] = httpMethod,
                ["path"] = apiPath
            };
            if (!string.IsNullOrEmpty(rawBody))
                fields["body"] = rawBody;
        }

        var entry = AddJournal(isError ? "error" : "action", "api", summary, details, fields: fields);

        if (!IsLogging || !Settings.LogApiUsage) return;

        var errorTag = isError ? " ❌" : "";
        var detailsPart = !string.IsNullOrEmpty(details) ? $" — {details}" : "";
        WriteEntry($"`{Timestamp()}` **API{errorTag}** — {summary}{detailsPart}");
    }

    /// <summary>Log a plain tester note from the GUI. Shortcut for <see cref="LogTesterNote"/> with kind="note".</summary>
    public void LogNote(string text) => LogTesterNote(NoteKinds.Note, text);

    /// <summary>
    /// Log a structured note from the GUI tester. Kind describes what this entry represents
    /// (bug, enhancement, charter, observation, test-idea, testing, user, note).
    /// For bug/enhancement, <paramref name="fields"/> may contain: steps, actual, expected, priority, oracle, notes.
    /// </summary>
    public JournalEntry LogTesterNote(string kind, string text, string? severity = null,
        IReadOnlyDictionary<string, string>? fields = null, List<string>? tags = null, string? url = null,
        string? details = null)
    {
        return LogStructuredNote("gui", kind, text, severity, fields, Settings.LogNotes, tags, url, details: details);
    }

    /// <summary>
    /// Log a structured note from an LLM via POST /api/journal.
    /// Kind describes what this entry represents (bug, enhancement, charter, observation, test-idea, testing, user, note).
    /// For bug/enhancement, <paramref name="fields"/> may contain: steps, actual, expected, priority, oracle, notes.
    /// </summary>
    public JournalEntry LogLlmNote(string text, string? severity = null, string? kind = null,
        IReadOnlyDictionary<string, string>? fields = null,
        List<string>? tags = null, string? url = null, bool stepsIsArray = false, string? details = null,
        string? evidence = null)
    {
        return LogStructuredNote("api", kind ?? NoteKinds.Note, text, severity, fields, Settings.LogLlmNotes,
            tags, url, stepsIsArray, details, evidence);
    }

    /// <summary>Log a system-generated journal note (compacts, orchestration, etc.).</summary>
    public JournalEntry LogSystemNote(string text, string? details = null, List<string>? tags = null, string? kind = null)
    {
        return LogStructuredNote("system", kind ?? NoteKinds.Note, text, severity: null, fields: null,
            fileEnabled: Settings.LogLlmNotes, tags: tags, details: details);
    }

    /// <summary>
    /// Core structured-note writer. The journal entry's <see cref="JournalEntry.Type"/>
    /// is set to the kind so callers can filter with ?type=bug|charter|… on /api/journal.
    /// </summary>
    private JournalEntry LogStructuredNote(string source, string kind, string text, string? severity,
        IReadOnlyDictionary<string, string>? fields, bool fileEnabled,
        List<string>? tags = null, string? url = null, bool stepsIsArray = false, string? details = null,
        string? evidence = null)
    {
        var normalizedKind = NoteKinds.Normalize(kind);
        var normalizedEvidence = NoteKinds.ResolveEvidence(evidence, normalizedKind, source);
        Dictionary<string, string>? fieldsCopy = null;
        if (fields != null && fields.Count > 0)
        {
            fieldsCopy = new Dictionary<string, string>(fields.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var (k, v) in fields)
            {
                if (!string.IsNullOrWhiteSpace(v))
                    fieldsCopy[k] = v;
            }
            if (fieldsCopy.Count == 0) fieldsCopy = null;
        }

        if (NoteKinds.IsStructured(normalizedKind))
        {
            fieldsCopy ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            NoteKinds.AbsorbSeverityIntoPriority(severity, fieldsCopy);
            severity = null;
            if (fieldsCopy.Count == 0) fieldsCopy = null;
        }

        var entry = AddJournal(normalizedKind, source, text, details, severity: severity, kind: normalizedKind, fields: fieldsCopy,
            tags: tags, url: url, stepsIsArray: stepsIsArray, evidence: normalizedEvidence);

        if (!IsLogging || !fileEnabled) return entry;

        var label = NoteKinds.DisplayLabel(normalizedKind);
        var sourceTag = source == "api" ? "LLM " : "";
        var rank = severity;
        if (string.IsNullOrEmpty(rank) && fieldsCopy != null && fieldsCopy.TryGetValue("priority", out var pri))
            rank = pri;
        var rankTag = !string.IsNullOrEmpty(rank) ? $" [{rank}]" : "";
        var evidenceTag = !string.IsNullOrEmpty(normalizedEvidence) ? $" ({normalizedEvidence})" : "";
        var header = $"`{Timestamp()}` **{sourceTag}{label}{rankTag}**{evidenceTag} — {text}";

        if (fieldsCopy == null || fieldsCopy.Count == 0)
        {
            if (tags != null && tags.Count > 0)
                header += $"  \n  Tags: {string.Join(", ", tags)}";
            if (!string.IsNullOrEmpty(details))
                header += Environment.NewLine + details;
            WriteEntry(header);
        }
        else
        {
            var sb = new StringBuilder();
            sb.AppendLine(header);
            if (!string.IsNullOrEmpty(details))
                sb.AppendLine(details);
            if (tags != null && tags.Count > 0)
                sb.AppendLine($"  - **Tags:** {string.Join(", ", tags)}");
            if (!string.IsNullOrEmpty(url))
                sb.AppendLine($"  - **URL:** {url}");
            foreach (var key in NoteKinds.StructuredFieldOrder)
            {
                if (fieldsCopy.TryGetValue(key, out var val))
                    sb.AppendLine($"  - **{NoteKinds.FieldLabel(key)}:** {val}");
            }
            // Any custom fields not in the canonical order (except screenshot — rendered as reference below).
            foreach (var (k, v) in fieldsCopy)
            {
                var lk = k.ToLowerInvariant();
                if (lk == "screenshot") continue;
                if (Array.IndexOf(NoteKinds.StructuredFieldOrder, lk) < 0)
                    sb.AppendLine($"  - **{NoteKinds.FieldLabel(k)}:** {v}");
            }
            // Reference the attached screenshot by path (not embedded — keeps the journal lightweight).
            if (fieldsCopy.TryGetValue("screenshot", out var shotPath))
            {
                var rel = GetRelativePath(shotPath).Replace('\\', '/');
                sb.AppendLine($"  - **Screenshot:** `{rel}`");
            }
            WriteEntry(sb.ToString().TrimEnd());
        }
        return entry;
    }

    /// <summary>
    /// Log one completed recording as a single journal entry (counted 1 per recording, not per step).
    /// The human-readable steps are stored newline-joined in <c>fields["steps"]</c> so the Journal panel
    /// can open the full detail in a tab. When <paramref name="forceJournal"/> is true (explicit destination),
    /// the in-memory journal entry is always written; <see cref="SessionLogSettings.LogRecordings"/> only
    /// gates the optional session <c>.md</c> file. When not forced, the setting gates the whole entry.
    /// Optional <paramref name="csx"/> embeds the replayable script for Show me.
    /// </summary>
    public JournalEntry? LogRecording(string label, IReadOnlyList<string> steps, string? url = null,
        string? csx = null, string? csxPath = null, bool forceJournal = false)
    {
        if (!forceJournal && !Settings.LogRecordings) return null;
        if ((steps == null || steps.Count == 0) && string.IsNullOrWhiteSpace(csx)) return null;

        var summary = string.IsNullOrWhiteSpace(label) ? "Recording" : label.Trim();
        var stepList = steps ?? Array.Empty<string>();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["steps"] = string.Join("\n", stepList)
        };
        if (!string.IsNullOrWhiteSpace(csx))
            fields["csx"] = csx;
        if (!string.IsNullOrWhiteSpace(csxPath))
            fields["csxPath"] = csxPath!;

        var entry = AddJournal("recording", "gui", summary, url: url, fields: fields);

        if (IsLogging && Settings.LogRecordings)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"`{Timestamp()}` **Recording** — {summary} ({stepList.Count} step{(stepList.Count == 1 ? "" : "s")})");
            foreach (var step in stepList)
                sb.AppendLine($"  - {step}");
            WriteEntry(sb.ToString().TrimEnd());
        }

        return entry;
    }

    /// <summary>Log a message displayed via POST /api/message.</summary>
    public void LogMessage(string text, string level)
    {
        if (!Settings.LogMessages) return;

        WriteEntry($"`{Timestamp()}` **Message** ({level}) — {text}");
        AddJournal("message", "api", text, level);
    }

    /// <summary>Log an assert from the right-click context menu.</summary>
    public void LogAssert(string text)
    {
        WriteEntry($"`{Timestamp()}` **Assert** — Page contains: \"{text}\"");
        AddJournal("assertion", "gui", $"Page contains: \"{text}\"");
    }

    /// <summary>Log an API assertion result.</summary>
    public void LogApiAssert(string description, bool passed, string? details = null)
    {
        var result = passed ? "PASS" : "FAIL";
        var entry = AddJournal("assertion", "api", $"{result}: {description}", details);

        if (!IsLogging || !Settings.LogApiUsage) return;
        var icon = passed ? "✅" : "❌";
        WriteEntry($"`{Timestamp()}` **Assert {icon}** — {result}: {description}");
    }

    /// <summary>Log an element of interest from the right-click context menu.</summary>
    public void LogElementOfInterest(string tag, string text, string role, string label)
    {
        var desc = !string.IsNullOrEmpty(label) ? $"{tag} \"{label}\""
                 : !string.IsNullOrEmpty(text) ? $"{tag} \"{text}\""
                 : tag;
        WriteEntry($"`{Timestamp()}` **Element of interest** — {desc}");
        AddJournal("observation", "gui", desc);
    }

    /// <summary>
    /// Log the creation of a pointer. The pointer id is stored in <c>Fields["pointerId"]</c>
    /// so the journal doubles as the handoff record and consumers can re-render the pointer.
    /// </summary>
    public JournalEntry LogPointer(string author, string kind, string? caption, string pointerId, string? url = null)
    {
        var source = author == "human" ? "gui" : "api";
        var summary = string.IsNullOrWhiteSpace(caption) ? $"Pointer ({kind})" : caption.Trim();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["pointerId"] = pointerId,
            ["pointerKind"] = kind
        };
        var entry = AddJournal("pointer", source, summary, fields: fields, url: url);

        if (IsLogging)
        {
            var sourceTag = source == "api" ? "Agent " : "";
            WriteEntry($"`{Timestamp()}` **{sourceTag}Pointer** ({kind}) — {summary}");
        }

        return entry;
    }

    /// <summary>
    /// Log the moment the agent asked the human to make a call. The decision id is stored in
    /// <c>Fields["decisionId"]</c> so the ask and its resolution can be paired up later.
    /// </summary>
    public JournalEntry LogDecisionAsked(string question, string lane, string options,
        string? recommendation, string decisionId, string? url = null)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["decisionId"] = decisionId,
            ["decisionLane"] = lane,
            ["decisionPhase"] = "asked",
            ["decisionOptions"] = options
        };
        if (!string.IsNullOrWhiteSpace(recommendation))
            fields["decisionRecommendation"] = recommendation;

        var entry = AddJournal("decision", "api", question.Trim(), details: options, fields: fields, url: url);

        if (IsLogging)
            WriteEntry($"`{Timestamp()}` **Agent asks** ({lane}) — {question.Trim()} — {options}");

        return entry;
    }

    /// <summary>
    /// Log how a decision ended. This is the accountability half of the record: it distinguishes a
    /// call the tester actually made from a default that fired because nobody answered.
    /// </summary>
    public JournalEntry LogDecisionResolved(string question, string decisionId, string status,
        string? answerKey, string? answerLabel, string? answeredBy, string? note = null, bool isOtherAnswer = false)
    {
        var source = answeredBy == "human" ? "gui" : "system";
        var answer = answerKey == null
            ? "(no answer)"
            : isOtherAnswer
                ? $"Other: {answerLabel}"
                : $"{answerKey}) {answerLabel}";

        var summary = status switch
        {
            "answered" => $"Tester chose {answer} — {question.Trim()}",
            "defaulted" => $"Defaulted to {answer} (nobody answered) — {question.Trim()}",
            "expired" => $"No answer and no default — {question.Trim()}",
            "cancelled" => $"Agent withdrew the question — {question.Trim()}",
            _ => $"{status}: {answer} — {question.Trim()}"
        };

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["decisionId"] = decisionId,
            ["decisionPhase"] = "resolved",
            ["decisionStatus"] = status
        };
        if (answerKey != null) fields["decisionAnswer"] = answerKey;
        if (!string.IsNullOrWhiteSpace(answerLabel)) fields["decisionAnswerLabel"] = answerLabel;
        if (!string.IsNullOrWhiteSpace(answeredBy)) fields["decisionAnsweredBy"] = answeredBy;

        var entry = AddJournal("decision", source, summary, details: note, fields: fields,
            evidence: NoteKinds.EvidenceObserved);

        if (IsLogging)
        {
            var suffix = string.IsNullOrWhiteSpace(note) ? "" : $" — \"{note.Trim()}\"";
            WriteEntry($"`{Timestamp()}` **Decision {status}** — {summary}{suffix}");
        }

        return entry;
    }

    /// <summary>Log script console output after execution.</summary>
    public void LogScriptOutput(string output)
    {
        if (!Settings.LogScriptOutput) return;
        if (string.IsNullOrWhiteSpace(output)) return;

        var entry = $"`{Timestamp()}` **Script Output**" + Environment.NewLine
            + "```" + Environment.NewLine
            + output.TrimEnd() + Environment.NewLine
            + "```";

        WriteEntry(entry);
        AddJournal("script-output", "system", output.Length > 200 ? output[..200] + "…" : output);
    }

    /// <summary>
    /// Log a screenshot. Always stored in the in-memory journal; written to the session .md
    /// when logging is on and <see cref="SessionLogSettings.LogScreenshots"/> is enabled.
    /// </summary>
    public JournalEntry LogScreenshot(string absolutePath, string source = "system", string? caption = null)
    {
        var relativePath = GetRelativePath(absolutePath);
        var summary = string.IsNullOrWhiteSpace(caption) ? relativePath : caption.Trim();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["screenshot"] = absolutePath
        };
        var entry = AddJournal("screenshot", source, summary, details: relativePath, fields: fields);

        if (IsLogging && Settings.LogScreenshots)
        {
            var rel = relativePath.Replace('\\', '/');
            var captionPart = string.IsNullOrWhiteSpace(caption) ? "" : $" — {caption.Trim()}";
            WriteEntry($"`{Timestamp()}` **Screenshot**{captionPart} — ![screenshot]({rel})");
        }

        return entry;
    }

    // ----- Journal API -----

    /// <summary>Get journal entries, with optional filtering by index, type, source, tag, evidence, and free-text search.</summary>
    public List<JournalEntry> GetJournal(int? since = null, int? last = null, string? type = null, string? source = null, string? tag = null, string? evidence = null, string? origin = null, string? q = null)
    {
        lock (_lock)
        {
            IEnumerable<JournalEntry> query = _journal;

            if (since.HasValue)
                query = query.Where(e => e.Index > since.Value);

            if (!string.IsNullOrEmpty(type))
                query = query.Where(e => e.Type.Equals(type, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(source))
                query = query.Where(e => e.Source.Equals(source, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(tag))
                query = query.Where(e => e.Tags != null && e.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(evidence))
                query = query.Where(e => e.Evidence.Equals(evidence, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(origin))
                query = query.Where(e => GetOrigin(e.Source).Equals(origin, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrEmpty(q))
                query = query.Where(e => MatchesSearch(e, q));

            var result = query.ToList();

            if (last.HasValue && last.Value > 0 && result.Count > last.Value)
                result = result.Skip(result.Count - last.Value).ToList();

            return result;
        }
    }

    /// <summary>Case-insensitive match across summary, details, URL, tags, and field values.</summary>
    public static bool MatchesSearch(JournalEntry e, string q)
    {
        if (string.IsNullOrWhiteSpace(q)) return true;
        if (ContainsIgnoreCase(e.Summary, q)
            || ContainsIgnoreCase(e.Details, q)
            || ContainsIgnoreCase(e.Url, q)
            || ContainsIgnoreCase(e.Type, q)
            || ContainsIgnoreCase(e.Kind, q)
            || ContainsIgnoreCase(e.Source, q)
            || ContainsIgnoreCase(e.Evidence, q)
            || ContainsIgnoreCase(e.Severity, q))
            return true;
        if (e.Tags != null && e.Tags.Any(t => ContainsIgnoreCase(t, q)))
            return true;
        if (e.Fields != null && e.Fields.Any(kv => ContainsIgnoreCase(kv.Key, q) || ContainsIgnoreCase(kv.Value, q)))
            return true;
        return false;
    }

    private static bool ContainsIgnoreCase(string? haystack, string needle) =>
        !string.IsNullOrEmpty(haystack) && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>Fetch specific journal entries by index (preserves caller order; skips missing/deleted).</summary>
    public List<JournalEntry> GetEntriesByIndexes(IEnumerable<int> indexes)
    {
        lock (_lock)
        {
            var result = new List<JournalEntry>();
            foreach (var index in indexes)
            {
                var entry = _journal.FirstOrDefault(e => e.Index == index);
                if (entry != null)
                    result.Add(entry);
            }
            return result;
        }
    }

    /// <summary>Map journal source to human-facing origin: agent, user, or auto.</summary>
    public static string GetOrigin(string source) => source switch
    {
        "api" => "agent",
        "gui" => "user",
        _ => "auto"
    };

    /// <summary>Total journal entry count (lock-free for perf checks).</summary>
    public int JournalCount
    {
        get { lock (_lock) { return _journal.Count; } }
    }

    /// <summary>
    /// Highest journal index assigned so far (-1 if none). Used to bound a checkpoint:
    /// pass this to <see cref="GetJournal"/>'s <c>since</c> to get "everything after".
    /// </summary>
    public int LastJournalIndex
    {
        get { lock (_lock) { return _nextJournalIndex - 1; } }
    }

    /// <summary>
    /// Monotonic generation counter. Increments on add, update, and delete so pollers
    /// can detect mutations that <c>?since=</c> (new indices only) would miss.
    /// </summary>
    public int Revision
    {
        get { lock (_lock) { return _revision; } }
    }

    /// <summary>Indices removed this process session. Never reused.</summary>
    public IReadOnlyList<int> DeletedIndices
    {
        get { lock (_lock) { return _deletedIndices.ToList(); } }
    }

    /// <summary>Look up a live entry by index, or null if missing / deleted.</summary>
    public JournalEntry? GetEntry(int index)
    {
        lock (_lock)
            return _journal.FirstOrDefault(e => e.Index == index);
    }

    /// <summary>
    /// Import a previously exported journal entry. A new index is assigned (never reused);
    /// timestamp, type, source, fields, tags, and pointer ids are preserved.
    /// </summary>
    public JournalEntry ImportEntry(JournalEntry source)
    {
        var fields = source.Fields == null
            ? null
            : new Dictionary<string, string>(source.Fields, StringComparer.OrdinalIgnoreCase);
        var tags = source.Tags == null ? null : new List<string>(source.Tags);

        JournalEntry entry;
        lock (_lock)
        {
            entry = new JournalEntry
            {
                Index = _nextJournalIndex++,
                Timestamp = source.Timestamp == default ? DateTime.Now : source.Timestamp,
                Type = string.IsNullOrWhiteSpace(source.Type) ? (source.Kind ?? "note") : source.Type,
                Source = string.IsNullOrWhiteSpace(source.Source) ? "system" : source.Source,
                Summary = source.Summary ?? "",
                Details = source.Details,
                Severity = source.Severity,
                Kind = source.Kind ?? source.Type,
                Fields = fields,
                Tags = tags,
                Url = source.Url,
                StepsIsArray = source.StepsIsArray,
                Evidence = string.IsNullOrWhiteSpace(source.Evidence)
                    ? NoteKinds.EvidenceInferred
                    : source.Evidence
            };
            _journal.Add(entry);
            _revision++;
        }

        try { JournalChanged?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"JournalChanged handler failed: {ex.Message}"); }
        return entry;
    }

    /// <summary>
    /// Replace editable fields on an existing entry. Index, timestamp, and original source are kept.
    /// Returns the updated entry, or null if the index is unknown.
    /// </summary>
    public JournalEntry? UpdateEntry(int index, string? kind = null, string? summary = null,
        string? details = null, bool setDetails = false,
        string? severity = null, bool setSeverity = false,
        IReadOnlyDictionary<string, string>? fields = null, bool setFields = false,
        List<string>? tags = null, bool setTags = false,
        string? url = null, bool setUrl = false,
        bool? stepsIsArray = null,
        string? evidence = null, bool setEvidence = false)
    {
        JournalEntry? entry;
        lock (_lock)
        {
            entry = _journal.FirstOrDefault(e => e.Index == index);
            if (entry == null) return null;

            if (!string.IsNullOrWhiteSpace(kind))
            {
                var normalized = NoteKinds.Normalize(kind);
                if (NoteKinds.IsKnown(normalized))
                {
                    entry.Kind = normalized;
                    entry.Type = normalized;
                }
            }

            if (summary != null)
                entry.Summary = summary;

            if (setDetails)
                entry.Details = string.IsNullOrWhiteSpace(details) ? null : details;

            if (setSeverity)
                entry.Severity = string.IsNullOrWhiteSpace(severity) ? null : severity;

            if (setFields)
            {
                if (fields == null || fields.Count == 0)
                {
                    entry.Fields = null;
                }
                else
                {
                    var copy = new Dictionary<string, string>(fields.Count, StringComparer.OrdinalIgnoreCase);
                    foreach (var (k, v) in fields)
                    {
                        if (!string.IsNullOrWhiteSpace(v))
                            copy[k] = v;
                    }
                    entry.Fields = copy.Count == 0 ? null : copy;
                }
            }

            if (setTags)
            {
                entry.Tags = tags == null || tags.Count == 0 ? null : tags;
            }

            if (setUrl)
                entry.Url = string.IsNullOrWhiteSpace(url) ? null : url;

            if (stepsIsArray.HasValue)
                entry.StepsIsArray = stepsIsArray.Value;

            if (setEvidence)
            {
                if (string.IsNullOrWhiteSpace(evidence))
                    entry.Evidence = NoteKinds.ResolveEvidence(null, entry.Kind ?? entry.Type, entry.Source);
                else if (NoteKinds.TryNormalizeEvidence(evidence, out var normalizedEvidence))
                    entry.Evidence = normalizedEvidence;
            }

            if (NoteKinds.IsStructured(entry.Kind ?? entry.Type))
            {
                var structuredFields = entry.Fields != null
                    ? new Dictionary<string, string>(entry.Fields, StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                NoteKinds.AbsorbSeverityIntoPriority(entry.Severity, structuredFields);
                entry.Severity = null;
                entry.Fields = structuredFields.Count == 0 ? null : structuredFields;
            }

            _revision++;
        }

        if (IsLogging)
        {
            var label = NoteKinds.DisplayLabel(entry.Kind ?? entry.Type);
            WriteEntry($"`{Timestamp()}` **Edited #{index}** — {label}: {entry.Summary}");
        }

        try { JournalChanged?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"JournalChanged handler failed: {ex.Message}"); }

        return entry;
    }

    /// <summary>
    /// Remove an entry by index. The index is never reused. Returns false if it was already gone.
    /// </summary>
    public bool DeleteEntry(int index)
    {
        JournalEntry? removed;
        lock (_lock)
        {
            var i = _journal.FindIndex(e => e.Index == index);
            if (i < 0) return false;
            removed = _journal[i];
            _journal.RemoveAt(i);
            _deletedIndices.Add(index);
            _revision++;
        }

        if (IsLogging)
            WriteEntry($"`{Timestamp()}` **Deleted #{index}** — {removed!.Type}: {removed.Summary}");

        try { JournalChanged?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"JournalChanged handler failed: {ex.Message}"); }

        return true;
    }

    /// <summary>Flush the session .md writer so another reader can see the latest bytes.</summary>
    public void Flush()
    {
        lock (_lock)
        {
            try { _writer?.Flush(); }
            catch (Exception ex) { TrowserLog.Warn($"SessionLogger flush failed: {ex.Message}"); }
        }
    }

    // ----- Helpers -----

    private void WriteEntry(string entry)
    {
        lock (_lock)
        {
            if (_writer == null) return;
            try
            {
                _writer.WriteLine(entry);
                _writer.WriteLine();
            }
            catch (Exception ex) { TrowserLog.Warn($"SessionLogger write failed: {ex.Message}"); }
        }
    }

    private JournalEntry AddJournal(string type, string source, string summary, string? details = null,
        string? severity = null, string? kind = null, Dictionary<string, string>? fields = null,
        List<string>? tags = null, string? url = null, bool stepsIsArray = false, string? evidence = null)
    {
        JournalEntry entry;
        lock (_lock)
        {
            var effectiveKind = kind ?? type;
            entry = new JournalEntry
            {
                Index = _nextJournalIndex++,
                Timestamp = DateTime.Now,
                Type = type,
                Source = source,
                Summary = summary,
                Details = details,
                Severity = severity,
                // Kind mirrors Type for auto-logged entries (action, assertion, message, screenshot, etc.)
                // so consumers can always filter/display by `kind` consistently with note-style entries.
                Kind = effectiveKind,
                Fields = fields,
                Tags = tags,
                Url = url,
                StepsIsArray = stepsIsArray,
                Evidence = NoteKinds.ResolveEvidence(evidence, effectiveKind, source, type)
            };
            _journal.Add(entry);
            _revision++;
        }

        // Fire outside the lock so slow/UI-marshalling handlers can't stall other writers.
        try { JournalChanged?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"JournalChanged handler failed: {ex.Message}"); }

        return entry;
    }

    private string Timestamp() => DateTime.Now.ToString("HH:mm:ss");

    private string GetRelativePath(string absolutePath)
    {
        if (_filePath == null) return absolutePath;
        try
        {
            var logDir = Path.GetDirectoryName(Path.GetFullPath(_filePath))!;
            return Path.GetRelativePath(logDir, absolutePath);
        }
        catch { return absolutePath; }
    }

    // ----- Entry types -----

    /// <summary>
    /// Unified journal entry that represents any session event — actions, notes,
    /// assertions, messages, screenshots, API usage, or errors.
    /// </summary>
    public class JournalEntry
    {
        /// <summary>Sequential index, monotonically increasing. Used for ?since=N polling.</summary>
        public int Index { get; set; }
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// Entry type: action, assertion, message, screenshot, script-output, error, or one of the
        /// note-kind values (note, bug, enhancement, observation, charter, testing, test-idea, user).
        /// </summary>
        public string Type { get; set; } = "";
        /// <summary>Who generated this entry: api, gui, system</summary>
        public string Source { get; set; } = "";
        /// <summary>Short human-readable description of what happened.</summary>
        public string Summary { get; set; } = "";
        /// <summary>Optional additional context (error message, assertion details, key params).</summary>
        public string? Details { get; set; }
        /// <summary>
        /// Optional severity for free-form notes (info, low, medium, high, critical).
        /// Bugs and enhancements use <c>fields["priority"]</c> instead — this is not stored for those kinds.
        /// </summary>
        public string? Severity { get; set; }
        /// <summary>
        /// Note kind (for note-style entries only): note, bug, enhancement, observation,
        /// charter, testing, test-idea, user. Null for action/assertion/message/etc.
        /// </summary>
        public string? Kind { get; set; }
        /// <summary>
        /// Structured fields for bug/enhancement (steps, actual, expected, priority, oracle, notes)
        /// or other extra metadata. Null when no structured fields were provided.
        /// </summary>
        public Dictionary<string, string>? Fields { get; set; }
        /// <summary>Optional tags for grouping/filtering by functionality, quality characteristic, etc.</summary>
        public List<string>? Tags { get; set; }
        /// <summary>Page URL at the time the entry was logged. Auto-captured or caller-supplied.</summary>
        public string? Url { get; set; }
        /// <summary>When true, the <c>steps</c> field was submitted as an array and should be returned as one.</summary>
        public bool StepsIsArray { get; set; }
        /// <summary>
        /// Epistemic classification orthogonal to kind: observed, inferred, hypothesis, or untested.
        /// </summary>
        public string Evidence { get; set; } = NoteKinds.EvidenceInferred;
    }
}

/// <summary>
/// Known note kinds for structured journal entries — the vocabulary shared between
/// the REST API (POST /api/journal), the MCP tools, and the GUI tester overlay.
/// </summary>
public static class NoteKinds
{
    public const string Note = "note";
    public const string User = "user";
    public const string Charter = "charter";
    public const string Testing = "testing";
    public const string TestIdea = "test-idea";
    public const string Observation = "observation";
    public const string Bug = "bug";
    public const string Enhancement = "enhancement";

    /// <summary>All valid kinds for note-style journal entries.</summary>
    public static readonly string[] All =
    [
        Note, User, Charter, Testing, TestIdea, Observation, Bug, Enhancement
    ];

    /// <summary>Kinds that accept structured fields (steps/actual/expected/priority/oracle/notes).</summary>
    public static readonly string[] StructuredKinds = [Bug, Enhancement];

    /// <summary>True when <paramref name="kind"/> is bug or enhancement (after synonym normalisation).</summary>
    public static bool IsStructured(string? kind) => Array.IndexOf(StructuredKinds, Normalize(kind)) >= 0;

    /// <summary>Canonical order for rendering structured fields in the log file.</summary>
    public static readonly string[] StructuredFieldOrder =
    [
        "steps", "actual", "expected", "priority", "oracle", "notes"
    ];

    /// <summary>
    /// Allowed <c>severity</c> values for free-form journal notes (<c>POST /api/journal</c>, MCP <c>browser_journal_add</c>).
    /// Not used for bug/enhancement — those rank with <c>priority</c>.
    /// </summary>
    public static readonly string[] JournalSeverities =
        ["info", "low", "medium", "high", "critical"];

    /// <summary>Allowed <c>priority</c> values for bug/enhancement entries.</summary>
    public static readonly string[] JournalPriorities = ["low", "medium", "high", "critical"];

    public const string EvidenceObserved = "observed";
    public const string EvidenceInferred = "inferred";
    public const string EvidenceHypothesis = "hypothesis";
    public const string EvidenceUntested = "untested";

    /// <summary>Allowed <c>evidence</c> values for journal entries.</summary>
    public static readonly string[] EvidenceLevels =
        [EvidenceObserved, EvidenceInferred, EvidenceHypothesis, EvidenceUntested];

    /// <summary>
    /// When <paramref name="raw"/> is non-null, validates and returns the canonical lowercase token.
    /// Returns false if <paramref name="raw"/> is empty/whitespace or not a known severity.
    /// </summary>
    public static bool TryNormalizeJournalSeverity(string? raw, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        normalized = raw.Trim().ToLowerInvariant();
        return Array.IndexOf(JournalSeverities, normalized) >= 0;
    }

    /// <summary>
    /// When <paramref name="raw"/> is non-null, validates and returns the canonical lowercase token.
    /// Returns false if <paramref name="raw"/> is empty/whitespace or not a known priority.
    /// </summary>
    public static bool TryNormalizeJournalPriority(string? raw, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        normalized = raw.Trim().ToLowerInvariant();
        return Array.IndexOf(JournalPriorities, normalized) >= 0;
    }

    /// <summary>
    /// When <paramref name="raw"/> is non-null, validates and returns the canonical lowercase token.
    /// Returns false if <paramref name="raw"/> is empty/whitespace or not a known evidence level.
    /// </summary>
    public static bool TryNormalizeEvidence(string? raw, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(raw)) return false;
        normalized = raw.Trim().ToLowerInvariant();
        return Array.IndexOf(EvidenceLevels, normalized) >= 0;
    }

    /// <summary>Default evidence when the caller omits it.</summary>
    public static string ResolveEvidence(string? raw, string kind, string source, string? type = null)
    {
        if (TryNormalizeEvidence(raw, out var normalized))
            return normalized;

        var k = Normalize(kind);
        if (k == TestIdea)
            return EvidenceUntested;

        var t = (type ?? k).ToLowerInvariant();
        if (t is "action" or "assertion" or "error" or "screenshot" or "recording"
            or "script-output" or "message")
            return EvidenceObserved;

        if (source is "api" or "gui")
            return EvidenceInferred;

        return EvidenceObserved;
    }

    /// <summary>
    /// Bugs and enhancements rank with <c>fields["priority"]</c> only. If the caller sent a
    /// compatible severity and no priority, copy it into <paramref name="fields"/>.
    /// </summary>
    public static void AbsorbSeverityIntoPriority(string? severity, Dictionary<string, string> fields)
    {
        if (fields.ContainsKey("priority")) return;
        if (TryNormalizeJournalPriority(severity, out var pri))
            fields["priority"] = pri;
    }

    /// <summary>Normalise a user-supplied kind string. Returns <see cref="Note"/> if null/empty.</summary>
    public static string Normalize(string? kind)
    {
        if (string.IsNullOrWhiteSpace(kind)) return Note;
        var k = kind.Trim().ToLowerInvariant().Replace('_', '-').Replace(' ', '-');
        // Accept common synonyms
        return k switch
        {
            "testidea" or "idea" => TestIdea,
            "enh" or "feature" or "feature-request" => Enhancement,
            "defect" or "issue" => Bug,
            _ => k
        };
    }

    /// <summary>True when <paramref name="kind"/> is a recognised note kind.</summary>
    public static bool IsKnown(string? kind) => kind != null && Array.IndexOf(All, kind) >= 0;

    /// <summary>
    /// Split a free-form text box into title (first line) and optional markdown body (the rest).
    /// </summary>
    public static void SplitTitleBody(string? text, out string title, out string? body)
    {
        title = "";
        body = null;
        if (string.IsNullOrWhiteSpace(text)) return;

        var raw = text.Replace("\r\n", "\n").Trim();
        var nl = raw.IndexOf('\n');
        if (nl < 0)
        {
            title = raw;
            return;
        }

        title = raw[..nl].Trim();
        var rest = raw[(nl + 1)..].Trim();
        body = string.IsNullOrEmpty(rest) ? null : rest;
        if (string.IsNullOrEmpty(title) && body != null)
        {
            var collapsed = body.Replace('\n', ' ').Trim();
            title = collapsed.Length > 120 ? collapsed[..117] + "..." : collapsed;
        }
    }

    /// <summary>Human-readable title-case label for a kind (used in markdown log file).</summary>
    public static string DisplayLabel(string kind) => kind switch
    {
        Note => "Note",
        User => "User",
        Charter => "Charter",
        Testing => "Testing",
        TestIdea => "Test idea",
        Observation => "Observation",
        Bug => "Bug",
        Enhancement => "Enhancement",
        _ => char.ToUpperInvariant(kind[0]) + kind[1..]
    };

    /// <summary>Human-readable label for a structured field key.</summary>
    public static string FieldLabel(string key) => key.ToLowerInvariant() switch
    {
        "steps" => "Steps",
        "actual" => "Actual",
        "expected" => "Expected",
        "priority" => "Priority",
        "oracle" => "Oracle",
        "notes" => "Notes",
        "screenshot" => "Screenshot",
        _ => char.ToUpperInvariant(key[0]) + key[1..]
    };
}
