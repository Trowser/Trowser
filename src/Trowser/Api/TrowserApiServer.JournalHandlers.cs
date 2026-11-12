using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    #region Message Overlay

    /// <summary>
    /// Display a message overlay in the Trowser UI. Bypasses the gate — no browser interaction.
    /// Called from both the REST endpoint and the MCP tool.
    /// </summary>
    internal Task<(bool Success, string? Error)> ShowMessageAsync(string text, string level, int durationMs)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Task.FromResult<(bool, string?)>((false, "Missing required field: text"));

        var validLevels = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "info", "warning", "error" };
        if (!validLevels.Contains(level))
            level = "info";

        durationMs = Math.Clamp(durationMs, 1000, 60000);

        var callback = OnShowMessage;
        if (callback == null)
            return Task.FromResult<(bool, string?)>((false, "Message display not available — no UI connected."));

        callback(text, level.ToLowerInvariant(), durationMs);
        return Task.FromResult<(bool, string?)>((true, null));
    }

    private async Task HandlePostMessage(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var text = body.GetString("text");
        var level = body.GetString("level") ?? "info";
        var durationMs = body.GetInt("duration", 8000);

        var (success, error) = await ShowMessageAsync(text ?? "", level, durationMs);
        if (!success)
        {
            await WriteError(response, 400, error!);
            return;
        }

        await WriteSuccess(response, new
        {
            message = "Message displayed.",
            text,
            level = level.ToLowerInvariant(),
            duration = durationMs
        });
    }

    #endregion

    #region Journal Endpoints

    /// <summary>
    /// Project a <see cref="SessionLogger.JournalEntry"/> into the shape returned by the REST API.
    /// </summary>
    private static object ProjectEntryForResponse(SessionLogger.JournalEntry e) =>
        JournalProjection.ProjectEntry(e);

    private static object ProjectEntryIndexForResponse(SessionLogger.JournalEntry e) =>
        JournalProjection.ProjectEntryIndex(e);

    private async Task HandleGetJournal(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (SessionLogger == null)
        {
            await WriteSuccess(response, new { entries = Array.Empty<object>(), count = 0, total = 0, logging = false, revision = 0, deleted = Array.Empty<int>() });
            return;
        }

        var query = ApiQuery(request);
        int? since = int.TryParse(query["since"], out var s) ? s : null;
        int? last = int.TryParse(query["last"], out var l) ? l : null;
        var type = query["type"];
        var source = query["source"];
        var tag = query["tag"];
        var evidence = query["evidence"];
        var origin = query["origin"];
        var q = query["q"] ?? query["search"];
        var view = query["view"];
        var indexes = JournalProjection.ParseIndexes(query["indexes"]);

        List<SessionLogger.JournalEntry> journal;
        if (indexes != null)
        {
            journal = SessionLogger.GetEntriesByIndexes(indexes);
        }
        else
        {
            journal = SessionLogger.GetJournal(since, last, type, source, tag, evidence, origin, q);
            if (string.IsNullOrEmpty(view)
                && SessionLogger.JournalCount > JournalProjection.DefaultIndexViewThreshold
                && indexes == null)
            {
                view = "index";
            }
        }

        var useIndexView = string.Equals(view, "index", StringComparison.OrdinalIgnoreCase);
        var entries = useIndexView
            ? journal.Select(e => ProjectEntryIndexForResponse(e)).ToArray()
            : journal.Select(e => ProjectEntryForResponse(e)).ToArray();

        await WriteSuccess(response, new
        {
            entries,
            count = entries.Length,
            total = SessionLogger.JournalCount,
            logging = SessionLogger.IsLogging,
            revision = SessionLogger.Revision,
            deleted = SessionLogger.DeletedIndices,
            view = useIndexView ? "index" : "full"
        });
    }

    private async Task HandlePostJournal(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        // Determine kind. Default to "note" when omitted; accept common synonyms via NoteKinds.Normalize.
        var rawKind = body.GetString("kind");
        var kind = NoteKinds.Normalize(rawKind);
        if (rawKind != null && !NoteKinds.IsKnown(kind))
        {
            await WriteError(response, 400,
                $"Invalid kind '{rawKind}'. Use one of: {string.Join(", ", NoteKinds.All)}.");
            return;
        }

        // Primary text: accept any of `note`, `text`, or `title` (in that priority order for legacy compat).
        var text = body.GetString("note")
                   ?? body.GetString("text")
                   ?? body.GetString("title");
        var details = body.GetString("details");
        if (details == null && text != null && text.IndexOf('\n') >= 0)
            NoteKinds.SplitTitleBody(text, out text, out details);

        string? severity = null;
        var rawSeverity = body.GetString("severity");
        if (rawSeverity != null)
        {
            if (!NoteKinds.TryNormalizeJournalSeverity(rawSeverity, out var normalizedSeverity))
            {
                await WriteError(response, 400,
                    $"Invalid severity. Use: {string.Join(", ", NoteKinds.JournalSeverities)}.");
                return;
            }
            severity = normalizedSeverity;
        }

        string? evidence = null;
        var rawEvidence = body.GetString("evidence");
        if (rawEvidence != null)
        {
            if (!NoteKinds.TryNormalizeEvidence(rawEvidence, out var normalizedEvidence))
            {
                await WriteError(response, 400,
                    $"Invalid evidence. Use: {string.Join(", ", NoteKinds.EvidenceLevels)}.");
                return;
            }
            evidence = normalizedEvidence;
        }

        // Tags: accept as string array, normalize (trim, lowercase, dedupe, drop empties)
        List<string>? tags = null;
        var rawTags = body.GetStringList("tags");
        if (rawTags != null)
        {
            tags = rawTags
                .Select(t => t.Trim().ToLowerInvariant())
                .Where(t => t.Length > 0)
                .Distinct()
                .ToList();
            if (tags.Count == 0) tags = null;
        }

        // URL: prefer caller-supplied; fall back to auto-capture from the browser (best effort)
        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            try { url = await _context.GetCurrentUrl(); } catch { /* best effort */ }
            if (string.IsNullOrWhiteSpace(url)) url = null;
        }

        // Gather structured fields. `screenshot` is allowed on any kind; the bug/enhancement
        // fields (steps/actual/expected/priority/oracle/notes) are collected when applicable.
        Dictionary<string, string>? fields = null;
        bool isStructured = Array.IndexOf(NoteKinds.StructuredKinds, kind) >= 0;
        bool stepsIsArray = false;

        var screenshot = body.GetString("screenshot");
        if (!string.IsNullOrWhiteSpace(screenshot))
        {
            fields ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            fields["screenshot"] = screenshot.Trim();
        }

        if (isStructured)
        {
            fields ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var key in NoteKinds.StructuredFieldOrder)
            {
                if (key == "steps")
                {
                    // Accept steps as either a string or a JSON array of strings
                    var stepsArray = body.GetStringList("steps");
                    if (stepsArray != null && stepsArray.Count > 0)
                    {
                        fields["steps"] = string.Join("\n", stepsArray);
                        stepsIsArray = true;
                    }
                    else
                    {
                        var v = body.GetString(key);
                        if (!string.IsNullOrWhiteSpace(v)) fields[key] = v;
                    }
                }
                else
                {
                    var v = body.GetString(key);
                    if (!string.IsNullOrWhiteSpace(v)) fields[key] = v;
                }
            }

            var priority = body.GetString("priority");
            if (priority != null
                && priority != "low" && priority != "medium" && priority != "high" && priority != "critical")
            {
                await WriteError(response, 400, "Invalid priority. Use: low, medium, high, or critical.");
                return;
            }

            // Require *some* substantive content for a bug/enhancement.
            if (string.IsNullOrWhiteSpace(text) && fields.Count == 0)
            {
                await WriteError(response, 400,
                    $"A '{kind}' entry needs at least a title/text, or one of: steps, actual, expected, notes.");
                return;
            }

            // Synthesise a title when only structured fields were supplied.
            if (string.IsNullOrWhiteSpace(text))
            {
                text = fields.TryGetValue("actual", out var a) ? a
                     : fields.TryGetValue("steps", out var s) ? s
                     : fields.TryGetValue("notes", out var n) ? n
                     : $"(untitled {kind})";
                var trimmed = text!.Replace("\r", " ").Replace("\n", " ").Trim();
                if (trimmed.Length > 120) trimmed = trimmed[..117] + "...";
                text = trimmed;
            }
        }
        else if (string.IsNullOrWhiteSpace(text))
        {
            await WriteError(response, 400,
                "Missing required field: provide `note` (or `text`/`title`) for the journal entry.");
            return;
        }

        var entry = SessionLogger!.LogLlmNote(text!, severity, kind, fields, tags, url, stepsIsArray, details, evidence);

        await WriteSuccess(response, ProjectEntryForResponse(entry));
    }

    private async Task HandlePatchJournal(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (SessionLogger == null)
        {
            await WriteError(response, 503, "Session logger not available.");
            return;
        }

        var body = await ReadJsonBody(request);
        if (!body.HasProperty("index"))
        {
            await WriteError(response, 400, "Missing required field: index.");
            return;
        }

        var index = body.GetInt("index", -1);
        if (index < 0)
        {
            await WriteError(response, 400, "Invalid index.");
            return;
        }

        var existing = SessionLogger.GetEntry(index);
        if (existing == null)
        {
            await WriteError(response, 404, $"No journal entry with index {index}.");
            return;
        }

        string? kind = null;
        if (body.HasProperty("kind"))
        {
            var rawKind = body.GetString("kind");
            kind = NoteKinds.Normalize(rawKind);
            if (rawKind != null && !NoteKinds.IsKnown(kind))
            {
                await WriteError(response, 400,
                    $"Invalid kind '{rawKind}'. Use one of: {string.Join(", ", NoteKinds.All)}.");
                return;
            }
        }

        var effectiveKind = kind ?? existing.Kind ?? existing.Type;
        string? summary = body.GetString("note") ?? body.GetString("text") ?? body.GetString("title");

        bool setSeverity = body.HasProperty("severity");
        string? severity = null;
        if (setSeverity)
        {
            var rawSeverity = body.GetString("severity");
            if (rawSeverity != null)
            {
                if (!NoteKinds.TryNormalizeJournalSeverity(rawSeverity, out var normalizedSeverity))
                {
                    await WriteError(response, 400,
                        $"Invalid severity. Use: {string.Join(", ", NoteKinds.JournalSeverities)}.");
                    return;
                }
                severity = normalizedSeverity;
            }
        }

        bool setEvidence = body.HasProperty("evidence");
        string? evidence = null;
        if (setEvidence)
        {
            var rawEvidence = body.GetString("evidence");
            if (rawEvidence != null)
            {
                if (!NoteKinds.TryNormalizeEvidence(rawEvidence, out var normalizedEvidence))
                {
                    await WriteError(response, 400,
                        $"Invalid evidence. Use: {string.Join(", ", NoteKinds.EvidenceLevels)}.");
                    return;
                }
                evidence = normalizedEvidence;
            }
        }

        bool setTags = body.HasProperty("tags");
        List<string>? tags = null;
        if (setTags)
        {
            var rawTags = body.GetStringList("tags") ?? body.GetStringArray("tags");
            if (rawTags != null)
            {
                tags = rawTags
                    .Select(t => t.Trim().ToLowerInvariant())
                    .Where(t => t.Length > 0)
                    .Distinct()
                    .ToList();
                if (tags.Count == 0) tags = null;
            }
        }

        bool setUrl = body.HasProperty("url");
        var url = setUrl ? body.GetString("url") : null;

        bool setDetails = body.HasProperty("details");
        var details = setDetails ? body.GetString("details") : null;

        Dictionary<string, string>? fields = null;
        bool setFields = false;
        bool? stepsIsArray = null;
        bool isStructured = Array.IndexOf(NoteKinds.StructuredKinds, effectiveKind) >= 0;

        if (body.HasProperty("screenshot") || (isStructured && NoteKinds.StructuredFieldOrder.Any(body.HasProperty)))
        {
            setFields = true;
            fields = existing.Fields != null
                ? new Dictionary<string, string>(existing.Fields, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            var screenshot = body.GetString("screenshot");
            if (body.HasProperty("screenshot"))
            {
                if (string.IsNullOrWhiteSpace(screenshot)) fields.Remove("screenshot");
                else fields["screenshot"] = screenshot.Trim();
            }

            if (isStructured)
            {
                foreach (var key in NoteKinds.StructuredFieldOrder)
                {
                    if (!body.HasProperty(key)) continue;
                    if (key == "steps")
                    {
                        var stepsArray = body.GetStringList("steps");
                        if (stepsArray != null && stepsArray.Count > 0)
                        {
                            fields["steps"] = string.Join("\n", stepsArray);
                            stepsIsArray = true;
                        }
                        else
                        {
                            var v = body.GetString(key);
                            if (string.IsNullOrWhiteSpace(v)) fields.Remove(key);
                            else fields[key] = v;
                            stepsIsArray = false;
                        }
                    }
                    else if (key == "priority")
                    {
                        var priority = body.GetString("priority");
                        if (priority != null && priority.Length > 0
                            && priority != "low" && priority != "medium" && priority != "high" && priority != "critical")
                        {
                            await WriteError(response, 400, "Invalid priority. Use: low, medium, high, or critical.");
                            return;
                        }
                        if (string.IsNullOrWhiteSpace(priority)) fields.Remove("priority");
                        else fields["priority"] = priority;
                    }
                    else
                    {
                        var v = body.GetString(key);
                        if (string.IsNullOrWhiteSpace(v)) fields.Remove(key);
                        else fields[key] = v;
                    }
                }
            }

            if (fields.Count == 0) fields = null;
        }

        var updated = SessionLogger.UpdateEntry(index, kind, summary,
            details, setDetails, severity, setSeverity, fields, setFields, tags, setTags, url, setUrl, stepsIsArray,
            evidence, setEvidence);

        if (updated == null)
        {
            await WriteError(response, 404, $"No journal entry with index {index}.");
            return;
        }

        await WriteSuccess(response, ProjectEntryForResponse(updated));
    }

    private async Task HandleDeleteJournal(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (SessionLogger == null)
        {
            await WriteError(response, 503, "Session logger not available.");
            return;
        }

        if (!int.TryParse(ApiQuery(request)["index"], out var index) || index < 0)
        {
            await WriteError(response, 400, "Missing or invalid query parameter: index.");
            return;
        }

        if (!SessionLogger.DeleteEntry(index))
        {
            await WriteError(response, 404, $"No journal entry with index {index}.");
            return;
        }

        await WriteSuccess(response, new
        {
            deleted = index,
            revision = SessionLogger.Revision,
            total = SessionLogger.JournalCount
        });
    }

    /// <summary>
    /// Generate a formatted test report from journal entries.
    /// Query params: ?format=html|markdown|md (default html), ?path=... (optional file save).
    /// Returns the report content directly; also writes to <c>path</c> when supplied.
    /// </summary>
    private async Task HandleJournalExport(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (SessionLogger == null)
        {
            await WriteError(response, 503, "Session logger not available.");
            return;
        }

        var format = (ApiQuery(request)["format"] ?? "html").ToLowerInvariant();
        if (format is not ("html" or "markdown" or "md" or "json"))
        {
            await WriteError(response, 400, "Invalid format. Use: html, markdown, or json.");
            return;
        }

        var entries = SessionLogger.GetJournal();
        var sessionFile = SessionLogger.FilePath;
        string? currentUrl = null;
        try { currentUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        string content;
        string contentType;
        string ext;
        if (format == "json")
        {
            content = JournalBundle.Serialize(entries, PointerStore);
            contentType = "application/json; charset=utf-8";
            ext = "json";
        }
        else if (format == "html")
        {
            content = JournalReportGenerator.GenerateHtml(entries, sessionFile, currentUrl);
            contentType = "text/html; charset=utf-8";
            ext = "html";
        }
        else
        {
            content = JournalReportGenerator.GenerateMarkdown(entries, sessionFile, currentUrl);
            contentType = "text/markdown; charset=utf-8";
            ext = "md";
        }

        // Optional: save to a file path supplied by the caller.
        string? savedPath = null;
        var path = ApiQuery(request)["path"];
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
            {
                await WriteError(response, 400, guardError ?? "Export path rejected.");
                return;
            }
            try
            {
                var dir = Path.GetDirectoryName(full);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                await File.WriteAllTextAsync(full, content, new UTF8Encoding(false));
                savedPath = full;
            }
            catch (Exception ex)
            {
                await WriteError(response, 400, $"Failed to write {ext} file: {ex.Message}");
                return;
            }
        }

        // JSON wrapper when caller asks for it (consistent with other /api/* responses),
        // otherwise return the raw document so browsers can render it directly.
        var asJson = ApiQuery(request)["json"] == "true";
        if (asJson)
        {
            await WriteSuccess(response, new
            {
                format = ext,
                path = savedPath,
                length = content.Length,
                entries = entries.Count,
                content
            });
            return;
        }

        response.StatusCode = 200;
        response.ContentType = contentType;
        var bytes = Encoding.UTF8.GetBytes(content);
        response.ContentLength64 = bytes.Length;
        if (savedPath != null)
            response.Headers.Add("X-Trowser-Saved-Path", savedPath);
        await response.OutputStream.WriteAsync(bytes);
        response.OutputStream.Close();
    }

    /// <summary>
    /// Import a JSON journal bundle (entries + attached pointers). New indexes are assigned.
    /// Backs <c>POST /api/journal/import</c> and MCP <c>browser_journal_import</c>.
    /// </summary>
    internal Task<object> BuildJournalImportAsync(JsonBody body)
    {
        if (SessionLogger == null)
            throw new ApiCommandException(503, "Session logger not available.");

        string json;
        var path = body.GetString("path");
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolveRead(path, out var full, out var pathError))
                throw new ApiCommandException(400, pathError ?? "Import path rejected.");
            if (!File.Exists(full))
                throw new ApiCommandException(404, $"File not found: {full}");
            json = File.ReadAllText(full);
        }
        else if (body.TryGetRoot(out var root) && root.TryGetProperty("entries", out _))
        {
            json = root.GetRawText();
        }
        else
        {
            var inline = body.GetString("json") ?? body.GetString("content");
            if (string.IsNullOrWhiteSpace(inline))
                throw new ApiCommandException(400, "Provide a journal bundle as the body, or path / json / content.");
            json = inline;
        }

        JournalBundle.BundleDto bundle;
        try { bundle = JournalBundle.Deserialize(json); }
        catch (Exception ex) { throw new ApiCommandException(400, $"Invalid journal JSON: {ex.Message}"); }

        var idMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var pointerCount = 0;
        if (bundle.Pointers != null && PointerStore != null)
        {
            foreach (var dto in bundle.Pointers)
            {
                var pointer = dto.ToPointer();
                if (!string.IsNullOrEmpty(pointer.Id) && PointerStore.Get(pointer.Id) != null)
                    pointer.Id = "";
                var stored = PointerStore.Add(pointer);
                pointerCount++;
                if (!string.IsNullOrEmpty(dto.Id) && dto.Id != stored.Id)
                    idMap[dto.Id] = stored.Id;
            }
        }

        var imported = new List<object>();
        foreach (var dto in bundle.Entries)
        {
            var entry = dto.ToEntry();
            if (entry.Fields != null && entry.Fields.TryGetValue("pointerId", out var oldId)
                && idMap.TryGetValue(oldId, out var newId))
                entry.Fields["pointerId"] = newId;
            imported.Add(ProjectEntryForResponse(SessionLogger.ImportEntry(entry)));
        }

        return Task.FromResult<object>(new
        {
            imported = imported.Count,
            pointers = pointerCount,
            revision = SessionLogger.Revision,
            total = SessionLogger.JournalCount,
            entries = imported
        });
    }

    private Task HandlePostJournalImport(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildJournalImportAsync);

    private async Task HandleGetSessionMemory(HttpListenerResponse response)
    {
        if (SessionMemory == null)
        {
            await WriteSuccess(response, new { mission = (string?)null, focus = (string?)null, tasks = Array.Empty<object>() });
            return;
        }

        await WriteSuccess(response, SessionMemory.ToApiObject());
    }

    private async Task HandlePostSessionMemory(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (SessionMemory == null)
        {
            await WriteError(response, 503, "Session memory not available.");
            return;
        }

        var body = await ReadJsonBody(request);
        var action = body.GetString("action") ?? "get";

        switch (action.ToLowerInvariant())
        {
            case "get":
                await WriteSuccess(response, SessionMemory.ToApiObject());
                return;
            case "set_focus":
                SessionMemory.SetFocus(body.GetString("focus"));
                await WriteSuccess(response, SessionMemory.ToApiObject());
                return;
            case "add_task":
                var text = body.GetString("text");
                if (string.IsNullOrWhiteSpace(text))
                {
                    await WriteError(response, 400, "Missing required field: text.");
                    return;
                }
                var journalIndex = body.HasProperty("journalIndex") ? body.GetInt("journalIndex", -1) : (int?)null;
                if (journalIndex < 0) journalIndex = null;
                SessionMemory.AddTask(text, journalIndex);
                await WriteSuccess(response, SessionMemory.ToApiObject());
                return;
            case "update_task":
                var id = body.GetString("id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    await WriteError(response, 400, "Missing required field: id.");
                    return;
                }
                var updated = SessionMemory.UpdateTask(id, body.GetString("text"), body.GetString("status"),
                    body.HasProperty("journalIndex") ? body.GetInt("journalIndex", -1) : null);
                if (updated == null)
                {
                    await WriteError(response, 404, $"No task with id '{id}'.");
                    return;
                }
                await WriteSuccess(response, SessionMemory.ToApiObject());
                return;
            default:
                await WriteError(response, 400, "Invalid action. Use: get, set_focus, add_task, update_task.");
                return;
        }
    }

    #endregion
}
