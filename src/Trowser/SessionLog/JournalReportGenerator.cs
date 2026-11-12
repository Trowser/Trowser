using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Web;
using Trowser.Chat;

namespace Trowser.SessionLog;

/// <summary>Scroll/accordion state restored across Journal panel HTML refreshes.</summary>
public sealed class JournalPanelViewState
{
    public double ScrollY { get; set; }
    public List<string> OpenSections { get; set; } = new();
}

/// <summary>
/// Generates a formatted test report (Markdown or HTML) directly from the in-memory
/// journal entries. Groups findings by kind (bugs, enhancements, observations, test ideas),
/// references screenshots from fields["screenshot"] (by path in the panel; embedded in the
/// full HTML report), and includes charters/user metadata, assertion totals, and an API-action count.
///
/// Used by <c>GET /api/journal/export</c>. Independent of <see cref="HtmlReportGenerator"/>
/// which converts an already-written session .md file.
/// </summary>
public static class JournalReportGenerator
{
    /// <summary>Render the journal as Markdown.</summary>
    public static string GenerateMarkdown(
        IReadOnlyList<SessionLogger.JournalEntry> entries,
        string? sessionFilePath = null,
        string? currentUrl = null)
    {
        var sb = new StringBuilder();
        var g = Group(entries);

        sb.AppendLine("# Trowser Session Report");
        sb.AppendLine();
        sb.AppendLine($"*Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}*  ");
        sb.AppendLine($"*Trowser v{Version()}*  ");
        if (!string.IsNullOrEmpty(currentUrl)) sb.AppendLine($"*URL: {currentUrl}*  ");
        if (!string.IsNullOrEmpty(sessionFilePath)) sb.AppendLine($"*Session log: {sessionFilePath}*  ");
        sb.AppendLine();

        if (g.Users.Count > 0 || g.Charters.Count > 0 || g.Testing.Count > 0)
        {
            sb.AppendLine("## Session context");
            sb.AppendLine();
            foreach (var e in g.Users) sb.AppendLine($"- **Tester:** {e.Summary}");
            foreach (var e in g.Charters) sb.AppendLine($"- **Charter:** {e.Summary}");
            foreach (var e in g.Testing) sb.AppendLine($"- **Currently testing:** {e.Summary}");
            sb.AppendLine();
        }

        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- **Bugs:** {g.Bugs.Count}{FormatSeverityBreakdown(g.Bugs)}");
        sb.AppendLine($"- **Enhancements:** {g.Enhancements.Count}");
        sb.AppendLine($"- **Observations:** {g.Observations.Count}");
        sb.AppendLine($"- **Test ideas:** {g.TestIdeas.Count}");
        sb.AppendLine($"- **Notes:** {g.Notes.Count}");
        sb.AppendLine($"- **API actions:** {g.Actions.Count}");
        sb.AppendLine($"- **Screenshots:** {g.Screenshots.Count}");
        if (g.Pointers.Count > 0) sb.AppendLine($"- **Pointers:** {g.Pointers.Count}");
        if (g.Decisions.Count > 0) sb.AppendLine($"- **Decisions:** {g.Decisions.Count}");
        if (g.Recordings.Count > 0) sb.AppendLine($"- **Recordings:** {g.Recordings.Count}");
        if (g.Errors.Count > 0) sb.AppendLine($"- **Errors:** {g.Errors.Count}");
        sb.AppendLine();

        RenderSection(sb, "Bugs", SortBySeverity(g.Bugs), includeFields: true);
        RenderSection(sb, "Enhancements", SortBySeverity(g.Enhancements), includeFields: true);
        RenderSection(sb, "Observations", g.Observations, includeFields: false);
        RenderSection(sb, "Test ideas", g.TestIdeas, includeFields: false);
        RenderSection(sb, "Pointers", g.Pointers, includeFields: true);
        RenderSection(sb, "Decisions", g.Decisions, includeFields: true);

        if (g.Notes.Count > 0)
        {
            sb.AppendLine("## Notes");
            sb.AppendLine();
            foreach (var e in g.Notes)
            {
                var sev = string.IsNullOrEmpty(e.Severity) ? "" : $" [{e.Severity}]";
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}`{sev} {e.Summary}");
                if (!string.IsNullOrEmpty(e.Details))
                {
                    foreach (var line in e.Details.Split('\n'))
                        sb.AppendLine($"  {line}");
                }
            }
            sb.AppendLine();
        }

        if (g.Screenshots.Count > 0)
        {
            sb.AppendLine("## Screenshots");
            sb.AppendLine();
            foreach (var e in g.Screenshots)
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}` ![screenshot]({e.Summary.Replace('\\', '/')})");
            sb.AppendLine();
        }

        if (g.Recordings.Count > 0)
        {
            sb.AppendLine("## Recordings");
            sb.AppendLine();
            foreach (var e in g.Recordings)
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}` {e.Summary}");
            sb.AppendLine();
        }

        if (g.Messages.Count > 0)
        {
            sb.AppendLine("## Messages");
            sb.AppendLine();
            foreach (var e in g.Messages)
            {
                var lvl = string.IsNullOrEmpty(e.Details) ? "" : $" [{e.Details}]";
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}`{lvl} {e.Summary}");
            }
            sb.AppendLine();
        }

        if (g.Errors.Count > 0)
        {
            sb.AppendLine("## Errors");
            sb.AppendLine();
            foreach (var e in g.Errors)
                sb.AppendLine($"- `{e.Timestamp:HH:mm:ss}` {e.Summary}"
                    + (string.IsNullOrEmpty(e.Details) ? "" : $" — {e.Details}"));
            sb.AppendLine();
        }

        return sb.ToString();
    }

    /// <summary>
    /// Render the journal as a self-contained HTML document. When <paramref name="compact"/> is true
    /// (the left-docked Journal panel), the report chrome is dropped and summary cards toggle
    /// in-panel sections. Screenshots are embedded only when <paramref name="compact"/> is false
    /// (the full Report / export).
    /// </summary>
    public static string GenerateHtml(
        IReadOnlyList<SessionLogger.JournalEntry> entries,
        string? sessionFilePath = null,
        string? currentUrl = null,
        bool compact = false,
        JournalPanelViewState? viewState = null)
    {
        var mdDir = !string.IsNullOrEmpty(sessionFilePath)
            ? Path.GetDirectoryName(Path.GetFullPath(sessionFilePath))
            : null;

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("<meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("<title>Trowser Session Report</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(CssStyles);
        if (compact) sb.AppendLine(CompactCss);
        sb.AppendLine("</style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine(compact ? "<div class=\"container compact\">" : "<div class=\"container\">");

        var g = Group(entries);

        if (!compact)
        {
            sb.AppendLine("<header>");
            sb.AppendLine("<h1>Trowser Session Report</h1>");
            sb.AppendLine($"<p class=\"meta\">Generated {DateTime.Now:yyyy-MM-dd HH:mm:ss} • Trowser v{Esc(Version())}</p>");
            if (!string.IsNullOrEmpty(currentUrl)) sb.AppendLine($"<p class=\"meta\">URL: {Esc(currentUrl)}</p>");
            if (!string.IsNullOrEmpty(sessionFilePath)) sb.AppendLine($"<p class=\"meta\">Session log: {Esc(sessionFilePath)}</p>");
            sb.AppendLine("</header>");
        }

        if (g.Users.Count > 0 || g.Charters.Count > 0 || g.Testing.Count > 0)
        {
            sb.AppendLine("<section><h2>Session context</h2><ul class=\"context\">");
            foreach (var e in g.Users) sb.AppendLine($"<li><strong>Tester:</strong> {MdInline(e.Summary)}</li>");
            foreach (var e in g.Charters) sb.AppendLine($"<li><strong>Charter:</strong> {MdInline(e.Summary)}</li>");
            foreach (var e in g.Testing) sb.AppendLine($"<li><strong>Currently testing:</strong> {MdInline(e.Summary)}</li>");
            sb.AppendLine("</ul></section>");
        }

        sb.AppendLine("<section class=\"summary-wrap\"><h2>Summary</h2><div class=\"summary-grid\">");
        sb.AppendLine(SummaryCard("Bugs", g.Bugs.Count, FormatSeverityBreakdownHtml(g.Bugs), compact, section: "bugs"));
        sb.AppendLine(SummaryCard("Enhancements", g.Enhancements.Count, null, compact, section: "enhancements"));
        sb.AppendLine(SummaryCard("Observations", g.Observations.Count, null, compact, section: "observations"));
        sb.AppendLine(SummaryCard("Test ideas", g.TestIdeas.Count, null, compact, section: "testideas"));
        sb.AppendLine(SummaryCard("Notes", g.Notes.Count, null, compact, section: "notes"));
        if (g.Pointers.Count > 0) sb.AppendLine(SummaryCard("Pointers", g.Pointers.Count, null, compact, section: "pointers"));
        if (g.Decisions.Count > 0) sb.AppendLine(SummaryCard("Decisions", g.Decisions.Count, null, compact, section: "decisions"));
        if (g.Messages.Count > 0) sb.AppendLine(SummaryCard("Messages", g.Messages.Count, null, compact, section: "messages"));
        sb.AppendLine(SummaryCard("API actions", g.Actions.Count, null, compact,
            link: compact && g.Actions.Count > 0 ? "trowser://apiactions" : null));
        sb.AppendLine(SummaryCard("Screenshots", g.Screenshots.Count, null, compact,
            section: compact ? "screenshots" : null,
            title: compact ? "Capture a screenshot: Ctrl+Shift+S" : null));
        if (g.Recordings.Count > 0) sb.AppendLine(SummaryCard("Recordings", g.Recordings.Count, null, compact, section: "recordings"));
        if (g.Errors.Count > 0) sb.AppendLine(SummaryCard("Errors", g.Errors.Count, null, compact, section: "errors"));
        sb.AppendLine("</div></section>");

        RenderHtmlSection(sb, "Bugs", "bugs", SortBySeverity(g.Bugs), mdDir, includeFields: true, compact, viewState);
        RenderHtmlSection(sb, "Enhancements", "enhancements", SortBySeverity(g.Enhancements), mdDir, includeFields: true, compact, viewState);
        RenderHtmlSection(sb, "Observations", "observations", g.Observations, mdDir, includeFields: false, compact, viewState);
        RenderHtmlSection(sb, "Test ideas", "testideas", g.TestIdeas, mdDir, includeFields: false, compact, viewState);
        RenderHtmlSection(sb, "Notes", "notes", g.Notes, mdDir, includeFields: false, compact, viewState);
        RenderHtmlSection(sb, "Pointers", "pointers", g.Pointers, mdDir, includeFields: true, compact, viewState);
        RenderHtmlSection(sb, "Decisions", "decisions", g.Decisions, mdDir, includeFields: true, compact, viewState);

        RenderScreenshotsSection(sb, g.Screenshots, mdDir, compact, viewState);

        if (g.Recordings.Count > 0)
        {
            var open = SectionOpen("recordings", g.Recordings.Count, compact, viewState);
            sb.AppendLine(SectionOpenTag("recordings", "Recordings", compact, open));
            sb.AppendLine("<ul class=\"findings recordings\">");
            foreach (var e in g.Recordings)
            {
                var stepCount = e.Fields != null && e.Fields.TryGetValue("steps", out var s) && !string.IsNullOrEmpty(s)
                    ? s.Split('\n').Length : 0;
                var suffix = stepCount > 0 ? $" <span class=\"muted\">({stepCount} step{(stepCount == 1 ? "" : "s")})</span>" : "";
                var text = $"{Esc(e.Summary ?? "Recording")}{suffix}";
                sb.AppendLine(compact
                    ? $"<li data-index=\"{e.Index}\">{EntryActions(e, compact)}<a class=\"rec-link\" href=\"trowser://recording/{e.Index}\">{text}</a></li>"
                    : $"<li>{text}</li>");
            }
            sb.AppendLine("</ul>");
            sb.AppendLine(SectionCloseTag(compact));
        }

        if (g.Messages.Count > 0)
        {
            var open = SectionOpen("messages", g.Messages.Count, compact, viewState);
            sb.AppendLine(SectionOpenTag("messages", "Messages", compact, open));
            sb.AppendLine("<ul class=\"findings\">");
            foreach (var e in g.Messages)
            {
                var lvl = string.IsNullOrEmpty(e.Details) ? "" : $" <span class=\"sev sev-{Esc(e.Details!)}\">{Esc(e.Details!)}</span>";
                sb.AppendLine($"<li data-index=\"{e.Index}\">{EntryActions(e, compact)}<time>{e.Timestamp:HH:mm:ss}</time>{lvl} {MdInline(e.Summary ?? "")}</li>");
            }
            sb.AppendLine("</ul>");
            sb.AppendLine(SectionCloseTag(compact));
        }

        if (g.Errors.Count > 0)
        {
            var open = SectionOpen("errors", g.Errors.Count, compact, viewState);
            sb.AppendLine(SectionOpenTag("errors", "Errors", compact, open));
            sb.AppendLine("<ul class=\"findings\">");
            foreach (var e in g.Errors)
            {
                sb.AppendLine($"<li data-index=\"{e.Index}\">{EntryActions(e, compact)}<time>{e.Timestamp:HH:mm:ss}</time> {Esc(e.Summary ?? "")}"
                    + (string.IsNullOrEmpty(e.Details) ? "" : $" — <em>{Esc(e.Details)}</em>") + "</li>");
            }
            sb.AppendLine("</ul>");
            sb.AppendLine(SectionCloseTag(compact));
        }

        sb.AppendLine("</div>");
        if (compact)
        {
            var stateJson = JsonSerializer.Serialize(new
            {
                scroll = viewState?.ScrollY ?? 0,
                open = viewState?.OpenSections ?? new List<string>()
            });
            sb.AppendLine("<script>");
            sb.AppendLine($"window.__journalState = {stateJson};");
            sb.AppendLine(CompactScript);
            sb.AppendLine("</script>");
        }
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Full detail page for a single recording, opened in a browser tab from the Journal panel.
    /// Lists the human-readable steps (no timestamps — the main use case is pasting into a bug report).
    /// </summary>
    public static string GenerateRecordingDetailHtml(SessionLogger.JournalEntry entry)
    {
        var title = entry.Summary ?? "Recording";
        var steps = entry.Fields != null && entry.Fields.TryGetValue("steps", out var s) && !string.IsNullOrEmpty(s)
            ? s.Split('\n')
            : Array.Empty<string>();

        var body = new StringBuilder();
        body.AppendLine($"<header><h1>Recording: {Esc(title)}</h1>");
        if (!string.IsNullOrEmpty(entry.Url)) body.AppendLine($"<p class=\"meta\">Start URL: {Esc(entry.Url)}</p>");
        body.AppendLine($"<p class=\"meta\">{steps.Length} step{(steps.Length == 1 ? "" : "s")}</p></header>");
        body.AppendLine("<section><h2>Steps</h2><ol class=\"steps\">");
        foreach (var step in steps)
        {
            if (string.IsNullOrWhiteSpace(step)) continue;
            body.AppendLine($"<li>{Esc(step.Trim())}</li>");
        }
        body.AppendLine("</ol></section>");
        return HtmlShell($"Recording — {title}", body.ToString());
    }

    /// <summary>
    /// Full detail page listing the session's API/GUI actions (method, path, details), opened from the
    /// Journal panel's clickable "API actions" card.
    /// </summary>
    public static string GenerateActionsDetailHtml(IReadOnlyList<SessionLogger.JournalEntry> entries)
    {
        var actions = entries.Where(e => string.Equals(e.Type, "action", StringComparison.OrdinalIgnoreCase)).ToList();

        var body = new StringBuilder();
        body.AppendLine($"<header><h1>API actions</h1><p class=\"meta\">{actions.Count} action{(actions.Count == 1 ? "" : "s")}</p></header>");
        body.AppendLine("<section><table class=\"actions\">");
        body.AppendLine("<tr><th>Time</th><th>Source</th><th>Action</th><th>Details</th></tr>");
        foreach (var e in actions)
        {
            body.AppendLine("<tr>"
                + $"<td class=\"ts\">{e.Timestamp:HH:mm:ss}</td>"
                + $"<td class=\"src\">{Esc(e.Source)}</td>"
                + $"<td>{Esc(e.Summary ?? "")}</td>"
                + $"<td>{(string.IsNullOrEmpty(e.Details) ? "" : Esc(e.Details))}</td>"
                + "</tr>");
        }
        body.AppendLine("</table></section>");
        return HtmlShell("API actions", body.ToString());
    }

    private static string HtmlShell(string title, string body)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\"><head><meta charset=\"UTF-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine($"<title>{Esc(title)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine(CssStyles);
        sb.AppendLine("</style></head><body><div class=\"container\">");
        sb.AppendLine(body);
        sb.AppendLine("</div></body></html>");
        return sb.ToString();
    }

    private record Grouped(
        List<SessionLogger.JournalEntry> Bugs,
        List<SessionLogger.JournalEntry> Enhancements,
        List<SessionLogger.JournalEntry> Observations,
        List<SessionLogger.JournalEntry> TestIdeas,
        List<SessionLogger.JournalEntry> Notes,
        List<SessionLogger.JournalEntry> Charters,
        List<SessionLogger.JournalEntry> Testing,
        List<SessionLogger.JournalEntry> Users,
        List<SessionLogger.JournalEntry> Assertions,
        List<SessionLogger.JournalEntry> Actions,
        List<SessionLogger.JournalEntry> Recordings,
        List<SessionLogger.JournalEntry> Messages,
        List<SessionLogger.JournalEntry> Errors,
        List<SessionLogger.JournalEntry> Screenshots,
        List<SessionLogger.JournalEntry> Pointers,
        List<SessionLogger.JournalEntry> Decisions);

    private static Grouped Group(IReadOnlyList<SessionLogger.JournalEntry> entries)
    {
        var g = new Grouped(new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new(), new());
        foreach (var e in entries)
        {
            switch ((e.Kind ?? e.Type)?.ToLowerInvariant())
            {
                case NoteKinds.Bug: g.Bugs.Add(e); break;
                case NoteKinds.Enhancement: g.Enhancements.Add(e); break;
                case NoteKinds.Observation: g.Observations.Add(e); break;
                case NoteKinds.TestIdea: g.TestIdeas.Add(e); break;
                case NoteKinds.Note: g.Notes.Add(e); break;
                case NoteKinds.Charter: g.Charters.Add(e); break;
                case NoteKinds.Testing: g.Testing.Add(e); break;
                case NoteKinds.User: g.Users.Add(e); break;
                case "assertion": g.Assertions.Add(e); break;
                case "action": g.Actions.Add(e); break;
                case "recording": g.Recordings.Add(e); break;
                case "message": g.Messages.Add(e); break;
                case "error": g.Errors.Add(e); break;
                case "screenshot": g.Screenshots.Add(e); break;
                case "pointer": g.Pointers.Add(e); break;
                case "decision": g.Decisions.Add(e); break;
            }
        }
        return g;
    }

    private static List<SessionLogger.JournalEntry> SortBySeverity(IEnumerable<SessionLogger.JournalEntry> items)
    {
        int Rank(SessionLogger.JournalEntry e)
        {
            string pri = "";
            if (e.Fields != null && e.Fields.TryGetValue("priority", out var p)) pri = p.ToLowerInvariant();
            if (string.IsNullOrEmpty(pri) && !string.IsNullOrEmpty(e.Severity)) pri = e.Severity!.ToLowerInvariant();
            return pri switch
            {
                "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4
            };
        }
        return items.OrderBy(Rank).ThenBy(e => e.Index).ToList();
    }

    private static string FormatSeverityBreakdown(List<SessionLogger.JournalEntry> bugs)
    {
        if (bugs.Count == 0) return "";
        var crit = bugs.Count(B => IsPriority(B, "critical"));
        var high = bugs.Count(B => IsPriority(B, "high"));
        if (crit == 0 && high == 0) return "";
        var parts = new List<string>();
        if (crit > 0) parts.Add($"{crit} critical");
        if (high > 0) parts.Add($"{high} high");
        return $" ({string.Join(", ", parts)})";
    }

    private static string? FormatSeverityBreakdownHtml(List<SessionLogger.JournalEntry> bugs)
    {
        var txt = FormatSeverityBreakdown(bugs);
        return string.IsNullOrEmpty(txt) ? null : txt.Trim('(', ')', ' ');
    }

    private static bool IsPriority(SessionLogger.JournalEntry e, string priority)
    {
        if (e.Fields != null && e.Fields.TryGetValue("priority", out var p)
            && string.Equals(p, priority, StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(e.Severity, priority, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Display rank for bugs/enhancements: priority first, then leftover severity from older entries.</summary>
    private static string? RankLabel(SessionLogger.JournalEntry e)
    {
        if (e.Fields != null && e.Fields.TryGetValue("priority", out var p) && !string.IsNullOrWhiteSpace(p))
            return p;
        return string.IsNullOrWhiteSpace(e.Severity) ? null : e.Severity;
    }

    private static bool SectionOpen(string id, int count, bool compact, JournalPanelViewState? viewState)
    {
        if (!compact) return true;
        if (viewState != null && viewState.OpenSections.Count > 0)
            return viewState.OpenSections.Contains("sec-" + id, StringComparer.OrdinalIgnoreCase);

        return id switch
        {
            "bugs" or "enhancements" => count is >= 1 and <= 8,
            "observations" or "notes" or "testideas" or "pointers" or "decisions" => count is >= 1 and <= 5,
            _ => false
        };
    }

    private static string SectionOpenTag(string id, string title, bool compact, bool open)
    {
        if (!compact)
            return $"<section class=\"{id}\"><h2>{Esc(title)}</h2>";
        var openAttr = open ? " open" : "";
        return $"<details class=\"sec {id}\" id=\"sec-{id}\"{openAttr}><summary>{Esc(title)}</summary>";
    }

    private static string SectionCloseTag(bool compact) => compact ? "</details>" : "</section>";

    private static string EntryActions(SessionLogger.JournalEntry e, bool compact)
    {
        if (!compact) return "";
        var origin = SessionLogger.GetOrigin(e.Source);
        var src = $"<span class=\"src src-{Esc(origin)}\">{Esc(origin)}</span>";
        var evidence = string.IsNullOrEmpty(e.Evidence)
            ? ""
            : $" <span class=\"ev ev-{Esc(e.Evidence)}\">{Esc(e.Evidence)}</span>";
        return $"<span class=\"entry-actions\">{src}{evidence}</span>";
    }

    /// <summary>
    /// True when Show me can navigate, scroll to a pointer, run an attached repro, or replay an embedded recording script.
    /// Used by the panel context menu to grey the command out.
    /// </summary>
    public static bool CanShowMe(SessionLogger.JournalEntry e) =>
        !string.IsNullOrEmpty(e.Url)
        || (e.Fields != null && (e.Fields.ContainsKey("pointerId")
            || e.Fields.ContainsKey("trwPath")
            || e.Fields.ContainsKey("reproPath")
            || e.Fields.ContainsKey("csx")
            || e.Fields.ContainsKey("csxPath")));

    private static void AppendPointerAndRepro(StringBuilder sb, SessionLogger.JournalEntry e, bool compact)
    {
        if (e.Fields == null) return;
        if (e.Fields.TryGetValue("pointerId", out var pid) && !string.IsNullOrWhiteSpace(pid))
        {
            var kind = e.Fields.TryGetValue("pointerKind", out var pk) ? pk : "";
            var kindBit = string.IsNullOrEmpty(kind) ? "" : $" ({Esc(kind)})";
            var link = compact
                ? $"<a href=\"trowser://show/{e.Index}\">{Esc(pid)}</a>"
                : Esc(pid);
            sb.AppendLine($"<p class=\"pointer-ref\">Pointer{kindBit}: {link}</p>");
        }
        var repro = e.Fields.TryGetValue("trwPath", out var tp) ? tp
            : e.Fields.TryGetValue("reproPath", out var rp) ? rp : null;
        if (!string.IsNullOrWhiteSpace(repro))
            sb.AppendLine($"<p class=\"pointer-ref\">Repro: <code>{Esc(repro)}</code></p>");
    }

    private static void RenderSection(StringBuilder sb, string title,
        List<SessionLogger.JournalEntry> items, bool includeFields)
    {
        if (items.Count == 0) return;
        sb.AppendLine($"## {title}");
        sb.AppendLine();
        foreach (var e in items)
        {
            var rank = RankLabel(e);
            var rankTag = string.IsNullOrEmpty(rank) ? "" : $" [{rank}]";
            sb.AppendLine($"### {e.Summary}{rankTag}");
            sb.AppendLine();
            sb.AppendLine($"*{e.Timestamp:yyyy-MM-dd HH:mm:ss}*  ");
            if (e.Tags != null && e.Tags.Count > 0)
                sb.AppendLine($"*Tags: {string.Join(", ", e.Tags)}*  ");
            if (!string.IsNullOrEmpty(e.Url))
                sb.AppendLine($"*URL: {e.Url}*  ");
            sb.AppendLine();
            if (!string.IsNullOrEmpty(e.Details))
            {
                sb.AppendLine(e.Details);
                sb.AppendLine();
            }
            if (includeFields && e.Fields != null)
            {
                foreach (var key in NoteKinds.StructuredFieldOrder)
                {
                    if (key == "priority") continue;
                    if (!e.Fields.TryGetValue(key, out var v)) continue;
                    if (key == "steps")
                    {
                        sb.AppendLine($"- **{NoteKinds.FieldLabel(key)}:**");
                        sb.AppendLine();
                        var stepNum = 1;
                        foreach (var line in v.Split('\n'))
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            sb.AppendLine($"{stepNum}. {line.Trim()}");
                            stepNum++;
                        }
                    }
                    else
                        sb.AppendLine($"- **{NoteKinds.FieldLabel(key)}:** {v}  ");
                }
                if (e.Fields.TryGetValue("screenshot", out var shot))
                    sb.AppendLine($"- **Screenshot:** `{shot}`  ");
            }
            sb.AppendLine();
        }
    }

    private static void RenderHtmlSection(StringBuilder sb, string title, string cssClass,
        List<SessionLogger.JournalEntry> items, string? mdDir, bool includeFields, bool compact,
        JournalPanelViewState? viewState)
    {
        if (items.Count == 0) return;
        var open = SectionOpen(cssClass, items.Count, compact, viewState);
        sb.AppendLine(SectionOpenTag(cssClass, title, compact, open));
        foreach (var e in items)
        {
            var rank = RankLabel(e);
            var badge = string.IsNullOrEmpty(rank)
                ? ""
                : $" <span class=\"sev sev-{Esc(rank)}\">{Esc(rank)}</span>";
            var evBadge = string.IsNullOrEmpty(e.Evidence)
                ? ""
                : $" <span class=\"ev ev-{Esc(e.Evidence)}\">{Esc(e.Evidence)}</span>";
            sb.AppendLine($"<article class=\"finding\" data-index=\"{e.Index}\">");
            sb.AppendLine(EntryActions(e, compact));
            sb.AppendLine($"<h3>{MdInline(e.Summary ?? "")}{badge}{evBadge}</h3>");
            sb.AppendLine($"<time>{e.Timestamp:yyyy-MM-dd HH:mm:ss}</time>");
            if (e.Tags != null && e.Tags.Count > 0)
                sb.AppendLine($"<div class=\"tags\">{string.Join(" ", e.Tags.Select(t => $"<span class=\"tag\">{Esc(t)}</span>"))}</div>");
            if (!string.IsNullOrEmpty(e.Url))
                sb.AppendLine($"<div class=\"entry-url\">URL: <a href=\"{Esc(e.Url)}\">{Esc(e.Url)}</a></div>");
            if (!string.IsNullOrEmpty(e.Details))
                sb.AppendLine($"<div class=\"md-body\">{MdBlock(e.Details)}</div>");
            if (includeFields && e.Fields != null)
            {
                sb.AppendLine("<dl>");
                foreach (var key in NoteKinds.StructuredFieldOrder)
                {
                    if (key == "priority") continue;
                    if (!e.Fields.TryGetValue(key, out var v)) continue;
                    sb.AppendLine($"<dt>{Esc(NoteKinds.FieldLabel(key))}</dt>");
                    if (key == "steps")
                    {
                        sb.AppendLine("<dd><ol class=\"steps\">");
                        foreach (var line in v.Split('\n'))
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;
                            sb.AppendLine($"<li>{Esc(line.Trim())}</li>");
                        }
                        sb.AppendLine("</ol></dd>");
                    }
                    else
                        sb.AppendLine($"<dd class=\"md-body\">{MdBlock(v)}</dd>");
                }
                sb.AppendLine("</dl>");
                if (e.Fields.TryGetValue("screenshot", out var shot))
                    sb.AppendLine(RenderScreenshot(shot, mdDir, compact));
                AppendPointerAndRepro(sb, e, compact);
            }
            else if (e.Fields != null && e.Fields.TryGetValue("screenshot", out var shot2))
            {
                sb.AppendLine(RenderScreenshot(shot2, mdDir, compact));
                AppendPointerAndRepro(sb, e, compact);
            }
            else if (e.Fields != null)
            {
                AppendPointerAndRepro(sb, e, compact);
            }
            sb.AppendLine("</article>");
        }
        sb.AppendLine(SectionCloseTag(compact));
    }

    private static void RenderScreenshotsSection(StringBuilder sb,
        List<SessionLogger.JournalEntry> shots, string? mdDir, bool compact, JournalPanelViewState? viewState)
    {
        if (shots.Count == 0) return;

        var open = SectionOpen("screenshots", shots.Count, compact, viewState);
        sb.AppendLine(SectionOpenTag("screenshots", "Screenshots", compact, open));

        foreach (var e in shots)
        {
            sb.AppendLine($"<article class=\"finding screenshot-entry\" data-index=\"{e.Index}\">");
            sb.AppendLine(EntryActions(e, compact));
            sb.AppendLine($"<time>{e.Timestamp:HH:mm:ss}</time>");
            sb.AppendLine(RenderScreenshot(e.Summary ?? "", mdDir, compact));
            sb.AppendLine("</article>");
        }
        sb.AppendLine(SectionCloseTag(compact));
    }

    private static string RenderScreenshot(string path, string? mdDir, bool compact = false)
    {
        if (compact)
        {
            return $"<div class=\"screenshot-ref\">Screenshot: <code>{Esc(path)}</code></div>";
        }

        var full = ResolvePath(path, mdDir);
        if (full != null && File.Exists(full))
        {
            try
            {
                var bytes = File.ReadAllBytes(full);
                var b64 = Convert.ToBase64String(bytes);
                var ext = Path.GetExtension(full).ToLowerInvariant().TrimStart('.');
                var mime = ext is "jpg" or "jpeg" ? "jpeg" : ext is "gif" ? "gif" : ext is "webp" ? "webp" : "png";
                return $"<div class=\"screenshot-embed\"><img src=\"data:image/{mime};base64,{b64}\" alt=\"screenshot\" class=\"screenshot\"></div>";
            }
            catch
            {
                // fall through to path reference
            }
        }

        var href = (full ?? path).Replace('\\', '/');
        var exists = full != null && File.Exists(full);
        if (!exists)
            return $"<div class=\"screenshot-ref missing\">Screenshot: <code>{Esc(path)}</code> <span class=\"hint\">(file not found at report-generation time)</span></div>";
        return $"<div class=\"screenshot-ref\">Screenshot: <a href=\"{Esc(href)}\" target=\"_blank\"><code>{Esc(path)}</code></a></div>";
    }

    private static string? ResolvePath(string path, string? mdDir)
    {
        try
        {
            if (Path.IsPathRooted(path)) return path;
            if (!string.IsNullOrEmpty(mdDir))
                return Path.Combine(mdDir, path.Replace('/', Path.DirectorySeparatorChar));
        }
        catch { }
        return null;
    }

    private static string SummaryCard(string label, int count, string? sub, bool compact = false,
        string? link = null, string? section = null, string? title = null)
    {
        var subHtml = string.IsNullOrEmpty(sub) ? "" : $"<span class=\"sub\">{Esc(sub)}</span>";
        var titleAttr = string.IsNullOrEmpty(title) ? "" : $" title=\"{Esc(title)}\"";
        var inner = $"<div class=\"count\">{count}</div><div class=\"label\">{Esc(label)}</div>{subHtml}";

        if (compact && !string.IsNullOrEmpty(link))
            return $"<a class=\"card card-link\" href=\"{Esc(link)}\"{titleAttr}>{inner}</a>";
        if (compact && !string.IsNullOrEmpty(section))
            return $"<a class=\"card card-link\" href=\"#sec-{Esc(section)}\" data-section=\"{Esc(section)}\"{titleAttr}>{inner}</a>";
        return $"<div class=\"card\"{titleAttr}>{inner}</div>";
    }

    private static string MdInline(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var html = MarkdownHelper.ToHtml(s).Trim();
        if (html.StartsWith("<p>", StringComparison.OrdinalIgnoreCase) && html.EndsWith("</p>", StringComparison.OrdinalIgnoreCase))
            html = html[3..^4].Trim();
        return html;
    }

    private static string MdBlock(string s) => string.IsNullOrEmpty(s) ? "" : MarkdownHelper.ToHtml(s);

    private static string Esc(string s) => HtmlExportText.Encode(s);

    private static string Version()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v != null ? $"{v.Major}.{v.Minor}.{v.Build}" : "1.0.0";
    }

    private const string CompactScript = """
        (function () {
          var state = window.__journalState || {};
          if (state.open && state.open.length) {
            document.querySelectorAll('details.sec').forEach(function (d) {
              d.open = state.open.indexOf(d.id) >= 0;
            });
          }
          if (typeof state.scroll === 'number' && state.scroll > 0) {
            window.scrollTo(0, state.scroll);
          }
          document.querySelectorAll('a.card[data-section]').forEach(function (a) {
            a.addEventListener('click', function (e) {
              var id = 'sec-' + a.getAttribute('data-section');
              var el = document.getElementById(id);
              if (!el) return;
              e.preventDefault();
              var willOpen = !el.open;
              document.querySelectorAll('details.sec').forEach(function (d) {
                if (d !== el) d.open = false;
              });
              el.open = willOpen;
              if (willOpen) window.scrollTo(0, 0);
            });
          });
          document.addEventListener('contextmenu', function (e) {
            e.preventDefault();
            var a = e.target && e.target.closest && e.target.closest('[data-index]');
            var idx = a ? parseInt(a.getAttribute('data-index'), 10) : null;
            if (window.chrome && window.chrome.webview)
              window.chrome.webview.postMessage({ type: 'journal-ctx', index: isNaN(idx) ? null : idx });
          }, true);
        })();
        """;

    private const string CompactCss = """
        .container.compact { max-width: none; padding: 8px 10px 16px; }
        .compact .summary-wrap { position: sticky; top: 0; z-index: 2; background: #1e1e1e; padding-bottom: 8px; margin: 0 0 8px; }
        .compact .summary-wrap h2 { display: none; }
        .compact .summary-grid { grid-template-columns: repeat(auto-fill, minmax(88px, 1fr)); gap: 6px; }
        .compact .card { padding: 8px 4px; }
        .compact .card .count { font-size: 20px; }
        .compact .card .label { font-size: 10px; }
        details.sec { margin: 10px 0; border-bottom: 1px solid #3f3f46; }
        details.sec > summary { color: #4ec9b0; font-size: 14px; font-weight: 600; cursor: pointer; padding: 4px 0; list-style: none; }
        details.sec > summary::-webkit-details-marker { display: none; }
        details.sec > summary::before { content: '▸ '; color: #888; }
        details.sec[open] > summary::before { content: '▾ '; }
        .entry-actions { float: right; font-size: 11px; }
        .entry-actions .act { color: #9cdcfe; text-decoration: none; margin-left: 8px; }
        .entry-actions .act:hover { text-decoration: underline; }
        .entry-actions .del { color: #f48771; }
        .src { display: inline-block; padding: 0 6px; border-radius: 8px; font-size: 10px; text-transform: uppercase; background: #3f3f46; color: #ccc; margin-right: 4px; }
        .src-gui { background: #1e4a5a; color: #9cdcfe; }
        .src-api, .src-agent { background: #3d3a1e; color: #dcdcaa; }
        .src-system, .src-auto { background: #3f3f46; color: #888; }
        .src-user { background: #1e4a5a; color: #9cdcfe; }
        .ev { display: inline-block; padding: 0 6px; border-radius: 8px; font-size: 10px; text-transform: uppercase; margin-right: 4px; }
        .ev-observed { background: #1e3a1e; color: #4ec9b0; }
        .ev-inferred { background: #3a3a1e; color: #dcdcaa; }
        .ev-hypothesis { background: #3a2a1e; color: #ce9178; }
        .ev-untested { background: #2a2a3a; color: #9cdcfe; }
        .hint { color: #888; font-size: 12px; margin: 8px 0; }
        kbd { background: #2d2d30; border: 1px solid #3f3f46; border-radius: 3px; padding: 1px 5px; font-size: 11px; }
        .md-body p { margin: 6px 0; }
        .md-body ul, .md-body ol { margin: 6px 0 6px 18px; }
        .md-body code { background: #1e1e1e; color: #ce9178; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
        .md-body pre { background: #0c0c0c; border: 1px solid #3f3f46; border-radius: 4px; padding: 8px; overflow-x: auto; }
        .md-body a { color: #4ec9b0; }
        """;

    private const string CssStyles = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #1e1e1e; color: #d4d4d4;
            font-family: 'Segoe UI', -apple-system, sans-serif;
            font-size: 14px; line-height: 1.6;
        }
        .container { max-width: 960px; margin: 0 auto; padding: 32px 24px; }
        header { margin-bottom: 24px; border-bottom: 1px solid #3f3f46; padding-bottom: 16px; }
        header h1 { font-size: 24px; color: #e0e0e0; font-weight: 600; }
        .meta { color: #888; font-size: 12px; margin-top: 2px; }
        section { margin: 28px 0; }
        h2 { color: #4ec9b0; font-size: 20px; margin-bottom: 12px;
             border-bottom: 1px solid #3f3f46; padding-bottom: 4px; }
        h3 { color: #dcdcaa; font-size: 15px; font-weight: 600; margin-bottom: 4px; }
        .context { list-style: none; }
        .context li { padding: 4px 0; color: #d4d4d4; }
        .context strong { color: #4ec9b0; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 10px;
        }
        .card {
            background: #252526; border: 1px solid #3f3f46;
            border-radius: 6px; padding: 12px; text-align: center;
        }
        .card .count { font-size: 28px; font-weight: 700; color: #e0e0e0; }
        .card .label { color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        .card .sub { display: block; color: #888; font-size: 11px; margin-top: 2px; }
        a.card-link { display: block; text-decoration: none; cursor: pointer; color: inherit; }
        a.card-link:hover { border-color: #007acc; background: #2a2d2e; }
        .recordings li a.rec-link { color: #9cdcfe; text-decoration: none; cursor: pointer; }
        .recordings li a.rec-link:hover { text-decoration: underline; }
        .muted { color: #888; font-size: 11px; }
        .steps { list-style: decimal; padding-left: 28px; }
        .steps li { padding: 3px 0; border-bottom: 1px solid #2d2d30; color: #d4d4d4; }
        table.actions { border-collapse: collapse; width: 100%; font-size: 13px; }
        table.actions th, table.actions td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #2d2d30; vertical-align: top; }
        table.actions th { color: #4ec9b0; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        table.actions td.ts { color: #888; font-family: Consolas, monospace; white-space: nowrap; }
        table.actions td.src { color: #dcdcaa; }
        .finding {
            background: #252526; border-left: 3px solid #007acc;
            border-radius: 0 6px 6px 0; padding: 12px 16px; margin: 10px 0;
            overflow: hidden;
        }
        .bugs .finding { border-left-color: #f48771; }
        .enhancements .finding { border-left-color: #4ec9b0; }
        .testideas .finding { border-left-color: #dcdcaa; }
        .observations .finding { border-left-color: #9cdcfe; }
        .finding time { color: #888; font-size: 11px; font-family: Consolas, monospace; }
        .finding dl { margin-top: 8px; display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }
        .finding dt { color: #4ec9b0; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding dd { color: #d4d4d4; }
        .sev {
            display: inline-block; padding: 1px 8px; border-radius: 3px;
            font-size: 11px; font-weight: 600; text-transform: uppercase;
            background: #3f3f46; color: #d4d4d4; margin-left: 6px;
        }
        .sev-critical { background: #7c2222; color: #ffdcdc; }
        .sev-high { background: #a04a1a; color: #ffddc4; }
        .sev-medium { background: #5a5a1a; color: #f0f0c4; }
        .sev-low { background: #1e4a5a; color: #c4e0f0; }
        .sev-info { background: #1e4a5a; color: #c4e0f0; }
        .findings { list-style: none; }
        .findings li { padding: 6px 10px; border-bottom: 1px solid #2d2d30; overflow: hidden; }
        .findings time { color: #888; font-family: Consolas, monospace; font-size: 12px; margin-right: 8px; }
        .findings em { color: #888; font-style: italic; }
        .tags { margin: 4px 0; }
        .tag {
            display: inline-block; padding: 2px 8px; margin: 2px 4px 2px 0;
            background: #2d4a6a; color: #9cdcfe; border-radius: 10px;
            font-size: 11px; font-weight: 500;
        }
        .entry-url { font-size: 12px; color: #888; margin: 2px 0; }
        .entry-url a { color: #4ec9b0; text-decoration: none; }
        .entry-url a:hover { text-decoration: underline; }
        .screenshot-ref {
            margin-top: 10px; padding: 8px 12px; background: #252526;
            border: 1px solid #3f3f46; border-radius: 4px;
            font-size: 13px; color: #d4d4d4;
        }
        .screenshot-ref code { background: transparent; padding: 0; color: #9cdcfe; }
        .screenshot-ref a { color: #4ec9b0; text-decoration: none; }
        .screenshot-ref a:hover { text-decoration: underline; }
        .screenshot-ref.missing { border-color: #5a3a1e; background: #2a1f14; }
        .screenshot-ref .hint { color: #888; font-style: italic; margin-left: 4px; }
        .screenshot { max-width: 100%; border: 1px solid #3f3f46; border-radius: 6px; margin: 8px 0; }
        .screenshot-embed { margin-top: 8px; }
        .md-body p { margin: 6px 0; }
        .md-body ul, .md-body ol { margin: 6px 0 6px 18px; }
        .md-body code { background: #1e1e1e; color: #ce9178; padding: 1px 4px; border-radius: 3px; }
        .md-body pre { background: #0c0c0c; border: 1px solid #3f3f46; border-radius: 4px; padding: 8px; overflow-x: auto; }
        .md-body a { color: #4ec9b0; }
        """;
}
