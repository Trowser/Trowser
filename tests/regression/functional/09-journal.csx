// Functional: journal add / update / delete and compact vs full HTML report.

await ResetBrowserState();

Assert.Section("In-memory mutate");
var log = new SessionLogger();
var added = log.LogTesterNote(NoteKinds.Note, "Title line", tags: new List<string> { "login" }, details: "**bold** body");
Assert.Equal("Title line", added.Summary, "title stored as summary");
Assert.Equal("**bold** body", added.Details, "markdown body stored as details");
Assert.Equal(0, added.Index, "first index is 0");

NoteKinds.SplitTitleBody("Hello\n**world**", out var splitTitle, out var splitBody);
Assert.Equal("Hello", splitTitle, "SplitTitleBody title");
Assert.Equal("**world**", splitBody, "SplitTitleBody body");
Assert.True(log.Revision >= 1, "revision increments on add");

var updated = log.UpdateEntry(added.Index, summary: "Renamed", details: "new body", setDetails: true);
Assert.NotNull(updated, "update finds the entry");
Assert.Equal("Renamed", updated!.Summary, "summary replaced");
Assert.Equal("new body", updated.Details, "details replaced");
Assert.Equal(added.Index, updated.Index, "index is stable");

var bug = log.LogLlmNote("Search is broken", kind: NoteKinds.Bug,
    fields: new Dictionary<string, string> { ["actual"] = "0 hits", ["expected"] = "results" },
    tags: new List<string> { "search" });
Assert.Equal("api", bug.Source, "LLM notes are source=api");

Assert.True(log.DeleteEntry(added.Index), "delete returns true");
Assert.Null(log.GetEntry(added.Index), "deleted entry is gone");
Assert.False(log.DeleteEntry(added.Index), "second delete is false");
Assert.True(log.DeletedIndices.Contains(added.Index), "tombstone recorded");
Assert.NotNull(log.GetEntry(bug.Index), "other entries remain");
Assert.Null(log.GetJournal().FirstOrDefault(e => e.Index == added.Index), "GET list omits deleted");

Assert.Section("Bug/enhancement rank is priority, not severity");
var folded = log.LogTesterNote(NoteKinds.Bug, "Folded rank", severity: "high");
Assert.Null(folded.Severity, "severity is not stored on bugs");
Assert.Equal("high", folded.Fields!["priority"], "severity folds into priority");

var both = log.LogTesterNote(NoteKinds.Enhancement, "Both ranks", severity: "critical",
    fields: new Dictionary<string, string> { ["priority"] = "low" });
Assert.Null(both.Severity, "severity dropped when priority is set");
Assert.Equal("low", both.Fields!["priority"], "existing priority wins");

var rankedNote = log.LogTesterNote(NoteKinds.Note, "Just a note", severity: "medium");
Assert.Equal("medium", rankedNote.Severity, "notes still store severity");

var observed = log.LogLlmNote("Works well", kind: NoteKinds.Observation, evidence: NoteKinds.EvidenceObserved);
Assert.Equal(NoteKinds.EvidenceObserved, observed.Evidence, "explicit evidence stored");
var inferredDefault = log.LogLlmNote("Maybe slow", kind: NoteKinds.Note);
Assert.Equal(NoteKinds.EvidenceInferred, inferredDefault.Evidence, "LLM note defaults to inferred");
var idea = log.LogTesterNote(NoteKinds.TestIdea, "Try edge case");
Assert.Equal(NoteKinds.EvidenceUntested, idea.Evidence, "test-idea defaults to untested");
log.LogApiAction("GET", "/api/state");
Assert.Equal(NoteKinds.EvidenceObserved, log.GetJournal(type: "action").Last().Evidence, "auto action is observed");

var edited = log.UpdateEntry(folded.Index, summary: "Folded rank (edited)");
Assert.Null(edited!.Severity, "editing a bug does not restore severity");
Assert.Equal("high", edited.Fields!["priority"], "priority survives edit");

Assert.Section("Compact HTML (panel)");
var compact = JournalReportGenerator.GenerateHtml(log.GetJournal(), compact: true);
Assert.True(compact.Contains("data-section=\"bugs\""), "summary cards toggle sections");
Assert.True(compact.Contains("data-section=\"screenshots\""), "screenshot card is always present");
Assert.True(compact.Contains("Ctrl+Shift+S"), "screenshot hint");
Assert.False(compact.Contains("trowser://edit/"), "edit is context-menu only");
Assert.False(compact.Contains("trowser://delete/"), "delete is context-menu only");
Assert.False(compact.Contains(">Show me<"), "show me is context-menu only");
Assert.True(compact.Contains("trowser://apiactions") || compact.Contains("API actions"), "API actions card");
Assert.False(compact.Contains("data:image"), "panel does not embed screenshots");
Assert.True(compact.Contains("container compact"), "compact chrome");
Assert.False(compact.Contains("<h1>Trowser Session Report") || compact.Contains("<h1>Trowser Session Report</h1>"), "compact drops report h1");
Assert.True(compact.Contains("sev-high"), "folded bug shows priority badge");
Assert.False(compact.Contains("priority: high"), "no duplicate priority: prefix on bugs");
Assert.True(compact.Contains("sev-low"), "enhancement keeps explicit priority");

Assert.Section("Full HTML report");
log.LogScreenshot(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "no-such-shot.png"));
var shotEntry = log.GetJournal(type: "screenshot").LastOrDefault();
Assert.NotNull(shotEntry, "screenshot entry created (file need not exist)");
var full = JournalReportGenerator.GenerateHtml(log.GetJournal(), compact: false);
Assert.True(full.Contains("Trowser Session Report"), "full report has title");
Assert.True(full.Contains("Screenshots"), "full report has screenshots section");
Assert.False(full.Contains("trowser://edit/"), "export has no panel edit links");
Assert.True(full.Contains("Search is broken"), "finding rendered");

Assert.Section("Full-text search");
var fieldHits = log.GetJournal(q: "0 hits");
Assert.True(fieldHits.Any(e => e.Index == bug.Index), "q matches field text, not only tags");
var titleHits = log.GetJournal(q: "Search is broken");
Assert.True(titleHits.Any(e => e.Index == bug.Index), "q matches summary");
var tagHits = log.GetJournal(q: "search");
Assert.True(tagHits.Any(e => e.Index == bug.Index), "q still matches tags");
Assert.Equal(0, log.GetJournal(q: "zzzz-not-present").Count, "q miss is empty");

Log($"Journal count={log.JournalCount} revision={log.Revision} deleted={string.Join(",", log.DeletedIndices)}");
