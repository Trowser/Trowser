using System.IO;
using System.IO.Compression;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Bookmarks;
using Trowser.Recording;
using Trowser.Repro;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class BookmarkTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "trowser-bookmark-tests-" + Guid.NewGuid().ToString("N")[..8]);

    public BookmarkTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    [Theory]
    [InlineData("/api/click", "{\"role\":\"button\",\"label\":\"Log in\"}", "Click button \"Log in\"")]
    [InlineData("/api/click", "{\"byText\":\"Next\"}", "Click \"Next\"")]
    [InlineData("/api/click", "{\"ref\":12}", "Click ref 12")]
    [InlineData("/api/type", "{\"label\":\"Email\",\"text\":\"a@b.test\"}", "Type \"a@b.test\" into \"Email\"")]
    [InlineData("/api/navigate", "{\"url\":\"https://trowser-regression.test/cart?x=1\"}", "Navigated to /cart?x=1")]
    [InlineData("/api/navigate", "{\"action\":\"reload\"}", "Reload the page")]
    [InlineData("/api/key", "{\"key\":\"Enter\"}", "Press Enter")]
    [InlineData("/api/go-back", null, "Go back")]
    [InlineData("/api/fetch", "{\"url\":\"x\"}", "POST /api/fetch")]
    [InlineData("/api/click", "not json", "POST /api/click")]
    [InlineData("/api/execute-js", "{\"script\":\"document.querySelector('#a')\\n  .click()\"}", "Run JS: document.querySelector('#a') .click()")]
    [InlineData("/api/batch", "{\"actions\":[{\"action\":\"click\",\"selector\":\"#a\"},{\"action\":\"type\",\"selector\":\"#b\",\"text\":\"x\"}]}", "Batch: Click #a; Type \"x\" into #b")]
    [InlineData("/api/tabs/new", "{\"url\":\"https://trowser-regression.test/p\"}", "Open a new tab at /p")]
    public void describe_api_action_narrates_rest_equivalents(string path, string? body, string expected)
    {
        Assert.Equal(expected, ActionNarrator.DescribeApiAction("POST", path, body));
    }

    [Fact]
    public void narrate_steps_skips_non_actions_and_marks_agent_steps()
    {
        var entries = new List<SessionLogger.JournalEntry>
        {
            Action("gui", "/api/click", "{\"byText\":\"Buy\"}"),
            new() { Type = "note", Source = "gui", Summary = "ignored" },
            Action("api", "/api/navigate", "{\"url\":\"https://trowser-regression.test/done\"}")
        };

        var (steps, omitted) = BookmarkEvidence.NarrateSteps(entries);

        Assert.Equal(0, omitted);
        Assert.Equal(["Click \"Buy\" (you)", "Navigated to /done (agent)"], steps);
    }

    [Fact]
    public void narrate_steps_keeps_the_last_steps_and_counts_the_rest()
    {
        var entries = Enumerable.Range(1, 7).Select(i => Action("gui", "/api/key", $"{{\"key\":\"K{i}\"}}")).ToList();

        var (steps, omitted) = BookmarkEvidence.NarrateSteps(entries, max: 3);

        Assert.Equal(4, omitted);
        Assert.Equal(["Press K5 (you)", "Press K6 (you)", "Press K7 (you)"], steps);
    }

    [Fact]
    public void api_action_carries_tab_id_for_bookmark_slice()
    {
        var logger = new SessionLogger();
        logger.LogApiAction("POST", "/api/click", "ref 1", rawBody: "{\"ref\":1}", tabId: 42);
        var entry = logger.GetJournal(type: "action").Single();
        Assert.Equal(42, BookmarkFields.TryGetTabId(entry.Fields));
        Assert.True(BookmarkFields.ActionMatchesTab(entry, 42));
        Assert.False(BookmarkFields.ActionMatchesTab(entry, 7));
    }

    [Fact]
    public void journal_index_starts_at_one()
    {
        var logger = new SessionLogger();
        var entry = logger.LogBookmark("gui", "hello", null, BookmarkEvidence.BuildFields("bm-1", 1, null, [], 0, null, _dir, null, null, null));
        Assert.Equal(1, entry.Index);
    }

    [Fact]
    public void reclassify_bookmark_moves_narration_off_bug_steps()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-steps", 1, null, ["Type \"x\" into Password (agent)"], 0,
            null, _dir, null, null, null);
        fields["steps"] = fields[BookmarkFields.CapturedSteps];
        fields.Remove(BookmarkFields.CapturedSteps);
        var entry = logger.LogBookmark("api", "Login", "https://example.test/", fields);
        var updated = logger.UpdateEntry(entry.Index, NoteKinds.Bug, "Weak password",
            fields: new Dictionary<string, string> { ["expected"] = "lockout" }, setFields: true);
        Assert.NotNull(updated);
        Assert.True(updated.Fields!.ContainsKey(BookmarkFields.CapturedSteps));
        Assert.False(updated.Fields.ContainsKey("steps"));
    }

    [Fact]
    public void promote_bookmark_to_bug_keeps_evidence_and_updates_type()
    {
        var logger = new SessionLogger();
        LogSampleBookmark(logger, "bm-promote");
        var entry = logger.GetJournal(type: "bookmark").Single();
        var updated = logger.UpdateEntry(entry.Index, NoteKinds.Bug, "Broken checkout",
            fields: new Dictionary<string, string> { ["actual"] = "total wrong" }, setFields: true);

        Assert.NotNull(updated);
        Assert.Equal(NoteKinds.Bug, updated.Type);
        Assert.Equal(NoteKinds.Bug, updated.Kind);
        Assert.False(BookmarkInfo.IsBookmark(updated));
        Assert.True(BookmarkInfo.HasBookmarkEvidence(updated));
        Assert.True(BookmarkInfo.FromEntry(updated).CanRestore);
        Assert.Empty(logger.GetJournal(type: "bookmark"));
    }

    [Fact]
    public void bookmark_number_uses_max_plus_one_after_delete()
    {
        var logger = new SessionLogger();
        LogSampleBookmark(logger, "bm-a");
        LogSampleBookmark(logger, "bm-b");
        var second = logger.GetJournal(type: "bookmark").Last();
        Assert.Equal(2, BookmarkInfo.FromEntry(second).BookmarkNumber);
        logger.DeleteEntry(second.Index);
        LogSampleBookmark(logger, "bm-c");
        var third = logger.GetJournal(type: "bookmark").Last();
        Assert.Equal(3, BookmarkInfo.FromEntry(third).BookmarkNumber);
    }

    [Fact]
    public void narrate_steps_includes_failed_api_errors()
    {
        var logger = new SessionLogger();
        logger.LogApiAction("POST", "/api/click", rawBody: "{\"ref\":99}", tabId: 1);
        var err = logger.GetJournal(type: "action").Single();
        err.Type = "error";
        err.Details = "Invalid ref";
        var (steps, _) = BookmarkEvidence.NarrateSteps([err]);
        Assert.Single(steps);
        Assert.Contains("(failed)", steps[0]);
        Assert.Contains("ref 99", steps[0]);
    }

    [Fact]
    public void logged_bookmark_round_trips_through_bookmark_info()
    {
        var logger = new SessionLogger();
        var request = new NetworkEntry { Method = "POST", Url = "https://trowser-regression.test/api/cart", StatusCode = 500 };
        var trw = Path.Combine(_dir, "repro.trw");
        File.WriteAllText(trw,
            JsonSerializer.Serialize(new
            {
                name = "Cart",
                trigger = new object[] { new { type = "navigate", url = "https://trowser-regression.test/cart" } },
                oracle = new { type = "and", checks = Array.Empty<object>() }
            }));

        var fields = BookmarkEvidence.BuildFields("bm-abc", 2, "tok-c1", ["Click \"Buy\""], 2, request,
            _dir, Path.Combine(_dir, "screenshot.png"), trw, statePath: null);

        var entry = logger.LogBookmark("gui", "Cart", "https://trowser-regression.test/cart", fields, "odd total");
        var info = BookmarkInfo.FromEntry(entry);

        Assert.Equal("bookmark", entry.Type);
        Assert.Equal("bm-abc", info.Id);
        Assert.Equal("tok-c1", info.CheckpointId);
        Assert.Equal("Cart", info.Title);
        Assert.Equal("odd total", info.Note);
        Assert.Equal(3, info.StepCount);
        Assert.Equal(2, info.StepsOmitted);
        Assert.Equal(500, info.LastRequest!.Status);
        Assert.Equal("POST", info.LastRequest.Method);
        Assert.True(info.CanVerify);
        Assert.False(info.CanRestore);
        Assert.Single(logger.GetJournal(type: "bookmark"));
    }

    [Fact]
    public void redact_keeps_names_and_replaces_values()
    {
        var redacted = BookmarkEvidence.Redact(SampleState());

        Assert.Equal("session", redacted.Cookies[0].Name);
        Assert.Equal(BookmarkEvidence.RedactedValue, redacted.Cookies[0].Value);
        Assert.Equal(BookmarkEvidence.RedactedValue, redacted.LocalStorage["token"]);
        Assert.Equal(BookmarkEvidence.RedactedValue, redacted.SessionStorage["step"]);
        Assert.DoesNotContain("s3cret", BookmarkEvidence.SerializeState(redacted));
    }

    [Fact]
    public void state_round_trips_through_json()
    {
        var back = BookmarkEvidence.DeserializeState(BookmarkEvidence.SerializeState(SampleState()));

        Assert.Equal(BrowserSessionScopeKind.Site, back.Scope);
        Assert.Equal("trowser-regression.test", back.AnchorHost);
        Assert.Equal("s3cret-cookie", back.Cookies[0].Value);
        Assert.Equal("s3cret-token", back.LocalStorage["token"]);
    }

    [Fact]
    public void export_then_import_keeps_evidence_and_never_leaks_or_restores_state()
    {
        var source = new SessionLogger();
        var entry = LogSampleBookmark(source, "bm-export1");
        var zip = Path.Combine(_dir, "out.zip");

        var result = BookmarkArchive.Export(entry, zip);

        Assert.True(result.StateRedacted);
        Assert.Contains(BookmarkFields.TrwFile, result.Files);
        using (var archive = ZipFile.OpenRead(zip))
        {
            foreach (var e in archive.Entries)
            {
                using var r = new StreamReader(e.Open());
                Assert.DoesNotContain("s3cret", r.ReadToEnd());
            }
        }

        var target = new SessionLogger();
        var root = Path.Combine(_dir, "imported");
        var imported = BookmarkInfo.FromEntry(BookmarkArchive.Import(zip, root, target));

        Assert.Equal("bm-export1", imported.Id);
        Assert.Equal("Checkout", imported.Title);
        Assert.True(imported.CanVerify);
        Assert.True(File.Exists(imported.TrwPath));
        Assert.True(File.Exists(imported.Screenshot));
        Assert.StartsWith(Path.Combine(root, "bm-export1"), imported.TrwPath);
        Assert.True(imported.StateRedacted);
        Assert.False(imported.CanRestore);
    }

    [Fact]
    public void import_assigns_a_new_id_when_the_bookmark_already_exists()
    {
        var logger = new SessionLogger();
        var entry = LogSampleBookmark(logger, "bm-dupe");
        var zip = Path.Combine(_dir, "dupe.zip");
        BookmarkArchive.Export(entry, zip);

        var imported = BookmarkInfo.FromEntry(BookmarkArchive.Import(zip, Path.Combine(_dir, "root"), logger));

        Assert.NotEqual("bm-dupe", imported.Id);
        Assert.True(BookmarkEvidence.IsValidId(imported.Id));
    }

    [Fact]
    public void import_ignores_unknown_and_traversal_entries()
    {
        var logger = new SessionLogger();
        var entry = LogSampleBookmark(logger, "bm-slip");
        var zip = Path.Combine(_dir, "slip.zip");
        BookmarkArchive.Export(entry, zip);
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Update))
        {
            using var w = new StreamWriter(archive.CreateEntry("../evil.txt").Open());
            w.Write("x");
        }

        var root = Path.Combine(_dir, "slip-root");
        BookmarkArchive.Import(zip, root, new SessionLogger());

        Assert.False(File.Exists(Path.Combine(root, "evil.txt")));
        Assert.False(File.Exists(Path.Combine(_dir, "evil.txt")));
    }

    [Fact]
    public void import_rejects_a_zip_without_a_bookmark_entry()
    {
        var zip = Path.Combine(_dir, "empty.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            archive.CreateEntry("readme.txt");

        Assert.Throws<InvalidOperationException>(() =>
            BookmarkArchive.Import(zip, Path.Combine(_dir, "r"), new SessionLogger()));
    }

    [Fact]
    public void restore_is_blocked_in_safe_mode_but_catch_and_read_are_not()
    {
        Assert.True(SafeModePolicy.IsRouteBlocked("/api/bookmark-restore", "POST", null));
        Assert.True(SafeModePolicy.IsToolBlocked("browser_bookmark_restore", default));
        Assert.False(SafeModePolicy.IsRouteBlocked("/api/bookmark", "POST", null));
        Assert.False(SafeModePolicy.IsToolBlocked("browser_bookmark", default));
    }

    [Fact]
    public void evidence_page_encodes_page_text()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-x", 1, null, ["Click \"<img src=x onerror=alert(1)>\""], 0,
            new NetworkEntry { Method = "GET", Url = "https://trowser-regression.test/?q=<script>", StatusCode = 200 },
            _dir, null, null, null);
        var entry = logger.LogBookmark("api", "<script>alert(1)</script>", "https://trowser-regression.test/", fields);

        var html = JournalReportGenerator.GenerateBookmarkDetailHtml(entry);

        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("No screenshot was captured", html);
    }

    [Fact]
    public void journal_bundle_round_trips_bookmark_entries()
    {
        var logger = new SessionLogger();
        LogSampleBookmark(logger, "bm-bundle");

        var bundle = JournalBundle.Deserialize(JournalBundle.Serialize(logger.GetJournal(), pointers: null));
        var back = BookmarkInfo.FromEntry(bundle.Entries.Single().ToEntry());

        Assert.Equal("bm-bundle", back.Id);
        Assert.True(back.CanRestore);
    }

    [Fact]
    public void deleting_an_imported_duplicate_keeps_the_original_evidence()
    {
        var logger = new SessionLogger();
        var original = LogSampleBookmark(logger, "bm-orig");
        var bundle = JournalBundle.Deserialize(JournalBundle.Serialize([original], pointers: null));

        var copy = logger.ImportEntry(bundle.Entries.Single().ToEntry());
        var copyInfo = BookmarkInfo.FromEntry(copy);

        Assert.NotEqual("bm-orig", copyInfo.Id);
        Assert.Equal("bm-orig", copy.Fields![BookmarkFields.ImportedId]);
        Assert.True(File.Exists(copyInfo.TrwPath));
        Assert.DoesNotContain(Path.Combine(_dir, "bm-orig"), copyInfo.TrwPath);

        Assert.True(logger.DeleteEntry(copy.Index));

        var back = BookmarkInfo.FromEntry(original);
        Assert.True(File.Exists(back.TrwPath));
        Assert.True(back.CanRestore);
        Assert.False(Directory.Exists(Path.Combine(_dir, copyInfo.Id)));
    }

    [Fact]
    public void evidence_cleanup_skips_shared_and_foreign_folders()
    {
        var logger = new SessionLogger();
        var entry = LogSampleBookmark(logger, "bm-shared");
        var twin = new SessionLogger.JournalEntry { Type = "bookmark", Fields = new(entry.Fields!, StringComparer.OrdinalIgnoreCase) };

        BookmarkEvidenceCleanup.TryDeleteFolder(entry, [twin]);
        Assert.True(File.Exists(Path.Combine(_dir, "bm-shared", BookmarkFields.TrwFile)));

        var foreign = Path.Combine(_dir, "not-a-bookmark");
        Directory.CreateDirectory(foreign);
        File.WriteAllText(Path.Combine(foreign, BookmarkFields.TrwFile), "{}");
        var stray = new SessionLogger.JournalEntry
        {
            Type = "bookmark",
            Fields = new(StringComparer.OrdinalIgnoreCase) { [BookmarkFields.BookmarkId] = "bm-stray", [BookmarkFields.Directory] = foreign }
        };
        BookmarkEvidenceCleanup.TryDeleteFolder(stray);
        Assert.True(File.Exists(Path.Combine(foreign, BookmarkFields.TrwFile)));

        BookmarkEvidenceCleanup.TryDeleteFolder(entry, []);
        Assert.False(Directory.Exists(Path.Combine(_dir, "bm-shared")));
    }

    [Fact]
    public void can_restore_follows_the_state_file_on_disk()
    {
        var entry = LogSampleBookmark(new SessionLogger(), "bm-gone");
        Assert.True(BookmarkInfo.FromEntry(entry).CanRestore);

        File.Delete(entry.Fields![BookmarkFields.StatePath]);

        Assert.False(BookmarkInfo.FromEntry(entry).CanRestore);
    }

    [Fact]
    public void importing_the_same_zip_twice_returns_the_first_import()
    {
        var zip = Path.Combine(_dir, "twice.zip");
        BookmarkArchive.Export(LogSampleBookmark(new SessionLogger(), "bm-twice"), zip);
        var target = new SessionLogger();
        var root = Path.Combine(_dir, "twice-root");

        var first = BookmarkArchive.ImportOrFind(zip, root, target, out var firstDup);
        var second = BookmarkArchive.ImportOrFind(zip, root, target, out var secondDup);

        Assert.False(firstDup);
        Assert.True(secondDup);
        Assert.Equal(first.Index, second.Index);
        Assert.Single(target.GetJournal(), BookmarkInfo.HasBookmarkEvidence);
    }

    [Fact]
    public void capture_opens_the_start_page_and_replays_refs_by_their_recorded_selector()
    {
        var logger = new SessionLogger();
        logger.LogApiAction("POST", "/api/click", "ref 3", rawBody: "{\"ref\":3}", tabId: 1,
            pageUrl: "https://trowser-regression.test/shop",
            extraFields: new Dictionary<string, string> { [ReproCaptureService.RefSelectorsField] = "{\"3\":\"#buy\"}" });

        var result = ReproCaptureService.Capture(logger, null, null, "t", null, null, sinceJournalIndex: -1, tabId: 1,
            setupNavigateUrl: "https://trowser-regression.test/shop");

        using var doc = JsonDocument.Parse(result.WorkflowJson);
        var setup = doc.RootElement.GetProperty("setup");
        Assert.Equal("navigate", setup[0].GetProperty("type").GetString());
        Assert.Equal("https://trowser-regression.test/shop", setup[0].GetProperty("url").GetString());
        Assert.Equal("#buy", doc.RootElement.GetProperty("trigger")[0].GetProperty("body").GetProperty("selector").GetString());
    }

    [Fact]
    public void batch_and_new_tab_actions_become_replay_steps()
    {
        var batch = ReproCaptureService.TryBuildSteps(Action("api", "/api/batch",
            "{\"actions\":[{\"action\":\"click\",\"ref\":5},{\"action\":\"wait\",\"ms\":10},{\"action\":\"type\",\"selector\":\"#q\",\"text\":\"hi\"}]}"));
        var tab = ReproCaptureService.TryBuildSteps(Action("api", "/api/tabs/new", "{\"url\":\"https://trowser-regression.test/\"}"));

        var json = JsonSerializer.Serialize(batch);
        Assert.Equal(2, batch!.Count);
        Assert.Contains("\"/api/click\"", json);
        Assert.Contains("\"/api/type\"", json);
        Assert.DoesNotContain("\"action\"", json);
        Assert.Contains("\"navigate\"", JsonSerializer.Serialize(tab));
    }

    [Fact]
    public void last_request_prefers_the_page_site_over_third_party_beacons()
    {
        var entries = new List<NetworkEntry>
        {
            new() { Method = "POST", Url = "https://api.trowser-regression.test/cart", StatusCode = 200, ResourceType = "Fetch" },
            new() { Method = "POST", Url = "https://telemetry.example.test/beacon", StatusCode = 401, ResourceType = "Fetch" }
        };

        var picked = BookmarkEvidence.PickLastMeaningfulRequest(entries, "https://www.trowser-regression.test/cart");

        Assert.Equal("https://api.trowser-regression.test/cart", picked?.Url);
    }

    [Theory]
    [InlineData("setup", 2, true)]
    [InlineData("trigger", 0, true)]
    [InlineData("trigger", 1, false)]
    [InlineData("oracle", null, false)]
    public void first_step_and_setup_failures_are_preconditions(string phase, int? step, bool expected)
    {
        Assert.Equal(expected, Repro.ReproVerifyService.IsPreconditionFailure(
            new Repro.ReproRunFailure { Phase = phase, StepIndex = step, Message = "x" }));
    }

    [Fact]
    public void slice_starts_after_the_latest_go_on_the_tab()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-a", 1, null, [], 0, null, _dir, null, null, null, tabId: 4);
        logger.LogBookmark("api", "A", "https://trowser-regression.test/", fields);
        var go = logger.LogBookmarkEvent("api", "restore", "bm-z", "Go", tabId: 4);
        logger.LogBookmarkEvent("api", "restore", "bm-other-tab", "Go", tabId: 9);

        var (boundary, startsFrom) = BookmarkService.FindSliceStart(logger.GetJournal(), 4);

        Assert.Equal(go.Index, boundary?.Index);
        Assert.Equal("bm-z", startsFrom);
    }

    [Fact]
    public void journal_index_names_bookmarks_by_number_and_note()
    {
        var logger = new SessionLogger();
        var fields = BookmarkEvidence.BuildFields("bm-n", 3, null, [], 0, null, _dir, null, null, null);
        var entry = logger.LogBookmark("api", "Swag Labs", null, fields, "cart badge wrong");

        Assert.EndsWith("#3 Swag Labs — cart badge wrong", JournalProjection.FormatIndexLine(entry));
    }

    private SessionLogger.JournalEntry LogSampleBookmark(SessionLogger logger, string id)
    {
        var folder = Path.Combine(_dir, id);
        Directory.CreateDirectory(folder);
        var shot = Path.Combine(folder, BookmarkFields.ScreenshotFile);
        File.WriteAllBytes(shot, [0x89, 0x50, 0x4E, 0x47]);
        var trw = Path.Combine(folder, BookmarkFields.TrwFile);
        File.WriteAllText(trw, JsonSerializer.Serialize(new { name = "Checkout", trigger = new[] { new { type = "navigate", url = "https://trowser-regression.test/" } } }));
        var state = Path.Combine(folder, BookmarkFields.StateFile);
        File.WriteAllText(state, BookmarkEvidence.SerializeState(SampleState()));

        var num = logger.AllocateBookmarkNumber();
        var fields = BookmarkEvidence.BuildFields(id, num, "tok-c1", ["Navigated to /"], 0, null, folder, shot, trw, state);
        return logger.LogBookmark("gui", "Checkout", "https://trowser-regression.test/checkout", fields);
    }

    private static BrowserSessionSnapshot SampleState() => new()
    {
        Scope = BrowserSessionScopeKind.Site,
        AnchorUrl = "https://trowser-regression.test/checkout",
        AnchorOrigin = "https://trowser-regression.test",
        AnchorHost = "trowser-regression.test",
        Cookies = [new BrowserSessionCookieRecord { Name = "session", Value = "s3cret-cookie", Domain = "trowser-regression.test" }],
        LocalStorage = new Dictionary<string, string> { ["token"] = "s3cret-token" },
        SessionStorage = new Dictionary<string, string> { ["step"] = "s3cret-step" }
    };

    private static SessionLogger.JournalEntry Action(string source, string path, string body) => new()
    {
        Type = "action",
        Source = source,
        Summary = $"POST {path}",
        Fields = new Dictionary<string, string> { ["method"] = "POST", ["path"] = path, ["body"] = body }
    };
}
