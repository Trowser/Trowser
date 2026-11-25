using System.IO;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Pointers;
using Trowser.Repro;
using Trowser.Security;
using Trowser.Security.Workflow;
using Trowser.SessionLog;

namespace Trowser.Bookmarks;

/// <summary>
/// Catch, list, restore, export, and import bookmarks. The nav button, Ctrl+B, REST, MCP, and
/// scripts all go through this one service, which <see cref="AutomationContext"/> owns.
/// Evidence files live in <c>bookmarks/{id}/</c> beside the session log (or under the temp
/// folder when logging is off).
/// </summary>
public sealed class BookmarkService
{
    private readonly AutomationContext _context;
    private readonly SessionLogger _logger;
    private readonly PointerStore _pointers;
    private readonly Func<bool> _isSafeMode;
    private readonly IdentityStore? _identityStore;
    private readonly SemaphoreSlim _catchLock = new(1, 1);

    public BookmarkService(AutomationContext context, SessionLogger logger, PointerStore pointers, Func<bool> isSafeMode,
        IdentityStore? identityStore = null)
    {
        _context = context;
        _logger = logger;
        _pointers = pointers;
        _isSafeMode = isSafeMode;
        _identityStore = identityStore;
    }

    public const string ServerNotRestoredNote =
        "Cookies, localStorage, and sessionStorage were restored in the browser. The server is not restored: " +
        "data created or deleted since the bookmark is still there. Use Verify to replay the steps.";

    public SessionLogger Logger => _logger;

    /// <summary>Folder that holds one subfolder per bookmark.</summary>
    public string RootDirectory
    {
        get
        {
            var logPath = _logger.IsLogging ? _logger.FilePath : null;
            if (!string.IsNullOrEmpty(logPath))
                return Path.Combine(Path.GetDirectoryName(Path.GetFullPath(logPath))!, "bookmarks");
            return Path.Combine(Path.GetTempPath(), "trowser-bookmarks");
        }
    }

    /// <summary>
    /// Bookmark this moment: one checkpoint, one screenshot, one journal entry. Steps are the journal
    /// actions since the previous bookmark; a <c>.trw</c> is written when any of them can be replayed.
    /// </summary>
    public async Task<BookmarkInfo> CatchAsync(string source, string? note = null)
    {
        await _catchLock.WaitAsync();
        try
        {
            var id = BookmarkEvidence.NewId();
            var dir = Path.Combine(RootDirectory, id);
            Directory.CreateDirectory(dir);

            string url = "", title = "";
            try
            {
                var tab = _context.ActiveTab;
                var raw = await _context.GetCurrentUrl();
                url = AgentUrlPolicy.ResolveLogicalPageUrl(raw, tab.DisplayUrlOverride) ?? raw;
                url = AgentUrlPolicy.ForAgent(url) ?? "";
            }
            catch { /* no live page */ }
            try { title = await _context.GetTitle(); } catch { /* no live page */ }

            var tabId = _context.ActiveTab.Id;
            var bookmarkNumber = _logger.AllocateBookmarkNumber();
            var (boundary, startsFrom) = FindSliceStart(_logger.GetJournal(), tabId);
            var sinceIndex = boundary?.Index ?? -1;
            var actions = _logger.GetJournal(since: sinceIndex)
                .Where(e => BookmarkFields.ActionMatchesTab(e, tabId))
                .ToList();
            var (steps, omitted) = BookmarkEvidence.NarrateSteps(actions);
            // The page the first step ran on; the .trw opens it first so a mid-flow slice replays on the right page.
            var startUrl = actions.FirstOrDefault(ReproJournalFilter.ShouldCaptureJournalAction)?.Url ?? boundary?.Url;

            var checkpoint = _pointers.AddCheckpoint(_logger.LastJournalIndex, $"bookmark {id}", NullIfEmpty(url));

            string? trwPath = null;
            try
            {
                // Selectors for refs were recorded when each action ran; re-resolving refs now would
                // map them against the current page, which is not the page they came from.
                var captured = ReproCaptureService.Capture(_logger, _pointers, checkpoint.Id,
                    string.IsNullOrWhiteSpace(title) ? "Bookmark" : title, Path.Combine(dir, BookmarkFields.TrwFile),
                    oracle: null, sinceJournalIndex: sinceIndex, tabId: tabId, setupNavigateUrl: startUrl);
                trwPath = captured.Path;
            }
            catch (InvalidOperationException) { /* nothing replayable since the previous bookmark */ }

            string? screenshotPath = null;
            try
            {
                // CDP capture with a bound wait — CapturePreview can hang when the window is Hidden.
                var bytes = await AwaitBounded(_context.ScreenshotToBytes(), TimeSpan.FromSeconds(12), "screenshot");
                if (bytes is { Length: > 0 })
                {
                    screenshotPath = Path.Combine(dir, BookmarkFields.ScreenshotFile);
                    await File.WriteAllBytesAsync(screenshotPath, bytes);
                }
            }
            catch (Exception ex) { TrowserLog.Warn($"Bookmark screenshot failed: {ex.Message}"); }

            NetworkEntry? lastRequest = null;
            try { lastRequest = BookmarkEvidence.PickLastMeaningfulRequest(_context.GetNetworkLog(), url); } catch { /* no network log */ }

            var statePath = await TryWriteStateAsync(dir, url);

            var fields = BookmarkEvidence.BuildFields(id, bookmarkNumber, checkpoint.Id, steps, omitted, lastRequest,
                dir, screenshotPath, trwPath, statePath, tabId, startUrl: startUrl, startsFrom: startsFrom);
            var summary = !string.IsNullOrWhiteSpace(title) ? title : !string.IsNullOrWhiteSpace(url) ? url : "Bookmark";
            var entry = _logger.LogBookmark(source, summary, NullIfEmpty(url), fields, NullIfEmpty(note?.Trim()));
            var info = BookmarkInfo.FromEntry(entry);
            if (!_logger.IsLogging)
                info.Warnings = [NotLoggingWarning];
            return info;
        }
        finally
        {
            _catchLock.Release();
        }
    }

    public const string NotLoggingWarning =
        "Session logging is off: the journal (and so this bookmark) is lost when Trowser closes, while its files stay in "
        + "%TEMP%\\trowser-bookmarks. Turn logging on to keep bookmarks, or export the ones you need.";

    /// <summary>
    /// Where this tab's step slice starts: the later of the previous bookmark on the tab and the last
    /// Go (restore) on the tab. Also returns the bookmark the slice continues from.
    /// </summary>
    internal static (SessionLogger.JournalEntry? Boundary, string? StartsFrom) FindSliceStart(
        IReadOnlyList<SessionLogger.JournalEntry> journal, int tabId)
    {
        for (var i = journal.Count - 1; i >= 0; i--)
        {
            var e = journal[i];
            if (BookmarkFields.TryGetTabId(e.Fields) != tabId) continue;
            if (BookmarkInfo.HasBookmarkEvidence(e))
                return (e, e.Fields!.GetValueOrDefault(BookmarkFields.BookmarkId));
            if (string.Equals(e.Type, BookmarkFields.EventEntryType, StringComparison.OrdinalIgnoreCase)
                && string.Equals(e.Fields!.GetValueOrDefault(BookmarkFields.EventName), "restore", StringComparison.OrdinalIgnoreCase))
                return (e, e.Fields!.GetValueOrDefault(BookmarkFields.EventBookmarkRef));
        }
        return (null, null);
    }

    /// <summary>
    /// Cookies, localStorage, and sessionStorage for the page's site. Skipped in safe mode (reading cookies
    /// is blocked there) and on pages that are not http(s).
    /// </summary>
    private async Task<string?> TryWriteStateAsync(string dir, string url)
    {
        if (_isSafeMode()) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps))
            return null;
        try
        {
            var snapshot = await AwaitBounded(
                _context.CaptureBrowserSessionSnapshotAsync(BrowserSessionScopeKind.Site, url),
                TimeSpan.FromSeconds(12), "state");
            var path = Path.Combine(dir, BookmarkFields.StateFile);
            await File.WriteAllTextAsync(path, BookmarkEvidence.SerializeState(snapshot));
            return path;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Bookmark state capture failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>Wait for <paramref name="task"/> or throw if it exceeds <paramref name="limit"/>.</summary>
    private static async Task<T> AwaitBounded<T>(Task<T> task, TimeSpan limit, string what)
    {
        var finished = await Task.WhenAny(task, Task.Delay(limit));
        if (finished != task)
            throw new TimeoutException($"Bookmark {what} timed out after {limit.TotalSeconds:0}s.");
        return await task;
    }

    public List<BookmarkInfo> List() =>
        _logger.GetJournal().Where(BookmarkInfo.HasBookmarkEvidence).Select(BookmarkInfo.FromEntry).ToList();

    /// <summary>Look up by bookmark id, or by journal index when <paramref name="idOrIndex"/> is a number.</summary>
    public SessionLogger.JournalEntry? FindEntry(string? idOrIndex)
    {
        if (string.IsNullOrWhiteSpace(idOrIndex)) return null;
        var bookmarks = _logger.GetJournal().Where(BookmarkInfo.HasBookmarkEvidence).ToList();
        var byId = bookmarks.FirstOrDefault(e =>
            e.Fields != null && e.Fields.TryGetValue(BookmarkFields.BookmarkId, out var v)
            && string.Equals(v, idOrIndex, StringComparison.OrdinalIgnoreCase));
        if (byId != null) return byId;
        return int.TryParse(idOrIndex, out var index) ? bookmarks.FirstOrDefault(e => e.Index == index) : null;
    }

    public BookmarkInfo? Get(string? idOrIndex)
    {
        var e = FindEntry(idOrIndex);
        return e == null ? null : BookmarkInfo.FromEntry(e);
    }

    /// <summary>
    /// Go: restore the saved cookies, localStorage, and sessionStorage, then navigate to the bookmark URL.
    /// The server is not restored. Cookies keep their saved expiry; cookies that have expired since the
    /// bookmark are skipped unless <paramref name="includeExpired"/> (then they come back as session cookies).
    /// The restore itself is journaled as one <c>bookmark-event</c> row, not as browser actions.
    /// </summary>
    public async Task<BookmarkRestoreResult> RestoreAsync(string idOrIndex, bool navigate = true,
        bool includeExpired = false, string source = "api")
    {
        if (_isSafeMode())
            throw new BookmarkException(403, "Safe mode: restoring a bookmark changes cookies and storage and is disabled.");

        var info = Get(idOrIndex) ?? throw new BookmarkException(404, $"Unknown bookmark: {idOrIndex}");
        var result = await RestoreCoreAsync(info, navigate, includeExpired);

        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["cookies"] = result.Cookies.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["localStorage"] = result.LocalStorage.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sessionStorage"] = result.SessionStorage.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (result.CookiesSkipped.Count > 0) extra["cookiesSkipped"] = string.Join(", ", result.CookiesSkipped);
        if (result.ExpiredCookiesRestored.Count > 0) extra["expiredCookiesRestored"] = string.Join(", ", result.ExpiredCookiesRestored);
        _logger.LogBookmarkEvent(source, "restore", info.Id, $"Go to {Label(info)}",
            details: null, extraFields: extra, url: result.Url, tabId: _context.ActiveTab?.Id);
        return result;
    }

    private async Task<BookmarkRestoreResult> RestoreCoreAsync(BookmarkInfo info, bool navigate, bool includeExpired)
    {
        if (info.StateRedacted)
            throw new BookmarkException(400, "This bookmark was imported with redacted cookies and storage, so it cannot be restored. Use Verify to replay its steps.");
        if (string.IsNullOrEmpty(info.StatePath))
            throw new BookmarkException(400, "This bookmark has no saved cookies or storage (it was caught in safe mode or on a page that is not http/https).");
        if (!ExportPathGuard.TryResolveRead(info.StatePath, out var full, out var pathError))
            throw new BookmarkException(400, pathError ?? "State path rejected.");
        if (!File.Exists(full))
            throw new BookmarkException(404, $"Bookmark state file not found: {full}");

        var snapshot = BookmarkEvidence.DeserializeState(await File.ReadAllTextAsync(full));
        var target = info.Url ?? snapshot.AnchorUrl;
        var hadStorage = snapshot.LocalStorage.Count > 0 || snapshot.SessionStorage.Count > 0;
        string? urlBefore = null;
        try { urlBefore = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var navigatedForStorage = hadStorage && !string.IsNullOrWhiteSpace(snapshot.AnchorUrl);
        var navigatedToBookmark = false;
        var restoredTesterUrl = false;
        CookieRestoreReport cookies;

        // The navigations below are part of Go, not something the tester did: keep them out of the
        // journal for the whole restore, and put back whatever the caller had set.
        var prevSuppress = _logger.SuppressGuiActions;
        var prevAgent = _context.IsAgentAutomation;
        _logger.SuppressGuiActions = true;
        _context.IsAgentAutomation = true;
        try
        {
            cookies = await _context.RestoreBrowserSessionSnapshotAsync(snapshot, keepExpiry: true, includeExpired: includeExpired);

            if (navigate && Uri.TryCreate(target, UriKind.Absolute, out var u)
                && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
            {
                var current = await _context.GetCurrentUrl();
                var sameUrl = AutomationContext.UrlEquivalentForNavigate(current, target!);
                if (!sameUrl || hadStorage)
                {
                    await _context.Navigate(target!, reload: hadStorage || !sameUrl);
                    navigatedToBookmark = true;
                }
            }
            else if (!navigate && !string.IsNullOrWhiteSpace(urlBefore))
            {
                await _context.Navigate(urlBefore, reload: hadStorage);
                restoredTesterUrl = true;
            }

            if (navigatedToBookmark || restoredTesterUrl || navigatedForStorage)
            {
                try { await _context.WaitForFinalNavigation(400, 5000); }
                catch { /* best effort: only here so late navigation events stay suppressed */ }
            }
        }
        finally
        {
            _context.IsAgentAutomation = prevAgent;
            _logger.SuppressGuiActions = prevSuppress;
        }

        return new BookmarkRestoreResult
        {
            Id = info.Id,
            Url = target,
            Navigated = navigatedToBookmark,
            NavigatedForStorage = navigatedForStorage,
            NavigatedToBookmarkUrl = navigatedToBookmark,
            RestoredPreviousUrl = restoredTesterUrl,
            Cookies = cookies.Restored,
            CookiesSkipped = cookies.SkippedExpired,
            ExpiredCookiesRestored = cookies.ExpiredRestoredAsSession,
            LocalStorage = snapshot.LocalStorage.Count,
            SessionStorage = snapshot.SessionStorage.Count,
            ServerRestored = false,
            Note = ServerNotRestoredNote
        };
    }

    /// <summary>Write one bookmark as a zip. <paramref name="zipPath"/> must already be validated with <see cref="ExportPathGuard"/>.</summary>
    public BookmarkArchive.ExportResult Export(string idOrIndex, string zipPath, string source = "api")
    {
        var entry = FindEntry(idOrIndex) ?? throw new BookmarkException(404, $"Unknown bookmark: {idOrIndex}");
        BookmarkArchive.ExportResult result;
        try { result = BookmarkArchive.Export(entry, zipPath); }
        catch (UnauthorizedAccessException ex) { throw new BookmarkException(400, $"Cannot write the export file: {ex.Message}"); }
        catch (IOException ex) { throw new BookmarkException(400, $"Cannot write the export file: {ex.Message}"); }
        var info = BookmarkInfo.FromEntry(entry);
        _logger.LogBookmarkEvent(source, "export", info.Id, $"Exported {Label(info)}", details: result.Path);
        return result;
    }

    /// <summary>
    /// Replay this bookmark's <c>.trw</c> workflow in the browser (needs active safety, not safe mode).
    /// Replayed steps are not journaled; one <c>bookmark-event</c> row records the verdict.
    /// With <paramref name="fromPrevious"/>, each run first restores the bookmark the steps continue from.
    /// </summary>
    public async Task<ReproVerifyResult> VerifyAsync(string idOrIndex, int runs = 1, bool clearSession = false,
        bool fromPrevious = false, string source = "api")
    {
        if (_isSafeMode())
            throw new BookmarkException(403, "Safe mode: verify replays steps and can change server state.");

        var info = Get(idOrIndex) ?? throw new BookmarkException(404, $"Unknown bookmark: {idOrIndex}");
        if (!info.CanVerify || string.IsNullOrEmpty(info.TrwPath))
            throw new BookmarkException(400, "This bookmark has no replayable steps.");

        if (!ExportPathGuard.TryResolveRead(info.TrwPath, out var full, out var pathError))
            throw new BookmarkException(400, pathError ?? "Trw path rejected.");
        if (!File.Exists(full))
            throw new BookmarkException(404, $"Bookmark workflow not found: {full}");

        BookmarkInfo? previous = null;
        if (fromPrevious)
        {
            if (string.IsNullOrEmpty(info.StartsFrom))
                throw new BookmarkException(400, "fromPrevious: this bookmark's steps do not continue from another bookmark.");
            previous = Get(info.StartsFrom)
                ?? throw new BookmarkException(404, $"fromPrevious: bookmark {info.StartsFrom} is no longer in the journal.");
            if (!previous.CanRestore)
                throw new BookmarkException(400, $"fromPrevious: bookmark {info.StartsFrom} has no restorable state.");
        }

        var workflowJson = await File.ReadAllTextAsync(full);
        using var doc = JsonDocument.Parse(workflowJson);
        var screenshotDir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
        Directory.CreateDirectory(screenshotDir);
        var deps = new WorkflowDependencies
        {
            Context = _context,
            IdentityStore = _identityStore ?? new IdentityStore(),
            ScreenshotDir = screenshotDir,
            Cancellation = _context.OperationCancellation
        };

        Func<int, Task>? beforeEachRun = previous == null
            ? null
            : async _ => await RestoreCoreAsync(previous, navigate: true, includeExpired: false);

        ReproVerifyResult result;
        var prevAgent = _context.IsAgentAutomation;
        var prevSuppress = _logger.SuppressGuiActions;
        _context.IsAgentAutomation = true;
        _logger.SuppressGuiActions = true;
        try
        {
            result = await ReproVerifyService.VerifyAsync(
                doc.RootElement, deps, deps.IdentityStore, runs, clearSession, identity: null, expect: null,
                startUrlAfterClear: info.StartUrl, workflowJsonForRebind: workflowJson,
                beforeEachRun: beforeEachRun, classifyPreconditions: true);
        }
        finally
        {
            _context.IsAgentAutomation = prevAgent;
            _logger.SuppressGuiActions = prevSuppress;
        }

        var verdict = ReproVerifyService.ToApiString(result.Verdict);
        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["verdict"] = verdict,
            ["passRate"] = result.Rate.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture),
            ["runs"] = result.Runs.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["passed"] = result.Passed.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (!string.IsNullOrEmpty(result.Reason)) extra["reason"] = result.Reason;
        if (fromPrevious) extra["fromPrevious"] = info.StartsFrom!;
        var errors = result.Runs
            .Where(r => !r.Passed)
            .Select(r => r.Failure is { } f
                ? $"run {r.Run}: {f.Phase}{(f.StepIndex.HasValue ? $" step {f.StepIndex}" : "")}: {f.Message}"
                : $"run {r.Run}: {r.Error}")
            .Distinct()
            .Take(5)
            .ToList();
        _logger.LogBookmarkEvent(source, "verify", info.Id,
            $"Verify {Label(info)}: {verdict} ({result.Passed}/{result.Runs.Count})",
            details: errors.Count > 0 ? string.Join("\n", errors) : null, extraFields: extra, url: info.Url);
        return result;
    }

    /// <summary>Add a bookmark from a zip. <paramref name="zipPath"/> must already be validated with <see cref="ExportPathGuard"/>.</summary>
    public BookmarkInfo Import(string zipPath) => ImportOrFind(zipPath, out _);

    /// <summary>
    /// Like <see cref="Import"/>; when this archive was already imported, returns that bookmark and sets
    /// <paramref name="alreadyImported"/> instead of adding a second copy.
    /// </summary>
    public BookmarkInfo ImportOrFind(string zipPath, out bool alreadyImported)
    {
        if (!File.Exists(zipPath))
            throw new BookmarkException(404, $"File not found: {zipPath}");
        try
        {
            var entry = BookmarkArchive.ImportOrFind(zipPath, RootDirectory, _logger, out alreadyImported);
            return BookmarkInfo.FromEntry(entry);
        }
        catch (InvalidDataException ex)
        {
            throw new BookmarkException(400, $"Not a valid zip file: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            throw new BookmarkException(400, ex.Message);
        }
        catch (System.Text.Json.JsonException ex)
        {
            throw new BookmarkException(400, $"The archive's bookmark entry is not valid JSON: {ex.Message}");
        }
    }

    private static string Label(BookmarkInfo info) =>
        info.BookmarkNumber > 0 ? $"bookmark #{info.BookmarkNumber}" : $"bookmark {info.Id}";
    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;
}

public sealed class BookmarkRestoreResult
{
    public string Id { get; init; } = "";
    public string? Url { get; init; }
    /// <summary>True when the optional final navigate-to-bookmark step ran (<c>navigate: true</c> in the request).</summary>
    public bool Navigated { get; init; }
    /// <summary>True when cookies/storage restore required navigating to the bookmark origin first.</summary>
    public bool NavigatedForStorage { get; init; }
    /// <summary>Same as <see cref="Navigated"/>; included for agents migrating from older responses.</summary>
    public bool NavigatedToBookmarkUrl { get; init; }
    /// <summary>True when <c>navigate: false</c> and the tab was returned to the pre-restore URL (with reload when storage was applied).</summary>
    public bool RestoredPreviousUrl { get; init; }
    /// <summary>Cookies set in the browser.</summary>
    public int Cookies { get; init; }
    /// <summary>Names of cookies not restored because they had expired since the bookmark (pass <c>includeExpired</c> to restore them).</summary>
    public List<string> CookiesSkipped { get; init; } = [];
    /// <summary>Names of expired cookies restored anyway as session cookies (<c>includeExpired: true</c>).</summary>
    public List<string> ExpiredCookiesRestored { get; init; } = [];
    public int LocalStorage { get; init; }
    public int SessionStorage { get; init; }
    public bool ServerRestored { get; init; }
    public string Note { get; init; } = "";
}

/// <summary>A bookmark operation the caller can fix. <see cref="StatusCode"/> follows HTTP.</summary>
public sealed class BookmarkException : Exception
{
    public int StatusCode { get; }
    public BookmarkException(int statusCode, string message) : base(message) => StatusCode = statusCode;
}
