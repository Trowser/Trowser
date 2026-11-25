using Trowser.Bookmarks;

namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>Bookmark service, wired by the host once the session log and pointer store exist.</summary>
    internal BookmarkService? BookmarkService { get; set; }

    private BookmarkService RequireBookmarks() =>
        BookmarkService ?? throw new InvalidOperationException("Bookmarks are not available in this session.");

    /// <summary>
    /// Bookmark this moment: a journal entry with a screenshot, the steps since the last bookmark,
    /// and the last request. Same as the nav-bar bookmark button and Ctrl+B.
    /// </summary>
    public Task<BookmarkInfo> CatchBookmark(string? note = null) =>
        RequireBookmarks().CatchAsync("api", note);

    /// <summary>All bookmarks in the journal, oldest first.</summary>
    public List<BookmarkInfo> GetBookmarks() => RequireBookmarks().List();

    /// <summary>One bookmark by id or journal index, or null when unknown.</summary>
    public BookmarkInfo? GetBookmark(string id) => RequireBookmarks().Get(id);

    /// <summary>
    /// Restore a bookmark's cookies, localStorage, and sessionStorage, then navigate to its URL.
    /// The server is not restored.
    /// </summary>
    public Task<BookmarkRestoreResult> RestoreBookmark(string id) =>
        RequireBookmarks().RestoreAsync(id);

    /// <summary>
    /// Export one bookmark as a zip (journal entry + evidence). Cookie and storage values are redacted.
    /// <paramref name="zipPath"/> must end in <c>.zip</c>.
    /// </summary>
    public BookmarkArchive.ExportResult ExportBookmark(string id, string zipPath) =>
        RequireBookmarks().Export(id, zipPath);

    /// <summary>
    /// Import a bookmark zip. The imported bookmark can be viewed and verified, but not restored
    /// (its state is redacted).
    /// </summary>
    public BookmarkInfo ImportBookmark(string zipPath) =>
        RequireBookmarks().Import(zipPath);
}
