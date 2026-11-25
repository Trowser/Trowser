using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// MCP tool handlers for bookmarks. Each delegates to the shared <c>Build*Async</c> on
/// <see cref="TrowserApiServer"/>, so the REST route and the MCP tool run identical code.
/// </summary>
public partial class McpHandler
{
    /// <summary>Create / list / get bookmarks. Backs <c>browser_bookmark</c>.</summary>
    private Task<object> ToolBookmark(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildBookmarkToolAsync);

    /// <summary>Restore a bookmark's cookies and storage, then navigate. Backs <c>browser_bookmark_restore</c>.</summary>
    private Task<object> ToolBookmarkRestore(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildBookmarkRestoreAsync);

  /// <summary>Replay a bookmark's <c>.trw</c>. Backs <c>browser_bookmark_verify</c>.</summary>
    private Task<object> ToolBookmarkVerify(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildBookmarkVerifyAsync);

    /// <summary>Export one bookmark as a zip. Backs <c>browser_bookmark_export</c>.</summary>
    private Task<object> ToolBookmarkExport(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildBookmarkExportAsync);

    /// <summary>Import a bookmark zip. Backs <c>browser_bookmark_import</c>.</summary>
    private Task<object> ToolBookmarkImport(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildBookmarkImportAsync);
}
