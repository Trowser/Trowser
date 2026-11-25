using System.IO;
using System.Net;
using System.Text.Json;
using Trowser.Bookmarks;
using Trowser.Security.Orchestration;

namespace Trowser.Api;

/// <summary>
/// REST + shared builders for bookmarks. Each capability is one <c>Build*Async</c> used by a REST
/// route and an MCP tool. Logic lives in <see cref="BookmarkService"/>, which the GUI button and
/// scripts call too.
/// </summary>
public partial class TrowserApiServer
{
    private BookmarkService RequireBookmarkService() =>
        _context.BookmarkService ?? throw new ApiCommandException(503, "Bookmarks are not available in this session.");

    /// <summary>Catch a bookmark. Backs <c>POST /api/bookmark</c> and <c>browser_bookmark</c> (action=create).</summary>
    internal async Task<object> BuildBookmarkCreateAsync(JsonBody body)
    {
        var service = RequireBookmarkService();
        if (body.GetJsonElement("note") is { } n && n.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            throw new ApiCommandException(400, "note must be a string.");
        var note = body.GetString("note");
        return await service.CatchAsync("api", note);
    }

    /// <summary>List bookmarks. <c>view=index</c> returns one compact row per bookmark instead of full projections.</summary>
    internal object DoListBookmarks(string? view = null)
    {
        var list = RequireBookmarkService().List();
        var v = view?.Trim();
        if (string.Equals(v, "index", StringComparison.OrdinalIgnoreCase))
            return new { bookmarks = list.Select(b => b.ToIndex()).ToList(), count = list.Count, view = "index" };
        if (!string.IsNullOrEmpty(v) && !string.Equals(v, "full", StringComparison.OrdinalIgnoreCase))
            throw new ApiCommandException(400, $"Unknown view '{view}'. Use index or full.");
        return new { bookmarks = list, count = list.Count };
    }

    /// <summary>Bookmark id as a string (<c>"bm-…"</c> or a journal index) or a JSON number (journal index).</summary>
    private static string? BookmarkIdArg(JsonBody body)
    {
        if (body.GetJsonElement("id") is not { } el) return null;
        return el.ValueKind switch
        {
            JsonValueKind.String => NullIfEmpty(el.GetString()),
            JsonValueKind.Number when el.TryGetInt32(out var i) => i.ToString(System.Globalization.CultureInfo.InvariantCulture),
            JsonValueKind.Null => null,
            _ => throw new ApiCommandException(400, "id must be a bookmark id string or a journal index number.")
        };
    }

    internal object DoGetBookmark(string id) =>
        RequireBookmarkService().Get(id) ?? throw new ApiCommandException(404, $"Unknown bookmark: {id}");

    /// <summary>MCP facade for <c>browser_bookmark</c>: create (default), list, or get by id.</summary>
    internal async Task<object> BuildBookmarkToolAsync(JsonBody body)
    {
        var action = (body.GetString("action") ?? "").Trim().ToLowerInvariant();
        var id = BookmarkIdArg(body);
        switch (action)
        {
            case "list":
                return DoListBookmarks(body.GetString("view"));
            case "get":
                return DoGetBookmark(id ?? throw new ApiCommandException(400, "id is required for action=get."));
            case "" or "create":
                if (id != null && action == "")
                    return DoGetBookmark(id);
                return await BuildBookmarkCreateAsync(body);
            default:
                throw new ApiCommandException(400, $"Unknown action '{action}'. Use create, list, or get.");
        }
    }

    /// <summary>Replay a bookmark's <c>.trw</c>. Backs <c>POST /api/bookmark-verify</c> and <c>browser_bookmark_verify</c>.</summary>
    internal async Task<object> BuildBookmarkVerifyAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Replaying a bookmark workflow",
            defaultWhenOmitted: SafetyMode.Active);
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var service = RequireBookmarkService();
        var id = BookmarkIdArg(body) ?? throw new ApiCommandException(400, "id is required.");
        var runs = Math.Clamp(body.GetInt("runs", 1), 1, 20);
        var clearSession = body.GetBool("clearSession", false);
        var fromPrevious = body.GetBool("fromPrevious", false);
        try
        {
            var result = await service.VerifyAsync(id, runs, clearSession, fromPrevious);
            return ReproVerifyServiceShape(result);
        }
        catch (BookmarkException ex)
        {
            throw new ApiCommandException(ex.StatusCode, ex.Message);
        }
    }

    internal static object ReproVerifyServiceShape(Repro.ReproVerifyResult result) => new
    {
        verdict = Repro.ReproVerifyService.ToApiString(result.Verdict),
        reason = result.Reason,
        passRate = result.Rate,
        passed = result.Passed,
        failed = result.Failed,
        runs = result.Runs.Select(r => new
        {
            run = r.Run,
            passed = r.Passed,
            precondition = r.Precondition ? true : (bool?)null,
            error = ReproFailureShape(r)
        }).ToArray()
    };

    /// <summary>Structured run failure (phase, step, message) instead of a message string.</summary>
    internal static object? ReproFailureShape(Repro.ReproRunResult r)
    {
        if (r.Passed) return null;
        if (r.Failure is { } f)
            return new { phase = f.Phase, stepIndex = f.StepIndex, stepType = f.StepType, message = f.Message };
        return string.IsNullOrEmpty(r.Error) ? null : new { phase = "unknown", stepIndex = (int?)null, stepType = (string?)null, message = r.Error };
    }

    /// <summary>Go: restore cookies and storage, then navigate. Backs <c>POST /api/bookmark-restore</c> and <c>browser_bookmark_restore</c>.</summary>
    internal async Task<object> BuildBookmarkRestoreAsync(JsonBody body)
    {
        var service = RequireBookmarkService();
        var id = BookmarkIdArg(body) ?? throw new ApiCommandException(400, "id is required.");
        try
        {
            return await service.RestoreAsync(id, body.GetBool("navigate", true), body.GetBool("includeExpired", false));
        }
        catch (BookmarkException ex)
        {
            throw new ApiCommandException(ex.StatusCode, ex.Message);
        }
    }

    /// <summary>Write one bookmark as a zip. Backs <c>POST /api/bookmark-export</c> and <c>browser_bookmark_export</c>.</summary>
    internal Task<object> BuildBookmarkExportAsync(JsonBody body)
    {
        var service = RequireBookmarkService();
        var id = BookmarkIdArg(body) ?? throw new ApiCommandException(400, "id is required.");
        var path = NullIfEmpty(body.GetString("path")) ?? throw new ApiCommandException(400, "path is required (a .zip file).");
        if (!string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase))
            throw new ApiCommandException(400, "path must end in .zip.");
        if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
            throw new ApiCommandException(400, guardError ?? "Export path rejected.");
        try
        {
            return Task.FromResult<object>(service.Export(id, full));
        }
        catch (BookmarkException ex)
        {
            throw new ApiCommandException(ex.StatusCode, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

    /// <summary>Add a bookmark from a zip. Backs <c>POST /api/bookmark-import</c> and <c>browser_bookmark_import</c>.</summary>
    internal Task<object> BuildBookmarkImportAsync(JsonBody body)
    {
        var service = RequireBookmarkService();
        var path = NullIfEmpty(body.GetString("path")) ?? throw new ApiCommandException(400, "path is required (a .zip file).");
        if (!ExportPathGuard.TryResolveRead(path, out var full, out var pathError))
            throw new ApiCommandException(400, pathError ?? "Import path rejected.");
        try
        {
            var info = service.ImportOrFind(full, out var alreadyImported);
            info.AlreadyImported = alreadyImported;
            return Task.FromResult<object>(info);
        }
        catch (BookmarkException ex)
        {
            throw new ApiCommandException(ex.StatusCode, ex.Message);
        }
    }

    private async Task HandleGetBookmarks(HttpListenerRequest request, HttpListenerResponse response)
    {
        try { await WriteSuccess(response, DoListBookmarks(request.QueryString["view"])); }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
    }

    /// <summary>Path-parameter route for <c>GET /api/bookmark/{id}</c>.</summary>
    private async Task<bool> TryRouteBookmarkAsync(string path, string method, HttpListenerResponse response)
    {
        const string prefix = "/api/bookmark/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

        var id = Uri.UnescapeDataString(path[prefix.Length..].Trim('/'));
        if (id.Length == 0 || id.Contains('/')) return false;
        if (method != "GET") return false;

        try { await WriteSuccess(response, DoGetBookmark(id)); }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
        return true;
    }
}
