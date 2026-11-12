using System.IO;
using System.Net;
using System.Text.Json;
using Trowser.Pointers;
using Trowser.Recording;

namespace Trowser.Api;

/// <summary>
/// REST + shared builders for the pointer primitive (P0). Every capability is one
/// <c>Build*Async</c> consumed by a REST route and an MCP tool via <c>RenderHostSafe</c>,
/// following the codebase's symmetry pattern. Reads hit the in-memory
/// <see cref="Pointers.PointerStore"/> only and are gate-free; creates capture a frozen
/// crop and touch the WebView, so they run through the gate.
/// </summary>
public partial class TrowserApiServer
{
    private PointerStore RequirePointerStore() =>
        PointerStore ?? throw new ApiCommandException(503, "Pointer store is not available.");

    // ----- Create a pointer -----

    /// <summary>
    /// Create a pointer from supplied anchors (locator fields, ref, selector, rect) and freeze
    /// a visual crop. Backs <c>POST /api/pointer</c> and MCP <c>browser_point</c>.
    /// </summary>
    internal async Task<object> BuildPointerCreateAsync(JsonBody body)
    {
        var store = RequirePointerStore();

        var kind = PointerKinds.Normalize(body.GetString("kind"));
        var author = PointerAuthors.Normalize(body.GetString("author"));
        var caption = body.GetString("caption");
        var source = body.GetString("source");

        var selector = NullIfEmpty(body.GetString("selector"));
        var testId = NullIfEmpty(body.GetString("testId"));
        var role = NullIfEmpty(body.GetString("role"));
        var label = NullIfEmpty(body.GetString("label"));
        var name = NullIfEmpty(body.GetString("name")) ?? label;
        var byText = NullIfEmpty(body.GetString("byText")) ?? NullIfEmpty(body.GetString("text"));
        var placeholder = NullIfEmpty(body.GetString("placeholder"));
        var refNum = body.GetInt("ref", -1);

        var anchors = new PointerAnchors
        {
            Selector = selector,
            Text = byText,
            Ref = refNum,
            RefGeneration = refNum >= 0 ? SafeRefGeneration() : -1
        };

        // Build a durable locator expression from whatever the caller supplied, in priority order.
        var choice =
            testId != null ? new LocatorChoice(LocatorKind.TestId, testId, null)
          : (role != null && name != null) ? new LocatorChoice(LocatorKind.Role, role, name)
          : byText != null ? new LocatorChoice(LocatorKind.Text, byText, null)
          : label != null ? new LocatorChoice(LocatorKind.Label, label, null)
          : placeholder != null ? new LocatorChoice(LocatorKind.Placeholder, placeholder, null)
          : selector != null ? new LocatorChoice(LocatorKind.Selector, selector, null)
          : LocatorChoice.None;

        if (choice.HasTarget)
        {
            anchors.Locator = LocatorBuilder.ToScriptExpression(choice, EscapeScriptLiteral);
            anchors.LocatorKind = choice.Kind.ToString().ToLowerInvariant();
        }

        var rect = ReadRect(body.GetJsonElement("rect"));
        if (rect != null) anchors.Rect = rect;

        var url = NullIfEmpty(body.GetString("url"));
        if (url == null)
        {
            try { url = await _context.GetCurrentUrl(); } catch { /* best effort */ }
        }

        int? tabId = null;
        try { tabId = _context.GetActiveTabIndex(); } catch { /* best effort */ }

        var checkpointId = NullIfEmpty(body.GetString("checkpointId")) ?? store.LatestCheckpoint?.Id;

        string? cropPath = null;
        if (body.GetBool("crop", true))
            cropPath = await TryCapturePointerCropAsync(selector);

        var pointer = new Pointer
        {
            Kind = kind,
            Anchors = anchors,
            Caption = caption,
            Author = author,
            TabId = tabId,
            Url = url,
            CheckpointId = checkpointId,
            CropPath = cropPath,
            Source = NullIfEmpty(source),
            Status = PointerStatuses.Resolved
        };

        store.Add(pointer);

        if (_sessionLogger != null)
        {
            try
            {
                var entry = _sessionLogger.LogPointer(author, kind, caption, pointer.Id, url);
                pointer.JournalIndex = entry.Index;
            }
            catch (Exception ex) { TrowserLog.Warn($"Pointer journal log failed: {ex.Message}"); }
        }

        return pointer;
    }

    // ----- List / get / remove -----

    internal object DoListPointers(JsonBody body)
    {
        var store = RequirePointerStore();
        var author = NullIfEmpty(body.GetString("author"));
        var kind = NullIfEmpty(body.GetString("kind"));
        var status = NullIfEmpty(body.GetString("status"));
        int? tabId = body.HasProperty("tabId") ? body.GetInt("tabId") : null;
        var checkpointId = NullIfEmpty(body.GetString("checkpointId"));

        var list = store.GetAll(author, kind, status, tabId, checkpointId);
        return new { pointers = list, count = list.Count, revision = store.Revision };
    }

    internal object DoGetPointer(string id)
    {
        var pointer = RequirePointerStore().Get(id)
            ?? throw new ApiCommandException(404, $"Unknown pointer: {id}");
        return pointer;
    }

    internal object DoRemovePointer(string id)
    {
        var removed = RequirePointerStore().Remove(id);
        if (!removed) throw new ApiCommandException(404, $"Unknown pointer: {id}");
        return new { removed = true, id };
    }

    // ----- Re-resolve a pointer against the live page -----

    /// <summary>
    /// Re-resolve a pointer's anchors against the current DOM and update its status. Prefers
    /// the CSS selector, then the stored rect (via <c>elementsFromPoint</c>). On failure the
    /// pointer becomes <c>unresolvable</c> — honest, so a reader falls back to the frozen crop
    /// instead of a confidently-wrong highlight.
    /// </summary>
    internal async Task<object> ResolvePointerAsync(string id, JsonBody body)
    {
        var store = RequirePointerStore();
        var pointer = store.Get(id) ?? throw new ApiCommandException(404, $"Unknown pointer: {id}");

        // Artifact pointers have no DOM anchor — they are always "unresolvable" against the page,
        // but that is expected; the crop is the record. Report resolved=false without downgrading.
        if (pointer.Kind == PointerKinds.Artifact)
            return new { pointer, resolved = false, reason = "artifact (no DOM anchor)" };

        var selector = pointer.Anchors.Selector;
        var rect = pointer.Anchors.Rect;

        try
        {
            var js = BuildResolveScript(selector, rect);
            var raw = await _context.ExecuteJs(js, 5000);
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(raw) ? "{}" : raw);
            var root = doc.RootElement;
            var found = root.ValueKind == JsonValueKind.Object
                        && root.TryGetProperty("found", out var f)
                        && f.ValueKind == JsonValueKind.True;

            if (found)
            {
                var newRect = ReadRect(root.TryGetProperty("rect", out var r) ? r : (JsonElement?)null);
                store.UpdateStatus(id, PointerStatuses.Resolved, newRect);
                return new { pointer = store.Get(id), resolved = true };
            }

            store.UpdateStatus(id, PointerStatuses.Unresolvable);
            return new { pointer = store.Get(id), resolved = false, reason = "anchor not found on current page" };
        }
        catch (Exception ex)
        {
            // JS blocked (safe mode) or page unavailable — do not lie about the pointer.
            store.UpdateStatus(id, PointerStatuses.Unresolvable);
            return new { pointer = store.Get(id), resolved = false, reason = ex.Message };
        }
    }

    /// <summary>
    /// MCP read/verify facade for <c>browser_pointers</c>: lists pointers, or fetches one when
    /// <c>id</c> is given, or re-resolves one when <c>id</c> + <c>resolve:true</c> are given.
    /// </summary>
    internal async Task<object> BuildPointersAsync(JsonBody body)
    {
        var id = NullIfEmpty(body.GetString("id"));
        if (id != null)
        {
            if (body.GetBool("resolve", false))
                return await ResolvePointerAsync(id, body);
            return DoGetPointer(id);
        }
        return DoListPointers(body);
    }

    // ----- Checkpoints -----

    /// <summary>Create a checkpoint bounding "now". Backs <c>POST /api/checkpoint</c> and MCP <c>browser_checkpoint</c>.</summary>
    internal async Task<object> BuildCheckpointCreateAsync(JsonBody body)
    {
        var store = RequirePointerStore();
        var label = NullIfEmpty(body.GetString("label"));

        var url = NullIfEmpty(body.GetString("url"));
        if (url == null)
        {
            try { url = await _context.GetCurrentUrl(); } catch { /* best effort */ }
        }

        var idx = _sessionLogger?.LastJournalIndex ?? -1;
        var cp = store.AddCheckpoint(idx, label, url);
        return cp;
    }

    /// <summary>
    /// MCP facade for <c>browser_checkpoint</c>: creates a checkpoint by default, lists when
    /// <c>action:"list"</c>, or fetches one (with a "since" summary) when <c>id</c> is given.
    /// </summary>
    internal async Task<object> BuildCheckpointToolAsync(JsonBody body)
    {
        var id = NullIfEmpty(body.GetString("id"));
        if (id != null) return DoGetCheckpoint(id);

        var action = body.GetString("action");
        if (string.Equals(action, "list", StringComparison.OrdinalIgnoreCase))
            return DoListCheckpoints();

        return await BuildCheckpointCreateAsync(body);
    }

    internal object DoListCheckpoints()
    {
        var store = RequirePointerStore();
        var list = store.GetCheckpoints();
        return new { checkpoints = list, count = list.Count, latest = store.LatestCheckpoint?.Id };
    }

    internal object DoGetCheckpoint(string id)
    {
        var store = RequirePointerStore();
        var cp = store.GetCheckpoint(id) ?? throw new ApiCommandException(404, $"Unknown checkpoint: {id}");

        // "What has happened since" — a lightweight summary in P0 (P1 builds the full handoff payload).
        var pointers = store.GetAll(checkpointId: id);
        object since;
        if (_sessionLogger != null)
        {
            var entries = _sessionLogger.GetJournal(since: cp.JournalIndex);
            since = new
            {
                journalEntries = entries.Count,
                guiActions = entries.Count(e => e.Type == "action" && e.Source == "gui"),
                errors = entries.Count(e => e.Type == "error"),
                pointers = pointers.Count
            };
        }
        else
        {
            since = new { journalEntries = 0, pointers = pointers.Count };
        }

        return new { checkpoint = cp, since };
    }

    // ----- REST plumbing -----

    private async Task HandleGetPointers(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var body = await ReadJsonBody(request);
            await WriteSuccess(response, DoListPointers(body));
        }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
    }

    private async Task HandleGetCheckpoints(HttpListenerResponse response)
    {
        try { await WriteSuccess(response, DoListCheckpoints()); }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
    }

    /// <summary>Path-parameter routes for <c>/api/pointer/{id}</c> and <c>/api/pointer/{id}/resolve</c>.</summary>
    private async Task<bool> TryRoutePointerAsync(string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        const string prefix = "/api/pointer/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

        var tail = path[prefix.Length..].Trim('/');
        if (tail.Length == 0) return false;

        // /api/pointer/{id}/resolve
        if (tail.EndsWith("/resolve", StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            var id = Uri.UnescapeDataString(tail[..^"/resolve".Length]);
            try
            {
                var body = await ReadJsonBody(request);
                await WriteSuccess(response, await ResolvePointerAsync(id, body));
            }
            catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
            return true;
        }

        if (tail.Contains('/')) return false; // no other nested routes

        var pointerId = Uri.UnescapeDataString(tail);
        switch (method)
        {
            case "GET":
                try { await WriteSuccess(response, DoGetPointer(pointerId)); }
                catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
                return true;
            case "DELETE":
                try { await WriteSuccess(response, DoRemovePointer(pointerId)); }
                catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
                return true;
            default:
                return false;
        }
    }

    /// <summary>Path-parameter route for <c>GET /api/checkpoint/{id}</c>.</summary>
    private async Task<bool> TryRouteCheckpointAsync(string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        const string prefix = "/api/checkpoint/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

        var id = Uri.UnescapeDataString(path[prefix.Length..].Trim('/'));
        if (id.Length == 0 || id.Contains('/')) return false;
        if (method != "GET") return false;

        try { await WriteSuccess(response, DoGetCheckpoint(id)); }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
        return true;
    }

    // ----- Helpers -----

    private int SafeRefGeneration()
    {
        try { return _context.RefGeneration; } catch { return -1; }
    }

    /// <summary>Capture a frozen crop: an element crop when a selector is known, else the viewport.</summary>
    private async Task<string?> TryCapturePointerCropAsync(string? selector)
    {
        try
        {
            byte[] bytes;
            if (!string.IsNullOrWhiteSpace(selector))
            {
                bytes = await _context.ScreenshotElementToBytes(selector, padding: 4);
                // ScreenshotElementToBytes returns an ERROR string encoded in bytes on failure paths
                // only via exceptions; a zero-length array means nothing captured.
            }
            else
            {
                bytes = await _context.ScreenshotToBytes();
            }

            if (bytes == null || bytes.Length == 0) return null;

            var fileName = $"pointer-{DateTime.Now:yyyyMMdd_HHmmss_fff}.png";
            var fullPath = Path.Combine(_screenshotDir, fileName);
            await File.WriteAllBytesAsync(fullPath, bytes);
            return fullPath;
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Pointer crop capture failed: {ex.Message}");
            return null;
        }
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    private static PointerRect? ReadRect(JsonElement? el)
    {
        if (el is not { ValueKind: JsonValueKind.Object } r) return null;
        return new PointerRect
        {
            X = GetNum(r, "x"),
            Y = GetNum(r, "y"),
            Width = GetNum(r, "width"),
            Height = GetNum(r, "height"),
            ScrollX = GetNum(r, "scrollX"),
            ScrollY = GetNum(r, "scrollY")
        };
    }

    private static double GetNum(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static string EscapeScriptLiteral(string value) =>
        "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") + "\"";

    /// <summary>
    /// JS that reports whether the pointer's anchor still exists and its current rect.
    /// Selector first; otherwise <c>elementsFromPoint</c> at the stored rect centre adjusted
    /// for scroll drift. Returns <c>{found, rect:{x,y,width,height,scrollX,scrollY}}</c>.
    /// </summary>
    private static string BuildResolveScript(string? selector, PointerRect? rect)
    {
        if (!string.IsNullOrWhiteSpace(selector))
        {
            var sel = EscapeScriptLiteral(selector);
            return $@"(function(){{
                try {{
                    var el = document.querySelector({sel});
                    if (!el) return JSON.stringify({{found:false}});
                    var r = el.getBoundingClientRect();
                    return JSON.stringify({{found:true, rect:{{x:r.x,y:r.y,width:r.width,height:r.height,scrollX:window.scrollX,scrollY:window.scrollY}}}});
                }} catch(e) {{ return JSON.stringify({{found:false, error:String(e)}}); }}
            }})()";
        }

        if (rect != null)
        {
            // Adjust the stored viewport point for any scroll drift since capture.
            var cx = rect.X + rect.Width / 2;
            var cy = rect.Y + rect.Height / 2;
            return $@"(function(){{
                try {{
                    var dx = (window.scrollX - {rect.ScrollX.ToString(System.Globalization.CultureInfo.InvariantCulture)});
                    var dy = (window.scrollY - {rect.ScrollY.ToString(System.Globalization.CultureInfo.InvariantCulture)});
                    var px = {cx.ToString(System.Globalization.CultureInfo.InvariantCulture)} - dx;
                    var py = {cy.ToString(System.Globalization.CultureInfo.InvariantCulture)} - dy;
                    var els = document.elementsFromPoint(px, py);
                    if (!els || els.length === 0) return JSON.stringify({{found:false}});
                    var r = els[0].getBoundingClientRect();
                    return JSON.stringify({{found:true, rect:{{x:r.x,y:r.y,width:r.width,height:r.height,scrollX:window.scrollX,scrollY:window.scrollY}}}});
                }} catch(e) {{ return JSON.stringify({{found:false, error:String(e)}}); }}
            }})()";
        }

        return "JSON.stringify({found:false})";
    }
}
