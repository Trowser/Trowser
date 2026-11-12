using System.IO;
using System.Net;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    #region Frames

    private async Task HandleGetFrames(HttpListenerResponse response)
    {
        var frames = await _context.GetFrames();
        await WriteSuccess(response, new { count = frames.Count, frames });
    }

    #endregion

    #region Downloads

    private async Task HandleGetDownloads(HttpListenerResponse response)
    {
        var entries = _context.GetDownloads().Select(DownloadToApi).ToList();
        await WriteSuccess(response, new { count = entries.Count, downloads = entries });
    }

    private async Task HandlePostDownloadsWait(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var fileNameContains = body.GetString("fileNameContains");
        var timeout = body.GetInt("timeout", 30000);
        var afterId = body.GetInt("afterId", 0);
        try
        {
            var entry = await _context.WaitForDownload(fileNameContains, timeout > 0 ? timeout : 30000, afterId);
            await WriteSuccess(response, DownloadToApi(entry));
        }
        catch (TimeoutException ex)
        {
            await WriteError(response, 408, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostDownloadsAssert(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        try
        {
            bool? exists = body.HasProperty("exists") ? body.GetBool("exists") : true;
            long? minBytes = body.HasProperty("minBytes") ? body.GetInt("minBytes") : null;
            var entry = _context.AssertDownload(
                fileNameContains: body.GetString("fileNameContains"),
                mimeContains: body.GetString("mime") ?? body.GetString("mimeContains"),
                minBytes: minBytes,
                exists: exists);
            await WriteSuccess(response, DownloadToApi(entry));
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostDownloadsClear(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var deleteFiles = body.GetBool("deleteFiles");
        _context.ClearDownloads(deleteFiles);
        await WriteSuccess(response, new { message = "Download log cleared.", deleteFiles });
    }

    private static object DownloadToApi(DownloadEntry e) => new
    {
        id = e.Id,
        url = e.Url,
        suggestedFileName = e.SuggestedFileName,
        path = e.Path,
        state = e.State.ToString().ToLowerInvariant(),
        bytes = e.BytesReceived,
        totalBytes = e.TotalBytes,
        mime = e.MimeType,
        timestamp = e.Timestamp,
        interruptReason = e.InterruptReason
    };

    #endregion

    #region Drag

    private async Task HandlePostDrag(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var frame = body.GetString("frame");
        var root = body.RootElement;

        string? fromSelector;
        string? toSelector;
        string? error;
        string? staleWarning;

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("from", out var fromEl) && fromEl.ValueKind == JsonValueKind.Object)
        {
            var fromBody = MaybeInjectFrame(JsonBody.FromToolArguments(fromEl), frame);
            (fromSelector, error, staleWarning) = ResolveSelector(fromBody);
        }
        else
        {
            (fromSelector, error, staleWarning) = ResolveSelector(BuildFlatTarget(body, "from", frame));
        }

        if (fromSelector == null)
        {
            await WriteError(response, 400, error ?? "Provide 'from' element (ref/selector/locator) or fromRef/fromSelector.");
            return;
        }

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("to", out var toEl) && toEl.ValueKind == JsonValueKind.Object)
        {
            var toBody = MaybeInjectFrame(JsonBody.FromToolArguments(toEl), frame);
            (toSelector, error, var toWarn) = ResolveSelector(toBody);
            staleWarning ??= toWarn;
        }
        else
        {
            (toSelector, error, var toWarn) = ResolveSelector(BuildFlatTarget(body, "to", frame));
            staleWarning ??= toWarn;
        }

        if (toSelector == null)
        {
            await WriteError(response, 400, error ?? "Provide 'to' element (ref/selector/locator) or toRef/toSelector.");
            return;
        }

        var steps = body.GetInt("steps", 10);
        var timeout = body.GetInt("timeout", 0);
        bool? html5 = null;
        if (body.RootElement.ValueKind == JsonValueKind.Object &&
            body.RootElement.TryGetProperty("html5", out var h5) &&
            h5.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            html5 = h5.GetBoolean();
        }

        var before = await _context.CapturePageState();
        var path = await _context.Drag(fromSelector, toSelector, steps, timeout > 0 ? timeout : null, html5);
        await Task.Delay(150);
        var after = await _context.CapturePageState();
        var changes = AutomationContext.DiffPageState(before, after);
        await WriteSuccess(response, new
        {
            from = fromSelector,
            to = toSelector,
            steps,
            path,
            html5,
            changes,
            staleRefWarning = staleWarning
        });
    }

    private static JsonBody MaybeInjectFrame(JsonBody body, string? frame)
    {
        if (string.IsNullOrEmpty(frame) || body.HasProperty("frame"))
            return body;
        var dict = new Dictionary<string, object?>();
        if (body.RootElement.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in body.RootElement.EnumerateObject())
                dict[prop.Name] = prop.Value.Clone();
        }
        dict["frame"] = frame;
        return new JsonBody(JsonDocument.Parse(JsonSerializer.Serialize(dict)));
    }

    private static JsonBody BuildFlatTarget(JsonBody body, string prefix, string? frame)
    {
        var dict = new Dictionary<string, object?>();
        var refKey = prefix + "Ref";
        var selKey = prefix + "Selector";
        if (body.HasProperty(refKey))
            dict["ref"] = body.GetInt(refKey);
        if (body.HasProperty(selKey))
            dict["selector"] = body.GetString(selKey);
        // Also allow bare ref/selector when nested objects omitted and prefix is unused —
        // not applied here.
        if (!string.IsNullOrEmpty(frame))
            dict["frame"] = frame;
        return new JsonBody(JsonDocument.Parse(JsonSerializer.Serialize(dict)));
    }

    #endregion

    #region Emulation

    private async Task HandleGetEmulation(HttpListenerResponse response)
    {
        await WriteSuccess(response, _context.Emulation.ToApiObject());
    }

    private async Task HandlePostEmulation(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var update = new EmulationUpdate();
        var root = body.RootElement;

        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("geolocation", out var geo))
        {
            if (geo.ValueKind == JsonValueKind.Null)
            {
                update.Geolocation = new GeoUpdate { Clear = true };
            }
            else if (geo.ValueKind == JsonValueKind.Object)
            {
                update.Geolocation = new GeoUpdate
                {
                    Clear = geo.TryGetProperty("clear", out var c) && c.ValueKind == JsonValueKind.True,
                    Latitude = geo.TryGetProperty("latitude", out var lat) && lat.ValueKind == JsonValueKind.Number
                        ? lat.GetDouble() : null,
                    Longitude = geo.TryGetProperty("longitude", out var lng) && lng.ValueKind == JsonValueKind.Number
                        ? lng.GetDouble() : null,
                    Accuracy = geo.TryGetProperty("accuracy", out var acc) && acc.ValueKind == JsonValueKind.Number
                        ? acc.GetDouble() : null
                };
            }
        }

        if (body.HasProperty("locale"))
            update.Locale = body.GetString("locale") ?? "";
        if (body.HasProperty("timezone"))
            update.Timezone = body.GetString("timezone") ?? "";
        if (body.HasProperty("colorScheme"))
            update.ColorScheme = body.GetString("colorScheme");
        if (body.HasProperty("reducedMotion"))
            update.ReducedMotion = body.GetString("reducedMotion");
        if (body.HasProperty("userAgent"))
            update.UserAgent = body.GetString("userAgent") ?? "";

        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Object)
        {
            update.Permissions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in perms.EnumerateObject())
                update.Permissions[prop.Name] = prop.Value.GetString() ?? "prompt";
        }

        try
        {
            await _context.SetEmulation(update);
            await WriteSuccess(response, _context.Emulation.ToApiObject());
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandleDeleteEmulation(HttpListenerResponse response)
    {
        await _context.ClearEmulation();
        await WriteSuccess(response, new { message = "Emulation overrides cleared." });
    }

    #endregion

    #region HAR + Trace

    private async Task HandleGetNetworkHar(HttpListenerRequest request, HttpListenerResponse response)
    {
        var tabIdx = ResolveTabIndexFromQuery(request);
        await _context.InvokeOnTabAsync(tabIdx, async () =>
        {
        var q = ApiQuery(request);
        var includeHeaders = q["includeHeaders"] != "false";
        var includeBodies = q["includeBody"] == "true" || q["includeBodies"] == "true";
        var errorsOnly = q["errors"] == "true";
        var pageOnly = q["page"] == "true";
        var urlContains = q["url"];
        var method = q["method"];
        var path = q["path"];

        var har = _context.ExportHar(includeHeaders, includeBodies, urlContains, method, errorsOnly, pageOnly);

        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
            {
                await WriteError(response, 400, guardError ?? "Export path rejected.");
                return false;
            }
            try
            {
                var json = JsonSerializer.Serialize(har, new JsonSerializerOptions { WriteIndented = true });
                var dir = Path.GetDirectoryName(full);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                await File.WriteAllTextAsync(full, json);
                await WriteSuccess(response, new { message = "HAR written.", path = full });
                return true;
            }
            catch (Exception ex)
            {
                await WriteError(response, 400, $"Failed to write HAR: {ex.Message}");
                return false;
            }
        }

        await WriteSuccess(response, har);
        return true;
        });
    }

    private async Task HandlePostTraceStart(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var domSnapshots = body.GetBool("domSnapshots");
        var maxSteps = body.GetInt("maxSteps", 200);
        var result = _context.StartTrace(domSnapshots, maxSteps);
        await WriteSuccess(response, result);
    }

    private async Task HandlePostTraceStop(HttpListenerResponse response)
    {
        await WriteSuccess(response, _context.StopTrace());
    }

    private async Task HandleGetTrace(HttpListenerResponse response)
    {
        await WriteSuccess(response, _context.GetTrace());
    }

    private async Task HandleGetTraceExport(HttpListenerResponse response)
    {
        await WriteSuccess(response, _context.ExportTrace());
    }

    #endregion
}
