using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security.Runtime;

/// <summary>
/// Enumerate live <c>message</c> listeners via CDP (covers handlers registered before the runtime sensor).
/// </summary>
internal static class RuntimeCdpMessageListeners
{
    internal sealed record CdpListener(string HandlerSource, string Via, string? FrameOrigin = null);

    internal static async Task<IReadOnlyList<CdpListener>> TryEnumerateAllAsync(AutomationContext ctx)
    {
        var merged = new List<CdpListener>();
        var seenFrameIds = new HashSet<string>(StringComparer.Ordinal);

        merged.AddRange(await TryEnumerateWindowAsync(ctx));

        foreach (var frame in ctx.ActiveTab.Frames.Snapshot())
        {
            if (string.IsNullOrEmpty(frame.Url))
                continue;
            try
            {
                var wvFrame = frame.TryGetFrame();
                if (wvFrame?.FrameId is > 0)
                    seenFrameIds.Add(wvFrame.FrameId.ToString());
                merged.AddRange(await TryEnumerateFrameAsync(ctx, frame));
            }
            catch (Exception ex) when (ex.Message.Contains("Frame5", StringComparison.OrdinalIgnoreCase)
                                       || ex.Message.Contains("ICoreWebView2Frame", StringComparison.OrdinalIgnoreCase))
            {
                /* WebView2 runtime lacks ICoreWebView2Frame5 — fall back to CDP frame tree */
            }
        }

        foreach (var (frameId, frameOrigin) in await TryGetCdpFrameTreeAsync(ctx))
        {
            if (!seenFrameIds.Add(frameId))
                continue;
            merged.AddRange(await TryEnumerateFrameByCdpIdAsync(ctx, frameId, frameOrigin));
        }

        return merged;
    }

    internal static async Task<IReadOnlyList<CdpListener>> TryEnumerateWindowAsync(AutomationContext ctx)
    {
        var webView = ctx.ActiveTab.WebView;
        try
        {
            return await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var core = webView.CoreWebView2;
                var evalJson = await core.CallDevToolsProtocolMethodAsync(
                    "Runtime.evaluate",
                    """{"expression":"window","objectGroup":"trowser-pm-audit","includeCommandLineAPI":false}""");

                using var evalDoc = JsonDocument.Parse(evalJson);
                if (!evalDoc.RootElement.TryGetProperty("result", out var resultEl))
                    return Array.Empty<CdpListener>();

                if (!resultEl.TryGetProperty("objectId", out var objectIdEl))
                    return Array.Empty<CdpListener>();

                var objectId = objectIdEl.GetString();
                if (string.IsNullOrEmpty(objectId))
                    return Array.Empty<CdpListener>();

                try
                {
                    var listenersJson = await core.CallDevToolsProtocolMethodAsync(
                        "DOMDebugger.getEventListeners",
                        JsonSerializer.Serialize(new { objectId }));

                    return await ParseMessageListenersAsync(core, listenersJson, null);
                }
                finally
                {
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Runtime.releaseObject",
                            JsonSerializer.Serialize(new { objectId }));
                    }
                    catch { /* best-effort */ }
                }
            });
        }
        catch
        {
            return Array.Empty<CdpListener>();
        }
    }

    private static async Task<IReadOnlyList<(string FrameId, string? Origin)>> TryGetCdpFrameTreeAsync(
        AutomationContext ctx)
    {
        var list = new List<(string, string?)>();
        var webView = ctx.ActiveTab.WebView;
        try
        {
            return await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var core = webView.CoreWebView2;
                var treeJson = await core.CallDevToolsProtocolMethodAsync("Page.getFrameTree", "{}");
                using var doc = JsonDocument.Parse(treeJson);
                if (doc.RootElement.TryGetProperty("frameTree", out var root))
                    WalkFrameTree(root, list);
                return list;
            });
        }
        catch
        {
            return list;
        }

        static void WalkFrameTree(JsonElement node, List<(string, string?)> acc)
        {
            if (node.TryGetProperty("frame", out var frame)
                && frame.TryGetProperty("id", out var idEl))
            {
                var id = idEl.ValueKind == JsonValueKind.String
                    ? idEl.GetString()
                    : idEl.GetRawText();
                string? origin = null;
                if (frame.TryGetProperty("url", out var urlEl) && urlEl.ValueKind == JsonValueKind.String)
                {
                    var url = urlEl.GetString();
                    if (!string.IsNullOrEmpty(url)
                        && Uri.TryCreate(url, UriKind.Absolute, out var uri))
                        origin = uri.GetLeftPart(UriPartial.Authority);
                }

                if (!string.IsNullOrEmpty(id))
                    acc.Add((id, origin));
            }

            if (node.TryGetProperty("childFrames", out var children)
                && children.ValueKind == JsonValueKind.Array)
            {
                foreach (var child in children.EnumerateArray())
                    WalkFrameTree(child, acc);
            }
        }
    }

    private static async Task<IReadOnlyList<CdpListener>> TryEnumerateFrameByCdpIdAsync(
        AutomationContext ctx, string frameId, string? frameOrigin)
    {
        var webView = ctx.ActiveTab.WebView;
        try
        {
            return await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var core = webView.CoreWebView2;
                var evalJson = await core.CallDevToolsProtocolMethodAsync(
                    "Runtime.evaluate",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["expression"] = "window",
                        ["objectGroup"] = "trowser-pm-audit-frame",
                        ["includeCommandLineAPI"] = false,
                        ["frameId"] = frameId
                    }));

                using var evalDoc = JsonDocument.Parse(evalJson);
                if (!evalDoc.RootElement.TryGetProperty("result", out var resultEl)
                    || !resultEl.TryGetProperty("objectId", out var objectIdEl))
                    return Array.Empty<CdpListener>();

                var objectId = objectIdEl.GetString();
                if (string.IsNullOrEmpty(objectId))
                    return Array.Empty<CdpListener>();

                try
                {
                    var listenersJson = await core.CallDevToolsProtocolMethodAsync(
                        "DOMDebugger.getEventListeners",
                        JsonSerializer.Serialize(new { objectId }));
                    return await ParseMessageListenersAsync(core, listenersJson, frameOrigin);
                }
                finally
                {
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Runtime.releaseObject",
                            JsonSerializer.Serialize(new { objectId }));
                    }
                    catch { /* best-effort */ }
                }
            });
        }
        catch
        {
            return [];
        }
    }

    private static async Task<IReadOnlyList<CdpListener>> TryEnumerateFrameAsync(
        AutomationContext ctx, FrameRegistry.FrameEntry frame)
    {
        var wvFrame = frame.TryGetFrame();
        if (wvFrame == null) return [];

        try
        {
            return await await ctx.ActiveTab.WebView.Dispatcher.InvokeAsync(async () =>
            {
                var core = ctx.ActiveTab.WebView.CoreWebView2;
                var frameId = wvFrame.FrameId;
                if (frameId == 0)
                    return Array.Empty<CdpListener>();

                var evalJson = await core.CallDevToolsProtocolMethodAsync(
                    "Runtime.evaluate",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["expression"] = "window",
                        ["objectGroup"] = "trowser-pm-audit-frame",
                        ["includeCommandLineAPI"] = false,
                        ["frameId"] = frameId.ToString()
                    }));

                using var evalDoc = JsonDocument.Parse(evalJson);
                if (!evalDoc.RootElement.TryGetProperty("result", out var resultEl)
                    || !resultEl.TryGetProperty("objectId", out var objectIdEl))
                    return Array.Empty<CdpListener>();

                var objectId = objectIdEl.GetString();
                if (string.IsNullOrEmpty(objectId))
                    return Array.Empty<CdpListener>();

                try
                {
                    var listenersJson = await core.CallDevToolsProtocolMethodAsync(
                        "DOMDebugger.getEventListeners",
                        JsonSerializer.Serialize(new { objectId }));
                    return await ParseMessageListenersAsync(core, listenersJson, frame.Origin ?? frame.Url);
                }
                finally
                {
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Runtime.releaseObject",
                            JsonSerializer.Serialize(new { objectId }));
                    }
                    catch { /* best-effort */ }
                }
            });
        }
        catch
        {
            return [];
        }
    }

    private static async Task<IReadOnlyList<CdpListener>> ParseMessageListenersAsync(
        Microsoft.Web.WebView2.Core.CoreWebView2 core,
        string listenersJson,
        string? frameOrigin)
    {
        var list = new List<CdpListener>();
        try
        {
            using var doc = JsonDocument.Parse(listenersJson);
            if (!doc.RootElement.TryGetProperty("listeners", out var arr)
                || arr.ValueKind != JsonValueKind.Array)
                return list;

            foreach (var item in arr.EnumerateArray())
            {
                var type = item.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
                if (!type.Equals("message", StringComparison.OrdinalIgnoreCase))
                    continue;

                var src = await ResolveHandlerSourceAsync(core, item);
                list.Add(new CdpListener(src, "cdp-getEventListeners", frameOrigin));
            }
        }
        catch { /* best-effort */ }

        return list;
    }

    private static async Task<string> ResolveHandlerSourceAsync(
        Microsoft.Web.WebView2.Core.CoreWebView2 core,
        JsonElement listener)
    {
        var preview = ExtractHandlerSource(listener);
        if (!listener.TryGetProperty("handler", out var handler)
            || !handler.TryGetProperty("objectId", out var objectIdEl))
            return preview;

        var objectId = objectIdEl.GetString();
        if (string.IsNullOrEmpty(objectId))
            return preview;

        try
        {
            var callJson = await core.CallDevToolsProtocolMethodAsync(
                "Runtime.callFunctionOn",
                JsonSerializer.Serialize(new
                {
                    objectId,
                    functionDeclaration = "function() { try { return this.toString(); } catch(e) { return ''; } }",
                    returnByValue = true
                }));

            using var callDoc = JsonDocument.Parse(callJson);
            if (callDoc.RootElement.TryGetProperty("result", out var resultEl)
                && resultEl.TryGetProperty("value", out var valueEl)
                && valueEl.ValueKind == JsonValueKind.String)
            {
                var full = valueEl.GetString();
                if (!string.IsNullOrWhiteSpace(full) && full.Length >= preview.Length)
                    return full;
            }
        }
        catch { /* best-effort */ }

        return preview;
    }

    private static string ExtractHandlerSource(JsonElement listener)
    {
        if (listener.TryGetProperty("handler", out var handler))
        {
            if (handler.TryGetProperty("description", out var desc) && desc.ValueKind == JsonValueKind.String)
                return desc.GetString() ?? "";
            if (handler.TryGetProperty("value", out var val) && val.ValueKind == JsonValueKind.String)
                return val.GetString() ?? "";
        }

        if (listener.TryGetProperty("functionName", out var fn) && fn.ValueKind == JsonValueKind.String)
            return fn.GetString() ?? "";

        return "";
    }
}
