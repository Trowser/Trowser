using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>
    /// Frame scope for the current async action chain (set by <see cref="BeginFrameScope"/> /
    /// <see cref="WaitForActionable"/>). Used by <see cref="WrapWithDeepQuery"/> so resolved
    /// <c>data-trowser-loc</c> selectors stay inside the same iframe document.
    /// </summary>
    private readonly AsyncLocal<string?> _actionFrame = new();

    /// <summary>
    /// Build a frame-scoped locator. Actions and waits that receive this string target elements
    /// inside the given iframe (CSS selector of <c>&lt;iframe&gt;</c>, frame <c>name</c>, or
    /// <c>frameId</c> from <see cref="GetFrames"/> / snapshot <c>frames[]</c>).
    /// </summary>
    public static string ByFrame(string frame, string selectorOrLocator)
    {
        if (string.IsNullOrWhiteSpace(frame))
            throw new ArgumentException("frame must be non-empty.", nameof(frame));
        if (string.IsNullOrWhiteSpace(selectorOrLocator))
            throw new ArgumentException("selectorOrLocator must be non-empty.", nameof(selectorOrLocator));
        if (selectorOrLocator.StartsWith("@frame:", StringComparison.Ordinal))
            return selectorOrLocator;
        return $"@frame:{frame}|{selectorOrLocator}";
    }

    /// <summary>Split <c>@frame:spec|inner</c> locators. Non-frame selectors return (null, input).</summary>
    internal static (string? Frame, string Inner) SplitFrameLocator(string selectorOrLocator)
    {
        if (string.IsNullOrEmpty(selectorOrLocator) ||
            !selectorOrLocator.StartsWith("@frame:", StringComparison.Ordinal))
            return (null, selectorOrLocator);

        var rest = selectorOrLocator[7..];
        var pipe = rest.IndexOf('|');
        if (pipe <= 0 || pipe >= rest.Length - 1)
            return (null, selectorOrLocator);
        return (rest[..pipe], rest[(pipe + 1)..]);
    }

    /// <summary>Apply frame scope for subsequent deepQuery calls; returns the inner selector.</summary>
    private string BeginFrameScope(string selectorOrLocator)
    {
        var (frame, inner) = SplitFrameLocator(selectorOrLocator);
        _actionFrame.Value = frame;
        return inner;
    }

    /// <summary>
    /// Re-attach current action frame to a resolved CSS selector (for post-wait deepQuery).
    /// Inspectable cross-origin frames execute in the child document — omit <c>@frame:</c> there.
    /// </summary>
    private async Task<string> EncodeFrameSelectorAsync(string selector)
    {
        var frame = _actionFrame.Value;
        if (string.IsNullOrEmpty(frame) || selector.StartsWith("@frame:", StringComparison.Ordinal))
            return selector;
        if (await IsActionFrameInspectableAsync())
            return selector;
        return ByFrame(frame, selector);
    }

    /// <summary>Optional explicit frame for REST/MCP when not encoded in the selector.</summary>
    internal void SetActionFrame(string? frame) => _actionFrame.Value = frame;

    internal string? CurrentActionFrame => _actionFrame.Value;

    /// <summary>
    /// When JS runs inside an inspectable child frame, <c>@frame:…|</c> locators must be stripped —
    /// <see cref="DeepQueryJs"/> resolves frames from the current document, not the parent.
    /// </summary>
    internal static string StripFrameLocatorsInJsForInspectableChild(string jsBody, string? actionFrame)
    {
        if (string.IsNullOrEmpty(actionFrame))
            return jsBody;

        var prefix = "@frame:" + actionFrame + "|";
        return jsBody.Replace(prefix, "", StringComparison.Ordinal);
    }

    /// <summary>
    /// JS that resolves an iframe by frameId (<c>data-trowser-frame-id</c>), name, or CSS selector
    /// and assigns <c>var document = contentDocument</c> for the rest of the IIFE. On failure,
    /// returns a JSON error string so the outer caller can surface <c>crossOrigin</c>.
    /// </summary>
    private static string BuildFramePreamble(string? frameSpec)
    {
        if (string.IsNullOrEmpty(frameSpec))
        {
            return """
                var __trowserRoot = document;
                var __trowserFrameOffset = { x: 0, y: 0 };
                function pageCenter(el) {
                    var r = el.getBoundingClientRect();
                    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
                }

                """;
        }

        return $$"""
            var __trowserFrameSpec = {{JsonEscape(frameSpec)}};
            var __trowserFrameResolved = (function(spec) {
                function stampAndList(doc, parentId, acc, counter) {
                    var iframes = doc.querySelectorAll('iframe, frame');
                    for (var i = 0; i < iframes.length; i++) {
                        var f = iframes[i];
                        var id = f.getAttribute('data-trowser-frame-id');
                        if (!id) {
                            id = 'f' + (counter.n++);
                            try { f.setAttribute('data-trowser-frame-id', id); } catch (e) {}
                        }
                        var sameOrigin = false, url = '', name = f.getAttribute('name') || f.name || '';
                        var cd = null;
                        try {
                            cd = f.contentDocument;
                            if (cd) {
                                sameOrigin = true;
                                try { url = cd.location.href; } catch (e2) { url = f.src || ''; }
                            }
                        } catch (e3) {
                            url = f.src || '';
                        }
                        if (!sameOrigin && !url) url = f.src || '';
                        acc.push({ el: f, frameId: id, name: name, url: url, sameOrigin: sameOrigin, parentFrameId: parentId, doc: cd });
                        if (cd) stampAndList(cd, id, acc, counter);
                    }
                }
                function withOffset(item, acc) {
                    if (!item) return null;
                    var ox = 0, oy = 0, cur = item, guard = 0;
                    while (cur && guard++ < 20) {
                        try {
                            var r = cur.el.getBoundingClientRect();
                            ox += r.left;
                            oy += r.top;
                        } catch (eOff) {}
                        if (!cur.parentFrameId) break;
                        var parent = null;
                        for (var pi = 0; pi < acc.length; pi++) {
                            if (acc[pi].frameId === cur.parentFrameId) { parent = acc[pi]; break; }
                        }
                        cur = parent;
                    }
                    item.offsetX = ox;
                    item.offsetY = oy;
                    return item;
                }
                var acc = [];
                stampAndList(window.document, null, acc, { n: 1 });
                for (var i = 0; i < acc.length; i++) {
                    var item = acc[i];
                    if (item.frameId === spec || item.name === spec) return withOffset(item, acc);
                }
                try {
                    var bySel = window.document.querySelector(spec);
                    if (bySel && bySel.tagName && bySel.tagName.toLowerCase() === 'iframe') {
                        for (var j = 0; j < acc.length; j++) {
                            if (acc[j].el === bySel) return withOffset(acc[j], acc);
                        }
                        var cd2 = null, same2 = false, url2 = bySel.src || '';
                        try {
                            cd2 = bySel.contentDocument;
                            if (cd2) { same2 = true; try { url2 = cd2.location.href; } catch (e4) {} }
                        } catch (e5) {}
                        return withOffset({
                            el: bySel,
                            frameId: bySel.getAttribute('data-trowser-frame-id') || '',
                            name: bySel.getAttribute('name') || bySel.name || '',
                            url: url2,
                            sameOrigin: same2,
                            parentFrameId: null,
                            doc: cd2
                        }, acc);
                    }
                } catch (e6) {}
                return null;
            })(__trowserFrameSpec);
            if (!__trowserFrameResolved) {
                return JSON.stringify({ __frameError: 'Frame not found: ' + __trowserFrameSpec });
            }
            if (!__trowserFrameResolved.sameOrigin || !__trowserFrameResolved.doc) {
                return JSON.stringify({
                    __frameError: 'crossOrigin',
                    frameId: __trowserFrameResolved.frameId || '',
                    url: __trowserFrameResolved.url || '',
                    name: __trowserFrameResolved.name || '',
                    message: 'Cannot access cross-origin frame. Same-origin frames only.'
                });
            }
            var __trowserRoot = __trowserFrameResolved.doc;
            var __trowserFrameOffset = {
                x: __trowserFrameResolved.offsetX || 0,
                y: __trowserFrameResolved.offsetY || 0
            };
            function pageCenter(el) {
                var r = el.getBoundingClientRect();
                return {
                    x: r.x + r.width / 2 + __trowserFrameOffset.x,
                    y: r.y + r.height / 2 + __trowserFrameOffset.y
                };
            }

            """;
    }

    /// <summary>
    /// List iframes on the page (nested). Cross-origin frames are included with
    /// <c>sameOrigin:false</c>; when a WebView2 frame handle is registered they are
    /// <c>inspectable:true</c> (subject to navigation scope).
    /// </summary>
    public async Task<List<Dictionary<string, object>>> GetFrames()
    {
        const string js = """
            (function() {
                try {
                    var acc = [];
                    var counter = { n: 1 };
                    function walk(doc, parentId) {
                        var iframes = doc.querySelectorAll('iframe, frame');
                        for (var i = 0; i < iframes.length; i++) {
                            var f = iframes[i];
                            var id = f.getAttribute('data-trowser-frame-id');
                            if (!id) {
                                id = 'f' + (counter.n++);
                                try { f.setAttribute('data-trowser-frame-id', id); } catch (e) {}
                            }
                            var sameOrigin = false, url = '', name = f.getAttribute('name') || f.name || '';
                            var cd = null;
                            try {
                                cd = f.contentDocument;
                                if (cd) {
                                    sameOrigin = true;
                                    try { url = cd.location.href; } catch (e2) { url = f.src || ''; }
                                }
                            } catch (e3) {
                                url = f.src || '';
                            }
                            if (!url) url = f.src || '';
                            acc.push({
                                frameId: id,
                                name: name,
                                url: url,
                                sameOrigin: sameOrigin,
                                parentFrameId: parentId
                            });
                            if (cd) walk(cd, id);
                        }
                    }
                    walk(document, null);
                    return JSON.stringify(acc);
                } catch (err) {
                    return JSON.stringify({ __error: err.message || String(err) });
                }
            })()
            """;

        var json = await RunJs(js);
        var domFrames = new List<Dictionary<string, object>>();
        if (!string.IsNullOrEmpty(json))
        {
            try
            {
                if (json.TrimStart().StartsWith('{'))
                {
                    var err = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    if (err != null && err.ContainsKey("__error"))
                        TrowserLog.Warn($"GetFrames JS error: {err["__error"]}");
                    else
                        domFrames = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json) ?? new();
                }
                else
                {
                    domFrames = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json) ?? new();
                }
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"GetFrames parse failed: {ex.Message}");
            }
        }

        // Enrich with CDP Page.getFrameTree when available.
        try { await EnrichFramesFromCdpAsync(domFrames); }
        catch { /* optional */ }

        string? pageOrigin = null;
        try
        {
            var url = await GetCurrentUrl();
            pageOrigin = FrameRegistry.TryOrigin(url);
        }
        catch { /* ignore */ }

        Func<string?, bool>? scopeCheck = null;
        var guard = NavigationGuard;
        if (guard != null && !string.IsNullOrWhiteSpace(guard.Scope) && guard.Scope != "*.*")
        {
            scopeCheck = origin =>
            {
                if (string.IsNullOrEmpty(origin)) return true;
                try { return guard.IsAllowed(origin + "/"); }
                catch { return true; }
            };
        }

        return ActiveTab.Frames.MergeWithDomFrames(domFrames, pageOrigin, scopeCheck);
    }

    private async Task EnrichFramesFromCdpAsync(List<Dictionary<string, object>> domFrames)
    {
        var webView = ActiveTab.WebView;
        var treeJson = await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.getFrameTree", "{}"));
        using var doc = JsonDocument.Parse(treeJson);
        if (!doc.RootElement.TryGetProperty("frameTree", out var root)) return;

        void walk(JsonElement node, string? parentDomId)
        {
            if (!node.TryGetProperty("frame", out var frame)) return;
            var url = frame.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
            var name = frame.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var origin = FrameRegistry.TryOrigin(url) ?? "";

            // Match into existing DOM rows by URL/name; otherwise append.
            Dictionary<string, object>? match = null;
            foreach (var row in domFrames)
            {
                var rowUrl = row.TryGetValue("url", out var ru) ? ru?.ToString() ?? "" : "";
                var rowName = row.TryGetValue("name", out var rn) ? rn?.ToString() ?? "" : "";
                if ((!string.IsNullOrEmpty(name) && name.Equals(rowName, StringComparison.OrdinalIgnoreCase))
                    || (!string.IsNullOrEmpty(url) && url.Equals(rowUrl, StringComparison.OrdinalIgnoreCase)))
                {
                    match = row;
                    break;
                }
            }

            if (match != null)
            {
                if (!string.IsNullOrEmpty(origin)) match["origin"] = origin;
                if (!string.IsNullOrEmpty(url) && string.IsNullOrEmpty(match.TryGetValue("url", out var _) ? match["url"]?.ToString() : ""))
                    match["url"] = url;
            }
            else if (!string.IsNullOrEmpty(url) && url != "about:blank")
            {
                // Skip the main frame (parentDomId null and typically already the page).
                if (parentDomId != null || (!string.IsNullOrEmpty(name)))
                {
                    var cdpId = frame.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
                    domFrames.Add(new Dictionary<string, object>
                    {
                        ["frameId"] = "cdp-" + (string.IsNullOrEmpty(cdpId) ? Guid.NewGuid().ToString("N")[..8] : cdpId),
                        ["name"] = name,
                        ["url"] = url,
                        ["origin"] = origin,
                        ["sameOrigin"] = false,
                        ["crossOrigin"] = true,
                        ["inspectable"] = !string.IsNullOrEmpty(cdpId),
                        ["parentFrameId"] = parentDomId ?? "",
                        ["cdpFrameId"] = cdpId
                    });
                }
            }

            if (node.TryGetProperty("childFrames", out var children) && children.ValueKind == JsonValueKind.Array)
            {
                var thisId = match != null && match.TryGetValue("frameId", out var fid) ? fid?.ToString() : null;
                foreach (var child in children.EnumerateArray())
                    walk(child, thisId);
            }
        }

        walk(root, null);
    }

    /// <summary>
    /// Execute JavaScript in a specific frame. Uses <see cref="CoreWebView2Frame.ExecuteScriptAsync"/>
    /// for registered (including cross-origin) frames; falls back to same-origin DOM access.
    /// </summary>
    internal static string UnwrapJsStringResult(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return raw;
        try
        {
            if (raw.Length >= 2 && raw[0] == '"' && raw[^1] == '"')
                return JsonSerializer.Deserialize<string>(raw) ?? raw;
        }
        catch { /* keep raw */ }
        return raw;
    }

    internal async Task<FrameRegistry.FrameEntry?> TryResolveInspectableFrameEntryAsync(string frame)
    {
        if (string.IsNullOrWhiteSpace(frame))
            return null;

        var entry = ActiveTab.Frames.Find(frame);
        if (entry != null)
            return entry;

        var frames = await GetFrames();
        foreach (var f in frames)
        {
            var fid = f.TryGetValue("frameId", out var a) ? a?.ToString() : null;
            var rid = f.TryGetValue("registryId", out var b) ? b?.ToString() : null;
            var name = f.TryGetValue("name", out var c) ? c?.ToString() : null;
            if (string.Equals(fid, frame, StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, frame, StringComparison.OrdinalIgnoreCase))
            {
                if (!string.IsNullOrEmpty(rid))
                    return ActiveTab.Frames.Find(rid);
            }
        }

        return null;
    }

    public async Task<string> ExecuteJsInFrame(string frame, string script, int timeoutMs = 30_000)
    {
        if (string.IsNullOrWhiteSpace(frame))
            return await ExecuteJs(script, timeoutMs);

        if (frame.StartsWith("cdp-", StringComparison.OrdinalIgnoreCase))
        {
            var cdpFrameId = frame[4..];
            return await ExecuteJsViaCdpFrameAsync(cdpFrameId, script, timeoutMs);
        }

        // Prefer WebView2 frame handle (works cross-origin).
        var entry = ActiveTab.Frames.Find(frame);
        // Also try matching DOM frameId via merged list → registryId
        if (entry == null)
        {
            var frames = await GetFrames();
            foreach (var f in frames)
            {
                var fid = f.TryGetValue("frameId", out var a) ? a?.ToString() : null;
                var rid = f.TryGetValue("registryId", out var b) ? b?.ToString() : null;
                var name = f.TryGetValue("name", out var c) ? c?.ToString() : null;
                if (string.Equals(fid, frame, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, frame, StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.IsNullOrEmpty(rid))
                        entry = ActiveTab.Frames.Find(rid);
                    if (f.TryGetValue("outOfScope", out var oos) && oos is true)
                        throw new InvalidOperationException($"Frame '{frame}' is out of navigation scope.");
                    break;
                }
            }
        }

        var coreFrame = entry?.TryGetFrame();
        if (coreFrame != null)
        {
            if (entry?.OutOfScope == true)
                throw new InvalidOperationException($"Frame '{frame}' is out of navigation scope.");

            var webView = ActiveTab.WebView;
            var prepared = ExecuteJsScriptPrep.Prepare(script);
            return await await webView.Dispatcher.InvokeAsync(async () =>
                await ExecuteScriptInCoreFrameAsync(webView.CoreWebView2, coreFrame, prepared));
        }

        // Same-origin fallback via DOM contentDocument
        var preparedScript = ExecuteJsScriptPrep.Prepare(script);
        var js = "(function(){\n" + BuildFramePreamble(frame)
            + "return (function(document, window){\n"
            + "  try { return (" + preparedScript + "); }\n"
            + "  catch (e) { return JSON.stringify({ __frameError: e.message || String(e) }); }\n"
            + "})(__trowserRoot, __trowserRoot.defaultView || window);\n"
            + "})()";
        var result = await RunJs(js);
        ThrowIfFrameError(result);
        if (string.IsNullOrEmpty(result) || result == "null")
            return "";
        try
        {
            if (result.Length >= 2 && result[0] == '"' && result[^1] == '"')
                return JsonSerializer.Deserialize<string>(result) ?? result;
        }
        catch { /* keep raw */ }
        return result;
    }

    /// <summary>Run prepared JS in a <see cref="CoreWebView2Frame"/> with syntax check and exception surfacing.</summary>
    private static async Task<string> ExecuteScriptInCoreFrameAsync(
        CoreWebView2 core,
        CoreWebView2Frame coreFrame,
        string preparedScript)
    {
        if (core == null)
            throw new InvalidOperationException("WebView2 is not initialized.");

        await ExecuteJsSyntaxCheck.ValidatePreparedScriptAsync(core, preparedScript);

        string resultJson;
        try
        {
            resultJson = await coreFrame.ExecuteScriptAsync(preparedScript);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new InvalidOperationException($"JavaScript error: {ex.Message}", ex);
        }
        if (string.IsNullOrEmpty(resultJson) || resultJson == "null")
            return "";
        try
        {
            if (resultJson.Length >= 2 && resultJson[0] == '"' && resultJson[^1] == '"')
                return JsonSerializer.Deserialize<string>(resultJson) ?? resultJson;
        }
        catch { /* keep raw */ }
        return resultJson;
    }

    /// <summary>HTML source of a frame document (same- or cross-origin when inspectable).</summary>
    public async Task<string> GetSourceInFrame(string frame)
    {
        var raw = await ExecuteJsInFrame(frame, "document.documentElement ? document.documentElement.outerHTML : ''");
        return raw ?? "";
    }

    /// <summary>
    /// Throw a clear exception when a frame-scoped JS result indicates cross-origin or missing frame.
    /// </summary>
    private static void ThrowIfFrameError(string result)
    {
        if (string.IsNullOrEmpty(result)) return;
        var trimmed = result.TrimStart();
        if (!trimmed.StartsWith('{')) return;
        try
        {
            using var doc = JsonDocument.Parse(result);
            if (!doc.RootElement.TryGetProperty("__frameError", out var errProp))
                return;
            var code = errProp.GetString() ?? "frameError";
            if (code == "crossOrigin")
            {
                var url = doc.RootElement.TryGetProperty("url", out var u) ? u.GetString() : "";
                var name = doc.RootElement.TryGetProperty("name", out var n) ? n.GetString() : "";
                var frameId = doc.RootElement.TryGetProperty("frameId", out var f) ? f.GetString() : "";
                throw new InvalidOperationException(
                    $"crossOrigin: Cannot interact with cross-origin frame" +
                    (string.IsNullOrEmpty(frameId) ? "" : $" '{frameId}'") +
                    (string.IsNullOrEmpty(name) ? "" : $" name='{name}'") +
                    (string.IsNullOrEmpty(url) ? "" : $" url={url}") +
                    ". Same-origin frames only.");
            }

            throw new InvalidOperationException(code);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            /* not a frame error payload */
        }
    }

    /// <summary>Visible text inside an iframe document (same- or cross-origin when inspectable).</summary>
    public async Task<string> GetPageTextInFrame(string frame, bool fullText = false)
    {
        string text;
        try
        {
            text = await ExecuteJsInFrame(frame,
                "(function(){ var body = document.body; return body ? (body.innerText || body.textContent || '') : ''; })()");
        }
        catch (InvalidOperationException)
        {
            // Fall back to same-origin DOM preamble for DOM frameIds without registry handles.
            var js = "(function(){\n" + BuildFramePreamble(frame) + @"
                return (function(document){
                    try {
                        var body = document.body;
                        var text = body ? (body.innerText || body.textContent || '') : '';
                        return text;
                    } catch (e) { return ''; }
                })(__trowserRoot);
            })()";
            text = await RunJs(js);
            ThrowIfFrameError(text);
        }

        if (string.IsNullOrEmpty(text)) return "";
        try
        {
            if (text.Length >= 2 && text[0] == '"' && text[^1] == '"')
                text = JsonSerializer.Deserialize<string>(text) ?? text;
        }
        catch { /* keep raw */ }

        if (!fullText && text.Length > 3000)
            return text[..3000];
        return text;
    }

    /// <summary>Headings inside an iframe document (same- or cross-origin when inspectable).</summary>
    public async Task<List<Dictionary<string, string>>> GetHeadingsInFrame(string frame)
    {
        string json;
        if (await TryResolveInspectableFrameEntryAsync(frame) != null)
        {
            json = await ExecuteJsInFrame(frame,
                """
                (function(){
                  try {
                    var list = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6')).map(function(h) {
                      return { level: h.tagName.toLowerCase(), text: (h.innerText || h.textContent || '').trim().substring(0, 200) };
                    });
                    return JSON.stringify(list);
                  } catch (e) { return '[]'; }
                })()
                """);
        }
        else
        {
            var js = "(function(){\n" + BuildFramePreamble(frame) + @"
            return (function(document){
                try {
                    var list = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6')).map(function(h) {
                        return { level: h.tagName.toLowerCase(), text: (h.innerText || h.textContent || '').trim().substring(0, 200) };
                    });
                    return JSON.stringify(list);
                } catch (e) { return '[]'; }
            })(__trowserRoot);
        })()";
            json = await RunJs(js);
            ThrowIfFrameError(json);
        }
        try
        {
            return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new();
        }
        catch
        {
            return new List<Dictionary<string, string>>();
        }
    }

    private async Task<string> ExecuteJsViaCdpFrameAsync(string cdpFrameId, string script, int timeoutMs)
    {
        if (string.IsNullOrWhiteSpace(cdpFrameId))
            throw new InvalidOperationException("Frame not found: empty CDP frame id.");

        script = ExecuteJsScriptPrep.Prepare(script);
        var webView = ActiveTab.WebView;
        return await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = webView.CoreWebView2
                       ?? throw new InvalidOperationException("WebView2 is not initialized.");
            await ExecuteJsSyntaxCheck.ValidatePreparedScriptAsync(core, script);

            var worldJson = await core.CallDevToolsProtocolMethodAsync(
                "Page.createIsolatedWorld",
                JsonSerializer.Serialize(new
                {
                    frameId = cdpFrameId,
                    worldName = "trowser-automation",
                    grantUniversalAccess = true
                }));
            using var worldDoc = JsonDocument.Parse(worldJson);
            if (!worldDoc.RootElement.TryGetProperty("executionContextId", out var ctxEl)
                || !ctxEl.TryGetInt32(out var contextId))
                throw new InvalidOperationException($"Frame not found or not inspectable: cdp-{cdpFrameId}");

            var evalJson = await core.CallDevToolsProtocolMethodAsync(
                "Runtime.evaluate",
                JsonSerializer.Serialize(new
                {
                    expression = script,
                    contextId,
                    awaitPromise = true,
                    returnByValue = true,
                    timeout = timeoutMs
                }));
            using var evalDoc = JsonDocument.Parse(evalJson);
            if (evalDoc.RootElement.TryGetProperty("exceptionDetails", out var details)
                && details.ValueKind != JsonValueKind.Null
                && details.ValueKind != JsonValueKind.Undefined)
            {
                var msg = details.TryGetProperty("text", out var t) ? t.GetString() : null;
                throw new InvalidOperationException($"JavaScript error: {msg ?? "frame execution failed"}");
            }

            if (evalDoc.RootElement.TryGetProperty("result", out var result)
                && result.TryGetProperty("value", out var value))
            {
                return value.ValueKind switch
                {
                    JsonValueKind.String => value.GetString() ?? "",
                    JsonValueKind.Null or JsonValueKind.Undefined => "",
                    _ => value.GetRawText()
                };
            }

            return "";
        });
    }
}
