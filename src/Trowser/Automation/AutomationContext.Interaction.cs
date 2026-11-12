using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Element Interaction

    /// <summary>
    /// Click an element identified by a CSS selector or locator.
    /// Auto-waits for the element to be visible and enabled before clicking.
    /// If the element is a navigation link, automatically waits for the page to load.
    /// </summary>
    public async Task Click(string selector, int? timeoutMs = null) =>
        await Click(selector, "left", 1, timeoutMs);

    /// <summary>
    /// Click an element with configurable button and click count.
    /// button: "left", "right", "middle". clickCount: 1 for single, 2 for double, etc.
    /// </summary>
    public async Task Click(string selector, string button, int clickCount, int? timeoutMs = null)
    {
        if (button is not ("left" or "right" or "middle"))
            throw new ArgumentException($"Invalid button: \"{button}\". Must be \"left\", \"right\", or \"middle\".");
        if (clickCount < 1)
            throw new ArgumentException($"clickCount must be >= 1, got {clickCount}.");

        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: true, checkObscured: true);

        if (button == "left" && clickCount == 1)
        {
            var result = await RunDeepQueryJsAsync($@"
                var el = deepQuery({JsonEscape(resolved)});
                if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
                var href = el.tagName === 'A' ? (el.href || '') : '';
                var isNavLink = href && el.tagName === 'A'
                    && href.indexOf('javascript:') !== 0
                    && href !== (window.location.href.split('#')[0] + '#')
                    && el.target !== '_blank';
                if (!isNavLink || el.hasAttribute('download')) {{ el.click(); return 'OK'; }}
                var cur = window.location.href;
                el.click();
                function sameDocDiffFrag(a, b) {{
                    try {{
                        var ua = new URL(a), ub = new URL(b);
                        return ua.origin === ub.origin && ua.pathname === ub.pathname
                            && ua.search === ub.search && ua.hash !== ub.hash;
                    }} catch (e) {{ return false; }}
                }}
                if (sameDocDiffFrag(cur, href)) return 'H:' + href;
                return 'N:' + href;
            ");

            if (result.StartsWith("ERROR:"))
                throw new InvalidOperationException(result[6..]);

            if (result.StartsWith("H:", StringComparison.Ordinal) || result.StartsWith("N:", StringComparison.Ordinal))
                await WaitForTargetUrlAsync(result[2..], timeoutMs ?? 5000);

            try
            {
                await RecordTraceStepAsync("click", new { selector, button, clickCount });
            }
            catch { /* best-effort */ }
            return;
        }

        // Right-click, double-click, etc. -- use CDP for real mouse events
        var coordResult = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            var r = el.getBoundingClientRect();
            return JSON.stringify({{ x: r.x + r.width / 2, y: r.y + r.height / 2 }});
        ");
        if (coordResult.StartsWith("ERROR:"))
            throw new InvalidOperationException(coordResult[6..]);

        using var doc = JsonDocument.Parse(coordResult);
        var x = doc.RootElement.GetProperty("x").GetDouble();
        var y = doc.RootElement.GetProperty("y").GetDouble();

        var cdpButton = button switch { "right" => "right", "middle" => "middle", _ => "left" };

        if (cdpButton == "right")
            ActiveTab.SuppressNextContextMenu = true;

        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var pressJson = JsonSerializer.Serialize(new
            {
                type = "mousePressed", x, y, button = cdpButton, clickCount
            });
            var releaseJson = JsonSerializer.Serialize(new
            {
                type = "mouseReleased", x, y, button = cdpButton, clickCount
            });

            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Input.dispatchMouseEvent", pressJson);
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Input.dispatchMouseEvent", releaseJson);
        });

        try { await RecordTraceStepAsync("click", new { selector, button, clickCount }); }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Fire <paramref name="times"/> separate left-clicks at the element center via CDP, without waiting
    /// for navigation between clicks. Use to simulate accidental multi-clicks (login, checkout, add-to-cart)
    /// before the first navigation replaces the DOM — unlike <see cref="Click(string,int?)"/>, which waits
    /// after a navigational <c>el.click()</c> and then cannot find the same target again.
    /// </summary>
    /// <param name="delayMs">Optional pause between clicks (not after the last).</param>
    public async Task RapidClick(string selector, int times, int delayMs = 0, int? timeoutMs = null)
    {
        if (times < 1)
            throw new ArgumentException($"times must be >= 1, got {times}.");
        if (delayMs < 0)
            throw new ArgumentException($"delayMs must be >= 0, got {delayMs}.");

        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: true);

        var coordResult = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            var r = el.getBoundingClientRect();
            return JSON.stringify({{ x: r.x + r.width / 2, y: r.y + r.height / 2 }});
        ");
        if (coordResult.StartsWith("ERROR:"))
            throw new InvalidOperationException(coordResult[6..]);

        using var doc = JsonDocument.Parse(coordResult);
        var x = doc.RootElement.GetProperty("x").GetDouble();
        var y = doc.RootElement.GetProperty("y").GetDouble();

        var webView = ActiveTab.WebView;
        using var loopCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);

        for (var i = 0; i < times; i++)
        {
            await CheckScriptExecutionAsync();

            await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var pressJson = JsonSerializer.Serialize(new
                {
                    type = "mousePressed", x, y, button = "left", clickCount = 1
                });
                var releaseJson = JsonSerializer.Serialize(new
                {
                    type = "mouseReleased", x, y, button = "left", clickCount = 1
                });

                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                    "Input.dispatchMouseEvent", pressJson);
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                    "Input.dispatchMouseEvent", releaseJson);
            });

            if (delayMs > 0 && i < times - 1)
                await Task.Delay(delayMs, loopCts.Token);
        }
    }

    /// <summary>
    /// Drag from one element to another via CDP mouse events and/or HTML5 DragEvent.
    /// Returns which path ran: <c>cdp</c>, <c>html5</c>, or <c>cdp+html5</c> (only when explicitly requested).
    /// By default: HTML5-only when the source is <c>draggable</c>; otherwise CDP-only (no double-fire).
    /// </summary>
    /// <param name="html5">
    /// null = auto (draggable → html5, else cdp);
    /// true = HTML5 DragEvent only;
    /// false = CDP mouse only.
    /// </param>
    public async Task<string> Drag(string fromSelector, string toSelector, int steps = 10, int? timeoutMs = null, bool? html5 = null)
    {
        if (steps < 1) steps = 1;
        if (steps > 200) steps = 200;

        await WaitForActionable(fromSelector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: false);
        await WaitForActionable(toSelector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: false);

        SetActionFrame(null);
        var probeJs = "(function(){\n" + DeepQueryJs + "\n" + $@"
            var src = deepQuery({JsonEscape(fromSelector)});
            if (!src) return JSON.stringify({{found:false}});
            var drag = src.getAttribute('draggable');
            return JSON.stringify({{found:true, draggable: drag === '' || drag === 'true'}});
        " + "\n})()";
        var probeRaw = await RunJs(probeJs);
        var useHtml5 = html5 == true;
        var useCdp = html5 == false;
        if (html5 == null)
        {
            try
            {
                using var probe = JsonDocument.Parse(probeRaw);
                useHtml5 = probe.RootElement.TryGetProperty("draggable", out var d) && d.ValueKind == JsonValueKind.True;
                useCdp = !useHtml5;
            }
            catch
            {
                useCdp = true;
                useHtml5 = false;
            }
        }

        string path;
        if (useHtml5 && !useCdp)
        {
            await RunHtml5DragAsync(fromSelector, toSelector);
            path = "html5";
        }
        else if (useCdp && !useHtml5)
        {
            await RunCdpDragAsync(fromSelector, toSelector, steps);
            path = "cdp";
        }
        else
        {
            // Explicit dual path only when both requested (html5 not used this way currently)
            await RunCdpDragAsync(fromSelector, toSelector, steps);
            await RunHtml5DragAsync(fromSelector, toSelector);
            path = "cdp+html5";
        }

        try
        {
            var url = await GetCurrentUrl();
            await RecordTraceStepAsync("drag", new { from = fromSelector, to = toSelector, steps, path }, url);
        }
        catch { /* best-effort */ }

        return path;
    }

    private async Task RunCdpDragAsync(string fromSelector, string toSelector, int steps)
    {
        var coordJs = "(function(){\n" + BuildFramePreamble(null) + DeepQueryJs + "\n" + $@"
            function centerOf(sel) {{
                var el = deepQuery(sel);
                if (!el) return null;
                var r = el.getBoundingClientRect();
                var ox = 0, oy = 0;
                if (sel.indexOf('@frame:') === 0) {{
                    var pipe = sel.indexOf('|');
                    var fspec = sel.substring(7, pipe);
                    var fdoc = __trowserResolveFrameRoot(fspec);
                    if (fdoc) {{
                        var frames = window.document.querySelectorAll('iframe');
                        for (var i = 0; i < frames.length; i++) {{
                            try {{
                                if (frames[i].contentDocument === fdoc) {{
                                    var fr = frames[i].getBoundingClientRect();
                                    ox = fr.left; oy = fr.top; break;
                                }}
                            }} catch (e) {{}}
                        }}
                    }}
                }}
                return {{ x: r.x + r.width/2 + ox, y: r.y + r.height/2 + oy }};
            }}
            var a = centerOf({JsonEscape(fromSelector)});
            var b = centerOf({JsonEscape(toSelector)});
            if (!a) return 'ERROR:from not found';
            if (!b) return 'ERROR:to not found';
            return JSON.stringify({{x0:a.x,y0:a.y,x1:b.x,y1:b.y}});
        " + "\n})()";

        var coordResult = await RunJs(coordJs);
        ThrowIfFrameError(coordResult);
        if (coordResult.StartsWith("ERROR:"))
            throw new InvalidOperationException(coordResult[6..]);

        using var doc = JsonDocument.Parse(coordResult);
        var x0 = doc.RootElement.GetProperty("x0").GetDouble();
        var y0 = doc.RootElement.GetProperty("y0").GetDouble();
        var x1 = doc.RootElement.GetProperty("x1").GetDouble();
        var y1 = doc.RootElement.GetProperty("y1").GetDouble();

        // WebView2 CDP mouse often does not deliver DOM mouse events to page listeners.
        // Drive pointer-based DnD with MouseEvents first, then also send CDP for apps that
        // listen at the compositor level.
        var mirrorJs = "(function(){\n" + DeepQueryJs + "\n" + $@"
            var src = deepQuery({JsonEscape(fromSelector)});
            var dst = deepQuery({JsonEscape(toSelector)});
            if (!src || !dst) return 'ERROR:drag endpoints not found';
            var x0 = {x0.ToString(System.Globalization.CultureInfo.InvariantCulture)};
            var y0 = {y0.ToString(System.Globalization.CultureInfo.InvariantCulture)};
            var x1 = {x1.ToString(System.Globalization.CultureInfo.InvariantCulture)};
            var y1 = {y1.ToString(System.Globalization.CultureInfo.InvariantCulture)};
            function fire(target, type, x, y, buttons) {{
                target.dispatchEvent(new MouseEvent(type, {{
                    bubbles: true, cancelable: true, view: window,
                    clientX: x, clientY: y, screenX: x, screenY: y,
                    buttons: buttons, button: 0
                }}));
            }}
            fire(src, 'pointerdown', x0, y0, 1);
            fire(src, 'mousedown', x0, y0, 1);
            var steps = {steps};
            for (var i = 1; i <= steps; i++) {{
                var t = i / steps;
                var x = x0 + (x1 - x0) * t;
                var y = y0 + (y1 - y0) * t;
                fire(document, 'pointermove', x, y, 1);
                fire(document, 'mousemove', x, y, 1);
            }}
            fire(document, 'pointerup', x1, y1, 0);
            fire(document, 'mouseup', x1, y1, 0);
            try {{ document.documentElement.setAttribute('data-trowser-drag', 'cdp'); }} catch (e2) {{}}
            return 'OK';
        " + "\n})()";
        var mirrorResult = await RunJs(mirrorJs);
        if (mirrorResult.StartsWith("ERROR:"))
            throw new InvalidOperationException(mirrorResult[6..]);

        var webView = ActiveTab.WebView;
        try
        {
            await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var core = webView.CoreWebView2;
                await core.CallDevToolsProtocolMethodAsync("Input.dispatchMouseEvent",
                    JsonSerializer.Serialize(new { type = "mouseMoved", x = x0, y = y0 }));
                await core.CallDevToolsProtocolMethodAsync("Input.dispatchMouseEvent",
                    JsonSerializer.Serialize(new { type = "mousePressed", x = x0, y = y0, button = "left", buttons = 1, clickCount = 1 }));

                for (var i = 1; i <= steps; i++)
                {
                    var t = (double)i / steps;
                    var x = x0 + (x1 - x0) * t;
                    var y = y0 + (y1 - y0) * t;
                    await core.CallDevToolsProtocolMethodAsync("Input.dispatchMouseEvent",
                        JsonSerializer.Serialize(new { type = "mouseMoved", x, y, button = "left", buttons = 1 }));
                }

                await core.CallDevToolsProtocolMethodAsync("Input.dispatchMouseEvent",
                    JsonSerializer.Serialize(new { type = "mouseReleased", x = x1, y = y1, button = "left", buttons = 0, clickCount = 1 }));
            });
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"CDP drag mouse events failed (JS mirror already ran): {ex.Message}");
        }
    }

    private async Task RunHtml5DragAsync(string fromSelector, string toSelector)
    {
        // Chromium clears DataTransfer on untrusted DragEvents — use a store + defineProperty
        // so page handlers (e.g. the-internet drag_and_drop) see setData/getData consistently.
        var dndJs = "(function(){\n" + DeepQueryJs + "\n" + $@"
            var src = deepQuery({JsonEscape(fromSelector)});
            var dst = deepQuery({JsonEscape(toSelector)});
            if (!src || !dst) return 'ERROR:drag endpoints not found';

            var store = Object.create(null);
            var types = [];
            var dt = {{
                dropEffect: 'move',
                effectAllowed: 'all',
                files: [],
                items: [],
                types: types,
                setData: function(format, data) {{
                    format = String(format);
                    if (!Object.prototype.hasOwnProperty.call(store, format)) types.push(format);
                    store[format] = String(data);
                }},
                getData: function(format) {{
                    format = String(format);
                    return Object.prototype.hasOwnProperty.call(store, format) ? store[format] : '';
                }},
                clearData: function(format) {{
                    if (format == null) {{
                        for (var k in store) delete store[k];
                        types.length = 0;
                        return;
                    }}
                    format = String(format);
                    delete store[format];
                    var ix = types.indexOf(format);
                    if (ix >= 0) types.splice(ix, 1);
                }},
                setDragImage: function() {{}}
            }};

            function fire(el, type) {{
                var ev;
                try {{
                    ev = new DragEvent(type, {{ bubbles: true, cancelable: true, composed: true, dataTransfer: dt }});
                }} catch (e0) {{
                    ev = document.createEvent('Event');
                    ev.initEvent(type, true, true);
                }}
                try {{
                    Object.defineProperty(ev, 'dataTransfer', {{
                        get: function() {{ return dt; }},
                        configurable: true
                    }});
                }} catch (e1) {{}}
                return el.dispatchEvent(ev);
            }}

            fire(src, 'dragstart');
            fire(dst, 'dragenter');
            fire(dst, 'dragover');
            fire(dst, 'drop');
            fire(src, 'dragend');
            try {{ document.documentElement.setAttribute('data-trowser-drag', '1'); }} catch (e2) {{}}
            return 'OK';
        " + "\n})()";
        var result = await RunJs(dndJs);
        if (result.StartsWith("ERROR:"))
            throw new InvalidOperationException(result[6..]);
    }

    /// <summary>
    /// Type text into an input element. By default clears existing content first.
    /// Set clearFirst=false to append to existing content.
    /// Auto-waits for the element to be visible and enabled.
    /// </summary>
    public async Task Type(string selector, string text, int? timeoutMs = null, string? html = null, bool clearFirst = true)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: true, checkObscured: true);

        var escapedText = JsonEscape(text);
        var escapedHtml = html != null ? JsonEscape(html) : "null";

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            el.focus();

            // Detect contenteditable elements (rich text editors)
            var isContentEditable = el.isContentEditable
                && !(el instanceof HTMLInputElement)
                && !(el instanceof HTMLTextAreaElement);

            var doClear = {(clearFirst ? "true" : "false")};
            if (isContentEditable) {{
                var htmlContent = {escapedHtml};
                var textContent = {escapedText};

                // Step 1: Clear existing content (unless clearFirst is false)
                if (doClear) {{
                // CKEditor 5 maintains its own model — DOM selection alone doesn't work.
                // Use the editor's selectAll command when available, then beforeinput delete.
                if (el.ckeditorInstance) {{
                    try {{ el.ckeditorInstance.execute('selectAll'); }} catch(e) {{}}
                }} else {{
                    var sel = window.getSelection();
                    var range = document.createRange();
                    range.selectNodeContents(el);
                    sel.removeAllRanges();
                    sel.addRange(range);
                }}
                el.dispatchEvent(new InputEvent('beforeinput', {{
                    inputType: 'deleteContentBackward', bubbles: true, cancelable: true
                }}));
                }}

                // Step 2: Insert content via clipboard paste — works with CKEditor 5,
                // ProseMirror, Tiptap, Slate, and other editors that intercept paste events.
                var sel = window.getSelection();
                var range = document.createRange();
                range.selectNodeContents(el);
                range.collapse(false);
                sel.removeAllRanges();
                sel.addRange(range);

                var dt = new DataTransfer();
                dt.setData('text/plain', textContent);
                if (htmlContent) dt.setData('text/html', htmlContent);
                var pasteEvent = new ClipboardEvent('paste', {{
                    bubbles: true, cancelable: true, clipboardData: dt
                }});
                if (doClear) {{
                    sel = window.getSelection();
                    range = document.createRange();
                    range.selectNodeContents(el);
                    sel.removeAllRanges();
                    sel.addRange(range);
                    document.execCommand('delete', false, null);
                }}

                el.dispatchEvent(pasteEvent);

                // Verify the paste was handled
                var pasteWorked = false;
                if (el.ckeditorInstance) {{
                    pasteWorked = el.ckeditorInstance.getData().length > 0;
                }} else {{
                    pasteWorked = (el.innerText || '').trim().length > 0;
                }}

                if (!pasteWorked && textContent) {{
                    // Fallback: execCommand — works for plain contenteditable divs
                    // and older rich text editors (TinyMCE 4, etc.).
                    sel = window.getSelection();
                    range = document.createRange();
                    range.selectNodeContents(el);
                    sel.removeAllRanges();
                    sel.addRange(range);
                    document.execCommand('delete', false, null);

                    if (htmlContent) {{
                        document.execCommand('insertHTML', false, htmlContent);
                    }} else {{
                        document.execCommand('insertText', false, textContent);
                    }}
                }}

                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return 'OK:contenteditable';
            }}

            // Standard input/textarea path: use native value setter to bypass
            // framework interceptors (React, Vue, Angular use Object.defineProperty
            // on the element instance to track value changes).
            var proto = el instanceof HTMLTextAreaElement
                ? HTMLTextAreaElement.prototype
                : HTMLInputElement.prototype;
            var nativeSetter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
            var newVal = doClear ? {escapedText} : (el.value || '') + {escapedText};
            if (nativeSetter) {{
                nativeSetter.call(el, newVal);
            }} else {{
                el.value = newVal;
            }}

            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return 'OK';
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }

        try { await RecordTraceStepAsync("type", new { selector, textLength = text?.Length ?? 0, clearFirst }); }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Assign absolute host file path(s) to a <c>&lt;input type="file"&gt;</c> via CDP
    /// <c>DOM.setFileInputFiles</c>. Hidden file inputs are supported.
    /// </summary>
    public async Task SetFileInput(string selector, IReadOnlyList<string> absoluteHostPaths,
        int? timeoutMs = null, bool submitForm = false)
    {
        if (absoluteHostPaths == null || absoluteHostPaths.Count == 0)
            throw new ArgumentException("At least one absolute file path is required.", nameof(absoluteHostPaths));

        foreach (var p in absoluteHostPaths)
        {
            if (string.IsNullOrWhiteSpace(p))
                throw new ArgumentException("File path cannot be empty.", nameof(absoluteHostPaths));
            if (!Path.IsPathFullyQualified(p))
                throw new ArgumentException($"File path must be fully qualified: {p}", nameof(absoluteHostPaths));
            if (!File.Exists(p))
                throw new FileNotFoundException($"Upload file not found: {p}", p);
        }

        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: false, requireEnabled: false);

        var deepExpr = "(function() {\n" + DeepQueryJs + "\n" +
            $"var el = deepQuery({JsonEscape(resolved)});\n" +
            "if (!el) return null;\n" +
            "if (el.tagName !== 'INPUT' || el.type !== 'file') return null;\n" +
            "return el;\n})()";

        var webView = ActiveTab.WebView;
        string? objectId;

        objectId = await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var evalPayload = JsonSerializer.Serialize(new
            {
                expression = deepExpr,
                returnByValue = false,
                awaitPromise = false
            });
            var evalJson = await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Runtime.evaluate", evalPayload);
            using var doc = JsonDocument.Parse(evalJson);
            var resultEl = doc.RootElement.GetProperty("result");
            if (resultEl.TryGetProperty("subtype", out var st) && st.GetString() == "null")
                return (string?)null;
            if (resultEl.TryGetProperty("objectId", out var oid))
                return oid.GetString();
            return null;
        });

        if (string.IsNullOrEmpty(objectId))
        {
            throw new InvalidOperationException(
                "Could not resolve a file input at this selector (element missing, wrong tag, or not type=file).");
        }

        var setPayload = JsonSerializer.Serialize(new { objectId, files = absoluteHostPaths.ToArray() });
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("DOM.setFileInputFiles", setPayload);
        });

        if (!submitForm)
            return;

        var r = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR';
            var form = el.form;
            if (!form) return 'NO_FORM';
            var btn = form.querySelector('input[type=""submit""], button[type=""submit""], button:not([type])');
            if (btn) btn.click();
            else if (form.requestSubmit) form.requestSubmit();
            else form.submit();
            return 'OK';
        ");
        if (r == "NO_FORM")
            throw new InvalidOperationException("submitForm was true but the file input is not inside a form.");
        if (r.StartsWith("ERROR", StringComparison.Ordinal))
            throw new InvalidOperationException("Could not submit the form after assigning files.");
    }

    /// <summary>
    /// Get the inner text of an element. Auto-waits for the element to exist.
    /// </summary>
    public async Task<string> GetText(string selector, int? timeoutMs = null)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: false, requireEnabled: false);

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            return el.innerText || el.textContent || '';
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }
        return result;
    }

    /// <summary>
    /// Get an attribute value of an element. Auto-waits for the element to exist.
    /// </summary>
    public async Task<string> GetAttribute(string selector, string attribute, int? timeoutMs = null)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: false, requireEnabled: false);

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            return el.getAttribute({JsonEscape(attribute)}) || '';
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }
        return result;
    }

    /// <summary>
    /// Read a live DOM property value from an element (e.g. value, checked, selectedIndex).
    /// Unlike GetAttribute, this reads the current property state managed by JavaScript frameworks
    /// (Angular, React, Vue) rather than the static HTML attribute.
    /// </summary>
    public async Task<string> GetProperty(string selector, string property, int? timeoutMs = null)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: false, requireEnabled: false);

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            var v = el[{JsonEscape(property)}];
            if (v === undefined || v === null) return '';
            return String(v);
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }
        return result;
    }

    /// <summary>
    /// Read a <c>&lt;meta&gt;</c> tag's <c>content</c> attribute by <c>name</c> or <c>http-equiv</c>.
    /// Avoids CSS attribute-selector quoting issues (e.g. Content-Security-Policy).
    /// </summary>
    /// <param name="name">Value of the meta tag's <c>name</c> or <c>http-equiv</c> attribute.</param>
    /// <param name="httpEquiv">When true, match <c>http-equiv</c> instead of <c>name</c>.</param>
    public async Task<string> GetMetaContent(string name, bool httpEquiv = false, int? timeoutMs = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Meta name must be non-empty.", nameof(name));

        var attr = httpEquiv ? "http-equiv" : "name";
        var js = $@"
            (function() {{
                var target = {JsonEscape(name)};
                var attr = {JsonEscape(attr)};
                var metas = document.querySelectorAll('meta');
                for (var i = 0; i < metas.length; i++) {{
                    if (metas[i].getAttribute(attr) === target)
                        return metas[i].getAttribute('content') || '';
                }}
                return 'ERROR:Meta tag not found: ' + attr + '=' + target;
            }})()";

        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs ?? DefaultActionTimeout);
        while (DateTime.UtcNow < deadline)
        {
            await CheckScriptExecutionAsync();
            var result = await RunJs(js);
            if (!result.StartsWith("ERROR:"))
                return result;
            await Task.Delay(100, ScriptCancellation);
        }

        throw new TimeoutException($"Meta tag not found: {attr}=\"{name}\" (timeout {timeoutMs ?? DefaultActionTimeout}ms)");
    }

    /// <summary>
    /// Check whether a checkbox or toggle element is currently checked.
    /// Reads the live DOM property, not the HTML attribute.
    /// </summary>
    public async Task<bool> IsChecked(string selector, int? timeoutMs = null)
    {
        var value = await GetProperty(selector, "checked", timeoutMs);
        return value == "true";
    }

    /// <summary>
    /// Wait until an element matching the selector or locator exists in the DOM.
    /// </summary>
    public async Task WaitForElement(string selector, int timeoutMs = 10000, string state = "attached")
    {
        var normalized = (state ?? "attached").Trim().ToLowerInvariant();
        var (requireVisible, requireHidden, checkObscured) = normalized switch
        {
            "visible" => (true, false, true),
            "hidden" => (false, true, false),
            _ => (false, false, false)
        };
        await WaitForActionable(selector, timeoutMs, requireVisible, requireEnabled: false,
            requireHidden, checkObscured);
    }

    /// <summary>Execute arbitrary JavaScript and return the result as a string. Awaits Promises.</summary>
    public async Task<string> ExecuteJs(string script, int timeoutMs = RunJsTimeoutMs)
    {
        // WebView2's ExecuteScriptAsync evaluates expressions, not function bodies.
        // Multi-statement scripts and top-level return need an IIFE wrapper first.
        script = ExecuteJsScriptPrep.Prepare(script);

        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = webView.CoreWebView2
                       ?? throw new InvalidOperationException("WebView2 is not initialized.");
            await ExecuteJsSyntaxCheck.ValidatePreparedScriptAsync(core, script);
        });

        // RunJsAsync (postMessage callback) resolves Promises; RunJs returns empty for async IIFEs/fetch().
        var result = await RunJsAsync(script, timeoutMs);

        try
        {
            var ingested = await ExecuteJsChainIngestion.TryIngestAsync(this, script, result);
            SetLastExecuteJsIngestions(ingested);
        }
        catch
        {
            SetLastExecuteJsIngestions([]);
            // Verification ingest must never break execute-js.
        }

        return result;
    }

    /// <summary>Execute JavaScript that returns a Promise and await its resolution.</summary>
    public Task<string> ExecuteJsAsync(string script, int timeoutMs = 30_000)
        => RunJsAsync(script, timeoutMs);

    /// <summary>
    /// Register a script to run before any page script on the next navigation(s).
    /// Used by trace-input sink monitoring so document.write during parse is captured.
    /// </summary>
    public async Task<string> AddDocumentCreatedScriptAsync(string script)
    {
        var webView = ActiveTab.WebView;
        var task = await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(script));
        return await task;
    }

    /// <summary>Remove a script previously added with <see cref="AddDocumentCreatedScriptAsync"/>.</summary>
    public async Task RemoveDocumentCreatedScriptAsync(string scriptId)
    {
        if (string.IsNullOrEmpty(scriptId)) return;
        var webView = ActiveTab.WebView;
        await webView.Dispatcher.InvokeAsync(() =>
            webView.CoreWebView2.RemoveScriptToExecuteOnDocumentCreated(scriptId));
    }

    /// <summary>
    /// Get a random test data string or security payload from the Test Data collections.
    /// Pass kind="strings" or kind="payloads"; omit to use the active kind from the Test Data dialog.
    /// </summary>
    public async Task<string?> GetRandomTestData(string? kind = null)
    {
        if (TestDataService == null)
            throw new InvalidOperationException("Test data service not available.");

        TestDataKind? parsedKind = null;
        if (!string.IsNullOrWhiteSpace(kind))
        {
            if (!TestDataService.TryParseKind(kind, out var parsed))
                throw new ArgumentException("Invalid kind. Use 'strings' or 'payloads'.", nameof(kind));
            parsedKind = parsed;
        }

        return await TestDataService.GetRandomAsync(parsedKind);
    }

    /// <summary>
    /// Execute a fetch() request in the browser context.
    /// Includes the page's cookies, auth tokens, and CORS rules automatically.
    /// Returns a JSON string with shape: {ok, status, statusText, headers, body, durationMs}.
    /// <c>durationMs</c> is the HTTP round-trip (in-page fetch or server-side fallback), not gate wait or <c>delayMs</c>.
    /// </summary>
    /// <param name="markSynthetic">
    /// When true (default), the request is hidden from attack-surface discovery and costly-operations.
    /// Public <c>POST /api/fetch</c>, <c>/api/fetch/batch</c>, and <c>browser_fetch</c> pass false so
    /// agent exploration is visible. Scanner replay keeps the default.
    /// </param>
    public async Task<string> Fetch(string url, string method, Dictionary<string, string>? headers,
        string? body, int timeoutMs = 30000, string? redirect = null, bool markSynthetic = true)
    {
        var sw = Stopwatch.StartNew();
        string result = "";
        string? error = null;
        try
        {
            result = await FetchCore(url, method, headers, body, timeoutMs, redirect, markSynthetic);
            return AppendDurationMs(result, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            CurrentRequestTrace?.Record(method, url, body, ParseFetchStatus(result), sw.ElapsedMilliseconds, error, "browser");
        }
    }

    /// <summary>
    /// Send HTTP/1.x bytes on a new TCP/TLS connection. Session header overrides are not applied.
    /// Returns JSON with requestSent, status, statusText, headers (string array), body, timedOut, durationMs, hostWasAdded, error.
    /// </summary>
    public async Task<string> FetchRaw(string url, string? requestLine = null, string? headers = null,
        string? body = null, string? method = null, int timeoutMs = 15000, bool normalizeHeaders = true)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new ArgumentException("url must be an absolute http or https URL.");

        var line = string.IsNullOrWhiteSpace(requestLine)
            ? RawHttpClient.DefaultRequestLine(method ?? "GET", uri)
            : requestLine.Trim();

        var result = await RawHttpClient.SendAsync(uri, line, headers, body, timeoutMs,
            new RawHttpClient.BuildOptions { NormalizeHeaders = normalizeHeaders });

        return JsonSerializer.Serialize(new
        {
            ok = result.Error == null && !result.TimedOut && result.Status is >= 200 and < 300,
            status = result.Status,
            statusText = result.StatusText,
            headers = result.Headers,
            body = result.Body,
            bodyRaw = result.BodyRaw,
            bodyWasChunked = result.BodyWasChunked,
            requestSent = result.RequestSent,
            timedOut = result.TimedOut,
            hostWasAdded = result.HostWasAdded,
            durationMs = result.DurationMs,
            error = result.Error
        });
    }

    /// <summary>Current session header overrides (WebView2 browsing only).</summary>
    public IReadOnlyList<HeaderOverride> GetHeaderOverrides() => HeaderOverrideSettings.GetAll();

    /// <summary>Replace session header overrides. Does not affect Direct/raw/server-side sends.</summary>
    public void SetHeaderOverrides(IEnumerable<HeaderOverride> items) => HeaderOverrideSettings.Replace(items);

    /// <summary>Clear all session header overrides.</summary>
    public void ClearHeaderOverrides() => HeaderOverrideSettings.Clear();

    /// <summary>Add or replace <c>durationMs</c> on a <see cref="FetchCore"/> JSON object.</summary>
    private static string AppendDurationMs(string fetchJson, long durationMs)
    {
        if (string.IsNullOrEmpty(fetchJson))
            return fetchJson;
        try
        {
            using var doc = JsonDocument.Parse(fetchJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return fetchJson;

            using var ms = new MemoryStream();
            using (var writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.NameEquals("durationMs"))
                        continue;
                    prop.WriteTo(writer);
                }
                writer.WriteNumber("durationMs", durationMs);
                writer.WriteEndObject();
            }

            return System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }
        catch
        {
            return fetchJson;
        }
    }

    /// <summary>Best-effort extraction of the <c>status</c> field from a <see cref="FetchCore"/> JSON result.</summary>
    private static int ParseFetchStatus(string fetchJson)
    {
        if (string.IsNullOrEmpty(fetchJson)) return 0;
        try
        {
            using var doc = JsonDocument.Parse(fetchJson);
            return doc.RootElement.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.Number
                ? s.GetInt32() : 0;
        }
        catch
        {
            return 0;
        }
    }

    private async Task<string> FetchCore(string url, string method, Dictionary<string, string>? headers,
        string? body, int timeoutMs, string? redirect, bool markSynthetic)
    {
        method = method.Trim().ToUpperInvariant();

        var sb = new System.Text.StringBuilder(256);
        sb.Append("(async function(){var opts={method:");
        sb.Append(JsonEscape(method));

        if (redirect is "manual" or "error")
            sb.Append(",redirect:").Append(JsonEscape(redirect));

        sb.Append("};");

        if (headers is { Count: > 0 })
        {
            sb.Append("opts.headers={");
            bool first = true;
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)
                    && RequestContentBuilder.IsExplicitlyEmpty(kv.Value))
                    continue;
                if (!first) sb.Append(',');
                sb.Append(JsonEscape(kv.Key)).Append(':').Append(JsonEscape(kv.Value));
                first = false;
            }
            sb.Append("};");
        }

        // Spec forbids a body on GET/HEAD — setting opts.body throws in Chromium fetch.
        if (body != null
            && !method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            && !method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            sb.Append("opts.body=").Append(JsonEscape(body)).Append(';');

        sb.Append("var r=await fetch(").Append(JsonEscape(url)).Append(",opts);");
        sb.Append("var h={};r.headers.forEach(function(v,k){h[k]=v;});");
        sb.Append("var b='';try{b=await r.text();}catch(e){}");
        sb.Append("return {ok:r.ok,status:r.status,statusText:r.statusText,redirected:r.redirected,type:r.type,url:r.url,headers:h,body:b};");
        sb.Append("})()");

        // Scanner and fuzzer replay stays synthetic so discovery does not feed on its own probes.
        // Agent-facing fetch passes markSynthetic: false.
        if (markSynthetic)
            ActiveTab.MarkSyntheticRequest(method, url);

        var result = await RunJsAsync(sb.ToString(), timeoutMs);

        // Browser fetch() with redirect:"manual" returns an opaque redirect (status 0, no headers,
        // no body) for cross-origin 3xx responses. Fall back to server-side HttpClient to expose
        // the actual status code, Location header, and response body.
        if (redirect == "manual")
        {
            using var doc = JsonDocument.Parse(result);
            var root = doc.RootElement;
            if (root.TryGetProperty("type", out var typeProp)
                && typeProp.GetString() == "opaqueredirect"
                && root.GetProperty("status").GetInt32() == 0)
            {
                return await FetchServerSideNoRedirect(url, method, headers, body, timeoutMs);
            }
        }

        return result;
    }

    /// <summary>
    /// Server-side fetch with <c>AllowAutoRedirect = false</c>, used as a fallback when the
    /// browser returns an opaque redirect for cross-origin 3xx responses. Includes the browser's
    /// cookies (including HttpOnly) so that authenticated redirects are captured faithfully.
    /// Returns JSON in the same shape as <see cref="Fetch"/>.
    /// </summary>
    private async Task<string> FetchServerSideNoRedirect(string url, string method,
        Dictionary<string, string>? headers, string? body, int timeoutMs)
    {
        var cookieHeader = await GetCookieHeaderForUrl(url);

        using var handler = new System.Net.Http.HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new System.Net.Http.HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(timeoutMs)
        };

        var msg = new System.Net.Http.HttpRequestMessage(new System.Net.Http.HttpMethod(method), url);

        if (!string.IsNullOrEmpty(cookieHeader))
            msg.Headers.TryAddWithoutValidation("Cookie", CookieHeaderSanitizer.SanitizeCookieHeader(cookieHeader));

        if (body != null)
        {
            string? contentType = null;
            var hasContentType = headers != null && headers.TryGetValue("Content-Type", out contentType);
            msg.Content = RequestContentBuilder.FromText(body, hasContentType ? contentType : null, "text/plain");
        }

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                if (!msg.Headers.TryAddWithoutValidation(kv.Key, CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value)))
                    msg.Content?.Headers.TryAddWithoutValidation(kv.Key, CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value));
            }
        }

        var resp = await client.SendAsync(msg);
        var respBody = await resp.Content.ReadAsStringAsync();

        var respHeaders = new Dictionary<string, string>();
        foreach (var h in resp.Headers)
            respHeaders[h.Key] = string.Join(", ", h.Value);
        foreach (var h in resp.Content.Headers)
            respHeaders[h.Key] = string.Join(", ", h.Value);

        var isRedirect = (int)resp.StatusCode >= 300 && (int)resp.StatusCode < 400;
        return JsonSerializer.Serialize(new
        {
            ok = resp.IsSuccessStatusCode,
            status = (int)resp.StatusCode,
            statusText = resp.ReasonPhrase ?? "",
            redirected = false,
            type = "manual-server-side",
            url = resp.RequestMessage?.RequestUri?.ToString() ?? url,
            headers = respHeaders,
            body = respBody
        });
    }

    /// <summary>
    /// Build a Cookie request header value for the given URL from the browser cookie jar
    /// (includes HttpOnly cookies). Relative URLs resolve against the active document.
    /// </summary>
    public async Task<string> GetCookieHeaderForUrl(string requestUrl)
    {
        var snapshot = await GetBrowserCookieSnapshotForUrl(requestUrl);
        return snapshot.Header;
    }

    /// <summary>
    /// Cookie jar snapshot for server-side replay: header value, lookup URL, and per-cookie scope (no values).
    /// </summary>
    public async Task<BrowserCookieSnapshot> GetBrowserCookieSnapshotForUrl(string requestUrl)
    {
        var sourceUrl = await ResolveFetchUrlAsync(requestUrl);
        if (string.IsNullOrEmpty(sourceUrl))
            return new BrowserCookieSnapshot("", requestUrl.Trim(), []);

        // B2 FIX: Extract cookie names/values entirely on the UI thread to avoid
        // COM interop crash when WebView2 cookie COM objects are accessed cross-thread.
        var webView = ActiveTab.WebView;
        var built = await webView.Dispatcher.InvokeAsync(async () =>
        {
            var cookies = await webView.CoreWebView2.CookieManager.GetCookiesAsync(sourceUrl);
            if (cookies == null || cookies.Count == 0)
                return (Header: "", Scopes: (IReadOnlyList<BrowserCookieScope>)[]);

            var scopes = new List<BrowserCookieScope>(cookies.Count);
            var pairs = new List<(string Name, string Value)>(cookies.Count);
            foreach (var c in cookies)
            {
                pairs.Add((c.Name, c.Value));
                scopes.Add(new BrowserCookieScope(c.Name, c.Domain ?? "", c.Path ?? ""));
            }

            return (
                Header: CookieHeaderSanitizer.BuildCookieHeader(pairs),
                Scopes: scopes);
        });

        var result = await built;
        return new BrowserCookieSnapshot(result.Header, sourceUrl, result.Scopes);
    }

    /// <summary>
    /// Remove cookies whose name or value contains non-ASCII characters (often set by injection probes).
    /// Returns the number of cookies purged.
    /// </summary>
    public async Task<int> PurgeNonAsciiCookiesAsync(string? scopeUrl = null)
    {
        var url = scopeUrl;
        if (string.IsNullOrEmpty(url))
            url = await GetCurrentUrl();
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
            return 0;

        var webView = ActiveTab.WebView;
        var purged = await webView.Dispatcher.InvokeAsync(async () =>
        {
            var cookies = await webView.CoreWebView2.CookieManager.GetCookiesAsync(url);
            var count = 0;
            foreach (var c in cookies)
            {
                if (CookieHeaderSanitizer.IsAsciiCookieName(c.Name)
                    && CookieHeaderSanitizer.IsAsciiCookieValue(c.Value))
                    continue;
                webView.CoreWebView2.CookieManager.DeleteCookie(c);
                count++;
            }
            return count;
        });

        return await purged;
    }

    /// <summary>
    /// Run multiple <see cref="Fetch"/> calls, optionally in parallel (same browser context, cookies, and CORS).
    /// </summary>
    public async Task<IReadOnlyList<FetchBatchResultItem>> FetchBatchAsync(
        IReadOnlyList<FetchBatchRequestItem> requests, bool concurrent = true, bool markSynthetic = true)
    {
        if (requests.Count == 0)
            return Array.Empty<FetchBatchResultItem>();

        async Task<FetchBatchResultItem> RunOne(int index, FetchBatchRequestItem req)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (req.UseServerSide)
                {
                    var allowRedirect = req.Redirect is not ("manual" or "error");
                    var direct = await DirectFetchHelper.FetchAsync(
                        this, req.Url, req.Method, req.Headers, req.Body, req.TimeoutMs, allowRedirect,
                        req.IncludeBrowserCookies);
                    sw.Stop();
                    if (direct.Error != null)
                    {
                        return new FetchBatchResultItem
                        {
                            Index = index,
                            RequestUrl = req.Url,
                            RequestMethod = req.Method,
                            RequestBody = req.Body,
                            Error = direct.Error,
                            DurationMs = sw.ElapsedMilliseconds,
                            IdentitySource = req.IdentitySource
                        };
                    }

                    var callerCookie = req.Headers != null
                        && req.Headers.TryGetValue("Cookie", out var callerCookieHeader)
                        && !string.IsNullOrWhiteSpace(callerCookieHeader);
                    return new FetchBatchResultItem
                    {
                        Index = index,
                        RequestUrl = req.Url,
                        RequestMethod = req.Method,
                        RequestBody = req.Body,
                        Ok = direct.Ok,
                        Status = direct.Status,
                        StatusText = direct.StatusText,
                        Redirected = direct.Redirected,
                        ResponseType = "server-side",
                        ResponseUrl = direct.FinalUrl ?? req.Url,
                        Headers = direct.Headers,
                        Body = direct.Body,
                        DurationMs = sw.ElapsedMilliseconds,
                        IdentitySource = req.IdentitySource,
                        CookiesSent = direct.CookiesSent,
                        IncludeBrowserCookies = direct.IncludedBrowserCookies,
                        IdentityUsed = FetchIdentity.Describe(
                            direct.IncludedBrowserCookies, direct.CookiesSent, req.IdentitySource, callerCookie)
                    };
                }

                var pageCookies = new List<string>();
                try
                {
                    var snapshot = await GetBrowserCookieSnapshotForUrl(req.Url);
                    pageCookies = CookieHeaderSanitizer.CookieNames(snapshot.Header);
                }
                catch
                {
                    /* identity audit is best-effort */
                }

                var json = await Fetch(req.Url, req.Method, req.Headers, req.Body, req.TimeoutMs, req.Redirect, markSynthetic);
                sw.Stop();
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var headers = new Dictionary<string, string>();
                if (root.TryGetProperty("headers", out var hdrs) && hdrs.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in hdrs.EnumerateObject())
                        headers[p.Name] = p.Value.GetString() ?? "";
                }

                return new FetchBatchResultItem
                {
                    Index = index,
                    RequestUrl = req.Url,
                    RequestMethod = req.Method,
                    RequestBody = req.Body,
                    Ok = root.GetProperty("ok").GetBoolean(),
                    Status = root.GetProperty("status").GetInt32(),
                    StatusText = root.TryGetProperty("statusText", out var st) ? st.GetString() : null,
                    Redirected = root.TryGetProperty("redirected", out var rd) && rd.ValueKind == JsonValueKind.True,
                    ResponseType = root.TryGetProperty("type", out var rt) ? rt.GetString() : null,
                    ResponseUrl = root.TryGetProperty("url", out var ru) ? ru.GetString() : null,
                    Headers = headers,
                    Body = root.TryGetProperty("body", out var b) ? b.GetString() : null,
                    DurationMs = root.TryGetProperty("durationMs", out var dms) && dms.TryGetInt64(out var dm)
                        ? dm
                        : sw.ElapsedMilliseconds,
                    IdentitySource = req.IdentitySource,
                    CookiesSent = pageCookies,
                    IncludeBrowserCookies = true,
                    IdentityUsed = "browser-page"
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new FetchBatchResultItem
                {
                    Index = index,
                    RequestUrl = req.Url,
                    RequestMethod = req.Method,
                    RequestBody = req.Body,
                    Error = ex.Message,
                    DurationMs = sw.ElapsedMilliseconds,
                    IdentitySource = req.IdentitySource
                };
            }
        }

        if (!concurrent)
        {
            var sequential = new List<FetchBatchResultItem>();
            for (var i = 0; i < requests.Count; i++)
                sequential.Add(await RunOne(i, requests[i]));
            return sequential;
        }

        var tasks = requests.Select((req, i) => RunOne(i, req));
        return await Task.WhenAll(tasks);
    }

    public async Task<string> GetPageSource()
    {
        return await RunJs("document.documentElement.outerHTML");
    }

    private const string EnrichAccessibleNameJs = """
        (function(el){
          var aria=el.getAttribute('aria-label');
          if(aria) return aria.trim().substring(0,500);
          var labelledBy=el.getAttribute('aria-labelledby');
          if(labelledBy){
            var lbl=document.getElementById(labelledBy);
            if(lbl) return (lbl.innerText||'').trim().substring(0,500);
          }
          if(el.id){
            var lf=document.querySelector('label[for="'+el.id.replace(/"/g,'\\"')+'"]');
            if(lf) return (lf.innerText||'').trim().substring(0,500);
          }
          if(el.labels&&el.labels.length>0){
            var lt=(el.labels[0].innerText||el.labels[0].textContent||'').trim();
            if(lt) return lt.substring(0,500);
          }
          if(el.tagName==='INPUT'||el.tagName==='SELECT'||el.tagName==='TEXTAREA'){
            var parent=el.closest('label');
            if(parent){
              var clone=parent.cloneNode(true);
              clone.querySelectorAll('input,select,textarea').forEach(function(n){n.remove();});
              var wrap=(clone.innerText||clone.textContent||'').trim();
              if(wrap) return wrap.substring(0,500);
            }
          }
          return '';
        })
        """;

    private static readonly Dictionary<string, string> EnrichFieldJs = new(StringComparer.OrdinalIgnoreCase)
    {
        ["text"] = "obj.text=(function(el){var t=(el.innerText||el.textContent||'').trim();if(!t&&(el.tagName==='INPUT'||el.tagName==='SELECT'||el.tagName==='TEXTAREA')){t=" + EnrichAccessibleNameJs + "(el);}return t.substring(0,500);})(el);",
        ["accessibleName"] = "obj.accessibleName=" + EnrichAccessibleNameJs + "(el);",
        ["label"] = "obj.label=" + EnrichAccessibleNameJs + "(el);",
        ["href"] = "obj.href=el.href||'';",
        ["ariaLabel"] = "obj.ariaLabel=el.getAttribute('aria-label')||'';",
        ["checked"] = "obj.checked=!!el.checked;",
        ["value"] = "obj.value=(el.value||'').substring(0,200);",
        ["placeholder"] = "obj.placeholder=el.placeholder||'';",
        ["disabled"] = "obj.disabled=!!el.disabled;",
        ["tag"] = "obj.tag=el.tagName.toLowerCase();",
        ["id"] = "obj.id=el.id||'';",
        ["className"] = "obj.className=el.className||'';",
        ["class"] = "obj.className=el.className||'';",
        ["name"] = "obj.name=el.name||'';",
        ["type"] = "obj.type=el.type||'';",
        ["role"] = "obj.role=el.getAttribute('role')||'';",
        ["title"] = "obj.title=el.title||'';",
        ["htmlFor"] = "obj.htmlFor=el.htmlFor||'';",
        ["for"] = "obj.htmlFor=el.htmlFor||'';",
        ["required"] = "obj.required=!!el.required;",
        ["readOnly"] = "obj.readOnly=!!el.readOnly;",
        ["maxLength"] = "obj.maxLength=el.maxLength!=null&&el.maxLength>=0?el.maxLength:null;",
        ["pattern"] = "obj.pattern=el.pattern||'';",
        ["min"] = "obj.min=el.min||'';",
        ["max"] = "obj.max=el.max||'';",
        ["step"] = "obj.step=el.step||'';",
        ["autocomplete"] = "obj.autocomplete=el.autocomplete||'';",
        ["multiple"] = "obj.multiple=!!el.multiple;",
        ["selected"] = "obj.selected=!!el.selected;",
        ["src"] = "obj.src=el.src||'';",
        ["alt"] = "obj.alt=el.alt||'';",
        ["target"] = "obj.target=el.target||'';",
        ["action"] = "obj.action=el.action||'';",
        ["method"] = "obj.method=el.method||'';",
        ["tabIndex"] = "obj.tabIndex=el.tabIndex;",
        ["contentEditable"] = "obj.contentEditable=el.contentEditable||'';",
        ["data-testid"] = "obj['data-testid']=el.getAttribute('data-testid')||'';",
        ["testId"] = "obj['data-testid']=el.getAttribute('data-testid')||'';",
    };

    public static bool IsEnrichFieldSupported(string field) => EnrichFieldJs.ContainsKey(field);

    /// <summary>Batch-fetch text and attributes for multiple refs in one call. Reduces API round-trips for "map all elements" workflows.</summary>
    public async Task<List<Dictionary<string, object?>>> EnrichRefs(IReadOnlyList<int> refs, IReadOnlyList<string> fields)
    {
        if (refs.Count == 0 || fields.Count == 0)
            return new List<Dictionary<string, object?>>();

        var selectors = refs.Select(r => GetSelectorByRef(r)).ToList();

        var sb = new System.Text.StringBuilder(4096);
        sb.Append("(function(){");
        sb.Append(DeepQueryJs);
        sb.Append("var selectors=").Append(JsonSerializer.Serialize(selectors)).Append(";");
        sb.Append("var results=[];");
        sb.Append("for(var i=0;i<selectors.length;i++){");
        sb.Append("var obj={};");
        sb.Append("var sel=selectors[i];");
        sb.Append("if(!sel){results.push(obj);continue;}");
        sb.Append("var el=deepQuery(sel);");
        sb.Append("if(!el){results.push(obj);continue;}");
        foreach (var field in fields)
        {
            if (EnrichFieldJs.TryGetValue(field, out var jsExpr))
                sb.Append(jsExpr);
        }
        sb.Append("results.push(obj);}");
        sb.Append("return JSON.stringify(results);})()");

        var json = await RunJs(sb.ToString());
        if (string.IsNullOrEmpty(json)) return refs.Select(r => new Dictionary<string, object?> { ["ref"] = r }).ToList();

        try
        {
            var list = JsonSerializer.Deserialize<List<Dictionary<string, object?>>>(json) ?? new List<Dictionary<string, object?>>();
            for (var i = 0; i < list.Count && i < refs.Count; i++)
                list[i]["ref"] = refs[i];
            return list;
        }
        catch
        {
            return refs.Select(r => new Dictionary<string, object?> { ["ref"] = r }).ToList();
        }
    }

    /// <summary>Get all visible text on the current page, including text inside shadow DOM.</summary>
    public async Task<string> GetPageText()
    {
        return await RunJs(@"
            (function() {
                function collectShadowText(root) {
                    var texts = [];
                    var all = root.querySelectorAll('*');
                    for (var i = 0; i < all.length; i++) {
                        var sr = all[i].shadowRoot;
                        if (sr) {
                            var children = sr.children;
                            for (var j = 0; j < children.length; j++) {
                                var t = children[j].innerText;
                                if (t) texts.push(t);
                            }
                            texts = texts.concat(collectShadowText(sr));
                        }
                    }
                    return texts;
                }
                var bodyText = document.body ? document.body.innerText || '' : '';
                var shadowTexts = collectShadowText(document);
                if (shadowTexts.length === 0) return bodyText;
                return bodyText + '\n' + shadowTexts.join('\n');
            })()");
    }

    /// <summary>
    /// Get text from every text node in the document, including content that is not visible
    /// (<c>display:none</c>, <c>visibility:hidden</c>, off-screen, etc.), including shadow DOM.
    /// Each non-empty trimmed text node is one line (useful for proof-reading and diffing).
    /// Script, style, noscript, and template contents are skipped.
    /// </summary>
    public async Task<string> GetAllPageText()
    {
        return await RunJs("""
            (function() {
                function skipTag(tag) {
                    return tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEMPLATE';
                }
                function skipAncestors(el) {
                    while (el) {
                        if (el.nodeType === 1 && skipTag(el.tagName)) return true;
                        el = el.parentElement;
                    }
                    return false;
                }
                var lines = [];
                function walk(node) {
                    if (!node) return;
                    if (node.nodeType === 11) {
                        var fragChild = node.firstChild;
                        while (fragChild) {
                            walk(fragChild);
                            fragChild = fragChild.nextSibling;
                        }
                        return;
                    }
                    if (node.nodeType === 3) {
                        if (skipAncestors(node.parentElement)) return;
                        var txt = node.nodeValue;
                        if (txt && txt.trim()) lines.push(txt.trim());
                        return;
                    }
                    if (node.nodeType !== 1) return;
                    if (skipTag(node.tagName)) return;
                    if (node.shadowRoot) walk(node.shadowRoot);
                    var c = node.firstChild;
                    while (c) {
                        walk(c);
                        c = c.nextSibling;
                    }
                }
                if (document.body) walk(document.body);
                return lines.join('\n');
            })()
            """);
    }

    /// <summary>
    /// Collect screen-reader-oriented strings: <c>alt</c>, <c>aria-label</c>, resolved
    /// <c>aria-labelledby</c> / <c>aria-describedby</c>, <c>title</c>, and SVG <c>title</c>/<c>desc</c>,
    /// including inside shadow DOM. Each entry is one line with a <c>[kind]</c> prefix.
    /// </summary>
    public async Task<string> GetScreenReaderTexts()
    {
        return await RunJs("""
            (function() {
                function skipTag(tag) {
                    return tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEMPLATE';
                }
                function resolveRefs(el, attr) {
                    var ids = el.getAttribute(attr);
                    if (!ids) return '';
                    var root = el.getRootNode();
                    var getById = root && root.getElementById
                        ? function(id) { return root.getElementById(id); }
                        : function(id) { return document.getElementById(id); };
                    return ids.split(/\s+/).map(function(id) {
                        if (!id) return '';
                        var t = getById(id);
                        if (!t) return '';
                        return (t.textContent || '').replace(/\s+/g, ' ').trim();
                    }).filter(Boolean).join(' ');
                }
                var lines = [];
                function visit(el) {
                    if (!el || el.nodeType !== 1 || skipTag(el.tagName)) return;
                    var tag = el.tagName;
                    if (tag === 'IMG' || tag === 'AREA' ||
                        (tag === 'INPUT' && el.type && el.type.toLowerCase() === 'image')) {
                        var alt = el.getAttribute('alt');
                        if (alt !== null && String(alt).trim() !== '')
                            lines.push('[alt] ' + String(alt).trim());
                    }
                    var al = el.getAttribute('aria-label');
                    if (al && al.trim()) lines.push('[aria-label] ' + al.trim());
                    var ltxt = resolveRefs(el, 'aria-labelledby');
                    if (ltxt) lines.push('[aria-labelledby] ' + ltxt);
                    var dtxt = resolveRefs(el, 'aria-describedby');
                    if (dtxt) lines.push('[aria-describedby] ' + dtxt);
                    var title = el.getAttribute('title');
                    if (title && title.trim()) lines.push('[title] ' + title.trim());
                    if (tag === 'SVG') {
                        var st = el.querySelector('title');
                        if (st && st.textContent && st.textContent.trim())
                            lines.push('[svg:title] ' + st.textContent.trim());
                        var sd = el.querySelector('desc');
                        if (sd && sd.textContent && sd.textContent.trim())
                            lines.push('[svg:desc] ' + sd.textContent.trim());
                    }
                    if (el.shadowRoot) visitChildren(el.shadowRoot);
                    var c = el.firstChild;
                    while (c) {
                        if (c.nodeType === 1) visit(c);
                        c = c.nextSibling;
                    }
                }
                function visitChildren(root) {
                    if (!root) return;
                    var c = root.firstChild;
                    while (c) {
                        var next = c.nextSibling;
                        if (c.nodeType === 1) visit(c);
                        c = next;
                    }
                }
                if (document.body) visit(document.body);
                return lines.join('\n');
            })()
            """);
    }

    public async Task<string> GetCurrentUrl()
    {
        var webView = ActiveTab.WebView;
        return await webView.Dispatcher.InvokeAsync(() =>
        {
            var raw = webView.CoreWebView2?.Source ?? webView.Source?.ToString() ?? "";
            return FormatUrlForApi(raw);
        });
    }

    /// <summary>
    /// Click at viewport coordinates (CSS pixels from the top-left of the page). Uses CDP
    /// <c>Input.dispatchMouseEvent</c> — hits the topmost painted target, including cross-origin iframe
    /// content, without DOM access inside the frame.
    /// </summary>
    public async Task ClickAt(double x, double y, string button = "left", int clickCount = 1)
    {
        if (button is not ("left" or "right" or "middle"))
            throw new ArgumentException($"Invalid button: \"{button}\". Must be \"left\", \"right\", or \"middle\".");
        if (clickCount < 1)
            throw new ArgumentException($"clickCount must be >= 1, got {clickCount}.");

        var cdpButton = button switch { "right" => "right", "middle" => "middle", _ => "left" };
        if (cdpButton == "right")
            ActiveTab.SuppressNextContextMenu = true;

        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var pressJson = JsonSerializer.Serialize(new
            {
                type = "mousePressed", x, y, button = cdpButton, clickCount
            });
            var releaseJson = JsonSerializer.Serialize(new
            {
                type = "mouseReleased", x, y, button = cdpButton, clickCount
            });

            await webView.CoreWebView2!.CallDevToolsProtocolMethodAsync(
                "Input.dispatchMouseEvent", pressJson);
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Input.dispatchMouseEvent", releaseJson);
        });

        try { await RecordTraceStepAsync("click-at", new { x, y, button, clickCount }); }
        catch { /* best-effort */ }
    }

    public async Task<string> GetTitle()
    {
        var webView = ActiveTab.WebView;
        return await webView.Dispatcher.InvokeAsync(() =>
            webView.CoreWebView2?.DocumentTitle ?? "");
    }

    /// <summary>Capture a screenshot and save it to a file.</summary>
    public async Task Screenshot(string filePath)
    {
        filePath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            using var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write);
            await webView.CoreWebView2.CapturePreviewAsync(
                CoreWebView2CapturePreviewImageFormat.Png, stream);
        });

        Log($"Screenshot saved to: {filePath}");
    }

    /// <summary>Capture a screenshot of a specific element and save it to a file.</summary>
    public async Task ScreenshotElement(string selector, string filePath, int padding = 0)
    {
        selector = ResolveRunScriptSelector(selector);
        filePath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(selector)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(selector)}';
            var rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) return 'ERROR:Element has zero dimensions';
            // Scroll into view if element is outside the viewport
            if (rect.bottom < 0 || rect.top > window.innerHeight ||
                rect.right < 0 || rect.left > window.innerWidth) {{
                el.scrollIntoView({{behavior: 'instant', block: 'center', inline: 'center'}});
                rect = el.getBoundingClientRect();
            }}
            var clipX = Math.max(0, rect.x - {padding});
            var clipY = Math.max(0, rect.y - {padding});
            var clipW = Math.min(rect.width + {padding} * 2, window.innerWidth - clipX);
            var clipH = Math.min(rect.height + {padding} * 2, window.innerHeight - clipY);
            if (clipW <= 0 || clipH <= 0) return 'ERROR:Element is not visible in viewport';
            return JSON.stringify({{ x: clipX, y: clipY, width: clipW, height: clipH }});
        ");

        if (result.StartsWith("ERROR:"))
            throw new InvalidOperationException(result[6..]);

        using var doc = JsonDocument.Parse(result);
        var x = doc.RootElement.GetProperty("x").GetDouble();
        var y = doc.RootElement.GetProperty("y").GetDouble();
        var width = doc.RootElement.GetProperty("width").GetDouble();
        var height = doc.RootElement.GetProperty("height").GetDouble();

        var webView = ActiveTab.WebView;
        var cdpTask = await webView.Dispatcher.InvokeAsync(async () =>
        {
            var cdpParams = JsonSerializer.Serialize(new
            {
                format = "png",
                clip = new { x, y, width, height, scale = 1.0 }
            });
            return await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Page.captureScreenshot", cdpParams);
        });
        using var cdpCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var cdpResult = await cdpTask.WaitAsync(cdpCts.Token);

        using var cdpDoc = JsonDocument.Parse(cdpResult);
        var base64 = cdpDoc.RootElement.GetProperty("data").GetString();
        var imageBytes = Convert.FromBase64String(base64!);
        await File.WriteAllBytesAsync(filePath, imageBytes);

        Log($"Element screenshot saved to: {filePath}");
    }

    /// <summary>Capture a screenshot and return the PNG bytes directly.</summary>
    public async Task<byte[]> ScreenshotToBytes()
    {
        var webView = ActiveTab.WebView;
        return await await webView.Dispatcher.InvokeAsync(async () =>
        {
            using var ms = new MemoryStream();
            await webView.CoreWebView2.CapturePreviewAsync(
                CoreWebView2CapturePreviewImageFormat.Png, ms);
            return ms.ToArray();
        });
    }

    /// <summary>Capture a screenshot with specified format. JPEG quality 1-100.</summary>
    public async Task<byte[]> ScreenshotToBytes(string format, int quality = 80)
    {
        if (format != "jpeg")
            return await ScreenshotToBytes();

        var webView = ActiveTab.WebView;
        return await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var cdpParams = JsonSerializer.Serialize(new { format = "jpeg", quality });
            var result = await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Page.captureScreenshot", cdpParams);
            using var doc = JsonDocument.Parse(result);
            var base64 = doc.RootElement.GetProperty("data").GetString();
            return Convert.FromBase64String(base64!);
        });
    }

    /// <summary>Capture an element screenshot and return bytes with format/quality control.</summary>
    public async Task<byte[]> ScreenshotElementToBytes(string selector, int padding = 0,
        string format = "png", int quality = 80)
    {
        selector = ResolveRunScriptSelector(selector);
        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(selector)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(selector)}';
            var rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) return 'ERROR:Element has zero dimensions';
            // Scroll into view if element is outside the viewport
            if (rect.bottom < 0 || rect.top > window.innerHeight ||
                rect.right < 0 || rect.left > window.innerWidth) {{
                el.scrollIntoView({{behavior: 'instant', block: 'center', inline: 'center'}});
                rect = el.getBoundingClientRect();
            }}
            var clipX = Math.max(0, rect.x - {padding});
            var clipY = Math.max(0, rect.y - {padding});
            var clipW = Math.min(rect.width + {padding} * 2, window.innerWidth - clipX);
            var clipH = Math.min(rect.height + {padding} * 2, window.innerHeight - clipY);
            if (clipW <= 0 || clipH <= 0) return 'ERROR:Element is not visible in viewport';
            return JSON.stringify({{ x: clipX, y: clipY, width: clipW, height: clipH }});
        ");

        if (result.StartsWith("ERROR:"))
            throw new InvalidOperationException(result[6..]);

        using var doc = JsonDocument.Parse(result);
        var x = doc.RootElement.GetProperty("x").GetDouble();
        var y = doc.RootElement.GetProperty("y").GetDouble();
        var width = doc.RootElement.GetProperty("width").GetDouble();
        var height = doc.RootElement.GetProperty("height").GetDouble();

        var webView = ActiveTab.WebView;
        var cdpTask = await webView.Dispatcher.InvokeAsync(async () =>
        {
            object cdpObj = format == "jpeg"
                ? (object)new { format = "jpeg", quality, clip = new { x, y, width, height, scale = 1.0 } }
                : new { format = "png", clip = new { x, y, width, height, scale = 1.0 } };
            return await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Page.captureScreenshot", JsonSerializer.Serialize(cdpObj));
        });
        using var cdpCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var cdpResult = await cdpTask.WaitAsync(cdpCts.Token);

        using var cdpDoc = JsonDocument.Parse(cdpResult);
        var base64 = cdpDoc.RootElement.GetProperty("data").GetString();
        return Convert.FromBase64String(base64!);
    }

    /// <summary>Compare two screenshots pixel-by-pixel. Dispatches to UI thread for WPF imaging.</summary>
    public async Task<ImageComparer.CompareResult> CompareScreenshots(
        byte[] before, byte[] after, int threshold = 30)
    {
        var dispatcher = ActiveTab.WebView.Dispatcher;
        return await dispatcher.InvokeAsync(
            () => ImageComparer.Compare(before, after, threshold));
    }

    /// <summary>Pause script execution for the specified number of milliseconds.</summary>
    public async Task Sleep(int ms)
    {
        var remaining = ms;
        while (remaining > 0)
        {
            await CheckScriptExecutionAsync();
            var chunk = Math.Min(remaining, 100);
            await Task.Delay(chunk, ScriptCancellation);
            remaining -= chunk;
        }
    }

    /// <summary>Check if an element exists in the DOM.</summary>
    public async Task<bool> Exists(string selector) =>
        await TryResolveLocatorOnce(selector) != null;

    /// <summary>Get the number of elements matching a CSS selector.</summary>
    public async Task<int> Count(string selector)
    {
        selector = ResolveRunScriptSelector(selector);
        if (IsSemanticLocator(selector))
            return await TryResolveLocatorOnce(selector) != null ? 1 : 0;

        selector = BeginFrameScope(selector);
        var js = "(function() {\n" + BuildFramePreamble(_actionFrame.Value) + DeepQueryJs + "\n" +
                 DeepQueryAllJs + "\nreturn String(deepQueryAll(" + JsonEscape(selector) + ").length);\n})()";
        var result = await RunJs(js);
        return int.TryParse(result, out var count) ? count : 0;
    }

    /// <summary>
    /// Extract structured data from repeating page elements.
    /// Auto-detects tables (uses headers as field names) or extracts text from each match.
    /// Use field mappings to extract specific sub-elements: ("name", "h3"), ("price", ".price").
    /// Append @attr to a sub-selector to extract an attribute: ("url", "a@href"), ("src", "img@src").
    /// Use "." or "@attr" to target the container element itself.
    /// </summary>
    public async Task<List<Dictionary<string, string>>> Extract(
        string selector, params (string field, string subSelector)[] fields)
    {
        var fieldMap = fields.Length > 0
            ? fields.ToDictionary(f => f.field, f => f.subSelector)
            : null;
        return await Extract(selector, fieldMap);
    }

    /// <summary>
    /// Extract structured data from repeating page elements.
    /// If fields is null and the selector matches a table, auto-extracts using column headers.
    /// If fields is null and no table, extracts innerText of each matched element.
    /// </summary>
    public async Task<List<Dictionary<string, string>>> Extract(
        string selector, Dictionary<string, string>? fields, int limit = 0)
    {
        selector = ResolveRunScriptSelector(selector);
        var js = BuildExtractJs(selector, fields, limit);
        var jsonResult = await RunJs(js);

        if (string.IsNullOrEmpty(jsonResult) || jsonResult == "[]")
            return [];

        return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(jsonResult) ?? [];
    }

    #region Text Search (Find)

    /// <summary>
    /// Search all visible text on the page for a query string or regex pattern.
    /// Returns matches with surrounding context, nearest element selector, and position.
    /// Optionally scrolls to the Nth match and/or highlights all matches.
    /// </summary>
    public async Task<Dictionary<string, object>> FindText(
        string query, bool caseSensitive = false, bool isRegex = false,
        int? scrollTo = null, bool highlight = false, bool visibleOnly = true)
    {
        var escapedQuery = JsonEscape(query);

        var js = $$"""
            (function() {
                var query = {{escapedQuery}};
                var caseSensitive = {{(caseSensitive ? "true" : "false")}};
                var isRegex = {{(isRegex ? "true" : "false")}};
                var scrollToIndex = {{(scrollTo.HasValue ? scrollTo.Value.ToString() : "null")}};
                var doHighlight = {{(highlight ? "true" : "false")}};
                var visibleOnly = {{(visibleOnly ? "true" : "false")}};

                // Build the search regex
                var flags = caseSensitive ? 'g' : 'gi';
                var pattern;
                try {
                    pattern = isRegex ? new RegExp(query, flags) : new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags);
                } catch(e) {
                    return JSON.stringify({ error: 'Invalid regex: ' + e.message });
                }

                // Remove previous highlights
                document.querySelectorAll('.__trowser-find-highlight').forEach(function(el) {
                    var parent = el.parentNode;
                    parent.replaceChild(document.createTextNode(el.textContent), el);
                    parent.normalize();
                });

                // Check if an element or any ancestor is hidden
                function isElVisible(el) {
                    var cur = el;
                    while (cur && cur !== document.documentElement) {
                        if (cur.nodeType !== 1) break;
                        try {
                            var st = window.getComputedStyle(cur);
                            if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0')
                                return false;
                        } catch(e) { break; }
                        cur = cur.parentElement;
                    }
                    var rect = el.getBoundingClientRect();
                    if (rect.width === 0 && rect.height === 0) return false;
                    return true;
                }

                // Walk text nodes, optionally filtering to visible only
                var matches = [];
                var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
                    acceptNode: function(node) {
                        var el = node.parentElement;
                        if (!el) return NodeFilter.FILTER_REJECT;
                        var tag = el.tagName;
                        if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;
                        if (visibleOnly && !isElVisible(el)) return NodeFilter.FILTER_REJECT;
                        return NodeFilter.FILTER_ACCEPT;
                    }
                });

                function getSelector(el) {
                    if (!el || el === document.body) return 'body';
                    if (el.id) {
                        try {
                            var escaped = CSS.escape(el.id);
                            if (document.querySelectorAll('#' + escaped).length === 1) return '#' + escaped;
                        } catch(e) {}
                    }
                    var testId = el.getAttribute('data-testid');
                    if (testId) return '[data-testid="' + testId.replace(/"/g, '\\"') + '"]';
                    var parts = [];
                    var cur = el;
                    while (cur && cur !== document.body && cur.nodeType === 1 && parts.length < 5) {
                        if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
                        var tag = cur.tagName.toLowerCase();
                        var parent = cur.parentElement;
                        if (parent) {
                            var siblings = Array.from(parent.children).filter(function(c) { return c.tagName === cur.tagName; });
                            if (siblings.length > 1) tag += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
                        }
                        parts.unshift(tag);
                        cur = cur.parentElement;
                    }
                    return parts.join(' > ');
                }

                var node;
                while (node = walker.nextNode()) {
                    var text = node.textContent;
                    var m;
                    pattern.lastIndex = 0;
                    while ((m = pattern.exec(text)) !== null) {
                        var el = node.parentElement;
                        var fullText = text;
                        var start = Math.max(0, m.index - 50);
                        var end = Math.min(fullText.length, m.index + m[0].length + 50);
                        var context = (start > 0 ? '...' : '') + fullText.substring(start, end) + (end < fullText.length ? '...' : '');

                        var rect = null;
                        try {
                            var range = document.createRange();
                            range.setStart(node, m.index);
                            range.setEnd(node, m.index + m[0].length);
                            var r = range.getBoundingClientRect();
                            rect = { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) };
                        } catch(e) {}

                        matches.push({
                            index: matches.length,
                            text: m[0],
                            matchText: m[0],
                            context: context,
                            selector: getSelector(el),
                            tag: el ? el.tagName.toLowerCase() : '',
                            rect: rect
                        });

                        if (!isRegex) break; // for literal search, only one match per text node
                    }
                }

                // Scroll to Nth match
                if (scrollToIndex !== null && scrollToIndex >= 0 && scrollToIndex < matches.length) {
                    var target = matches[scrollToIndex];
                    try {
                        var el = document.querySelector(target.selector);
                        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    } catch(e) {}
                }

                // Highlight all matches
                if (doHighlight && matches.length > 0) {
                    // Re-walk and wrap matches in <mark> elements
                    var walker2 = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
                        acceptNode: function(node) {
                            var el = node.parentElement;
                            if (!el) return NodeFilter.FILTER_REJECT;
                            var tag = el.tagName;
                            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;
                            if (el.classList && el.classList.contains('__trowser-find-highlight')) return NodeFilter.FILTER_REJECT;
                            try {
                                var style = window.getComputedStyle(el);
                                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0')
                                    return NodeFilter.FILTER_REJECT;
                            } catch(e) {}
                            return NodeFilter.FILTER_ACCEPT;
                        }
                    });
                    var textNodes = [];
                    var n2;
                    while (n2 = walker2.nextNode()) textNodes.push(n2);

                    var highlightPattern = caseSensitive ? new RegExp(isRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')
                        : new RegExp(isRegex ? query : query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');

                    textNodes.forEach(function(tn) {
                        var text = tn.textContent;
                        highlightPattern.lastIndex = 0;
                        if (!highlightPattern.test(text)) return;
                        highlightPattern.lastIndex = 0;

                        var frag = document.createDocumentFragment();
                        var lastIdx = 0;
                        var hm;
                        while ((hm = highlightPattern.exec(text)) !== null) {
                            if (hm.index > lastIdx) frag.appendChild(document.createTextNode(text.substring(lastIdx, hm.index)));
                            var mark = document.createElement('mark');
                            mark.className = '__trowser-find-highlight';
                            mark.style.backgroundColor = '#ffeb3b';
                            mark.style.color = '#000';
                            mark.textContent = hm[0];
                            frag.appendChild(mark);
                            lastIdx = hm.index + hm[0].length;
                        }
                        if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.substring(lastIdx)));
                        tn.parentNode.replaceChild(frag, tn);
                    });
                }

                return JSON.stringify({ matchCount: matches.length, matches: matches.slice(0, 100) });
            })()
            """;

        var resultJson = await RunJs(js);
        if (string.IsNullOrEmpty(resultJson))
            return new Dictionary<string, object> { ["matchCount"] = 0, ["matches"] = new List<object>() };

        try
        {
            var result = JsonSerializer.Deserialize<Dictionary<string, object>>(resultJson);
            if (result != null && result.ContainsKey("error"))
                throw new InvalidOperationException(result["error"]?.ToString() ?? "Find failed");
            return result ?? new Dictionary<string, object> { ["matchCount"] = 0, ["matches"] = new List<object>() };
        }
        catch (JsonException)
        {
            return new Dictionary<string, object> { ["matchCount"] = 0, ["matches"] = new List<object>() };
        }
    }

    /// <summary>
    /// Remove all text search highlights previously added by FindText with highlight=true.
    /// </summary>
    public async Task ClearFindHighlights()
    {
        await RunJs("""
            (function() {
                document.querySelectorAll('.__trowser-find-highlight').forEach(function(el) {
                    var parent = el.parentNode;
                    parent.replaceChild(document.createTextNode(el.textContent), el);
                    parent.normalize();
                });
            })()
            """);
    }

    #endregion

    #region WebMCP Tool Discovery

    /// <summary>
    /// Detect and return all WebMCP tools registered on the current page via navigator.modelContext.
    /// Returns tool definitions with name, description, inputSchema, and annotations.
    /// </summary>
    public async Task<List<Dictionary<string, object>>> GetWebMcpTools()
    {
        var js = """
            (function() {
                var result = [];
                var seen = {};
                function add(t) {
                    if (!t || !t.name || seen[t.name]) return;
                    seen[t.name] = true;
                    result.push({
                        name: t.name,
                        description: t.description || '',
                        inputSchema: t.inputSchema || {},
                        annotations: t.annotations || null
                    });
                }
                function addMap(map) {
                    if (map && typeof map.forEach === 'function')
                        map.forEach(function(v) { add(v); });
                }
                var wm = window.__trowserWebMcp;
                if (wm && wm.tools) {
                    for (var k in wm.tools) add(wm.tools[k]);
                }
                var mc = navigator.modelContext;
                if (mc) {
                    addMap(mc.dynamicTools);
                    addMap(mc.provideContextTools);
                }
                return JSON.stringify(result);
            })()
            """;
        var jsonResult = await RunJs(js);

        if (string.IsNullOrEmpty(jsonResult) || jsonResult == "[]")
            return [];

        return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(jsonResult) ?? [];
    }

    /// <summary>
    /// Call a WebMCP tool registered on the current page.
    /// The tool's execute function is invoked with the given arguments and the result is returned.
    /// Arguments are passed as a raw JSON string to preserve types (numbers, booleans, nested objects).
    /// </summary>
    public async Task<Dictionary<string, object>> CallWebMcpTool(string toolName, string? argumentsJson = null)
    {
        var argsJson = argumentsJson ?? "{}";

        var nameJs = JsonEscape(toolName);
        var asyncExpr =
            "(function(){" +
            "var name=" + nameJs + ";" +
            "var exec=null;" +
            "var wm=window.__trowserWebMcp;" +
            "if(wm&&wm.tools&&wm.tools[name]&&typeof wm.tools[name]._exec==='function')" +
            "  exec=wm.tools[name]._exec;" +
            "if(!exec){" +
            "  var mc=navigator.modelContext;" +
            "  if(mc){" +
            "    var t=(mc.dynamicTools&&mc.dynamicTools.get(name))||" +
            "          (mc.provideContextTools&&mc.provideContextTools.get(name));" +
            "    if(t&&typeof t.execute==='function')exec=t.execute;" +
            "  }" +
            "}" +
            "if(!exec)return JSON.stringify({error:'WebMCP tool not found: '+name});" +
            "return exec(" + argsJson + ").then(function(r){" +
            "  return JSON.stringify({success:true,result:r});" +
            "},function(e){" +
            "  return JSON.stringify({error:e.message||String(e)});" +
            "});" +
            "})()";

        string jsonResult;
        try
        {
            jsonResult = await RunJsAsync(asyncExpr);
        }
        catch (InvalidOperationException ex)
        {
            return new Dictionary<string, object> { ["error"] = ex.Message };
        }

        if (string.IsNullOrEmpty(jsonResult))
            return new Dictionary<string, object> { ["error"] = "No response from tool" };

        return JsonSerializer.Deserialize<Dictionary<string, object>>(jsonResult)
            ?? new Dictionary<string, object> { ["error"] = "Failed to parse tool response" };
    }

    #endregion

    /// <summary>
    /// Hover over an element. Auto-waits for the element to be visible.
    /// Uses CDP Input.dispatchMouseEvent to trigger CSS :hover pseudo-class.
    /// </summary>
    public async Task Hover(string selector, int? timeoutMs = null)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: false, checkObscured: true);

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            return JSON.stringify(pageCenter(el));
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }

        try
        {
            using var doc = JsonDocument.Parse(result);
            var x = doc.RootElement.GetProperty("x").GetDouble();
            var y = doc.RootElement.GetProperty("y").GetDouble();

            var webView = ActiveTab.WebView;
            await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var moveJson = JsonSerializer.Serialize(new { type = "mouseMoved", x, y });
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                    "Input.dispatchMouseEvent", moveJson);
            });
        }
        catch (JsonException)
        {
            // Fallback: if coordinate parsing fails, dispatch JS events
            var fallbackJs = WrapWithDeepQuery($@"
                var el = deepQuery({JsonEscape(resolved)});
                if (el) {{
                    el.dispatchEvent(new MouseEvent('mouseenter', {{ bubbles: true, cancelable: true }}));
                    el.dispatchEvent(new MouseEvent('mouseover', {{ bubbles: true, cancelable: true }}));
                }}
                return 'OK';
            ");
            await RunJs(fallbackJs);
        }

        try { await RecordTraceStepAsync("hover", new { selector }); }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Simulate a keyboard key press.
    /// </summary>
    public async Task PressKey(string key, string? selector = null, string[]? modifiers = null, int? timeoutMs = null)
    {
        modifiers ??= Array.Empty<string>();
        var shift = modifiers.Any(m => m.Equals("Shift", StringComparison.OrdinalIgnoreCase));
        var ctrl = modifiers.Any(m => m.Equals("Control", StringComparison.OrdinalIgnoreCase)
                                   || m.Equals("Ctrl", StringComparison.OrdinalIgnoreCase));
        var alt = modifiers.Any(m => m.Equals("Alt", StringComparison.OrdinalIgnoreCase));
        var meta = modifiers.Any(m => m.Equals("Meta", StringComparison.OrdinalIgnoreCase));

        var (code, keyCode) = ResolveKeyCode(key);

        string resolvedSelector = selector != null
            ? await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
                requireVisible: true, requireEnabled: true)
            : null!;

        string targetExpr = selector != null
            ? $"deepQuery({JsonEscape(resolvedSelector)})"
            : "(document.activeElement || document.body)";

        var result = await RunDeepQueryJsAsync($@"
            var target = {targetExpr};
            if (!target) return 'ERROR:Element not found: {EscapeForJs(selector ?? "(active element)")}';
            var props = {{
                key: {JsonEscape(key)},
                code: {JsonEscape(code)},
                keyCode: {keyCode},
                which: {keyCode},
                bubbles: true,
                cancelable: true,
                shiftKey: {(shift ? "true" : "false")},
                ctrlKey: {(ctrl ? "true" : "false")},
                altKey: {(alt ? "true" : "false")},
                metaKey: {(meta ? "true" : "false")}
            }};
            var pressedKey = {JsonEscape(key)};
            var downEvt = new KeyboardEvent('keydown', props);
            var cancelled = !target.dispatchEvent(downEvt);
            if (!cancelled && (pressedKey.length === 1 || pressedKey === 'Enter')) {{
                target.dispatchEvent(new KeyboardEvent('keypress', props));
            }}
            target.dispatchEvent(new KeyboardEvent('keyup', props));

            if (pressedKey === 'Enter' && !cancelled) {{
                var tag = target.tagName;
                if (tag === 'BUTTON' || tag === 'A' ||
                    (tag === 'INPUT' && (target.type === 'submit' || target.type === 'button' || target.type === 'image'))) {{
                    target.click();
                }} else if (tag === 'INPUT' || tag === 'SELECT') {{
                    var form = target.closest('form');
                    if (form) {{
                        var submitBtn = form.querySelector('input[type=""submit""], button[type=""submit""], button:not([type])');
                        if (submitBtn) submitBtn.click();
                        else if (form.requestSubmit) form.requestSubmit();
                        else form.submit();
                    }}
                }}
            }}

            if ((pressedKey === ' ' || pressedKey === 'Space') && !cancelled) {{
                var tag = target.tagName;
                if (tag === 'BUTTON' ||
                    (tag === 'INPUT' && (target.type === 'submit' || target.type === 'button'))) {{
                    target.click();
                }} else if (tag === 'INPUT' && (target.type === 'checkbox' || target.type === 'radio')) {{
                    target.click();
                }} else if (tag === 'DETAILS') {{
                    var summary = target.querySelector('summary');
                    if (summary) summary.click();
                }}
            }}

            if (pressedKey === 'Tab' && !cancelled) {{
                var sel = 'a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=""-1""])';
                function collectFocusable(root) {{
                    var results = Array.from(root.querySelectorAll(sel));
                    var all = root.querySelectorAll('*');
                    for (var i = 0; i < all.length; i++) {{
                        if (all[i].shadowRoot) {{
                            results = results.concat(collectFocusable(all[i].shadowRoot));
                        }}
                    }}
                    return results;
                }}
                var focusable = collectFocusable(document).filter(function(el) {{
                    if (el.offsetParent !== null) return true;
                    var r = el.getBoundingClientRect();
                    return r.width > 0 && r.height > 0;
                }});
                focusable.sort(function(a, b) {{
                    var ti_a = parseInt(a.getAttribute('tabindex') || '0', 10);
                    var ti_b = parseInt(b.getAttribute('tabindex') || '0', 10);
                    if (ti_a !== ti_b) {{
                        if (ti_a > 0 && ti_b > 0) return ti_a - ti_b;
                        if (ti_a > 0) return -1;
                        if (ti_b > 0) return 1;
                    }}
                    var pos = a.compareDocumentPosition ? a.compareDocumentPosition(b) : 0;
                    if (pos & 4) return -1;
                    if (pos & 2) return 1;
                    return 0;
                }});
                var idx = focusable.indexOf(target);
                var nextIdx = {(shift ? "true" : "false")}
                    ? (idx <= 0 ? focusable.length - 1 : idx - 1)
                    : (idx < 0 ? 0 : (idx + 1) % focusable.length);
                var next = focusable[nextIdx];
                if (next) next.focus();
            }}
            return 'OK';
        ");

        if (result.StartsWith("ERROR:"))
            throw new InvalidOperationException(result[6..]);
    }

    private static (string code, int keyCode) ResolveKeyCode(string key)
    {
        return key.ToLower() switch
        {
            "tab" => ("Tab", 9),
            "enter" => ("Enter", 13),
            "escape" or "esc" => ("Escape", 27),
            "space" or " " => ("Space", 32),
            "backspace" => ("Backspace", 8),
            "delete" => ("Delete", 46),
            "arrowup" or "up" => ("ArrowUp", 38),
            "arrowdown" or "down" => ("ArrowDown", 40),
            "arrowleft" or "left" => ("ArrowLeft", 37),
            "arrowright" or "right" => ("ArrowRight", 39),
            "home" => ("Home", 36),
            "end" => ("End", 35),
            "pageup" => ("PageUp", 33),
            "pagedown" => ("PageDown", 34),
            "insert" => ("Insert", 45),
            "f1" => ("F1", 112), "f2" => ("F2", 113), "f3" => ("F3", 114), "f4" => ("F4", 115),
            "f5" => ("F5", 116), "f6" => ("F6", 117), "f7" => ("F7", 118), "f8" => ("F8", 119),
            "f9" => ("F9", 120), "f10" => ("F10", 121), "f11" => ("F11", 122), "f12" => ("F12", 123),
            _ when key.Length == 1 && char.IsLetter(key[0]) => ($"Key{char.ToUpper(key[0])}", char.ToUpper(key[0])),
            _ when key.Length == 1 && char.IsDigit(key[0]) => ($"Digit{key[0]}", key[0]),
            _ => (key, 0)
        };
    }

    /// <summary>Scroll the page or a specific element.</summary>
    public async Task Scroll(string? selector = null, string direction = "down", bool scrollIntoView = false, int? timeoutMs = null, double? x = null, double? y = null)
    {
        using var cts = new CancellationTokenSource(timeoutMs ?? 10_000);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, ScriptCancellation, OperationCancellation);

        string js;
        if (x.HasValue || y.HasValue)
        {
            var left = (x ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var top = (y ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!string.IsNullOrEmpty(selector))
            {
                var leftExpr = x.HasValue ? left : "target.scrollLeft";
                var topExpr = y.HasValue ? top : "target.scrollTop";
                js = WrapWithDeepQuery($@"
                    var target = deepQuery({JsonEscape(selector)});
                    if (!target) return 'ERROR:Element not found: {EscapeForJs(selector)}';
                    target.scrollTo({leftExpr}, {topExpr});
                    return 'OK';
                ");
            }
            else
            {
                var leftExpr = x.HasValue ? left : "(window.scrollX || window.pageXOffset || 0)";
                var topExpr = y.HasValue ? top : "(window.scrollY || window.pageYOffset || 0)";
                js = $@"
                    (function() {{
                        window.scrollTo({leftExpr}, {topExpr});
                        return 'OK';
                    }})()";
            }
        }
        else if (scrollIntoView && !string.IsNullOrEmpty(selector))
        {
            js = WrapWithDeepQuery($@"
                var el = deepQuery({JsonEscape(selector)});
                if (!el) return 'ERROR:Element not found: {EscapeForJs(selector)}';
                el.scrollIntoView({{ behavior: 'instant', block: 'center' }});
                return 'OK';
            ");
        }
        else if (!string.IsNullOrEmpty(selector))
        {
            js = WrapWithDeepQuery($@"
                var target = deepQuery({JsonEscape(selector)});
                if (!target) return 'ERROR:Element not found: {EscapeForJs(selector)}';
                var h = target.clientHeight;
                var dir = {JsonEscape(direction)};
                if (dir === 'down') target.scrollBy(0, h);
                else if (dir === 'up') target.scrollBy(0, -h);
                else if (dir === 'top') target.scrollTo(0, 0);
                else if (dir === 'bottom') target.scrollTo(0, target.scrollHeight);
                return 'OK';
            ");
        }
        else
        {
            js = $@"
                (function() {{
                    var target = null;
                    var docEl = document.documentElement;
                    if (docEl.scrollHeight > docEl.clientHeight + 10) {{
                        target = window;
                    }} else {{
                        var candidates = document.querySelectorAll('main, [role=""main""], .main-content, .content');
                        for (var i = 0; i < candidates.length; i++) {{
                            if (candidates[i].scrollHeight > candidates[i].clientHeight + 10) {{
                                target = candidates[i];
                                break;
                            }}
                        }}
                        if (!target) {{
                            var all = document.querySelectorAll('div, section, article, aside, nav');
                            for (var i = 0; i < all.length; i++) {{
                                var style = window.getComputedStyle(all[i]);
                                var ov = style.overflowY;
                                if ((ov === 'auto' || ov === 'scroll') && all[i].scrollHeight > all[i].clientHeight + 10) {{
                                    target = all[i];
                                    break;
                                }}
                            }}
                        }}
                        if (!target) target = window;
                    }}
                    var h = target === window ? window.innerHeight : target.clientHeight;
                    var dir = {JsonEscape(direction)};
                    if (dir === 'down') target.scrollBy(0, h);
                    else if (dir === 'up') target.scrollBy(0, -h);
                    else if (dir === 'top') target.scrollTo(0, 0);
                    else if (dir === 'bottom') target.scrollTo(0, target === window ? document.body.scrollHeight : target.scrollHeight);
                    return 'OK';
                }})()";
        }

        try
        {
            var result = await RunJs(js).WaitAsync(linked.Token);
            if (result.StartsWith("ERROR:"))
            {
                throw new InvalidOperationException(result[6..]);
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !ScriptCancellation.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Scroll operation timed out after {timeoutMs ?? 10_000}ms. " +
                "The page may be unresponsive or a dialog may be blocking interaction.");
        }

        try { await RecordTraceStepAsync("scroll", new { selector, direction, scrollIntoView, x, y }); }
        catch { /* best-effort */ }
    }

    /// <summary>Wait for a navigation event to complete.</summary>
    public async Task<bool> WaitForNavigation(int timeoutMs = 10000)
    {
        var webView = ActiveTab.WebView;
        var tcs = new TaskCompletionSource<bool>();

        void handler(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            webView.CoreWebView2.NavigationCompleted -= handler;
            tcs.TrySetResult(true);
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.NavigationCompleted += handler;
        });

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation);
        timeoutCts.CancelAfter(timeoutMs);

        try
        {
            await tcs.Task.WaitAsync(timeoutCts.Token);
            return true;
        }
        catch (OperationCanceledException)
        {
            await webView.Dispatcher.InvokeAsync(() =>
                webView.CoreWebView2.NavigationCompleted -= handler);

            if (ScriptCancellation.IsCancellationRequested)
                throw;

            return false;
        }
    }

    /// <summary>
    /// Wait for a chain of navigations to settle. After each navigation completes,
    /// waits for quietPeriodMs of no new navigations before returning.
    /// Handles redirect chains, auto-submitting forms (SAML/OAuth), and multi-step SSO flows.
    /// Returns the number of navigations observed.
    /// </summary>
    public async Task<int> WaitForFinalNavigation(int quietPeriodMs = 500, int timeoutMs = 15000)
    {
        var webView = ActiveTab.WebView;
        var navCount = 0;
        var lastNavTime = DateTime.UtcNow;
        var tcs = new TaskCompletionSource<bool>();

        void handler(object? s, CoreWebView2NavigationCompletedEventArgs e)
        {
            navCount++;
            lastNavTime = DateTime.UtcNow;
        }

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.NavigationCompleted += handler;
        });

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation);
        timeoutCts.CancelAfter(timeoutMs);

        try
        {
            while (!timeoutCts.Token.IsCancellationRequested)
            {
                await Task.Delay(Math.Min(quietPeriodMs / 2, 250), timeoutCts.Token);

                var elapsed = (DateTime.UtcNow - lastNavTime).TotalMilliseconds;
                if (navCount > 0 && elapsed >= quietPeriodMs)
                    break;
            }
        }
        catch (OperationCanceledException) when (!ScriptCancellation.IsCancellationRequested)
        {
            // Overall timeout — return what we have
        }
        finally
        {
            await webView.Dispatcher.InvokeAsync(() =>
                webView.CoreWebView2.NavigationCompleted -= handler);
        }

        if (ScriptCancellation.IsCancellationRequested)
            throw new OperationCanceledException();

        return navCount;
    }

    /// <summary>Select an option in a dropdown by its value.</summary>
    public async Task Select(string selector, string value, string? label = null, int? timeoutMs = null)
    {
        var resolved = await WaitForActionable(selector, timeoutMs ?? DefaultActionTimeout,
            requireVisible: true, requireEnabled: true, checkObscured: true);

        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(resolved)});
            if (!el) return 'ERROR:Element not found: {EscapeForJs(resolved)}';
            if (el.tagName !== 'SELECT') return 'ERROR:Element is not a select: ' + el.tagName;
            var wantVal = {JsonEscape(value ?? "")};
            var wantLabel = {JsonEscape(label ?? "")};
            var opts = Array.from(el.options || []);
            var match = null;
            if (wantVal) {{
                match = opts.find(function(o) {{ return o.value === wantVal; }});
                if (!match) {{
                    var partial = opts.filter(function(o) {{ return o.value === wantVal || o.text.trim() === wantVal; }});
                    if (partial.length === 1) match = partial[0];
                }}
            }}
            if (!match && wantLabel) {{
                match = opts.find(function(o) {{ return o.text.trim() === wantLabel; }});
                if (!match) {{
                    var lp = opts.filter(function(o) {{ return o.text.trim().indexOf(wantLabel) >= 0; }});
                    if (lp.length === 1) match = lp[0];
                }}
            }}
            if (!match) {{
                var listed = opts.map(function(o) {{ return o.value + ' (' + o.text.trim() + ')'; }}).join(', ');
                var msg = 'ERROR:No matching option';
                if (wantVal) msg += ' for value ' + wantVal;
                if (wantLabel) msg += ' for label ' + wantLabel;
                return msg + '; options: ' + listed;
            }}
            var nativeSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set;
            if (nativeSetter) {{
                nativeSetter.call(el, match.value);
            }} else {{
                el.value = match.value;
            }}
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            if (el.value !== match.value) return 'ERROR:Select did not apply; actual value is ' + (el.value || '(empty)');
            return 'OK:' + match.value;
        ");

        if (result.StartsWith("ERROR:"))
        {
            throw new InvalidOperationException(result[6..]);
        }

        try { await RecordTraceStepAsync("select", new { selector, value, label }); }
        catch { /* best-effort */ }
    }

    /// <summary>Read back the actual DOM state of a select/input element.</summary>
    public async Task<Dictionary<string, object>> GetSelectState(string selector)
    {
        var result = await RunDeepQueryJsAsync($@"
            var el = deepQuery({JsonEscape(selector)});
            if (!el) return JSON.stringify({{value:'',selectedIndex:-1,selectedText:'',tagName:''}});
            var idx = typeof el.selectedIndex === 'number' ? el.selectedIndex : -1;
            var txt = el.options && idx >= 0 ? (el.options[idx].text || '') : '';
            return JSON.stringify({{
                value: el.value || '',
                selectedIndex: idx,
                selectedText: txt,
                tagName: el.tagName.toLowerCase()
            }});
        ");

        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, object>>(result) ?? new();
        }
        catch
        {
            return new() { ["value"] = result, ["selectedIndex"] = -1, ["selectedText"] = "", ["tagName"] = "" };
        }
    }

    /// <summary>Summary of <c>document.activeElement</c> for API responses (keyboard focus diagnostics).</summary>
    public async Task<Dictionary<string, object>> GetActiveElementSummary()
    {
        const string js = """
            (function() {
                var ae = document.activeElement || document.body;
                if (!ae) return JSON.stringify({ tag: 'unknown', description: '(none)' });
                var tag = (ae.tagName || '').toLowerCase() || 'unknown';
                var id = ae.id || '';
                var name = ae.name || ae.getAttribute('name') || '';
                var role = ae.getAttribute('role') || '';
                var type = ae.type || '';
                var desc = tag;
                if (id) desc += '#' + id;
                else if (name) desc += '[name=' + name + ']';
                else if (tag === 'body') desc = 'body';
                return JSON.stringify({
                    tag: tag,
                    id: id,
                    name: name,
                    role: role,
                    type: type,
                    description: desc
                });
            })()
            """;
        var json = await RunJs(js);
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, object>>(json)
                   ?? new Dictionary<string, object> { ["description"] = json };
        }
        catch
        {
            return new Dictionary<string, object> { ["description"] = json };
        }
    }

    /// <summary>Look up a CSS selector by ref index from the active tab's ref cache.</summary>
    public string? GetSelectorByRef(int refIndex)
    {
        return ActiveTab.GetSelectorByRef(refIndex);
    }

    /// <summary>Frame id for a ref from the last interactive scan (null = main frame).</summary>
    public string? GetFrameIdByRef(int refIndex)
    {
        return ActiveTab.GetFrameIdByRef(refIndex);
    }

    /// <summary>
    /// Apply an optional frame scope to a selector/locator (used by REST/MCP <c>frame</c> field).
    /// </summary>
    public static string ApplyFrame(string selectorOrLocator, string? frame)
    {
        if (string.IsNullOrWhiteSpace(frame))
            return selectorOrLocator;
        return ByFrame(frame, selectorOrLocator);
    }

    #endregion
}
