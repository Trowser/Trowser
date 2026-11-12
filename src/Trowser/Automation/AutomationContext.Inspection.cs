using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
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
    #region LLM Integration

    /// <summary>
    /// Get a comprehensive snapshot of the current page state, designed for LLM consumption.
    /// Pass <paramref name="frame"/> to collect interactive refs inside that iframe (including inspectable cross-origin frames).
    /// </summary>
    public async Task<Dictionary<string, object>> GetSnapshot(bool fullText = false, string? textSelector = null, string? frame = null)
    {
        var url = await GetCurrentUrl();
        var title = await GetTitle();
        string? parentUrl = null;
        string? parentTitle = null;
        var readyState = await ExecuteJs("document.readyState");
        var frames = await GetFrames();
        var interactive = await GetInteractiveElements(frame);
        List<Dictionary<string, string>> images = string.IsNullOrEmpty(frame)
            ? await GetImages()
            : new List<Dictionary<string, string>>();

        List<Dictionary<string, string>> headings;
        string visibleText;

        if (!string.IsNullOrEmpty(frame))
        {
            headings = await GetHeadingsInFrame(frame);
            visibleText = await GetPageTextInFrame(frame, fullText);
        }
        else if (!string.IsNullOrEmpty(textSelector))
        {
            headings = await GetHeadings();
            var escapedSel = JsonEscape(textSelector);
            visibleText = fullText
                ? await ExecuteJs($"(function(){{ var el = document.querySelector({escapedSel}); return el ? el.innerText || '' : ''; }})()")
                : await ExecuteJs($"(function(){{ var el = document.querySelector({escapedSel}); return el ? (el.innerText || '').substring(0, 3000) : ''; }})()");
        }
        else
        {
            headings = await GetHeadings();
            var text = await GetPageText();
            visibleText = fullText ? text : text.Length > 3000 ? text[..3000] : text;
        }

        var pageMetaJson = await ExecuteJs("""
            (function() {
                var html = document.documentElement;
                var metas = Array.from(document.querySelectorAll('meta'));
                return JSON.stringify({
                    lang: html.getAttribute('lang') || '',
                    charset: document.characterSet || '',
                    viewport: (metas.find(function(m){ return m.name === 'viewport'; }) || {}).content || '',
                    description: (metas.find(function(m){ return m.name === 'description'; }) || {}).content || '',
                    doctype: document.doctype ? '<!DOCTYPE ' + document.doctype.name + '>' : ''
                });
            })()
            """);

        var consoleErrors = Console.GetErrors();
        var networkErrors = Network.FindErrors();

        var pageKind = CertificateInterstitialActive ||
                       title.Contains("certificate", StringComparison.OrdinalIgnoreCase) ||
                       title.Contains("privacy error", StringComparison.OrdinalIgnoreCase)
            ? "certificate-error"
            : "document";

        var snapshot = new Dictionary<string, object>
        {
            ["url"] = url,
            ["title"] = title,
            ["pageKind"] = pageKind,
            ["readyState"] = readyState,
            ["pageText"] = !fullText && visibleText.Length >= 3000
                ? visibleText[..3000] + "..."
                : visibleText,
            ["headings"] = headings,
            ["frames"] = frames,
            ["interactiveElements"] = interactive,
            ["imageSummary"] = new Dictionary<string, object>
            {
                ["total"] = images.Count,
                // GetImages() sets hasAlt via JS String(hasAttribute) → "true"/"false" (lowercase), not .NET "True"/"False".
                ["missingAlt"] = images.Count(i =>
                {
                    if (!i.TryGetValue("hasAlt", out var v)) return true;
                    return !(bool.TryParse(v, out var hasAlt) && hasAlt);
                })
            },
            ["consoleErrors"] = consoleErrors
                .TakeLast(20)
                .Select(e => new Dictionary<string, object>
                {
                    ["level"] = e.Level.ToString().ToLower(),
                    ["message"] = e.Message
                }).ToList(),
            ["networkErrors"] = networkErrors
                .TakeLast(20)
                .Select(e => new Dictionary<string, object>
                {
                    ["method"] = e.Method,
                    ["url"] = e.Url,
                    ["statusCode"] = e.StatusCode
                }).ToList(),
            ["assertionSummary"] = new Dictionary<string, object>
            {
                ["passed"] = Assert.PassCount,
                ["failed"] = Assert.FailCount,
                ["total"] = Assert.TotalCount
            }
        };

        if (!string.IsNullOrEmpty(frame))
        {
            snapshot["frame"] = frame;
            parentUrl = url;
            parentTitle = title;
            snapshot["parentUrl"] = parentUrl;
            snapshot["parentTitle"] = parentTitle;

            try
            {
                var frameUrl = await ExecuteJsInFrame(frame, "location.href");
                var frameTitle = await ExecuteJsInFrame(frame, "document.title");
                snapshot["frameUrl"] = UnwrapJsStringResult(frameUrl);
                snapshot["frameTitle"] = UnwrapJsStringResult(frameTitle);
            }
            catch
            {
                snapshot["frameUrl"] = "";
                snapshot["frameTitle"] = "";
            }

            var inspectable = await TryResolveInspectableFrameEntryAsync(frame) != null;
            var sameOrigin = frames.FirstOrDefault(f =>
            {
                var fid = f.TryGetValue("frameId", out var a) ? a?.ToString() : null;
                var name = f.TryGetValue("name", out var b) ? b?.ToString() : null;
                return string.Equals(fid, frame, StringComparison.OrdinalIgnoreCase)
                       || string.Equals(name, frame, StringComparison.OrdinalIgnoreCase);
            });
            var isSameOrigin = sameOrigin != null
                               && sameOrigin.TryGetValue("sameOrigin", out var so)
                               && so is bool bso
                               && bso;
            snapshot["refsActionable"] = isSameOrigin || inspectable;
            if (!((bool)snapshot["refsActionable"]))
            {
                snapshot["interactionHint"] =
                    "Refs in this frame are not actionable via click/ref. Use POST /api/click-at, navigate the app URL in its own tab, or POST /api/execute-js with frame.";
            }
        }

        // Include page metadata (lang, charset, viewport, etc.)
        try
        {
            if (!string.IsNullOrEmpty(pageMetaJson))
            {
                var meta = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(pageMetaJson);
                if (meta != null) snapshot["pageMeta"] = meta;
            }
        }
        catch (Exception ex) { TrowserLog.Warn($"Page metadata parse failed: {ex.Message}"); }

        // Include viewport info (frame document when snapshot is frame-scoped)
        if (!string.IsNullOrEmpty(frame))
        {
            var (fw, fh) = await GetViewportSizeInFrame(frame);
            snapshot["viewport"] = new Dictionary<string, object>
            {
                ["width"] = fw,
                ["height"] = fh,
                ["coordinateSpace"] = "frame",
                ["isOverridden"] = _viewportOverride.HasValue
            };
            var (pw, ph) = await GetViewportSize();
            snapshot["parentViewport"] = new Dictionary<string, object>
            {
                ["width"] = pw,
                ["height"] = ph,
                ["coordinateSpace"] = "top"
            };
        }
        else
        {
            var (vw, vh) = await GetViewportSize();
            snapshot["viewport"] = new Dictionary<string, object>
            {
                ["width"] = vw,
                ["height"] = vh,
                ["coordinateSpace"] = "top",
                ["isOverridden"] = _viewportOverride.HasValue
            };
        }

        // Include WebMCP tools if any detected
        var webMcpTools = await GetWebMcpTools();
        if (webMcpTools.Count > 0)
        {
            snapshot["webMcpTools"] = webMcpTools.Select(t => new Dictionary<string, object>
            {
                ["name"] = t.GetValueOrDefault("name", ""),
                ["description"] = t.GetValueOrDefault("description", "")
            }).ToList();
        }

        // Include tab info when multiple tabs are open
        if (_tabs.Count > 1)
        {
            snapshot["activeTab"] = _activeTabIndex;
            snapshot["tabCount"] = _tabs.Count;
        }

        return snapshot;
    }

    /// <summary>
    /// Given a CSS container selector and the already-collected interactive elements list,
    /// returns the set of ref numbers for elements that are descendants of the container.
    /// </summary>
    public async Task<HashSet<int>> GetRefsInContainer(string containerSelector, List<Dictionary<string, object>> elements)
    {
        var selectorsByRef = new List<(int refNum, string selector)>();
        foreach (var el in elements)
        {
            if (!el.TryGetValue("ref", out var refObj) || !el.TryGetValue("selector", out var selObj))
                continue;

            int refVal = refObj is JsonElement je ? je.GetInt32() : Convert.ToInt32(refObj);
            var sel = selObj?.ToString();
            if (refVal >= 0 && !string.IsNullOrEmpty(sel) && !sel.Contains(">>>"))
                selectorsByRef.Add((refVal, sel));
        }

        if (selectorsByRef.Count == 0)
            return new HashSet<int>();

        var escapedContainer = JsonEscape(containerSelector);
        var selectorsJson = JsonSerializer.Serialize(selectorsByRef.Select(s => s.selector).ToArray());

        var js = "(function(){" +
            "var containers=document.querySelectorAll(" + escapedContainer + ");" +
            "if(!containers.length)return '[]';" +
            "var selectors=" + selectorsJson + ";" +
            "var result=[];" +
            "for(var i=0;i<selectors.length;i++){" +
            "try{var el=document.querySelector(selectors[i]);" +
            "if(!el)continue;" +
            "for(var j=0;j<containers.length;j++){" +
            "if(containers[j].contains(el)){result.push(i);break;}" +
            "}}catch(e){}}" +
            "return JSON.stringify(result);})()";


        var resultJson = await RunJs(js);
        var matchingRefs = new HashSet<int>();
        try
        {
            var indices = JsonSerializer.Deserialize<int[]>(resultJson);
            if (indices != null)
                foreach (var idx in indices)
                    if (idx >= 0 && idx < selectorsByRef.Count)
                        matchingRefs.Add(selectorsByRef[idx].refNum);
        }
        catch { /* empty set on parse failure */ }

        return matchingRefs;
    }

    /// <summary>
    /// Get all interactive elements on the current page with selectors, labels, and state.
    /// Pass <paramref name="frame"/> to scan inside that iframe (including inspectable cross-origin frames).
    /// </summary>
    public async Task<List<Dictionary<string, object>>> GetInteractiveElements(string? frame = null)
    {
        SetActionFrame(frame);
        const string scanBody = """
            try {
                function collectAll(root, sel) {
                    var results = Array.from(root.querySelectorAll(sel));
                    var all = root.querySelectorAll('*');
                    for (var i = 0; i < all.length; i++) {
                        if (all[i].shadowRoot) {
                            results = results.concat(collectAll(all[i].shadowRoot, sel));
                        }
                    }
                    return results;
                }

                function getLocalSelector(el, root) {
                    if (el.id) {
                        try {
                            var escaped = CSS.escape(el.id);
                            if (root.querySelectorAll('#' + escaped).length === 1)
                                return '#' + escaped;
                        } catch(e) {}
                    }

                    var testId = el.getAttribute('data-testid');
                    if (testId) {
                        var sel = '[data-testid="' + testId.replace(/"/g, '\\"') + '"]';
                        try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                    }

                    var dataTest = el.getAttribute('data-test');
                    if (dataTest) {
                        var sel = '[data-test="' + dataTest.replace(/"/g, '\\"') + '"]';
                        try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                    }

                    if (el.name) {
                        var sel = '[name="' + el.name.replace(/"/g, '\\"') + '"]';
                        try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                    }

                    var ariaLabel = el.getAttribute('aria-label');
                    if (ariaLabel) {
                        var sel = '[aria-label="' + ariaLabel.replace(/"/g, '\\"') + '"]';
                        try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                    }

                    var parts = [];
                    var cur = el;
                    while (cur && cur !== root && cur.nodeType === 1) {
                        if (cur.id) {
                            parts.unshift('#' + CSS.escape(cur.id));
                            break;
                        }
                        var tag = cur.tagName.toLowerCase();
                        var parent = cur.parentElement;
                        if (parent) {
                            var siblings = Array.from(parent.children).filter(function(c) {
                                return c.tagName === cur.tagName;
                            });
                            if (siblings.length > 1) {
                                tag += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
                            }
                        }
                        parts.unshift(tag);
                        cur = cur.parentElement;
                        if (parts.length >= 6) {
                            var sel = parts.join(' > ');
                            try { if (root.querySelectorAll(sel).length === 1) break; } catch(e) { break; }
                        }
                    }
                    return parts.join(' > ');
                }

                function getSelector(el) {
                    var root = el.getRootNode();
                    if (root instanceof ShadowRoot) {
                        var innerSel = getLocalSelector(el, root);
                        var hostSel = getSelector(root.host);
                        return hostSel + ' >>> ' + innerSel;
                    }
                    return getLocalSelector(el, document);
                }

                function getLabel(el) {
                    var aria = el.getAttribute('aria-label');
                    if (aria) return aria.trim().substring(0, 100);

                    var labelledBy = el.getAttribute('aria-labelledby');
                    if (labelledBy) {
                        var root = el.getRootNode();
                        var queryRoot = (root instanceof ShadowRoot) ? root : document;
                        var lbl = queryRoot.getElementById ? queryRoot.getElementById(labelledBy) : null;
                        if (lbl) return (lbl.innerText || '').trim().substring(0, 100);
                    }

                    if (el.id) {
                        var root = el.getRootNode();
                        var queryRoot = (root instanceof ShadowRoot) ? root : document;
                        var lbl = queryRoot.querySelector('label[for="' + el.id + '"]');
                        if (lbl) return (lbl.innerText || '').trim().substring(0, 100);
                    }

                    if (el.labels && el.labels.length > 0) {
                        var lt = (el.labels[0].innerText || el.labels[0].textContent || '').trim();
                        if (lt) return lt.substring(0, 100);
                    }

                    if (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') {
                        var parent = el.closest('label');
                        if (parent) {
                            var clone = parent.cloneNode(true);
                            var inputs = clone.querySelectorAll('input,select,textarea');
                            for (var ci = 0; ci < inputs.length; ci++) inputs[ci].remove();
                            var wrapText = (clone.innerText || clone.textContent || '').trim();
                            if (wrapText) return wrapText.substring(0, 100);
                        }
                    }

                    var labelAttr = el.getAttribute('label');
                    if (labelAttr) return labelAttr.trim().substring(0, 100);

                    var text = (el.innerText || el.textContent || '').trim();
                    if (text && text.length < 100) return text;
                    if (text) return text.substring(0, 100);

                    if (el.shadowRoot) {
                        var shadowText = (el.shadowRoot.textContent || '').trim();
                        if (shadowText && shadowText.length < 100) return shadowText;
                        if (shadowText) return shadowText.substring(0, 100);
                    }

                    if (el.title) return el.title.trim().substring(0, 100);
                    if (el.placeholder) return el.placeholder.trim().substring(0, 100);
                    if (el.alt) return el.alt.trim().substring(0, 100);

                    if (el.value && (el.type === 'button' || el.type === 'submit' || el.type === 'reset'))
                        return el.value.trim().substring(0, 100);

                    return '';
                }

                function isVisible(el) {
                    var cur = el;
                    while (cur) {
                        if (cur === document.documentElement) break;
                        if (cur.nodeType !== 1) break;
                        try {
                            var style = window.getComputedStyle(cur);
                            if (style.display === 'none' || style.visibility === 'hidden')
                                return false;
                        } catch(e) {
                            break;
                        }
                        if (cur.parentElement) {
                            cur = cur.parentElement;
                        } else {
                            var root = cur.getRootNode();
                            if (root instanceof ShadowRoot) {
                                cur = root.host;
                            } else {
                                break;
                            }
                        }
                    }
                    var rect = el.getBoundingClientRect();
                    if (rect.width === 0 && rect.height === 0) return false;
                    return true;
                }

                var selectors = [
                    'a', 'button', 'input:not([type="hidden"])', 'select', 'textarea',
                    '[role="button"]', '[role="link"]', '[role="tab"]', '[role="checkbox"]',
                    '[role="switch"]', '[role="menuitem"]', '[role="option"]', '[role="radio"]',
                    '[role="combobox"]', '[role="slider"]', '[role="spinbutton"]',
                    '[role="treeitem"]', '[role="gridcell"]',
                    '[contenteditable="true"]', 'summary',
                    '[tabindex]:not([tabindex="-1"])',
                    '[onclick]'
                ].join(',');

                var elements = [];
                var visibleRef = 0;
                var all = collectAll(document, selectors);
                var frameId = (typeof __trowserFrameResolved !== 'undefined' && __trowserFrameResolved)
                    ? (__trowserFrameResolved.frameId || null) : null;

                var selectorSet = new Set(all);
                var bodyEls = document.body ? document.body.querySelectorAll('*') : [];
                var heuristicCount = 0;
                for (var i = 0; i < bodyEls.length && i < 10000; i++) {
                    if (heuristicCount >= 200) break;
                    var el = bodyEls[i];
                    if (selectorSet.has(el)) continue;
                    try {
                        if (window.getComputedStyle(el).cursor !== 'pointer') continue;
                    } catch(e) { continue; }
                    var t = (el.innerText || el.textContent || '').trim();
                    if (!t && !el.getAttribute('aria-label') && !el.title) continue;
                    var skip = false;
                    var p = el.parentElement;
                    while (p) { if (selectorSet.has(p)) { skip = true; break; } p = p.parentElement; }
                    if (skip) continue;
                    try { if (el.querySelector(selectors)) continue; } catch(e) {}
                    all.push(el);
                    selectorSet.add(el);
                    heuristicCount++;
                }

                all.forEach(function(el) {
                    var tag = el.tagName.toLowerCase();
                    var type = el.type || el.getAttribute('role') || '';
                    var vis = isVisible(el);
                    var rect = el.getBoundingClientRect();
                    var inVp = vis && rect.bottom > 0 && rect.right > 0
                        && rect.top < (window.innerHeight || 0)
                        && rect.left < (window.innerWidth || 0);

                    var labelText = getLabel(el);
                    var text = (el.innerText || el.textContent || '').trim();
                    if (!text && (tag === 'input' || tag === 'select' || tag === 'textarea') && labelText)
                        text = labelText;
                    text = text.substring(0, 200);
                    var item = {
                        ref: vis ? visibleRef++ : -1,
                        tag: tag,
                        type: type,
                        name: (el.name || el.getAttribute('name') || ''),
                        id: (el.id || el.getAttribute('id') || ''),
                        selector: getSelector(el),
                        label: labelText,
                        accessibleName: labelText,
                        text: text,
                        value: (el.value || '').substring(0, 100),
                        placeholder: el.placeholder || '',
                        enabled: !el.disabled,
                        required: el.required || false,
                        href: tag === 'a' ? (el.href || '') : '',
                        visible: vis,
                        inViewport: inVp,
                        frameId: frameId
                    };
                    if (type === 'checkbox' || type === 'radio') {
                        item.checked = !!el.checked;
                    }
                    elements.push(item);
                });

                // Return the array directly (not JSON.stringify) so WebView2 encodes once.
                // Avoids double-encoding that can corrupt emoji / non-ASCII on some bridges.
                return elements;
            } catch(err) {
                return { __error: err.message || String(err) };
            }
            """;

        // IMPORTANT: never inject `var document = ...` into the same IIFE as code that reads
        // `document` earlier — JS hoists `var document`, so `__trowserRoot = document` becomes
        // undefined on the main-frame path and the scan returns []. Use a nested function
        // parameter to shadow `document` only for framed scans.
        if (!string.IsNullOrEmpty(frame) && await TryResolveInspectableFrameEntryAsync(frame) != null)
        {
            var frameIdJs = JsonSerializer.Serialize(frame);
            var frameScan = "(function() {\n"
                + "var __trowserFrameResolved = { frameId: " + frameIdJs + " };\n"
                + scanBody.Replace(
                "return elements;",
                "return JSON.stringify(elements);",
                StringComparison.Ordinal) + "\n})()";
            var jsonFromFrame = await ExecuteJsInFrame(frame, frameScan);
            var frameResult = ParseInteractiveElementsResult(AutomationContext.UnwrapJsStringResult(jsonFromFrame));
            frameResult ??= new();
            ActiveTab.UpdateInteractiveElements(frameResult);
            await RecordRefGenerationSnapshotAsync(frameResult).ConfigureAwait(false);
            return frameResult;
        }

        string js;
        if (string.IsNullOrEmpty(frame))
        {
            js = "(function() {\n" + scanBody + "\n})()";
        }
        else
        {
            js = "(function() {\n" + BuildFramePreamble(frame) +
                 "return (function(document){\n" + scanBody + "\n})(__trowserRoot);\n})()";
        }

        var json = await RunJs(js);
        ThrowIfFrameError(json);
        var result = ParseInteractiveElementsResult(json);

        if (result == null || result.Count == 0)
        {
            foreach (var delayMs in new[] { 400, 900, 1500 })
            {
                await Task.Delay(delayMs);
                json = await RunJs(js);
                ThrowIfFrameError(json);
                result = ParseInteractiveElementsResult(json);
                if (result is { Count: > 0 })
                    break;
            }

            if (result == null || result.Count == 0)
                TrowserLog.Warn("GetInteractiveElements: scan returned 0 elements after retry. " +
                    "The page may have no interactive elements, or a DOM mutation may have disrupted scanning.");
        }

        result ??= new();
        ActiveTab.UpdateInteractiveElements(result);
        await RecordRefGenerationSnapshotAsync(result).ConfigureAwait(false);
        return result;
    }

    /// <summary>Count of HTML <c>&lt;form&gt;</c> elements in the live document (for attack-surface <c>spaMode</c> metrics).</summary>
    public async Task<int> GetHtmlFormCountAsync()
    {
        var s = await RunJs(
            """
            (function() {
            try { return String(document.querySelectorAll('form').length); } catch(e) { return '0'; }
            })()
            """);
        return int.TryParse(s?.Trim(), out var n) ? n : 0;
    }

    /// <summary>
    /// Execute the interactive-elements JS scan with error handling and retry.
    /// If the first scan returns empty (possible after DOM mutations), retries once after a short delay.
    /// </summary>
    private async Task<List<Dictionary<string, object>>> RunInteractiveElementsScan(string js)
    {
        var json = await RunJs(js);
        var result = ParseInteractiveElementsResult(json);

        // If the scan returned empty, the DOM may still be settling after navigation/mutation.
        // Retry with increasing delays — SPAs often mount interactive controls after paint.
        if (result == null || result.Count == 0)
        {
            foreach (var delayMs in new[] { 400, 900, 1500 })
            {
                await Task.Delay(delayMs);
                json = await RunJs(js);
                result = ParseInteractiveElementsResult(json);
                if (result is { Count: > 0 })
                    break;
            }

            if (result == null || result.Count == 0)
                TrowserLog.Warn("GetInteractiveElements: scan returned 0 elements after retry. " +
                    "The page may have no interactive elements, or a DOM mutation may have disrupted scanning.");
        }

        result ??= new();
        ActiveTab.UpdateInteractiveElements(result);
        await RecordRefGenerationSnapshotAsync(result).ConfigureAwait(false);
        return result;
    }

    /// <summary>
    /// Resolve a snapshot ref for a CSS selector, including DOM-identity matching when selector strings differ.
    /// </summary>
    public async Task<int?> FindRefForSelectorAsync(string selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
            return null;

        var direct = ActiveTab.GetRefBySelector(selector);
        if (direct.HasValue)
            return direct;

        var pairs = ActiveTab.GetRefSelectorPairs();
        if (pairs.Count == 0)
            return null;

        var selectorsJson = JsonSerializer.Serialize(pairs.Select(p => p.Selector).ToArray());
        var js = "(function(){" + DeepQueryJs +
                 "var target=deepQuery(" + JsonEscape(selector) + ");" +
                 "if(!target)return '-1';" +
                 "var sels=" + selectorsJson + ";" +
                 "for(var i=0;i<sels.length;i++){" +
                 "try{var el=deepQuery(sels[i]);if(el===target)return String(i);}catch(e){}}" +
                 "return '-1';})()";

        var result = await RunJs(js);
        if (!int.TryParse(result, out var idx) || idx < 0 || idx >= pairs.Count)
            return null;

        return pairs[idx].Ref;
    }

    private static List<Dictionary<string, object>>? ParseInteractiveElementsResult(string json)
    {
        if (string.IsNullOrEmpty(json)) return null;

        try
        {
            // Check for error object returned by the try-catch wrapper in the JS
            if (json.TrimStart().StartsWith('{'))
            {
                var errorCheck = JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                if (errorCheck != null && errorCheck.ContainsKey("__error"))
                {
                    var errMsg = errorCheck["__error"]?.ToString() ?? "unknown";
                    TrowserLog.Warn($"GetInteractiveElements JS error: {errMsg}");
                    return null;
                }
            }

            return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json);
        }
        catch
        {
            TrowserLog.Warn($"GetInteractiveElements: failed to parse JSON ({json.Length} chars)");
            return null;
        }
    }

    #endregion

    #region Page Inspection (Exploratory Testing)

    public async Task<List<Dictionary<string, string>>> GetLinks()
    {
        var js = @"
            (function() {
                return JSON.stringify(
                    Array.from(document.querySelectorAll('a[href]')).map(a => ({
                        href: a.href,
                        text: (a.innerText || a.textContent || '').trim().substring(0, 200),
                        target: a.target || ''
                    }))
                );
            })()";

        var json = await RunJs(js);
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new(); }
        catch (Exception ex) { TrowserLog.Warn($"JS result deserialization failed: {ex.Message}"); return new(); }
    }

    public async Task<List<Dictionary<string, string>>> GetHeadings()
    {
        var js = @"
            (function() {
                function isVisible(el) {
                    var cur = el;
                    while (cur) {
                        if (cur === document.documentElement) break;
                        if (cur.nodeType !== 1) break;
                        try {
                            var style = window.getComputedStyle(cur);
                            if (style.display === 'none' || style.visibility === 'hidden')
                                return false;
                        } catch(e) { break; }
                        if (cur.parentElement) {
                            cur = cur.parentElement;
                        } else {
                            var root = cur.getRootNode();
                            if (root instanceof ShadowRoot) {
                                cur = root.host;
                            } else {
                                break;
                            }
                        }
                    }
                    var rect = el.getBoundingClientRect();
                    if (rect.width === 0 && rect.height === 0) return false;
                    return true;
                }
                function collectHeadings(root) {
                    var results = Array.from(root.querySelectorAll('h1,h2,h3,h4,h5,h6'));
                    var all = root.querySelectorAll('*');
                    for (var i = 0; i < all.length; i++) {
                        if (all[i].shadowRoot) {
                            results = results.concat(collectHeadings(all[i].shadowRoot));
                        }
                    }
                    return results;
                }
                return JSON.stringify(
                    collectHeadings(document).map(h => ({
                        level: h.tagName.toLowerCase(),
                        text: (h.innerText || h.textContent || '').trim().substring(0, 200),
                        visible: String(isVisible(h))
                    }))
                );
            })()";

        var json = await RunJs(js);
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new(); }
        catch (Exception ex) { TrowserLog.Warn($"JS result deserialization failed: {ex.Message}"); return new(); }
    }

    public async Task<List<Dictionary<string, string>>> GetImages()
    {
        var js = @"
            (function() {
                return JSON.stringify(
                    Array.from(document.querySelectorAll('img')).map(img => ({
                        src: img.src,
                        alt: img.alt || '',
                        width: String(img.naturalWidth || img.width || 0),
                        height: String(img.naturalHeight || img.height || 0),
                        hasAlt: String(img.hasAttribute('alt'))
                    }))
                );
            })()";

        var json = await RunJs(js);
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new(); }
        catch (Exception ex) { TrowserLog.Warn($"JS result deserialization failed: {ex.Message}"); return new(); }
    }

    /// <summary>
    /// Collect SEO-oriented data from the live DOM: title, meta description, robots, canonical,
    /// Open Graph and Twitter meta tags, hreflang, JSON-LD, and basic technical hints.
    /// </summary>
    public async Task<SeoAuditResult> RunSeoAuditAsync()
    {
        const string js = """
            (function() {
                try {
                    var r = {};
                    r.url = location.href || '';
                    r.title = document.title || '';
                    r.language = document.documentElement.getAttribute('lang') || '';
                    var md = document.querySelector('meta[name="description"]');
                    r.description = md ? (md.getAttribute('content') || '') : '';
                    var robots = document.querySelector('meta[name="robots"]');
                    r.robots = robots ? (robots.getAttribute('content') || '') : '';
                    var canonical = document.querySelector('link[rel="canonical"]');
                    r.canonicalUrl = canonical ? (canonical.getAttribute('href') || '') : '';
                    var charsetMeta = document.querySelector('meta[charset]');
                    r.charset = charsetMeta ? (charsetMeta.getAttribute('charset') || '') : (document.characterSet || '');
                    var viewport = document.querySelector('meta[name="viewport"]');
                    r.viewport = viewport ? (viewport.getAttribute('content') || '') : '';
                    r.h1Count = document.querySelectorAll('h1').length;

                    r.ogTags = {};
                    var ogMetas = document.querySelectorAll('meta[property^="og:"]');
                    for (var i = 0; i < ogMetas.length; i++) {
                        var m = ogMetas[i];
                        var prop = m.getAttribute('property');
                        if (prop) r.ogTags[prop] = m.getAttribute('content') || '';
                    }

                    r.twitterTags = {};
                    var twMetas = document.querySelectorAll('meta[name^="twitter:"]');
                    for (var i = 0; i < twMetas.length; i++) {
                        var m = twMetas[i];
                        var name = m.getAttribute('name');
                        if (name) r.twitterTags[name] = m.getAttribute('content') || '';
                    }

                    r.hreflang = [];
                    var alts = document.querySelectorAll('link[rel="alternate"][hreflang]');
                    for (var i = 0; i < alts.length; i++) {
                        var l = alts[i];
                        r.hreflang.push({ hreflang: l.getAttribute('hreflang') || '', href: l.getAttribute('href') || '' });
                    }

                    r.structuredData = [];
                    var scripts = document.querySelectorAll('script[type="application/ld+json"]');
                    for (var i = 0; i < scripts.length; i++) {
                        var raw = (scripts[i].textContent || '').trim();
                        if (!raw) {
                            r.structuredData.push({ valid: false, error: 'empty block', raw: '' });
                            continue;
                        }
                        try {
                            var data = JSON.parse(raw);
                            r.structuredData.push({ valid: true, data: data });
                        } catch (e) {
                            var msg = (e && e.message) ? String(e.message) : String(e);
                            r.structuredData.push({
                                valid: false,
                                error: msg.substring(0, 300),
                                raw: raw.length > 4000 ? raw.substring(0, 4000) : raw
                            });
                        }
                    }

                    return JSON.stringify(r);
                } catch (e) {
                    return JSON.stringify({ error: (e && e.message) ? String(e.message) : String(e) });
                }
            })()
            """;

        var json = await RunJs(js);
        if (string.IsNullOrWhiteSpace(json))
            return new SeoAuditResult { Error = "No data returned from page." };

        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        try
        {
            var result = JsonSerializer.Deserialize<SeoAuditResult>(json, opts);
            return result ?? new SeoAuditResult { Error = "Deserialization returned null." };
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"SEO audit JSON parse failed: {ex.Message}");
            return new SeoAuditResult { Error = ex.Message };
        }
    }

    public async Task<List<Dictionary<string, string>>> GetFormFields()
    {
        var js = @"
            (function() {
                var fields = Array.from(document.querySelectorAll('input,select,textarea,button'));
                return JSON.stringify(fields.map(f => {
                    var label = '';
                    if (f.id) {
                        var lbl = document.querySelector('label[for=""' + f.id + '""]');
                        if (lbl) label = (lbl.innerText || '').trim();
                    }
                    return {
                        tag: f.tagName.toLowerCase(),
                        type: f.type || '',
                        name: f.name || '',
                        id: f.id || '',
                        value: (f.value || '').substring(0, 100),
                        placeholder: f.placeholder || '',
                        label: label.substring(0, 100),
                        required: String(f.required || false)
                    };
                }));
            })()";

        var json = await RunJs(js);
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new(); }
        catch (Exception ex) { TrowserLog.Warn($"JS result deserialization failed: {ex.Message}"); return new(); }
    }

    public async Task<List<Dictionary<string, string>>> GetMetaTags()
    {
        var js = @"
            (function() {
                return JSON.stringify(
                    Array.from(document.querySelectorAll('meta')).map(m => ({
                        name: m.name || m.getAttribute('property') || m.getAttribute('http-equiv') || '',
                        content: m.content || '',
                        charset: m.getAttribute('charset') || ''
                    }))
                );
            })()";

        var json = await RunJs(js);
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<List<Dictionary<string, string>>>(json) ?? new(); }
        catch (Exception ex) { TrowserLog.Warn($"JS result deserialization failed: {ex.Message}"); return new(); }
    }

    #endregion

    #region Page State Diffing

    private sealed class RefGenerationStateSnapshot
    {
        public int TabId { get; init; }
        public int RefGeneration { get; init; }
        public string Url { get; init; } = "";
        public string Title { get; init; } = "";
        public int NetworkErrorCount { get; init; }
        public int ConsoleErrorCount { get; init; }
        public List<Dictionary<string, object>> InteractiveElements { get; init; } = new();
        public List<string> ConsoleErrorMessages { get; init; } = new();
        public List<string> NetworkErrorFingerprints { get; init; } = new();
    }

    private void ClearRefGenerationSnapshots()
    {
        lock (_refGenSnapshotLock)
        {
            _refGenSnapshots.Clear();
            _refGenSnapshotOrder.Clear();
        }
    }

    private static List<Dictionary<string, object>> CloneInteractiveElementsForSnapshot(
        List<Dictionary<string, object>> elements)
    {
        try
        {
            var json = JsonSerializer.Serialize(elements);
            return JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json) ?? new();
        }
        catch
        {
            return elements
                .Select(e => new Dictionary<string, object>(e, StringComparer.Ordinal))
                .ToList();
        }
    }

    private async Task RecordRefGenerationSnapshotAsync(List<Dictionary<string, object>> interactiveElements)
    {
        var tab = ActiveTab;
        var snap = new RefGenerationStateSnapshot
        {
            TabId = tab.Id,
            RefGeneration = tab.RefGeneration,
            Url = await GetCurrentUrl().ConfigureAwait(false),
            Title = await GetTitle().ConfigureAwait(false),
            NetworkErrorCount = tab.Network.FindErrors().Count,
            ConsoleErrorCount = tab.Console.GetErrors().Count,
            InteractiveElements = CloneInteractiveElementsForSnapshot(interactiveElements),
            ConsoleErrorMessages = tab.Console.GetErrors().TakeLast(20).Select(e => e.Message).ToList(),
            NetworkErrorFingerprints = tab.Network.FindErrors().TakeLast(20)
                .Select(e => $"{e.Method} {e.Url} {e.StatusCode}").ToList()
        };

        lock (_refGenSnapshotLock)
        {
            _refGenSnapshots[(snap.TabId, snap.RefGeneration)] = snap;
            _refGenSnapshotOrder.Enqueue((snap.TabId, snap.RefGeneration));
            while (_refGenSnapshots.Count > MaxRefGenerationSnapshots && _refGenSnapshotOrder.TryDequeue(out var key))
                _refGenSnapshots.Remove(key);
        }
    }

    /// <summary>
    /// Compare two stored page snapshots keyed by <see cref="RefGeneration"/> (from GET /api/state or /api/interactive).
    /// Snapshots are recorded per tab whenever interactive elements are rescanned.
    /// </summary>
    /// <param name="tabIndex">Optional tab index; defaults to the active tab.</param>
    /// <returns>Diff payload, or null with <paramref name="error"/> when a snapshot is missing or tab index is invalid.</returns>
    public Dictionary<string, object>? BuildRefGenerationDiff(int beforeGeneration, int afterGeneration,
        out string? error, int? tabIndex = null)
    {
        error = null;
        BrowserTab? tab;
        if (tabIndex.HasValue)
        {
            tab = GetTabByIndex(tabIndex.Value);
            if (tab == null)
            {
                error = $"Invalid tabIndex: {tabIndex.Value}";
                return null;
            }
        }
        else tab = ActiveTab;

        if (tab == null)
        {
            error = "No active browser tab.";
            return null;
        }

        RefGenerationStateSnapshot? beforeSnap;
        RefGenerationStateSnapshot? afterSnap;
        lock (_refGenSnapshotLock)
        {
            _refGenSnapshots.TryGetValue((tab.Id, beforeGeneration), out beforeSnap);
            _refGenSnapshots.TryGetValue((tab.Id, afterGeneration), out afterSnap);
        }

        if (beforeSnap == null)
        {
            error = $"No snapshot for refGeneration {beforeGeneration} on this tab. " +
                    "Call GET /api/state or GET /api/interactive first to capture that generation.";
            return null;
        }

        if (afterSnap == null)
        {
            error = $"No snapshot for refGeneration {afterGeneration} on this tab. " +
                    "Call GET /api/state or GET /api/interactive first to capture that generation.";
            return null;
        }

        error = null;
        return BuildRefGenerationDiffCore(beforeSnap, afterSnap);
    }

    private static Dictionary<string, object> BuildRefGenerationDiffCore(
        RefGenerationStateSnapshot before, RefGenerationStateSnapshot after)
    {
        var beforeMap = IndexInteractiveElementsBySelector(before.InteractiveElements);
        var afterMap = IndexInteractiveElementsBySelector(after.InteractiveElements);

        var elementsAdded = new List<Dictionary<string, object>>();
        var elementsRemoved = new List<Dictionary<string, object>>();
        var textChanged = new List<Dictionary<string, object>>();

        foreach (var (sel, el) in afterMap)
        {
            if (!beforeMap.ContainsKey(sel))
                elementsAdded.Add(SummarizeElement(el));
        }

        foreach (var (sel, el) in beforeMap)
        {
            if (!afterMap.ContainsKey(sel))
                elementsRemoved.Add(SummarizeElement(el));
        }

        foreach (var (sel, beforeEl) in beforeMap)
        {
            if (!afterMap.TryGetValue(sel, out var afterEl))
                continue;

            var t0 = ElementTextish(beforeEl);
            var t1 = ElementTextish(afterEl);
            var v0 = ElementValueStr(beforeEl);
            var v1 = ElementValueStr(afterEl);
            if (t0 != t1 || v0 != v1)
            {
                var row = new Dictionary<string, object>
                {
                    ["selector"] = sel,
                    ["before"] = t0,
                    ["after"] = t1
                };
                if (v0 != v1)
                {
                    row["valueBefore"] = v0;
                    row["valueAfter"] = v1;
                }

                textChanged.Add(row);
            }
        }

        var beforeConsole = before.ConsoleErrorMessages.ToHashSet(StringComparer.Ordinal);
        var newConsoleErrors = after.ConsoleErrorMessages.Where(m => !beforeConsole.Contains(m)).ToList();

        var beforeNet = before.NetworkErrorFingerprints.ToHashSet(StringComparer.Ordinal);
        var newNetworkErrors = after.NetworkErrorFingerprints.Where(f => !beforeNet.Contains(f)).ToList();

        var urlChanged = before.Url != after.Url;
        var titleChanged = before.Title != after.Title;

        var result = new Dictionary<string, object>
        {
            ["beforeRefGeneration"] = before.RefGeneration,
            ["afterRefGeneration"] = after.RefGeneration,
            ["elementsAdded"] = elementsAdded,
            ["elementsRemoved"] = elementsRemoved,
            ["textChanged"] = textChanged,
            ["urlChanged"] = urlChanged,
            ["titleChanged"] = titleChanged,
            ["newConsoleErrors"] = newConsoleErrors,
            ["newNetworkErrors"] = newNetworkErrors
        };
        if (urlChanged)
        {
            result["urlFrom"] = before.Url;
            result["urlTo"] = after.Url;
        }

        if (titleChanged)
        {
            result["titleFrom"] = before.Title;
            result["titleTo"] = after.Title;
        }

        return result;
    }

    private static Dictionary<string, Dictionary<string, object>> IndexInteractiveElementsBySelector(
        List<Dictionary<string, object>> elements)
    {
        var map = new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal);
        foreach (var el in elements)
        {
            var sel = ElementFieldString(el, "selector");
            if (string.IsNullOrEmpty(sel))
                continue;
            map[sel] = el;
        }

        return map;
    }

    private static Dictionary<string, object> SummarizeElement(Dictionary<string, object> el)
    {
        return new Dictionary<string, object>
        {
            ["selector"] = ElementFieldString(el, "selector"),
            ["tag"] = ElementFieldString(el, "tag"),
            ["type"] = ElementFieldString(el, "type"),
            ["text"] = ElementFieldString(el, "text"),
            ["label"] = ElementFieldString(el, "label"),
            ["visible"] = ElementFieldBool(el, "visible")
        };
    }

    private static string ElementTextish(Dictionary<string, object> el)
    {
        var text = ElementFieldString(el, "text");
        if (!string.IsNullOrEmpty(text))
            return text;
        return ElementFieldString(el, "label");
    }

    private static string ElementValueStr(Dictionary<string, object> el) =>
        ElementFieldString(el, "value");

    private static string ElementFieldString(Dictionary<string, object> el, string key)
    {
        if (!el.TryGetValue(key, out var v))
            return "";
        if (v is string s)
            return s;
        if (v is JsonElement je)
        {
            return je.ValueKind switch
            {
                JsonValueKind.String => je.GetString() ?? "",
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => je.ToString(),
                _ => je.ToString()
            };
        }

        return v?.ToString() ?? "";
    }

    private static bool ElementFieldBool(Dictionary<string, object> el, string key)
    {
        if (!el.TryGetValue(key, out var v))
            return false;
        if (v is bool b)
            return b;
        if (v is JsonElement je)
        {
            if (je.ValueKind == JsonValueKind.True) return true;
            if (je.ValueKind == JsonValueKind.False) return false;
        }

        return false;
    }

    public class PageStateSnapshot
    {
        public string Url { get; init; } = "";
        public string Title { get; init; } = "";
        public int NetworkErrorCount { get; init; }
        public int ConsoleErrorCount { get; init; }
    }

    public async Task<PageStateSnapshot> CapturePageState()
    {
        return new PageStateSnapshot
        {
            Url = await GetCurrentUrl(),
            Title = await GetTitle(),
            NetworkErrorCount = Network.FindErrors().Count,
            ConsoleErrorCount = Console.GetErrors().Count
        };
    }

    public static Dictionary<string, object>? DiffPageState(PageStateSnapshot before, PageStateSnapshot after)
    {
        var changes = new Dictionary<string, object>();

        if (before.Url != after.Url)
            changes["urlChanged"] = new { from = before.Url, to = after.Url };
        if (before.Title != after.Title)
            changes["titleChanged"] = new { from = before.Title, to = after.Title };

        var newNetworkErrors = after.NetworkErrorCount - before.NetworkErrorCount;
        if (newNetworkErrors > 0)
            changes["newNetworkErrors"] = newNetworkErrors;

        var newConsoleErrors = after.ConsoleErrorCount - before.ConsoleErrorCount;
        if (newConsoleErrors > 0)
            changes["newConsoleErrors"] = newConsoleErrors;

        return changes.Count > 0 ? changes : null;
    }

    #endregion
}
