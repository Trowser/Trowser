namespace Trowser.Recording;

/// <summary>
/// One-shot script run when the host handles <c>ContextMenuRequested</c>: resolve a CSS selector for the
/// element at the menu coordinates (no persistent page listeners).
/// </summary>
internal static class RunScriptContextScript
{
    /// <summary>Builds an IIFE that returns element metadata JSON for the context menu target.</summary>
    public static string BuildElementAtPointScript(int x, int y) =>
        $$"""
        (function() {
            var x = {{x}}, y = {{y}};

            function isDynamicId(id) {
                if (/^ids-[a-z0-9]+-[a-z0-9]+$/i.test(id)) return true;
                if (/[0-9a-f]{8}-[0-9a-f]{4}-/i.test(id)) return true;
                return false;
            }

            function getLocalSelector(el, root) {
                if (el.id && !isDynamicId(el.id)) {
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
                if (el.name && !isDynamicId(el.name)) {
                    var sel = '[name="' + el.name.replace(/"/g, '\\"') + '"]';
                    try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
                }
                var tagOnly = el.tagName.toLowerCase();
                try { if (root.querySelectorAll(tagOnly).length === 1) return tagOnly; } catch(e) {}

                var parts = [];
                var cur = el;
                while (cur && cur !== root && cur.nodeType === 1 && parts.length < 10) {
                    if (cur.id && !isDynamicId(cur.id)) {
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
                            var visCount = siblings.filter(function(s) { return !s.hasAttribute('hidden'); }).length;
                            if (visCount === 1 && !cur.hasAttribute('hidden')) {
                                tag += ':not([hidden])';
                            } else {
                                tag += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
                            }
                        }
                    }
                    parts.unshift(tag);
                    cur = cur.parentElement;
                }
                if (parts.length > 0 && !parts[0].startsWith('#')) {
                    var anchor = cur;
                    while (anchor && anchor !== root && anchor.nodeType === 1) {
                        if (anchor.id && !isDynamicId(anchor.id)) {
                            return '#' + CSS.escape(anchor.id) + ' ' + parts.join(' > ');
                        }
                        var at = anchor.tagName.toLowerCase();
                        try {
                            if (root.querySelectorAll(at).length === 1) {
                                return at + ' ' + parts.join(' > ');
                            }
                        } catch(e) {}
                        anchor = anchor.parentElement;
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

            function getRole(el) {
                return el.getAttribute('role') || '';
            }

            function getLabel(el) {
                var aria = el.getAttribute('aria-label');
                if (aria) return aria.trim().substring(0, 100);
                var labelledBy = el.getAttribute('aria-labelledby');
                if (labelledBy) {
                    var lbl = document.getElementById(labelledBy);
                    if (lbl) return (lbl.innerText || '').trim().substring(0, 100);
                }
                if (el.id) {
                    var lbl = document.querySelector('label[for="' + el.id + '"]');
                    if (lbl) return (lbl.innerText || '').trim().substring(0, 100);
                }
                var text = (el.innerText || el.textContent || '').trim();
                if (text && text.length < 100) return text;
                if (text) return text.substring(0, 100);
                if (el.placeholder) return el.placeholder.trim().substring(0, 100);
                return '';
            }

            function getVisibleText(el) {
                var text = (el.innerText || el.textContent || '').trim();
                if (text.length > 200) return text.substring(0, 200);
                return text;
            }

            function isInteractiveTag(node) {
                var t = node.tagName.toLowerCase();
                if (t === 'a' || t === 'button' || t === 'input' ||
                    t === 'select' || t === 'textarea' || t === 'summary') return true;
                var r = node.getAttribute('role');
                if (r === 'button' || r === 'link' || r === 'tab' ||
                    r === 'menuitem' || r === 'checkbox' || r === 'switch') return true;
                return false;
            }

            function buildPayload(target) {
                var tag = target.tagName.toLowerCase();
                var visText = getVisibleText(target);
                return {
                    selector: getSelector(target),
                    tag: tag,
                    text: visText || getLabel(target) || '',
                    role: getRole(target),
                    label: getLabel(target),
                    inputType: target.type || '',
                    href: target.href || '',
                    testId: target.getAttribute('data-testid') || '',
                    placeholder: target.placeholder || ''
                };
            }

            var el = document.elementFromPoint(x, y);
            if (!el || el.nodeType !== 1) {
                return JSON.stringify({ selector: '' });
            }
            var interactive = null;
            var walk = el;
            while (walk && walk.nodeType === 1) {
                if (isInteractiveTag(walk)) {
                    interactive = walk;
                    break;
                }
                walk = walk.parentElement;
            }
            var target = interactive || el;
            try {
                return JSON.stringify(buildPayload(target));
            } catch (err) {
                return JSON.stringify({ selector: '' });
            }
        })();
        """;
}
