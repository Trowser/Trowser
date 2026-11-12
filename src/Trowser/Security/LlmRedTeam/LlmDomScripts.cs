namespace Trowser.Security.LlmRedTeam;

/// <summary>Shared DOM search/interaction JS for LLM chat discovery and interaction.</summary>
internal static class LlmDomScripts
{
    /// <summary>Deep query: document, shadow roots, same-origin iframes.</summary>
    public const string DeepSearchJs = """
        function deepQueryAll(sel, roots) {
          var results = [];
          function scan(root) {
            if (!root || !root.querySelectorAll) return;
            try { results = results.concat(Array.from(root.querySelectorAll(sel))); } catch(e) {}
            var hosts = root.querySelectorAll ? root.querySelectorAll('*') : [];
            for (var i = 0; i < hosts.length; i++) {
              if (hosts[i].shadowRoot) scan(hosts[i].shadowRoot);
            }
          }
          (roots || [document]).forEach(function(r) { scan(r); });
          try {
            document.querySelectorAll('iframe').forEach(function(fr) {
              try { if (fr.contentDocument) scan(fr.contentDocument); } catch(e) {}
            });
          } catch(e) {}
          return results;
        }
        function deepQuery(sel) {
          return deepQueryBest(sel);
        }
        function deepQueryBest(sel) {
          var all = deepQueryAll(sel);
          if (!all.length) return null;
          var best = null, bestScore = -1;
          for (var i = 0; i < all.length; i++) {
            var el = all[i];
            if (!isVisibleEnough(el)) continue;
            var score = visibleArea(el);
            if (score > bestScore) { bestScore = score; best = el; }
          }
          return best || all[0];
        }
        """;

    public const string VisibilityJs = """
        function visibleArea(el) {
          if (!el) return 0;
          var r = el.getBoundingClientRect();
          var iw = window.innerWidth || document.documentElement.clientWidth || 0;
          var ih = window.innerHeight || document.documentElement.clientHeight || 0;
          var visW = Math.max(0, Math.min(r.right, iw) - Math.max(r.left, 0));
          var visH = Math.max(0, Math.min(r.bottom, ih) - Math.max(r.top, 0));
          return visW * visH;
        }
        function isVisibleEnough(el) {
          if (!el || el.nodeType !== 1) return false;
          try {
            var st = window.getComputedStyle(el);
            if (st.display === 'none' || st.visibility === 'hidden') return false;
            if (parseFloat(st.opacity) === 0) return false;
          } catch(e) { return false; }
          var rect = el.getBoundingClientRect();
          if (rect.width < 8 || rect.height < 8) return false;
          if (visibleArea(el) < 64) return false;
          var cur = el.parentElement;
          while (cur && cur !== document.documentElement) {
            try {
              var pst = window.getComputedStyle(cur);
              if (pst.display === 'none' || pst.visibility === 'hidden') return false;
            } catch(e) { break; }
            cur = cur.parentElement;
          }
          return true;
        }
        function isDomPresent(el) {
          if (!el || el.nodeType !== 1) return false;
          if (!document.contains(el)) return false;
          try {
            var st = window.getComputedStyle(el);
            if (st.display === 'none' || st.visibility === 'hidden') return false;
            if (parseFloat(st.opacity) === 0) return false;
          } catch(e) { return false; }
          var rect = el.getBoundingClientRect();
          return rect.width >= 1 && rect.height >= 1;
        }
        function scrollToReachable(el) {
          if (!el) return;
          try { el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch(e) {}
          var p = el.parentElement;
          while (p) {
            try {
              if (p.scrollHeight > p.clientHeight + 4) {
                var rect = el.getBoundingClientRect();
                var prect = p.getBoundingClientRect();
                if (rect.bottom > prect.bottom) p.scrollTop += (rect.bottom - prect.bottom + 8);
                if (rect.top < prect.top) p.scrollTop -= (prect.top - rect.top + 8);
              }
            } catch(e) {}
            p = p.parentElement;
          }
        }
        """;

    /// <summary>React/Vue-compatible value assignment (native value setter + input events).</summary>
    public const string ReactInputJs = """
        function setReactInputValue(el, text) {
          if (!el) return false;
          var tag = (el.tagName || '').toLowerCase();
          if (el.isContentEditable && tag !== 'input' && tag !== 'textarea') {
            el.textContent = text;
            try {
              el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertText', data: text }));
            } catch(e) {
              el.dispatchEvent(new Event('input', { bubbles: true }));
            }
            el.dispatchEvent(new Event('change', { bubbles: true }));
            return true;
          }
          var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
            : el instanceof HTMLInputElement ? HTMLInputElement.prototype : null;
          var nativeSetter = proto ? Object.getOwnPropertyDescriptor(proto, 'value')?.set : null;
          if (nativeSetter) nativeSetter.call(el, text);
          else el.value = text;
          try {
            el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'insertFromPaste', data: text }));
          } catch(e) {
            el.dispatchEvent(new Event('input', { bubbles: true }));
          }
          el.dispatchEvent(new Event('change', { bubbles: true }));
          return true;
        }
        function clickElement(el) {
          if (!el) return false;
          scrollToReachable(el);
          try { el.focus(); } catch(e) {}
          try {
            el.dispatchEvent(new MouseEvent('pointerdown', { bubbles: true, cancelable: true, view: window }));
            el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true, view: window }));
            el.dispatchEvent(new MouseEvent('pointerup', { bubbles: true, cancelable: true, view: window }));
            el.dispatchEvent(new MouseEvent('mouseup', { bubbles: true, cancelable: true, view: window }));
          } catch(e) {}
          el.click();
          return true;
        }
        """;
}
