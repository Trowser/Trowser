using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Security;

/// <summary>
/// Injects CSS/JS so hidden, off-screen, and disabled UI is visible for manual security testing.
/// </summary>
public sealed class PowerModeManager
{
    public PowerModeConfig Config { get; } = new();

    /// <summary>Fired after <see cref="Configure"/> changes enablement or options (GUI, API, MCP).</summary>
    public event Action? ConfigChanged;

    public void Configure(bool enabled, bool? showOverlays = null)
    {
        Config.Enabled = enabled;
        if (showOverlays.HasValue) Config.ShowOverlays = showOverlays.Value;
        ConfigChanged?.Invoke();
    }

    /// <summary>Apply Power mode to the page. No-op if URL is not http(s).</summary>
    public async Task ApplyAsync(WebView2 webView, bool showOverlays)
    {
        if (!Config.Enabled) return;
        var core = webView.CoreWebView2;
        if (core == null) return;
        var url = core.Source ?? "";
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return;

        var script = BuildInjectionScript(showOverlays);
        try
        {
            await webView.Dispatcher.InvokeAsync(async () =>
            {
                await core.ExecuteScriptAsync(script);
            });
        }
        catch
        {
            /* page may have navigated away */
        }
    }

    /// <summary>Remove Power mode artifacts from the page.</summary>
    public async Task RemoveAsync(WebView2 webView)
    {
        var core = webView.CoreWebView2;
        if (core == null) return;
        const string cleanup = """
(function(){
  if (typeof window.__trowserPowerModeCleanup === 'function') {
    try { window.__trowserPowerModeCleanup(); } catch(e) {}
    window.__trowserPowerModeCleanup = null;
  }
})();
""";
        try
        {
            await webView.Dispatcher.InvokeAsync(async () =>
            {
                await core.ExecuteScriptAsync(cleanup);
            });
        }
        catch { /* ignore */ }
    }

    private static string BuildInjectionScript(bool showOverlays)
    {
        return InjectionScriptTemplate.Replace("__SHOW_OVERLAYS__", showOverlays ? "true" : "false", StringComparison.Ordinal);
    }

    private const string InjectionScriptTemplate = """
(function(){
  if (typeof window.__trowserPowerModeCleanup === 'function') {
    try { window.__trowserPowerModeCleanup(); } catch(e) {}
  }
  var SHOW_OVERLAYS = __SHOW_OVERLAYS__;
  document.documentElement.classList.add('trowser-pm-active');
  var style = document.createElement('style');
  style.id = 'trowser-pm-style';
  style.textContent = [
    'html.trowser-pm-active .trowser-pm-forced-visible { display: revert !important; visibility: visible !important; opacity: 1 !important; }',
    'html.trowser-pm-active .trowser-pm-disabled-outline { outline: 2px solid #f9a825 !important; outline-offset: 1px !important; }',
    'html.trowser-pm-active .trowser-pm-hidden-input-badge { display: inline-block !important; font: 11px/1.2 Segoe UI, sans-serif !important; margin: 2px !important; padding: 2px 6px !important; border-radius: 3px !important; background: #5c2d91 !important; color: #fff !important; vertical-align: middle !important; }',
    '#trowser-pm-overlay-host { position: fixed; left: 0; top: 0; width: 100%; height: 100%; pointer-events: none; z-index: 2147483646; }',
    '.trowser-pm-float-label { position: fixed; z-index: 2147483647; font: 10px Segoe UI, sans-serif; padding: 2px 4px; border-radius: 2px; color: #fff; pointer-events: none; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }'
  ].join('\n');
  document.head.appendChild(style);

  function isIgnorable(el) {
    if (!el || el.nodeType !== 1) return true;
    var tag = el.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEMPLATE') return true;
    if (el.id === 'trowser-pm-overlay-host') return true;
    if (el.closest && el.closest('#trowser-pm-overlay-host')) return true;
    return false;
  }

  function markHiddenInputs() {
    document.querySelectorAll('input[type="hidden"]').forEach(function(inp) {
      if (inp.dataset.trowserPmBadge) return;
      inp.dataset.trowserPmBadge = '1';
      var badge = document.createElement('span');
      badge.className = 'trowser-pm-hidden-input-badge';
      var v = String(inp.value || '');
      badge.textContent = 'hidden: ' + (inp.name || inp.id || 'field') + '=' + v.slice(0, 40) + (v.length > 40 ? '\u2026' : '');
      if (inp.parentNode) inp.parentNode.insertBefore(badge, inp.nextSibling);
    });
  }

  function scan() {
    var root = document.body;
    if (!root) return;
    document.querySelectorAll('.trowser-pm-forced-visible').forEach(function(el) {
      el.classList.remove('trowser-pm-forced-visible');
    });
    document.querySelectorAll('.trowser-pm-disabled-outline').forEach(function(el) {
      el.classList.remove('trowser-pm-disabled-outline');
    });

    var all = root.getElementsByTagName('*');
    for (var i = 0; i < all.length; i++) {
      var el = all[i];
      if (isIgnorable(el)) continue;
      try {
        var cs = getComputedStyle(el);
        var hiddenAttr = el.hasAttribute('hidden');
        var ariaHidden = el.getAttribute('aria-hidden') === 'true';
        var displayNone = cs.display === 'none';
        var visHidden = cs.visibility === 'hidden';
        var opacity0 = parseFloat(cs.opacity) === 0;
        if (hiddenAttr || ariaHidden || displayNone || visHidden || opacity0) {
          el.classList.add('trowser-pm-forced-visible');
        }
        if ((el.disabled === true || el.getAttribute('disabled') !== null) && (el.tagName === 'INPUT' || el.tagName === 'BUTTON' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA')) {
          el.classList.add('trowser-pm-disabled-outline');
        }
      } catch (e) { }
    }
    markHiddenInputs();
    if (SHOW_OVERLAYS) buildFloatLabels();
  }

  var overlayHost = null;
  var scrollHandler = null;
  function buildFloatLabels() {
    if (!SHOW_OVERLAYS) return;
    if (!overlayHost) {
      overlayHost = document.createElement('div');
      overlayHost.id = 'trowser-pm-overlay-host';
      document.documentElement.appendChild(overlayHost);
    }
    overlayHost.innerHTML = '';
    function addLabel(el, text, color) {
      var r = el.getBoundingClientRect();
      if (r.width < 1 && r.height < 1 && !el.classList.contains('trowser-pm-hidden-input-badge')) return;
      var div = document.createElement('div');
      div.className = 'trowser-pm-float-label';
      div.style.background = color;
      div.style.left = Math.max(0, r.left) + 'px';
      div.style.top = Math.max(0, r.top - 16) + 'px';
      div.textContent = text;
      overlayHost.appendChild(div);
    }
    document.querySelectorAll('.trowser-pm-forced-visible').forEach(function(el) {
      if (isIgnorable(el)) return;
      addLabel(el, 'was hidden', '#c62828');
    });
    document.querySelectorAll('.trowser-pm-disabled-outline').forEach(function(el) {
      addLabel(el, 'disabled', '#f9a825');
    });
    document.querySelectorAll('.trowser-pm-hidden-input-badge').forEach(function(el) {
      addLabel(el, 'hidden input', '#5c2d91');
    });
  }

  scan();
  var mo = new MutationObserver(function() { requestAnimationFrame(scan); });
  mo.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ['hidden', 'style', 'class', 'disabled', 'type'] });

  scrollHandler = function() { if (SHOW_OVERLAYS) buildFloatLabels(); };
  window.addEventListener('scroll', scrollHandler, true);
  window.addEventListener('resize', scrollHandler);

  window.__trowserPowerModeCleanup = function() {
    mo.disconnect();
    window.removeEventListener('scroll', scrollHandler, true);
    window.removeEventListener('resize', scrollHandler);
    document.documentElement.classList.remove('trowser-pm-active');
    var s = document.getElementById('trowser-pm-style');
    if (s) s.remove();
    if (overlayHost) { overlayHost.remove(); overlayHost = null; }
    document.querySelectorAll('input[data-trowser-pm-badge]').forEach(function(inp) {
      var b = inp.nextSibling;
      if (b && b.classList && b.classList.contains('trowser-pm-hidden-input-badge')) b.remove();
      delete inp.dataset.trowserPmBadge;
    });
    document.querySelectorAll('.trowser-pm-forced-visible, .trowser-pm-disabled-outline').forEach(function(el) {
      el.classList.remove('trowser-pm-forced-visible', 'trowser-pm-disabled-outline');
    });
  };
})();
""";
}
