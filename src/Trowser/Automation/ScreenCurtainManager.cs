using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Automation;

/// <summary>
/// Injects a full-viewport black div into the page. WebView2 renders in a native layer above
/// WPF controls, so an in-page overlay is required. The div is aria-hidden so screen readers
/// still read the underlying page.
/// </summary>
public sealed class ScreenCurtainManager
{
    public async Task ApplyAsync(WebView2 webView)
    {
        var core = webView.CoreWebView2;
        if (core == null) return;

        try
        {
            await webView.Dispatcher.InvokeAsync(async () =>
            {
                await core.ExecuteScriptAsync(ApplyScript);
            });
        }
        catch
        {
            /* page may have navigated away */
        }
    }

    public async Task RemoveAsync(WebView2 webView)
    {
        var core = webView.CoreWebView2;
        if (core == null) return;

        try
        {
            await webView.Dispatcher.InvokeAsync(async () =>
            {
                await core.ExecuteScriptAsync(RemoveScript);
            });
        }
        catch
        {
            /* ignore */
        }
    }

    private const string ApplyScript = """
(function(){
  var id = '__trowser_screen_curtain';
  var el = document.getElementById(id);
  if (!el) {
    el = document.createElement('div');
    el.id = id;
    el.setAttribute('aria-hidden', 'true');
    el.setAttribute('role', 'presentation');
    el.style.cssText = 'position:fixed;left:0;top:0;right:0;bottom:0;width:100%;height:100%;background:#000;z-index:2147483647;pointer-events:auto;margin:0;padding:0;border:0;';
    var root = document.documentElement || document.body;
    if (root) root.appendChild(el);
  }
  el.style.display = 'block';
})();
""";

    private const string RemoveScript = """
(function(){
  document.getElementById('__trowser_screen_curtain')?.remove();
})();
""";
}
