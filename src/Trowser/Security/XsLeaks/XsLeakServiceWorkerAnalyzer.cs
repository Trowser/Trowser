using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>Service worker scope/boundary hints for XS-Leaks posture.</summary>
internal static class XsLeakServiceWorkerAnalyzer
{
    public static async Task<XsLeakPostureAnalyzer.ControlVerdict> InspectAsync(AutomationContext ctx)
    {
        try
        {
            var raw = await ctx.ExecuteJs(
                """
                (async function(){
                  if (!('serviceWorker' in navigator)) return JSON.stringify({ status: 'unsupported' });
                  var regs = await navigator.serviceWorker.getRegistrations();
                  if (!regs.length) return JSON.stringify({ status: 'none' });
                  var scopes = regs.map(function(r){ return r.scope; });
                  var path = location.pathname || '/';
                  var broad = scopes.some(function(s){
                    try {
                      var u = new URL(s);
                      return u.pathname === '/' || path.indexOf(u.pathname) === 0 && u.pathname.length > 1;
                    } catch(e) { return false; }
                  });
                  return JSON.stringify({ status: 'registered', count: regs.length, scopes: scopes, broadScope: broad });
                })()
                """);
            var json = (raw ?? "").Trim().Trim('"').Replace("\\\"", "\"");
            if (json.StartsWith("{\"", StringComparison.Ordinal))
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                var root = doc.RootElement;
                var status = root.TryGetProperty("status", out var st) ? st.GetString() : "unknown";
                if (status == "registered")
                {
                    var broad = root.TryGetProperty("broadScope", out var b) && b.GetBoolean();
                    var count = root.TryGetProperty("count", out var c) && c.TryGetInt32(out var n) ? n : 1;
                    var scopes = root.TryGetProperty("scopes", out var sc)
                        ? string.Join(", ", sc.EnumerateArray().Select(e => e.GetString()))
                        : "";
                    var scopeVerdict = new XsLeakPostureAnalyzer.ControlVerdict
                    {
                        Control = "Service-Worker-scope",
                        Status = broad ? "partial" : "present",
                        Detail = broad
                            ? $"{count} registration(s); broad scope ({scopes}) may intercept responses used in XS-Leak state pairs."
                            : $"{count} registration(s); scopes: {scopes}."
                    };
                    return scopeVerdict;
                }
            }
        }
        catch
        {
            /* fall through */
        }

        return new XsLeakPostureAnalyzer.ControlVerdict
        {
            Control = "Service-Worker-scope",
            Status = "unknown",
            Detail = "Could not enumerate service worker registrations on the active document."
        };
    }

    public static async Task<XsLeakPostureAnalyzer.ControlVerdict?> InspectCacheAsync(AutomationContext ctx)
    {
        try
        {
            var raw = await ctx.ExecuteJs(
                """
                (async function(){
                  if (!('caches' in window)) return JSON.stringify({ status: 'no-api' });
                  var keys = await caches.keys();
                  var t0 = performance.now();
                  var hit = await caches.match(location.href);
                  var ms = Math.round(performance.now() - t0);
                  return JSON.stringify({
                    status: 'ok',
                    cacheCount: keys.length,
                    matchMs: ms,
                    hit: !!hit
                  });
                })()
                """);
            var json = (raw ?? "").Trim().Trim('"').Replace("\\\"", "\"");
            if (!json.StartsWith("{\"", StringComparison.Ordinal)) return null;
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("status", out var st) && st.GetString() == "ok")
            {
                var ms = root.TryGetProperty("matchMs", out var m) && m.TryGetInt32(out var n) ? n : 0;
                var caches = root.TryGetProperty("cacheCount", out var c) && c.TryGetInt32(out var cn) ? cn : 0;
                var hit = root.TryGetProperty("hit", out var h) && h.GetBoolean();
                return new XsLeakPostureAnalyzer.ControlVerdict
                {
                    Control = "Service-Worker-cache",
                    Status = caches > 0 ? "present" : "partial",
                    Detail =
                        $"Cache API: {caches} named cache(s); caches.match(document URL) in {ms}ms (hit={hit}). " +
                        "SW-mediated cache may act as an XS-Leak oracle across states."
                };
            }
        }
        catch
        {
            /* ignore */
        }

        return null;
    }
}
