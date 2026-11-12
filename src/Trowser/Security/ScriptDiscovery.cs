using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Same-origin script URLs from the DOM and network log.</summary>
public static class ScriptDiscovery
{
    public static async Task<List<string>> CollectScriptUrlsAsync(
        AutomationContext ctx,
        bool sameOriginOnly = true,
        int max = 40)
    {
        max = Math.Clamp(max, 1, 80);
        var order = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? u)
        {
            if (string.IsNullOrWhiteSpace(u) || !u.Contains(".js", StringComparison.OrdinalIgnoreCase))
                return;
            if (seen.Add(u))
                order.Add(u);
        }

        string? pageHref = null;
        try
        {
            var listJson = await ctx.ExecuteJs(
                """
                (function(){
                  var list = [];
                  var seen = Object.create(null);
                  try {
                    document.querySelectorAll('script[src]').forEach(function(s) {
                      try {
                        var u = new URL(s.getAttribute('src'), location.href).href;
                        if (!seen[u]) { seen[u] = true; list.push(u); }
                      } catch(e) {}
                    });
                  } catch(e) {}
                  return JSON.stringify({ href: location.href, scripts: list });
                })()
                """);
            using var doc = JsonDocument.Parse(Unquote(listJson));
            pageHref = doc.RootElement.TryGetProperty("href", out var h) ? h.GetString() : null;
            if (doc.RootElement.TryGetProperty("scripts", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                    Add(el.GetString());
            }
        }
        catch { /* ignore */ }

        Uri? pageUri = null;
        if (!string.IsNullOrEmpty(pageHref) && Uri.TryCreate(pageHref, UriKind.Absolute, out var pu))
            pageUri = pu;

        foreach (var e in ctx.ActiveTab.Network.Entries)
        {
            if (e.IsTrowserGenerated)
                continue;
            var u = e.Url;
            if (!u.Contains(".js", StringComparison.OrdinalIgnoreCase))
                continue;
            if (sameOriginOnly && pageUri != null
                && Uri.TryCreate(u, UriKind.Absolute, out var au)
                && !string.Equals(au.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            Add(u);
        }

        return order.Take(max).ToList();
    }

    private static string Unquote(string? json)
    {
        if (string.IsNullOrEmpty(json)) return "{}";
        var s = json.Trim();
        if (s.Length >= 2 && s[0] == '"')
        {
            try { return JsonSerializer.Deserialize<string>(s) ?? "{}"; }
            catch { return "{}"; }
        }
        return s;
    }
}
