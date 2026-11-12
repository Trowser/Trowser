using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Collects external <c>script[src]</c> URLs from the loaded document for bundle inspection.</summary>
internal static class JsBundleScripts
{
    public static async Task<List<string>> ListExternalScriptsAsync(AutomationContext ctx)
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
                  return JSON.stringify({ scripts: list });
                })()
                """)
            .ConfigureAwait(false);

        using var doc = JsonDocument.Parse(listJson ?? "{\"scripts\":[]}");
        var root = doc.RootElement;
        var urls = root.GetProperty("scripts").EnumerateArray()
            .Select(x => x.GetString() ?? "")
            .Where(s => s.Length > 0 && s.Contains(".js", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var unique = new List<string>();
        var order = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in urls)
        {
            if (order.Add(u))
                unique.Add(u);
        }

        return unique;
    }
}
