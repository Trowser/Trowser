using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

/// <summary>AutoLeak-style inclusion-method observation vectors per state.</summary>
public sealed class XsLeakObserveMode
{
    public sealed class ObserveResult
    {
        public Dictionary<string, string> VectorsByState { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> DiffFeatures { get; init; } = [];
        public string Summary { get; init; } = "";
    }

    public static async Task<ObserveResult?> RunAsync(
        AutomationContext ctx,
        int homeTabIdx,
        int probeTabIdx,
        string attackerOrigin,
        string runId,
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        Func<XsLeakScanner.StateSpec, Task> applyState)
    {
        if (states.Count < 2) return null;
        var vectors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var state in states.Take(4))
        {
            ctx.SwitchTab(homeTabIdx);
            await applyState(state);
            ctx.SwitchTab(probeTabIdx);

            var pageUrl = AttackerPageBuilder.PageUrl($"{runId}/observe/{state.Label}", attackerOrigin);
            var html = BuildObserveHtml(state);
            ctx.ActiveTab.MockResponse(pageUrl, 200, html,
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
            await ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
            await ctx.WaitForIdle(300, 12000);

            string? vector = null;
            for (var i = 0; i < 50; i++)
            {
                var title = await ctx.GetTitle();
                if (title != null && title.StartsWith("XSLEAK:", StringComparison.Ordinal))
                {
                    vector = title["XSLEAK:".Length..];
                    break;
                }
                await Task.Delay(100);
            }

            vectors[state.Label] = vector ?? "timeout";
        }

        var diffs = new List<string>();
        if (vectors.Count >= 2)
        {
            var a = vectors.Values.First();
            var b = vectors.Values.Skip(1).First();
            if (!string.Equals(a, b, StringComparison.Ordinal))
                diffs.Add("observe-vector");
        }

        return new ObserveResult
        {
            VectorsByState = vectors,
            DiffFeatures = diffs,
            Summary = diffs.Count > 0
                ? "Cross-state observation vector differs (AutoLeak-style signal)."
                : "Observation vectors matched across states."
        };
    }

    private static string BuildObserveHtml(XsLeakScanner.StateSpec state)
    {
        var victim = JsonSerializer.Serialize(state.Url);
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>observe</title></head><body>
<script>
(async function(){
  var victim = {{victim}};
  var parts = [];
  function push(k,v){ parts.push(k+'='+String(v)); }
  await new Promise(function(res){
    var img = new Image();
    img.onload = function(){ push('img','load'); res(); };
    img.onerror = function(){ push('img','error'); res(); };
    setTimeout(res, 2500);
    img.src = victim;
  });
  await new Promise(function(res){
    fetch(victim, { mode: 'no-cors', credentials: 'include' }).then(function(){ push('fetch','ok'); res(); }, function(){ push('fetch','err'); res(); });
    setTimeout(res, 2500);
  });
  document.title = 'XSLEAK:' + JSON.stringify({ observe: parts.join('|') });
})();
</script>
</body></html>
""";
    }
}
