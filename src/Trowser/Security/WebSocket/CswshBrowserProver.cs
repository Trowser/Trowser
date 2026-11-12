using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.XsLeaks;

namespace Trowser.Security.WebSocket;

/// <summary>Cross-site WebSocket proof from a mocked attacker origin (Chromium cookie + handshake rules).</summary>
public static class CswshBrowserProver
{
    public sealed class BrowserProofResult
    {
        public string TargetUrl { get; init; } = "";
        public string AttackerOrigin { get; init; } = "";
        public bool HandshakeAttempted { get; init; }
        public bool ConnectionOpened { get; init; }
        public bool Vulnerable { get; init; }
        public string Severity { get; init; } = "info";
        public string Detail { get; init; } = "";
        public List<string> ReceivedMessages { get; init; } = [];
        public string? PageResult { get; init; }
        public int ElapsedMs { get; init; }
    }

    public sealed class BrowserProofOptions
    {
        public string TargetUrl { get; init; } = "";
        public string AttackerOrigin { get; init; } = PostMessageProbeBuilder.AttackerOrigin;
        public string? Protocol { get; init; }
        public string? SendAfterConnect { get; init; }
        public int MonitorMs { get; init; } = 5000;
    }

    public static async Task<BrowserProofResult> TestAsync(
        AutomationContext ctx,
        BrowserProofOptions options,
        CancellationToken ct = default)
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
            var probeIdx = await ctx.NewTab($"{attackerOrigin}/cswsh/{runId}", owner: "agent");
            if (homeIdx >= 0 && probeIdx >= 0 && homeIdx < ctx.Tabs.Count && probeIdx < ctx.Tabs.Count)
                ctx.Tabs[probeIdx].CopyNetworkRulesFrom(ctx.Tabs[homeIdx]);

            var pageUrl = $"{attackerOrigin}/cswsh/{runId}";
            var html = BuildAttackerHtml(options);
            ctx.Tabs[probeIdx].MockResponse(pageUrl, 200, html,
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

            ctx.SwitchTab(probeIdx);
            var mark = ctx.ActiveTab.Network.Count;
            await ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
            await ctx.WaitForIdle(400, 12_000);

            string? pageJson = null;
            var waitMs = Math.Clamp(options.MonitorMs + 2500, 4000, 20_000);
            for (var i = 0; i < waitMs / 100; i++)
            {
                ct.ThrowIfCancellationRequested();
                var title = await ctx.GetTitle();
                if (title != null && title.StartsWith("CSWSH:", StringComparison.Ordinal))
                {
                    pageJson = title["CSWSH:".Length..];
                    break;
                }

                await Task.Delay(100);
            }

            var messages = new List<string>();
            var opened = false;
            var attempted = false;
            if (pageJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(pageJson);
                    var root = doc.RootElement;
                    attempted = root.TryGetProperty("attempted", out var a) && a.ValueKind == JsonValueKind.True;
                    opened = root.TryGetProperty("open", out var o) && o.ValueKind == JsonValueKind.True;
                    if (root.TryGetProperty("messages", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in arr.EnumerateArray())
                        {
                            if (el.GetString() is { } s)
                                messages.Add(s.Length > 500 ? s[..500] + "..." : s);
                        }
                    }
                }
                catch
                {
                    /* ignore parse */
                }
            }

            if (!opened)
                opened = NetworkShowsWsOpen(ctx.ActiveTab, options.TargetUrl, mark);

            sw.Stop();
            var vulnerable = opened;
            var severity = messages.Count > 0 ? "critical" : opened ? "high" : "info";
            var detail = opened
                ? $"Browser cross-site WebSocket from {attackerOrigin} reached OPEN state for {options.TargetUrl}."
                : "Browser cross-site WebSocket did not reach OPEN (Origin validation, SameSite cookies, or CSP may block).";

            try { await ctx.CloseTab(probeIdx); } catch { /* ignore */ }

            return new BrowserProofResult
            {
                TargetUrl = options.TargetUrl,
                AttackerOrigin = attackerOrigin,
                HandshakeAttempted = attempted || pageJson != null,
                ConnectionOpened = opened,
                Vulnerable = vulnerable,
                Severity = severity,
                Detail = detail,
                ReceivedMessages = messages,
                PageResult = pageJson,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }
        finally
        {
            ctx.SwitchTab(homeIdx);
            await tabScope.FinishAsync(victimHost, runId);
        }
    }

    private static bool NetworkShowsWsOpen(BrowserTab tab, string wsUrl, int networkMark)
    {
        foreach (var e in tab.Network.Entries.Skip(networkMark))
        {
            if (!string.Equals(e.Url, wsUrl, StringComparison.OrdinalIgnoreCase)
                && !e.Url.Contains(wsUrl, StringComparison.OrdinalIgnoreCase))
                continue;
            if (e.StatusCode is 101 or >= 200 and < 300)
                return true;
        }

        return false;
    }

    private static string BuildAttackerHtml(BrowserProofOptions options)
    {
        var url = JsonSerializer.Serialize(options.TargetUrl);
        var protocol = options.Protocol != null ? JsonSerializer.Serialize(options.Protocol) : "null";
        var sendAfter = options.SendAfterConnect != null
            ? JsonSerializer.Serialize(options.SendAfterConnect)
            : "null";
        var monitor = options.MonitorMs;
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSWSH probe</title></head><body>
<script>
(function(){
  var result = { attempted: true, open: false, state: 'connecting', messages: [], error: null };
  function finish() { document.title = 'CSWSH:' + JSON.stringify(result); }
  try {
    var url = {{url}};
    var protocols = {{protocol}};
    var ws = protocols ? new WebSocket(url, protocols) : new WebSocket(url);
    ws.onopen = function() {
      result.open = true;
      result.state = 'open';
      var payload = {{sendAfter}};
      if (payload) { try { ws.send(payload); } catch(e) {} }
    };
    ws.onmessage = function(ev) {
      result.messages.push(String(ev.data).substring(0, 500));
      if (result.messages.length >= 5) finish();
    };
    ws.onerror = function() { result.state = 'error'; };
    ws.onclose = function(ev) {
      result.state = 'closed';
      result.code = ev.code;
      finish();
    };
    setTimeout(function(){
      if (result.state === 'open') finish();
      else if (result.state === 'connecting') { result.state = 'timeout'; finish(); }
    }, {{monitor}});
  } catch(e) {
    result.error = e && e.message || String(e);
    finish();
  }
})();
</script></body></html>
""";
    }
}
