using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.WebSocket;

/// <summary>Static scan of page scripts for dangerous WebSocket message handlers (eval/Function on event.data).</summary>
public static class WebSocketPageHandlerAnalyzer
{
    private static readonly Regex WsHandlerPattern = new(
        @"new\s+WebSocket|\.onmessage\s*=|addEventListener\s*\(\s*['""]message['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DangerousConsumePattern = new(
        @"\beval\s*\(|new\s+Function\s*\(|\.constructor\s*\(|setTimeout\s*\(\s*[^,]+,\s*0\s*\)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EvalEventDataPattern = new(
        @"\beval\s*\(\s*(event\.data|e\.data|message\.data|msg\.data|JSON\.parse\s*\(\s*event\.data)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static async Task<List<WebSocketAuditFinding>> AnalyzeAsync(AutomationContext ctx)
    {
        var findings = new List<WebSocketAuditFinding>();
        try
        {
            var pageUrl = await ctx.GetCurrentUrl();
            findings.AddRange(ScanCapturedScriptBodies(ctx, pageUrl));
            if (findings.Count > 0)
                return findings;

            var json = await ctx.ExecuteJs("""
                (function(){
                  var out = [];
                  var scripts = document.querySelectorAll('script:not([src])');
                  scripts.forEach(function(s){
                    var t = s.textContent || '';
                    if (!t) return;
                    if (/new WebSocket|\.onmessage\s*=|addEventListener\s*\(\s*['"]message['"]/i.test(t))
                      out.push(t.slice(0, 1200));
                  });
                  return JSON.stringify(out);
                })()
                """);
            var raw = json.Trim();
            if (raw.Length >= 2 && raw[0] == '"')
                raw = JsonSerializer.Deserialize<string>(raw) ?? "[]";

            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                return findings;

            foreach (var block in doc.RootElement.EnumerateArray())
            {
                var text = block.GetString();
                if (string.IsNullOrWhiteSpace(text)) continue;
                if (!WsHandlerPattern.IsMatch(text)) continue;
                if (!DangerousConsumePattern.IsMatch(text) && !EvalEventDataPattern.IsMatch(text)) continue;

                findings.Add(MakeHandlerFinding(text, "inline script"));
                break;
            }
        }
        catch
        {
            /* best-effort */
        }

        return findings;
    }

    private static IEnumerable<WebSocketAuditFinding> ScanCapturedScriptBodies(AutomationContext ctx, string? pageUrl)
    {
        if (string.IsNullOrEmpty(pageUrl) || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            yield break;

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        foreach (var entry in ctx.Network.Entries
                     .Where(e => e.StatusCode is >= 200 and < 400 && !string.IsNullOrEmpty(e.ResponseBody))
                     .Where(e => e.Url.Contains(".js", StringComparison.OrdinalIgnoreCase)
                                 || (e.ResponseHeaders.Values.Any(h => h.Contains("javascript", StringComparison.OrdinalIgnoreCase))))
                     .Take(60))
        {
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var scriptUri)) continue;
            if (!string.Equals(scriptUri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var body = entry.ResponseBody!;
            if (body.Length is 0 or > 512_000) continue;
            if (!WsHandlerPattern.IsMatch(body)) continue;
            if (!DangerousConsumePattern.IsMatch(body) && !EvalEventDataPattern.IsMatch(body)) continue;

            yield return MakeHandlerFinding(body, scriptUri.AbsolutePath);
            yield break;
        }
    }

    private static WebSocketAuditFinding MakeHandlerFinding(string text, string sourceLabel) =>
        new()
        {
            Check = "message-handler",
            Severity = "high",
            Title = "WebSocket message handler may execute inbound data",
            Detail = $"Page script ({sourceLabel}) registers a WebSocket message listener and uses eval/Function (or similar) " +
                     "on message content — same class of risk as postMessage→eval sinks.",
            Evidence = text.Length > 240 ? text[..240] + "..." : text,
            Remediation = "Never eval WebSocket frames. Parse JSON safely and validate message types server-side. " +
                          "Run POST /api/security/websocket-fuzz with ws-code-exec-oracle probes."
        };
}
