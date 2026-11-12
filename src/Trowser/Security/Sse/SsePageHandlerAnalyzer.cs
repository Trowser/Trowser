using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.WebSocket;

namespace Trowser.Security.Sse;

/// <summary>Scan page scripts for dangerous EventSource <c>onmessage</c> / <c>addEventListener</c> sinks.</summary>
public static class SsePageHandlerAnalyzer
{
    private static readonly Regex EsHandlerPattern = new(
        @"new\s+EventSource|\.onmessage\s*=|addEventListener\s*\(\s*['""]message['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DangerousConsumePattern = new(
        @"\beval\s*\(|new\s+Function\s*\(|\.innerHTML\s*=|insertAdjacentHTML\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EvalEventDataPattern = new(
        @"\beval\s*\(\s*(event\.data|e\.data)|\.innerHTML\s*=\s*(event\.data|e\.data)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static async Task<List<SseAuditFinding>> AnalyzeAsync(AutomationContext ctx)
    {
        var findings = new List<SseAuditFinding>();
        try
        {
            var json = await ctx.ExecuteJs("""
                (function(){
                  var out = [];
                  var scripts = document.querySelectorAll('script:not([src])');
                  scripts.forEach(function(s){
                    var t = s.textContent || '';
                    if (!t) return;
                    if (/new EventSource|\.onmessage\s*=|addEventListener\s*\(\s*['"]message['"]/i.test(t))
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
                if (!EsHandlerPattern.IsMatch(text)) continue;
                if (!DangerousConsumePattern.IsMatch(text) && !EvalEventDataPattern.IsMatch(text)) continue;

                findings.Add(new SseAuditFinding
                {
                    Check = "event-data-sink",
                    Severity = "high",
                    Title = "EventSource handler may execute or HTML-sink inbound event data",
                    Detail = "Inline script registers EventSource/message handling and uses eval, Function, or innerHTML on event data.",
                    Evidence = text.Length > 240 ? text[..240] + "..." : text,
                    Remediation = "Parse event data safely; never eval or assign raw event.data to innerHTML."
                });
                break;
            }
        }
        catch
        {
            /* best-effort */
        }

        return findings;
    }
}
