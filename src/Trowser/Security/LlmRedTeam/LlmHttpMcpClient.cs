using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Thin HTTP JSON-RPC MCP helper (server-side /api/mcp style) — list tools for DIY abuse.
/// Distinct from in-page WebMCP (<c>navigator.modelContext</c>).
/// </summary>
public static class LlmHttpMcpClient
{
    public sealed class ListToolsResult
    {
        public string Url { get; init; } = "";
        public bool Ok { get; init; }
        public string? Error { get; init; }
        public string? SessionId { get; init; }
        public List<string> ToolNames { get; init; } = [];
        public object? RawTools { get; init; }
    }

    public static async Task<ListToolsResult> ListToolsAsync(
        AutomationContext ctx,
        string url,
        bool includeBrowserCookies = true,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            return new ListToolsResult { Ok = false, Error = "url is required" };

        try
        {
            var initHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json, text/event-stream"
            };
            var initBody =
                """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"trowser","version":"1.0"}}}""";
            var init = await SecurityProbeHttp.FetchAsync(
                ctx, url, "POST", initHeaders, initBody, 20000, includeBrowserCookies, ct);

            string? sessionId = null;
            foreach (var kv in init.ResponseHeaders)
            {
                if (kv.Key.Equals("mcp-session-id", StringComparison.OrdinalIgnoreCase))
                {
                    sessionId = kv.Value;
                    break;
                }
            }

            sessionId ??= TryReadSession(init.Body);

            var listHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json, text/event-stream"
            };
            if (!string.IsNullOrWhiteSpace(sessionId))
                listHeaders["Mcp-Session-Id"] = sessionId!;

            var listBody = """{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}""";
            var listed = await SecurityProbeHttp.FetchAsync(
                ctx, url, "POST", listHeaders, listBody, 20000, includeBrowserCookies, ct);

            var tools = ExtractToolNames(listed.Body);
            return new ListToolsResult
            {
                Url = url,
                Ok = listed.Status is >= 200 and < 300,
                SessionId = sessionId,
                ToolNames = tools.Names,
                RawTools = tools.Raw,
                Error = listed.Status is >= 200 and < 300
                    ? null
                    : $"HTTP {listed.Status}: {Truncate(listed.Body, 200)}"
            };
        }
        catch (Exception ex)
        {
            return new ListToolsResult { Url = url, Ok = false, Error = ex.Message };
        }
    }

    private static string? TryReadSession(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("result", out var result)
                && result.TryGetProperty("sessionId", out var sid))
                return sid.GetString();
        }
        catch { /* ignore */ }
        return null;
    }

    private static (List<string> Names, object? Raw) ExtractToolNames(string? body)
    {
        var names = new List<string>();
        if (string.IsNullOrWhiteSpace(body)) return (names, null);
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("result", out var result)
                && result.TryGetProperty("tools", out var tools)
                && tools.ValueKind == JsonValueKind.Array)
            {
                foreach (var t in tools.EnumerateArray())
                {
                    if (t.TryGetProperty("name", out var n))
                    {
                        var name = n.GetString();
                        if (!string.IsNullOrWhiteSpace(name))
                            names.Add(name!);
                    }
                }
                return (names, JsonNode.Parse(tools.GetRawText()));
            }
        }
        catch { /* ignore */ }
        return (names, null);
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "...");
}
