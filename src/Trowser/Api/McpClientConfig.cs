using System.IO;
using System.Text;
using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// Builds copy-paste MCP client configuration snippets for common agents.
/// Embeds the live API key so localhost setups work without env-var restart quirks.
/// Optional env-var form remains documented for shareable configs.
/// </summary>
public static class McpClientConfig
{
    public enum ClientKind
    {
        OpenCode,
        Cursor,
        ClaudeCode,
        CopilotCli
    }

    public const string ApiKeyEnvVar = "TROWSER_API_KEY";

    public static IReadOnlyList<(ClientKind Kind, string DisplayName)> Clients { get; } =
    [
        (ClientKind.OpenCode, "OpenCode"),
        (ClientKind.Cursor, "Cursor"),
        (ClientKind.ClaudeCode, "Claude Code"),
        (ClientKind.CopilotCli, "GitHub Copilot CLI")
    ];

    public static string FormatMode(ExternalMcpMode mode) =>
        mode == ExternalMcpMode.Security ? "security" : "core";

    /// <summary>
    /// Parse <c>core</c>/<c>security</c> (case-insensitive). Returns null if unrecognized.
    /// Legacy aliases: <c>economical</c>, <c>eco</c>, <c>agent</c>, <c>chat</c> → Core;
    /// <c>full</c> → Security.
    /// </summary>
    public static ExternalMcpMode? TryParseMode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return value.Trim().ToLowerInvariant() switch
        {
            "core" or "economical" or "eco" or "agent" or "chat" => ExternalMcpMode.Core,
            "security" or "full" => ExternalMcpMode.Security,
            _ => null
        };
    }

    public static string BuildMcpUrl(int port, ExternalMcpMode mode) =>
        $"http://localhost:{port}/mcp?mode={FormatMode(mode)}";

    /// <summary>Bearer value with the client's env-var interpolation syntax (for shareable configs).</summary>
    public static string BearerEnvRef(ClientKind client) => client switch
    {
        ClientKind.OpenCode => $"Bearer {{env:{ApiKeyEnvVar}}}",
        ClientKind.Cursor => $"Bearer ${{env:{ApiKeyEnvVar}}}",
        ClientKind.ClaudeCode => $"Bearer ${{{ApiKeyEnvVar}}}",
        ClientKind.CopilotCli => $"Bearer ${{{ApiKeyEnvVar}}}",
        _ => $"Bearer ${{{ApiKeyEnvVar}}}"
    };

    /// <summary>A starter prompt for Claude Code, opened by the LLM Settings launch button.</summary>
    public sealed record ClaudeStarter(string Name, ExternalMcpMode Mode, string Prompt);

    public static IReadOnlyList<ClaudeStarter> ClaudeStarters { get; } =
    [
        new("Explore a site", ExternalMcpMode.Core,
            "You are connected to Trowser through the MCP server named trowser. Check that its tools respond, then ask me which site to explore and what I am testing. Then navigate, look around, and report what you find with evidence."),
        new("Accessibility check", ExternalMcpMode.Core,
            "You are connected to Trowser through the MCP server named trowser. Ask me for the page URL, then run the accessibility checks on it and report the findings by severity with evidence."),
        new("Security check (safe mode)", ExternalMcpMode.Security,
            "You are connected to Trowser through the MCP server named trowser in security mode. Stay in safe mode: run only passive checks unless I approve an active probe. Ask me for the target URL before you start."),
        new("Write a regression script", ExternalMcpMode.Core,
            "You are connected to Trowser through the MCP server named trowser. Ask me what flow to cover. Then drive the browser through it and write a C# .csx script that repeats the steps.")
    ];

    /// <summary>
    /// Build the command line that registers Trowser with Claude Code (user scope) and starts a
    /// session with <paramref name="starter"/>. Removes any old registration first so the key is current.
    /// </summary>
    public static string BuildClaudeCodeLaunch(int port, ClaudeStarter starter, string? apiKey)
    {
        var url = BuildMcpUrl(port, starter.Mode);
        var bearer = string.IsNullOrWhiteSpace(apiKey) ? "trowser_YOUR_API_KEY" : apiKey.Trim();
        var prompt = starter.Prompt.Replace("'", "''");
        return
            "claude mcp remove trowser -s user 2>$null; " +
            $"claude mcp add -s user --transport http trowser \"{url}\" --header \"Authorization: Bearer {bearer}\"; " +
            $"claude '{prompt}'";
    }

    /// <summary>
    /// Build a ready-to-paste JSON config for the selected client.
    /// Embeds <paramref name="apiKey"/> when provided so Cursor/etc. work without a restart.
    /// </summary>
    public static string Build(ClientKind client, int port, ExternalMcpMode mode, string? apiKey = null)
    {
        var url = BuildMcpUrl(port, mode);
        var bearer = string.IsNullOrWhiteSpace(apiKey) ? "trowser_YOUR_API_KEY" : apiKey.Trim();
        var auth = $"Bearer {bearer}";

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            switch (client)
            {
                case ClientKind.OpenCode:
                    writer.WriteString("$schema", "https://opencode.ai/config.json");
                    writer.WritePropertyName("mcp");
                    writer.WriteStartObject();
                    WriteRemoteServer(writer, "trowser", url, auth,
                        type: "remote", includeOauthFalse: true, includeToolsAll: false);
                    writer.WriteEndObject();
                    break;

                case ClientKind.Cursor:
                    writer.WritePropertyName("mcpServers");
                    writer.WriteStartObject();
                    WriteRemoteServer(writer, "trowser", url, auth,
                        type: null, includeOauthFalse: false, includeToolsAll: false);
                    writer.WriteEndObject();
                    break;

                case ClientKind.ClaudeCode:
                    writer.WritePropertyName("mcpServers");
                    writer.WriteStartObject();
                    WriteRemoteServer(writer, "trowser", url, auth,
                        type: "http", includeOauthFalse: false, includeToolsAll: false);
                    writer.WriteEndObject();
                    break;

                case ClientKind.CopilotCli:
                    writer.WritePropertyName("mcpServers");
                    writer.WriteStartObject();
                    WriteRemoteServer(writer, "trowser", url, auth,
                        type: "http", includeOauthFalse: false, includeToolsAll: true);
                    writer.WriteEndObject();
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(client));
            }
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + Environment.NewLine;
    }

    private static void WriteRemoteServer(
        Utf8JsonWriter writer, string name, string url, string auth,
        string? type, bool includeOauthFalse, bool includeToolsAll)
    {
        writer.WritePropertyName(name);
        writer.WriteStartObject();
        if (type != null)
            writer.WriteString("type", type);
        writer.WriteString("url", url);
        if (includeOauthFalse)
        {
            writer.WriteBoolean("enabled", true);
            writer.WriteBoolean("oauth", false);
        }
        writer.WritePropertyName("headers");
        writer.WriteStartObject();
        writer.WriteString("Authorization", auth);
        writer.WriteEndObject();
        if (includeToolsAll)
        {
            writer.WritePropertyName("tools");
            writer.WriteStartArray();
            writer.WriteStringValue("*");
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }
}
