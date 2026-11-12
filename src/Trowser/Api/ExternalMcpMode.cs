using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser.Api;

/// <summary>
/// Tool pack for external <c>POST /mcp</c> clients. Separate from built-in Chat
/// <see cref="Chat.InteractionMode"/> (Chat / Economical / Full).
/// </summary>
[JsonConverter(typeof(ExternalMcpModeJsonConverter))]
public enum ExternalMcpMode
{
    /// <summary>Interact, observe, quality audits, and basic security scan (<c>browser_security_auto_scan</c>).</summary>
    Core,
    /// <summary>Complete MCP surface: core plus specialist scanners, intercept/mock, identities, and peers.</summary>
    Security
}

/// <summary>
/// Reads <c>core</c>/<c>security</c> (and legacy aliases including <c>full</c> → Security). Legacy numeric
/// <see cref="Chat.InteractionMode"/> values in api-user.json map to <see cref="ExternalMcpMode.Core"/>.
/// </summary>
public sealed class ExternalMcpModeJsonConverter : JsonConverter<ExternalMcpMode>
{
    public override ExternalMcpMode Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number)
            return ExternalMcpMode.Core;
        if (reader.TokenType == JsonTokenType.String)
            return McpClientConfig.TryParseMode(reader.GetString()) ?? ExternalMcpMode.Core;
        reader.Skip();
        return ExternalMcpMode.Core;
    }

    public override void Write(Utf8JsonWriter writer, ExternalMcpMode value, JsonSerializerOptions options) =>
        writer.WriteStringValue(McpClientConfig.FormatMode(value));
}
