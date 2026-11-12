using System.Text.Encodings.Web;
using System.Text.Json;
using Trowser.Api;

namespace Trowser.Chat;

/// <summary>
/// Bridges LLM tool calls to the McpHandler, executing browser automation
/// tools and returning results as JSON strings for the LLM.
/// </summary>
public class LlmToolExecutor
{
    private readonly McpHandler _mcpHandler;

    /// <summary>GitHub Copilot chat/completions rejects requests with more than 128 tools.</summary>
    public const int CopilotMaxTools = 128;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        // Preserve emoji / © / non-ASCII literally for the model (same as MCP/REST).
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly HashSet<string> CopilotUnsupportedSchemaKeys = new(StringComparer.Ordinal)
    {
        "anyOf", "allOf", "oneOf", "not",
        "if", "then", "else",
        "$ref", "$defs", "$schema", "$id", "$comment",
        "unevaluatedProperties", "patternProperties",
        "dependentSchemas", "dependentRequired"
    };

    public LlmToolExecutor(McpHandler mcpHandler)
    {
        _mcpHandler = mcpHandler;
    }

    /// <summary>
    /// Asks the user to approve a call flagged by <see cref="ChatToolApproval"/>
    /// (tool name, raw arguments, reason). Null means every flagged call is refused.
    /// </summary>
    public Func<string, string, string, Task<bool>>? ConfirmAsync { get; set; }

    /// <summary>
    /// Execute a tool call and return the result as a JSON string for the LLM.
    /// </summary>
    public async Task<string> ExecuteAsync(string toolName, string argumentsJson)
    {
        try
        {
            var args = string.IsNullOrWhiteSpace(argumentsJson) || argumentsJson == "{}"
                ? default
                : JsonDocument.Parse(argumentsJson).RootElement;

            var reason = ChatToolApproval.RequiresConfirmation(toolName, args);
            if (reason != null)
            {
                var approved = ConfirmAsync != null
                    && await ConfirmAsync(toolName, argumentsJson ?? "", reason).ConfigureAwait(false);
                if (!approved)
                {
                    return JsonSerializer.Serialize(new
                    {
                        error = $"The user declined {toolName}. Do not retry it; explain what you wanted to do and ask the user."
                    }, JsonOptions);
                }
            }

            var result = await _mcpHandler.ExecuteToolAsync(toolName, args);
            return JsonSerializer.Serialize(result, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    /// <summary>
    /// Returns the MCP tool definitions for the current mode.
    /// </summary>
    public List<object> GetToolDefinitions() =>
        _mcpHandler.GetToolDefinitions(_mcpHandler.Mode);

    /// <summary>
    /// Journal + snapshot first when a provider caps tools at <see cref="CopilotMaxTools"/>.
    /// Definition order otherwise drops these (they sit near the end of the full tool list).
    /// </summary>
    private static readonly string[] ProviderCapKeepFirst =
    [
        "browser_snapshot",
        "browser_take_screenshot",
        "browser_journal_add", "browser_journal_get", "browser_journal_export", "browser_journal_update", "browser_journal_delete",
        "browser_compact", "browser_session_memory"
    ];

    /// <summary>
    /// Returns tool definitions formatted for OpenAI function calling.
    /// Capped at <see cref="CopilotMaxTools"/> with core/journal tools kept first
    /// (OpenAI-compatible APIs reject more than 128 functions).
    /// </summary>
    public List<object> GetOpenAiToolDefinitions()
    {
        var mcpTools = CapMcpToolsForProvider(GetToolDefinitions(), "OpenAI-compatible");
        var openAiTools = new List<object>();

        foreach (var tool in mcpTools)
        {
            var json = JsonSerializer.Serialize(tool, JsonOptions);
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var name = root.GetProperty("name").GetString()!;
            var description = root.GetProperty("description").GetString()!;
            var inputSchema = root.GetProperty("inputSchema");

            openAiTools.Add(new Dictionary<string, object>
            {
                ["type"] = "function",
                ["function"] = new Dictionary<string, object>
                {
                    ["name"] = name,
                    ["description"] = description,
                    ["parameters"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                        inputSchema.GetRawText(), JsonOptions)!
                }
            });
        }

        return openAiTools;
    }

    /// <summary>
    /// OpenAI-style tools flattened for GitHub Copilot: no anyOf/allOf/oneOf, non-empty
    /// descriptions, and at most <see cref="CopilotMaxTools"/> entries (core/journal first).
    /// </summary>
    public List<object> GetCopilotOpenAiToolDefinitions()
    {
        var mcpTools = CapMcpToolsForProvider(GetToolDefinitions(), "GitHub Copilot");
        var openAiTools = new List<object>();

        foreach (var tool in mcpTools)
        {
            var json = JsonSerializer.Serialize(tool, JsonOptions);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var name = root.GetProperty("name").GetString() ?? "";
            var description = root.GetProperty("description").GetString();
            if (string.IsNullOrWhiteSpace(description))
                description = string.IsNullOrEmpty(name) ? "tool" : name;

            var inputSchema = root.TryGetProperty("inputSchema", out var schemaEl)
                ? schemaEl
                : default;
            var parameters = inputSchema.ValueKind == JsonValueKind.Object
                ? SanitizeCopilotJsonSchema(inputSchema)
                : new Dictionary<string, object?> { ["type"] = "object", ["properties"] = new Dictionary<string, object?>() };

            openAiTools.Add(new Dictionary<string, object>
            {
                ["type"] = "function",
                ["function"] = new Dictionary<string, object>
                {
                    ["name"] = name,
                    ["description"] = description,
                    ["parameters"] = parameters
                }
            });
        }

        return openAiTools;
    }

    /// <summary>
    /// Keep snapshot, screenshot, and journal first, then the Core pack, then remaining tools until
    /// <see cref="CopilotMaxTools"/>. Naive first-N truncation dropped journal
    /// (tools near the end of the full catalog) along with console/network/fetch.
    /// </summary>
    internal static List<object> CapMcpToolsForProvider(List<object> mcpTools, string providerLabel)
    {
        if (mcpTools.Count <= CopilotMaxTools)
            return mcpTools;

        var named = new List<(string Name, object Tool)>(mcpTools.Count);
        foreach (var tool in mcpTools)
        {
            var name = ReadToolName(tool);
            if (!string.IsNullOrEmpty(name))
                named.Add((name, tool));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var ordered = new List<object>(CopilotMaxTools);

        void Take(Func<string, bool> include)
        {
            foreach (var (name, tool) in named)
            {
                if (ordered.Count >= CopilotMaxTools)
                    return;
                if (!include(name) || !seen.Add(name))
                    continue;
                ordered.Add(tool);
            }
        }

        Take(n => ProviderCapKeepFirst.Contains(n));
        Take(McpHandler.IsCoreTool);
        Take(_ => true);

        var omitted = named.Count - ordered.Count;
        if (omitted > 0)
        {
            TrowserLog.Warn(
                $"{providerLabel} allows at most {CopilotMaxTools} tools; " +
                $"keeping journal/core tools and omitting {omitted} specialist tools.");
        }

        return ordered;
    }

    private static string? ReadToolName(object tool)
    {
        var json = JsonSerializer.Serialize(tool, JsonOptions);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.TryGetProperty("name", out var n) ? n.GetString() : null;
    }

    /// <summary>
    /// Copilot's completions API accepts only a subset of JSON Schema. Locator tools use
    /// top-level <c>anyOf</c>/<c>allOf</c>, which CAPI rejects with HTTP 400.
    /// </summary>
    internal static object SanitizeCopilotJsonSchema(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var obj = new Dictionary<string, object?>();
                foreach (var prop in el.EnumerateObject())
                {
                    if (CopilotUnsupportedSchemaKeys.Contains(prop.Name))
                        continue;
                    obj[prop.Name] = SanitizeCopilotJsonSchema(prop.Value);
                }

                if (obj.TryGetValue("type", out var typeVal) && typeVal is string type)
                {
                    if (type == "array" && !obj.ContainsKey("items"))
                    {
                        obj["items"] = new Dictionary<string, object?>
                        {
                            ["type"] = "object",
                            ["additionalProperties"] = true
                        };
                    }
                    else if (type == "object" &&
                             !obj.ContainsKey("properties") &&
                             !obj.ContainsKey("additionalProperties"))
                    {
                        obj["additionalProperties"] = true;
                    }
                }

                return obj;
            }
            case JsonValueKind.Array:
                return el.EnumerateArray().Select(SanitizeCopilotJsonSchema).ToList();
            case JsonValueKind.String:
                return el.GetString() ?? "";
            case JsonValueKind.Number:
                if (el.TryGetInt64(out var n))
                    return n;
                return el.GetDouble();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            default:
                return null!;
        }
    }

    /// <summary>
    /// Returns tool definitions formatted for the Anthropic API.
    /// </summary>
    public List<object> GetAnthropicToolDefinitions()
    {
        var mcpTools = GetToolDefinitions();
        var anthropicTools = new List<object>();

        foreach (var tool in mcpTools)
        {
            var json = JsonSerializer.Serialize(tool, JsonOptions);
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var name = root.GetProperty("name").GetString()!;
            var description = root.GetProperty("description").GetString()!;
            var inputSchema = root.GetProperty("inputSchema");

            anthropicTools.Add(new Dictionary<string, object>
            {
                ["name"] = name,
                ["description"] = description,
                ["input_schema"] = JsonSerializer.Deserialize<Dictionary<string, object>>(
                    inputSchema.GetRawText(), JsonOptions)!
            });
        }

        return anthropicTools;
    }
}
