namespace Trowser.Chat;

public enum ChatRole
{
    System,
    User,
    Assistant,
    Tool
}

/// <summary>
/// A single tool call requested by the LLM.
/// </summary>
public class ToolCall
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string ArgumentsJson { get; set; } = "{}";
}

/// <summary>
/// A message in the chat conversation. Supports text, tool calls, and tool results.
/// </summary>
public class ChatMessage
{
    public ChatRole Role { get; set; }
    public string? Content { get; set; }
    public List<ToolCall>? ToolCalls { get; set; }

    /// <summary>For Role=Tool: the id of the tool call this is a result for.</summary>
    public string? ToolCallId { get; set; }

    /// <summary>For Role=Tool: the name of the tool.</summary>
    public string? ToolName { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.Now;

    public static ChatMessage System(string content) =>
        new() { Role = ChatRole.System, Content = content };

    public static ChatMessage FromUser(string content) =>
        new() { Role = ChatRole.User, Content = content };

    public static ChatMessage FromAssistant(string? content, List<ToolCall>? toolCalls = null) =>
        new() { Role = ChatRole.Assistant, Content = content, ToolCalls = toolCalls };

    public static ChatMessage ToolResult(string toolCallId, string toolName, string content) =>
        new() { Role = ChatRole.Tool, Content = content, ToolCallId = toolCallId, ToolName = toolName };
}
