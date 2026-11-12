using System.Text.Json;

namespace Trowser.ApiTests;

internal static class McpContent
{
    public static string FirstText(JsonElement toolsCallResponse)
    {
        if (!toolsCallResponse.TryGetProperty("result", out var result))
            return "";
        if (!result.TryGetProperty("content", out var content))
            return "";
        foreach (var block in content.EnumerateArray())
        {
            if (block.TryGetProperty("text", out var text))
                return text.GetString() ?? "";
        }
        return "";
    }
}
