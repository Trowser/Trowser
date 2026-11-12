using System.Text.Json;
using Xunit;

namespace Trowser.ApiTests;

internal static class McpAssert
{
    public static void NotError(JsonElement toolsCallResponse, string toolName)
    {
        if (toolsCallResponse.TryGetProperty("result", out var result)
            && result.TryGetProperty("isError", out var isError)
            && isError.GetBoolean())
        {
            var text = McpContent.FirstText(toolsCallResponse);
            Assert.Fail($"{toolName} returned isError: {text}");
        }
    }
}
