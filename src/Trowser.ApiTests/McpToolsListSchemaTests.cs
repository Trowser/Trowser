using System.Text.Json;
using Xunit;

namespace Trowser.ApiTests;

[Collection(BrowserCollection.Name)]
[Trait("Category", "Smoke")]
public class McpToolsListSchemaTests
{
    private readonly TrowserInstance _instance;

    public McpToolsListSchemaTests(TrowserInstance instance) => _instance = instance;

    [Fact]
    public async Task Every_listed_tool_has_object_schema_with_valid_required_keys()
    {
        var mcp = new McpClient(_instance);
        await mcp.InitializeAsync();
        var tools = await mcp.ToolsListAsync();

        var problems = new List<string>();
        foreach (var tool in tools.EnumerateArray())
        {
            var name = tool.GetProperty("name").GetString() ?? "";
            if (!tool.TryGetProperty("description", out var desc) || string.IsNullOrWhiteSpace(desc.GetString()))
                problems.Add($"{name}: missing description");

            if (!tool.TryGetProperty("inputSchema", out var schema))
            {
                problems.Add($"{name}: missing inputSchema");
                continue;
            }

            if (schema.TryGetProperty("type", out var type) && type.GetString() != "object")
                problems.Add($"{name}: inputSchema.type is not object");

            var hasProperties = schema.TryGetProperty("properties", out var props)
                                && props.ValueKind == JsonValueKind.Object
                                && props.EnumerateObject().Any();

            var requiredKeys = new List<string>();
            if (schema.TryGetProperty("required", out var required) && required.ValueKind == JsonValueKind.Array)
            {
                foreach (var req in required.EnumerateArray())
                {
                    var key = req.GetString();
                    if (key != null) requiredKeys.Add(key);
                }
            }

            if (requiredKeys.Count > 0 && !hasProperties)
                problems.Add($"{name}: required fields declared but inputSchema.properties missing or empty");

            if (requiredKeys.Count > 0 && hasProperties)
            {
                var propNames = props!.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
                foreach (var key in requiredKeys)
                {
                    if (!propNames.Contains(key))
                        problems.Add($"{name}: required '{key}' not in properties");
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join("\n", problems.Take(30)));
    }
}
