using System.Text.Json;
using Trowser.Chat;
using Xunit;

namespace Trowser.Tests;

public class LlmToolSchemaSanitizationTests
{
    [Fact]
    public void Strips_top_level_anyOf_from_element_style_schema()
    {
        const string json = """
            {
              "type": "object",
              "properties": {
                "ref": { "type": "integer", "description": "ref" },
                "selector": { "type": "string" }
              },
              "anyOf": [
                { "required": ["ref"] },
                { "required": ["selector"] }
              ]
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var result = Assert.IsType<Dictionary<string, object?>>(
            LlmToolExecutor.SanitizeLlmProviderJsonSchema(doc.RootElement));

        Assert.Equal("object", result["type"]);
        Assert.DoesNotContain("anyOf", result.Keys);
        Assert.True(result.ContainsKey("properties"));
    }

    [Fact]
    public void Strips_top_level_allOf_from_browser_type_style_schema()
    {
        const string json = """
            {
              "type": "object",
              "properties": { "value": { "type": "string" } },
              "allOf": [
                { "anyOf": [ { "required": ["ref"] } ] },
                { "anyOf": [ { "required": ["value"] } ] }
              ]
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var result = Assert.IsType<Dictionary<string, object?>>(
            LlmToolExecutor.SanitizeLlmProviderJsonSchema(doc.RootElement));

        Assert.DoesNotContain("anyOf", result.Keys);
        Assert.DoesNotContain("allOf", result.Keys);
    }

    [Fact]
    public void Preserves_enum_on_nested_properties()
    {
        const string json = """
            {
              "type": "object",
              "properties": {
                "button": { "type": "string", "enum": ["left", "right"] }
              }
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var result = Assert.IsType<Dictionary<string, object?>>(
            LlmToolExecutor.SanitizeLlmProviderJsonSchema(doc.RootElement));
        var props = Assert.IsType<Dictionary<string, object?>>(result["properties"]);
        var button = Assert.IsType<Dictionary<string, object?>>(props["button"]);
        Assert.Equal(new object[] { "left", "right" }, button["enum"]);
    }

    [Fact]
    public void Strips_enum_and_const_at_parameters_root_only()
    {
        const string json = """
            {
              "type": "object",
              "enum": ["unexpected"],
              "const": "bad",
              "properties": { "x": { "type": "string" } }
            }
            """;

        using var doc = JsonDocument.Parse(json);
        var result = Assert.IsType<Dictionary<string, object?>>(
            LlmToolExecutor.SanitizeLlmProviderJsonSchema(doc.RootElement));

        Assert.DoesNotContain("enum", result.Keys);
        Assert.DoesNotContain("const", result.Keys);
    }
}