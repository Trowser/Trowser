using System.IO;
using System.Text.RegularExpressions;
using Xunit;

namespace Trowser.Tests;

public class McpToolSchemaTests
{
    private static string ApiDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "Trowser", "Api");
    }

    private static HashSet<string> ParseToolNames(string definitionsText) =>
        Regex.Matches(definitionsText, @"\bTool\(""(?<n>(?:browser_\w+|get_test_heuristics))""")
            .Select(m => m.Groups["n"].Value)
            .ToHashSet();

    private static HashSet<string> ParseDispatchedTools(string protocolText) =>
        Regex.Matches(protocolText, @"^\s*""(?<n>(?:browser_\w+|get_test_heuristics))"" =>", RegexOptions.Multiline)
            .Select(m => m.Groups["n"].Value)
            .ToHashSet();

    private static HashSet<string> ParseCorePack(string definitionsText)
    {
        var start = definitionsText.IndexOf("CoreTools =", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var slice = definitionsText[start..];
        var end = slice.IndexOf("];", StringComparison.Ordinal);
        var block = slice[..end];
        return Regex.Matches(block, @"""([^""]+)""")
            .Select(m => m.Groups[1].Value)
            .ToHashSet();
    }

    [Fact]
    public void Every_defined_tool_is_dispatched()
    {
        var api = ApiDir();
        var defined = ParseToolNames(File.ReadAllText(Path.Combine(api, "McpHandler.ToolDefinitions.cs")));
        var dispatched = ParseDispatchedTools(File.ReadAllText(Path.Combine(api, "McpHandler.Protocol.cs")));
        Assert.NotEmpty(defined);
        var missing = defined.Where(t => !dispatched.Contains(t)).OrderBy(t => t).ToList();
        Assert.True(missing.Count == 0, "Defined but not dispatched: " + string.Join(", ", missing));
    }

    [Fact]
    public void Core_pack_tools_are_defined()
    {
        var text = File.ReadAllText(Path.Combine(ApiDir(), "McpHandler.ToolDefinitions.cs"));
        var defined = ParseToolNames(text);
        var core = ParseCorePack(text);
        var missing = core.Where(t => !defined.Contains(t)).OrderBy(t => t).ToList();
        Assert.True(missing.Count == 0, "Core pack tools missing from definitions: " + string.Join(", ", missing));
    }

    [Fact]
    public void Tool_catalog_is_substantial()
    {
        var defined = ParseToolNames(File.ReadAllText(Path.Combine(ApiDir(), "McpHandler.ToolDefinitions.cs")));
        Assert.True(defined.Count >= 200, $"Expected 200+ MCP tools, found {defined.Count}");
    }
}
