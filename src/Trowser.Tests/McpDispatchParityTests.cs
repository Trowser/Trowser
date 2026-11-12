using System.IO;
using System.Text.RegularExpressions;
using Xunit;

namespace Trowser.Tests;

/// <summary>
/// Every tool advertised in <c>tools/list</c> must have an arm in the single dispatch switch
/// (<c>McpHandler.ExecuteToolAsync</c>); otherwise MCP clients see the tool but get "Unknown tool".
/// </summary>
public class McpDispatchParityTests
{
    private static string ApiDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "Trowser", "Api");
    }

    [Fact]
    public void Every_defined_tool_is_dispatched()
    {
        var api = ApiDir();
        var defined = Regex.Matches(File.ReadAllText(Path.Combine(api, "McpHandler.ToolDefinitions.cs")),
                @"\bTool\(""(browser_\w+)""")
            .Select(m => m.Groups[1].Value)
            .ToHashSet();
        var dispatched = Regex.Matches(File.ReadAllText(Path.Combine(api, "McpHandler.Protocol.cs")),
                @"^\s*""(browser_\w+)"" =>", RegexOptions.Multiline)
            .Select(m => m.Groups[1].Value)
            .ToHashSet();

        Assert.NotEmpty(defined);
        var missing = defined.Where(t => !dispatched.Contains(t)).OrderBy(t => t).ToList();
        Assert.True(missing.Count == 0, "Defined but not dispatched: " + string.Join(", ", missing));
    }
}
