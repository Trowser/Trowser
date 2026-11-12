using System.Text.RegularExpressions;
using Xunit;

namespace Trowser.Tests;

/// <summary>
/// MCP tool rows in <c>trowser-api-index.md</c> should name a real REST route when they claim one.
/// </summary>
public class McpRestHintTests
{
    private static readonly Regex RouteRow = new(@"^\| (GET|POST|PUT|DELETE|PATCH) \| `(/[^`]+)`", RegexOptions.Compiled);
    private static readonly Regex ToolRow = new(@"^\| `(browser_\w+)` \| ([^|]+) \|", RegexOptions.Compiled);
    private static readonly Regex SingleHint = new(@"^(GET|POST|PUT|DELETE|PATCH) (/api/\S+)$", RegexOptions.Compiled);

    private static string[] IndexLines()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllLines(Path.Combine(dir!.FullName, "trowserkit", "trowser-api-index.md"));
    }

    [Fact]
    public void Single_method_rest_hints_point_at_indexed_routes()
    {
        var lines = IndexLines();
        var routes = lines.Select(l => RouteRow.Match(l)).Where(m => m.Success)
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value)).ToHashSet();

        var bad = new List<string>();
        foreach (var m in lines.Select(l => ToolRow.Match(l)).Where(m => m.Success))
        {
            var tool = m.Groups[1].Value;
            var hint = m.Groups[2].Value.Trim();
            if (hint.StartsWith('(') ||
                hint.Contains('*', StringComparison.Ordinal) ||
                hint.Contains(" or ", StringComparison.Ordinal) ||
                hint.Contains("GET/PUT", StringComparison.Ordinal) ||
                hint.Contains("GET/POST", StringComparison.Ordinal))
            {
                continue;
            }

            var hm = SingleHint.Match(hint);
            if (!hm.Success)
                continue;

            var key = (hm.Groups[1].Value, hm.Groups[2].Value);
            if (!routes.Contains(key))
                bad.Add($"{tool} → {hint}");
        }

        Assert.True(bad.Count == 0,
            "MCP REST hints that do not match a REST row in trowser-api-index.md:\n" + string.Join("\n", bad));
    }
}
