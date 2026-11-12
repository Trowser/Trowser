using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Api;
using Xunit;

namespace Trowser.Tests;

/// <summary>
/// <c>--safe</c> must block the same operations over REST and MCP. The API index
/// (<c>trowserkit/trowser-api-index.md</c>, generated from source) lists every route and, for
/// each MCP tool, the REST route it wraps; these tests hold the policy to both.
/// </summary>
public class SafeModePolicyTests
{
    private static readonly Regex RouteRow = new(@"^\| (GET|POST|PUT|DELETE|PATCH) \| `(/[^`]+)`", RegexOptions.Compiled);
    private static readonly Regex ToolRow = new(@"^\| `(browser_\w+)` \| (GET|POST|PUT|DELETE|PATCH) (/\S+) \|", RegexOptions.Compiled);

    private static string[] IndexLines()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Trowser.sln")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllLines(Path.Combine(dir!.FullName, "trowserkit", "trowser-api-index.md"));
    }

    private static HashSet<(string Method, string Path)> Routes(string[] lines) =>
        lines.Select(l => RouteRow.Match(l)).Where(m => m.Success)
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value)).ToHashSet();

    [Fact]
    public void Tool_and_its_rest_route_are_blocked_alike()
    {
        var lines = IndexLines();
        var routes = Routes(lines);
        var mismatches = new List<string>();

        foreach (var m in lines.Select(l => ToolRow.Match(l)).Where(m => m.Success))
        {
            var tool = m.Groups[1].Value;
            var method = m.Groups[2].Value;
            var path = m.Groups[3].Value;
            if (!routes.Contains((method, path)))
                continue; // index synthesizes a pseudo-route for tools without a REST twin

            var toolBlocked = SafeModePolicy.IsToolBlocked(tool, default);
            var routeBlocked = SafeModePolicy.IsRouteBlocked(path, method, null);
            if (toolBlocked != routeBlocked)
                mismatches.Add($"{tool} (blocked={toolBlocked}) vs {method} {path} (blocked={routeBlocked})");
        }

        Assert.True(mismatches.Count == 0, "Safe-mode REST/MCP drift:\n" + string.Join("\n", mismatches));
    }

    [Fact]
    public void Every_blocked_operation_exists()
    {
        var lines = IndexLines();
        var routeKeys = Routes(lines).Where(r => r.Method != "GET").Select(r => SafeModePolicy.RouteKey(r.Path)).ToHashSet();
        var toolKeys = lines.Select(l => Regex.Match(l, @"^\| `(browser_\w+)`")).Where(m => m.Success)
            .Select(m => SafeModePolicy.ToolKey(m.Groups[1].Value)).OfType<string>().ToHashSet();

        var dead = SafeModePolicy.BlockedOperations.Where(k => !routeKeys.Contains(k) && !toolKeys.Contains(k)).ToList();
        Assert.True(dead.Count == 0, "Blocked operations that match no route or tool (renamed?):\n" + string.Join("\n", dead));
    }

    [Theory]
    [InlineData("POST", "/api/execute-script", true)]
    [InlineData("POST", "/api/fetch-direct", true)]
    [InlineData("POST", "/api/peer/identity/apply", true)]
    [InlineData("POST", "/api/orchestrate/a05-injection", true)]
    [InlineData("POST", "/api/orchestrate/dry-run/a05-injection", false)]
    [InlineData("POST", "/api/race-lab/baseline", true)]
    [InlineData("PUT", "/api/header-overrides", true)]
    [InlineData("GET", "/api/header-overrides", false)]
    [InlineData("GET", "/api/storage", false)]
    [InlineData("POST", "/api/security/storage", false)]
    [InlineData("POST", "/api/click", false)]
    public void Route_decisions(string method, string path, bool blocked) =>
        Assert.Equal(blocked, SafeModePolicy.IsRouteBlocked(path, method, null));

    [Theory]
    [InlineData("browser_run_script", "{}", true)]
    [InlineData("browser_dom_xss_audit", "{}", true)]
    [InlineData("browser_orchestrate_run", "{}", true)]
    [InlineData("browser_orchestrate_dry_run", "{}", false)]
    [InlineData("browser_header_overrides", "{}", false)]
    [InlineData("browser_header_overrides", "{\"action\":\"set\"}", true)]
    [InlineData("browser_security_oauth_flow_test", "{\"passiveOnly\":true}", false)]
    [InlineData("browser_security_oauth_flow_test", "{}", true)]
    [InlineData("browser_security_storage", "{}", false)]
    [InlineData("browser_click", "{}", false)]
    public void Tool_decisions(string tool, string argsJson, bool blocked)
    {
        using var doc = JsonDocument.Parse(argsJson);
        Assert.Equal(blocked, SafeModePolicy.IsToolBlocked(tool, doc.RootElement));
    }

    [Fact]
    public void Passive_oauth_body_is_allowed_over_rest() =>
        Assert.False(SafeModePolicy.IsRouteBlocked("/api/security/oauth-flow-test", "POST", "{\"passiveOnly\":true}"));
}
