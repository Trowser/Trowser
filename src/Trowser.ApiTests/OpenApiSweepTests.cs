using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Readers;
using Trowser.Api;
using Xunit;

namespace Trowser.ApiTests;

public class OpenApiSweepTests
{
    private static string ResolvePath(string template) =>
        System.Text.RegularExpressions.Regex.Replace(template, @"\{[^}]+\}", "test");

    private static OpenApiDocument LoadOpenApi()
    {
        var path = Path.Combine(RepoPaths.Root(), "trowserkit", "swagger", "openapi.yaml");
        using var stream = File.OpenRead(path);
        return new OpenApiStreamReader().Read(stream, out _);
    }

    private static List<(HttpMethod Method, string Path)> AllOperations(OpenApiDocument doc)
    {
        var list = new List<(HttpMethod, string)>();
        foreach (var (p, item) in doc.Paths)
        {
            foreach (var op in item.Operations)
                list.Add((new HttpMethod(op.Key.ToString().ToUpperInvariant()), p));
        }
        return list;
    }

    private static HashSet<(string Method, string Path)> LoadRestDenylist()
    {
        var json = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "sweep-denylist.json"));
        using var doc = JsonDocument.Parse(json);
        var set = new HashSet<(string, string)>();
        foreach (var e in doc.RootElement.GetProperty("rest").EnumerateArray())
            set.Add((e.GetProperty("method").GetString()!, e.GetProperty("path").GetString()!));
        return set;
    }

    [Fact]
    [Trait("Category", "Sweep")]
    public async Task Rest_operations_do_not_return_500_on_bad_input()
    {
        var instance = new TrowserInstance();
        await instance.InitializeAsync();
        try
        {
            var api = new RestClient(instance);
            var deny = LoadRestDenylist();
            var ops = AllOperations(LoadOpenApi());
            var failures = new List<string>();

            foreach (var (method, pathTemplate) in ops)
            {
                var path = ResolvePath(pathTemplate);
                if (deny.Contains((method.Method, pathTemplate)))
                    continue;

                var attempts = new (object? Body, string Label)[]
                {
                    (null, "empty"),
                    (new { }, "empty-object"),
                    (new { definitelyNotAValidField = 12345, nested = new { x = true } }, "noise-object")
                };

                foreach (var (body, label) in attempts)
                {
                    var (status, doc) = await api.SendAsync(method, path, body);
                    using (doc)
                    {
                        if (status == 500)
                            failures.Add($"{method} {path} ({label}) => 500");
                    }
                }

                var ping = await api.SendAsync(HttpMethod.Get, "/api/ping", null);
                ping.Json.Dispose();
                if (ping.Status != 200)
                    failures.Add($"Gate hung after {method} {path} (ping {ping.Status})");
            }

            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(40)));
        }
        finally
        {
            instance.Dispose();
        }
    }

    private static List<(string Method, string Path)> IndexPostRoutes()
    {
        var indexPath = Path.Combine(RepoPaths.Root(), "trowserkit", "trowser-api-index.md");
        var row = new Regex(@"^\| (GET|POST|PUT|DELETE|PATCH) \| `(/[^`]+)`", RegexOptions.Compiled);
        return File.ReadAllLines(indexPath)
            .Select(l => row.Match(l))
            .Where(m => m.Success)
            .Select(m => (m.Groups[1].Value, m.Groups[2].Value))
            .Where(r => r.Item1 is "POST" or "PUT" or "DELETE" or "PATCH")
            .ToList();
    }

    private static List<(string Method, string Path)> SampleBlockedRoutes(int max = 12)
    {
        var routes = IndexPostRoutes();
        var keys = SafeModePolicy.BlockedOperations.OrderBy(k => k, StringComparer.Ordinal).ToList();
        var step = Math.Max(1, keys.Count / max);
        var picked = new List<(string Method, string Path)>();

        for (var i = 0; i < keys.Count && picked.Count < max; i += step)
        {
            var key = keys[i];
            var match = routes.FirstOrDefault(r => SafeModePolicy.RouteKey(r.Path) == key);
            if (match != default)
                picked.Add(match);
        }

        foreach (var fallback in new[] { ( "POST", "/api/execute-script" ), ( "POST", "/api/fetch-direct" ), ( "POST", "/api/mock" ) })
        {
            if (picked.Count >= max) break;
            if (!picked.Contains(fallback))
                picked.Add(fallback);
        }

        return picked;
    }

    [Fact]
    [Trait("Category", "Sweep")]
    public async Task Rest_requires_auth_except_ping()
    {
        var instance = new TrowserInstance();
        await instance.InitializeAsync();
        try
        {
            var api = new RestClient(instance);
            var wrongKey = new RestClient(instance, "wrong-key-apitest");
            var deny = LoadRestDenylist();
            var ops = AllOperations(LoadOpenApi()).Where(o => o.Path != "/api/ping");
            var failures = new List<string>();

            foreach (var (method, pathTemplate) in ops)
            {
                if (deny.Contains((method.Method, pathTemplate)))
                    continue;

                var path = ResolvePath(pathTemplate);
                if (path.Contains('{', StringComparison.Ordinal))
                    continue;

                var (noKeyStatus, noKeyDoc) = await api.SendAsync(method, path, new { }, includeAuth: false);
                noKeyDoc.Dispose();
                if (noKeyStatus != 401)
                    failures.Add($"{method} {path} no auth => {noKeyStatus} (expected 401)");

                var (badKeyStatus, badKeyDoc) = await wrongKey.SendAsync(method, path, new { });
                badKeyDoc.Dispose();
                if (badKeyStatus != 401)
                    failures.Add($"{method} {path} wrong key => {badKeyStatus} (expected 401)");
            }

            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(40)));
        }
        finally
        {
            instance.Dispose();
        }
    }

    [Fact]
    [Trait("Category", "Sweep")]
    public async Task Safe_mode_blocks_sample_of_blocked_routes()
    {
        var instance = new TrowserInstance { SafeMode = true };
        await instance.InitializeAsync();
        try
        {
            var api = new RestClient(instance);
            var failures = new List<string>();

            foreach (var (method, path) in SampleBlockedRoutes())
            {
                var httpMethod = new HttpMethod(method);
                var (status, doc) = await api.SendAsync(httpMethod, path, new { });
                using (doc)
                {
                    if (status is 500 or >= 200 and < 300)
                        failures.Add($"{method} {path} => {status} (expected safe-mode block, not success/server error)");
                    else if (status is not (403 or 400 or 423))
                        failures.Add($"{method} {path} => {status} (expected 403/400/423 block)");
                }
            }

            Assert.True(failures.Count == 0, string.Join("\n", failures));
        }
        finally
        {
            instance.Dispose();
        }
    }

    [Fact]
    [Trait("Category", "Sweep")]
    public async Task Mcp_tools_call_returns_json_rpc_result()
    {
        var instance = new TrowserInstance();
        await instance.InitializeAsync();
        try
        {
            var mcp = new McpClient(instance, "core");
            await mcp.InitializeAsync();
            var tools = await mcp.ToolsListAsync();
            var deny = new HashSet<string>(
                JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "sweep-denylist.json")))
                    .RootElement.GetProperty("mcpTools").EnumerateArray()
                    .Select(e => e.GetProperty("name").GetString()!));

            var count = 0;
            foreach (var tool in tools.EnumerateArray())
            {
                var name = tool.GetProperty("name").GetString()!;
                if (deny.Contains(name)) continue;
                var result = await mcp.ToolsCallAsync(name);
                Assert.True(result.TryGetProperty("result", out _) || result.TryGetProperty("error", out _),
                    $"No JSON-RPC result for {name}");
                count++;
                if (count >= 40) break;
            }

            Assert.True(count >= 10, "Expected to exercise a sample of core MCP tools");
        }
        finally
        {
            instance.Dispose();
        }
    }
}
