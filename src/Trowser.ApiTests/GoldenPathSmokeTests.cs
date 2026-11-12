using System.Text.Json;
using Xunit;

namespace Trowser.ApiTests;

[Collection(BrowserCollection.Name)]
[Trait("Category", "Smoke")]
public class GoldenPathSmokeTests
{
    private readonly TrowserInstance _instance;

    public GoldenPathSmokeTests(TrowserInstance instance) => _instance = instance;

    [Fact]
    public async Task Ping_and_state_after_mocked_navigate()
    {
        var api = new RestClient(_instance);
        await MockFixtures.SeedExamplePageAsync(api);

        var ping = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/ping");
        Xunit.Assert.True(ping.ValueKind == JsonValueKind.Object);

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        var state = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/state");
        Xunit.Assert.Contains("Example Domain", state.GetProperty("title").GetString());
        Xunit.Assert.True(state.GetProperty("interactiveElements").GetArrayLength() >= 1);
    }

    [Fact]
    public async Task Type_and_text_via_rest()
    {
        var api = new RestClient(_instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 5000 });

        var state = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/state");
        int inputRef = -1;
        foreach (var el in state.GetProperty("interactiveElements").EnumerateArray())
        {
            if (el.TryGetProperty("tag", out var tag) && tag.GetString() == "input")
            {
                inputRef = el.GetProperty("ref").GetInt32();
                break;
            }
        }

        Xunit.Assert.True(inputRef >= 0, "Expected input ref from state");
        var typed = await api.ExpectSuccessAsync(HttpMethod.Post, "/api/type", new { @ref = inputRef, text = "ApiTester" });
        Xunit.Assert.Equal("ApiTester", typed.GetProperty("typed").GetString());
    }

    [Fact]
    public async Task Mcp_snapshot_matches_navigated_fixture()
    {
        var api = new RestClient(_instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });

        var mcp = new McpClient(_instance);
        await mcp.InitializeAsync();
        var snap = await mcp.ToolsCallAsync("browser_snapshot");
        Xunit.Assert.True(snap.TryGetProperty("result", out var result));
        var content = result.GetProperty("content").EnumerateArray().First().GetProperty("text").GetString() ?? "";
        Xunit.Assert.Contains("Example Domain", content);
    }
}
