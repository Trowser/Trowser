using System.Text.Json;
using Xunit;

namespace Trowser.ApiTests;

internal static class ParityCatalog
{
    public static readonly string[] CaseIds =
    [
        "ping",
        "navigate",
        "snapshot",
        "type",
        "mock-add",
        "clear-session",
        "journal",
        "console",
        "go-back"
    ];

    public static async Task RunAsync(string caseId, TrowserInstance instance)
    {
        if (caseId is not ("ping" or "clear-session"))
        {
            var reset = new RestClient(instance);
            await reset.ExpectSuccessAsync(HttpMethod.Post, "/api/clear-session", new { });
        }

        switch (caseId)
        {
            case "ping":
                await RunPingAsync(instance);
                break;
            case "navigate":
                await RunNavigateAsync(instance);
                break;
            case "snapshot":
                await RunSnapshotAsync(instance);
                break;
            case "type":
                await RunTypeAsync(instance);
                break;
            case "mock-add":
                await RunMockAddAsync(instance);
                break;
            case "clear-session":
                await RunClearSessionAsync(instance);
                break;
            case "journal":
                await RunJournalAsync(instance);
                break;
            case "console":
                await RunConsoleAsync(instance);
                break;
            case "go-back":
                await RunGoBackAsync(instance);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(caseId), caseId, "Unknown parity case.");
        }
    }

    private static async Task RunPingAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        var ping = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/ping");
        Assert.True(ping.TryGetProperty("busy", out _));

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        var mcpPing = await mcp.ToolsCallAsync("browser_ping");
        McpAssert.NotError(mcpPing, "browser_ping");
        var text = McpContent.FirstText(mcpPing);
        if (!string.IsNullOrEmpty(text))
            Assert.Contains("alive", text, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task RunNavigateAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        var restTitle = (await api.ExpectSuccessAsync(HttpMethod.Get, "/api/state")).GetProperty("title").GetString();

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_navigate", new { url = MockFixtures.Url() });
        var assert = await mcp.ToolsCallAsync("browser_assert_title", new { expected = "Example Domain", contains = false });
        var err = assert.TryGetProperty("result", out var r) && r.TryGetProperty("isError", out var ie) && ie.GetBoolean();
        Assert.False(err, "MCP assert_title should pass on fixture page");
        Assert.Equal("Example Domain", restTitle);
    }

    private static async Task RunSnapshotAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        var restTitle = (await api.ExpectSuccessAsync(HttpMethod.Get, "/api/state")).GetProperty("title").GetString();

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_navigate", new { url = MockFixtures.Url() });
        var snap = await mcp.ToolsCallAsync("browser_snapshot");
        var body = McpContent.FirstText(snap);
        Assert.Contains("Example Domain", restTitle ?? "");
        Assert.Contains("Example Domain", body);
    }

    private static async Task RunTypeAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 5000 });

        var inputRef = await FindInputRefAsync(api);
        var restTyped = await api.ExpectSuccessAsync(HttpMethod.Post, "/api/type", new { @ref = inputRef, text = "ParityRow" });
        Assert.Equal("ParityRow", restTyped.GetProperty("typed").GetString());

        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 5000 });
        inputRef = await FindInputRefAsync(api);

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_navigate", new { url = MockFixtures.Url() });
        var mcpTyped = await mcp.ToolsCallAsync("browser_type", new { @ref = inputRef, text = "ParityRow" });
        var text = McpContent.FirstText(mcpTyped);
        Assert.Contains("ParityRow", text);
    }

    private static async Task RunMockAddAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        var before = await MockRuleCountAsync(api);

        var extraUrl = MockFixtures.Url("/parity-mock-only");
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new
        {
            urlPattern = extraUrl,
            status = 200,
            body = "<html><body>mock</body></html>"
        });
        var afterRest = await MockRuleCountAsync(api);
        Assert.Equal(before + 1, afterRest);

        await MockFixtures.SeedExamplePageAsync(api);
        before = await MockRuleCountAsync(api);
        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        var mcpAdd = await mcp.ToolsCallAsync("browser_mock", new
        {
            action = "add",
            urlPattern = MockFixtures.Url("/parity-mcp-mock"),
            status = 200,
            body = "<html><body>mcp mock</body></html>"
        });
        McpAssert.NotError(mcpAdd, "browser_mock add");
        var afterMcp = await MockRuleCountAsync(api);
        Assert.Equal(before + 1, afterMcp);
    }

    private static async Task RunClearSessionAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new
        {
            urlPattern = MockFixtures.Url("/extra-after-seed"),
            status = 200,
            body = "x"
        });
        Assert.True(await MockRuleCountAsync(api) >= 2);

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/clear-session", new { });
        var afterRest = await MockRuleCountAsync(api);
        Assert.Equal(0, afterRest);

        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new
        {
            urlPattern = MockFixtures.Url("/mcp-clear-check"),
            status = 200,
            body = "y"
        });

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_clear_session", new { });
        var afterMcp = await MockRuleCountAsync(api);
        Assert.Equal(0, afterMcp);
    }

    private static async Task RunJournalAsync(TrowserInstance instance)
    {
        var marker = "parity-journal-marker-" + Guid.NewGuid().ToString("N")[..8];

        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/journal", new { kind = "note", note = marker });
        var journal = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/journal");
        Assert.Contains(marker, journal.GetRawText());

        await MockFixtures.SeedExamplePageAsync(api);
        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        var mcpMarker = "parity-mcp-journal-" + Guid.NewGuid().ToString("N")[..8];
        await mcp.ToolsCallAsync("browser_journal_add", new { kind = "note", note = mcpMarker });
        journal = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/journal");
        Assert.Contains(mcpMarker, journal.GetRawText());
    }

    private static async Task RunConsoleAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await MockFixtures.SeedExamplePageAsync(api);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = MockFixtures.Url() });
        var restConsole = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/console");
        Assert.True(restConsole.TryGetProperty("entries", out var entries));
        Assert.Equal(JsonValueKind.Array, entries.ValueKind);

        await MockFixtures.SeedExamplePageAsync(api);
        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_navigate", new { url = MockFixtures.Url() });
        var mcpConsole = await mcp.ToolsCallAsync("browser_console");
        var text = McpContent.FirstText(mcpConsole);
        Assert.False(string.IsNullOrWhiteSpace(text));
    }

    private static async Task RunGoBackAsync(TrowserInstance instance)
    {
        var api = new RestClient(instance);
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/clear-session", new { });

        var urlA = MockFixtures.Url("/page-a");
        var urlB = MockFixtures.Url("/page-b");
        var htmlA = MockFixtures.MinimalHtml("Page A Title", "<h1>Page A</h1>");
        var htmlB = MockFixtures.MinimalHtml("Page B Title", "<h1>Page B</h1>");

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new { urlPattern = urlA, status = 200, body = htmlA });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new { urlPattern = urlB, status = 200, body = htmlB });

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = urlA });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 10000 });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/navigate", new { url = urlB });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 10000 });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/go-back", new { });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/wait-for-idle", new { quietMs = 200, timeoutMs = 10000 });
        var pageText = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/page-text");
        var restText = pageText.GetProperty("text").GetString() ?? "";
        Assert.Contains("Page A", restText);

        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/clear-session", new { });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new { urlPattern = urlA, status = 200, body = htmlA });
        await api.ExpectSuccessAsync(HttpMethod.Post, "/api/mock", new { urlPattern = urlB, status = 200, body = htmlB });

        var mcp = new McpClient(instance);
        await mcp.InitializeAsync();
        await mcp.ToolsCallAsync("browser_navigate", new { url = urlA });
        await mcp.ToolsCallAsync("browser_navigate", new { url = urlB });
        await mcp.ToolsCallAsync("browser_go_back");
        var mcpPageText = await mcp.ToolsCallAsync("browser_page_text");
        var body = McpContent.FirstText(mcpPageText);
        Assert.Contains("Page A", body);
    }

    private static async Task<int> MockRuleCountAsync(RestClient api)
    {
        var data = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/mock");
        if (data.TryGetProperty("count", out var count))
            return count.GetInt32();
        if (data.TryGetProperty("rules", out var arr))
            return arr.GetArrayLength();
        return 0;
    }

    private static async Task<int> FindInputRefAsync(RestClient api)
    {
        var state = await api.ExpectSuccessAsync(HttpMethod.Get, "/api/state");
        foreach (var el in state.GetProperty("interactiveElements").EnumerateArray())
        {
            if (el.TryGetProperty("tag", out var tag) && tag.GetString() == "input")
                return el.GetProperty("ref").GetInt32();
        }
        throw new InvalidOperationException("Expected input ref from state");
    }
}
