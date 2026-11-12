using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Trowser.ApiTests;

internal sealed class McpClient
{
    private readonly HttpClient _http;
    private readonly string _endpoint;
    private readonly string _apiKey;
    private int _id;

    public McpClient(TrowserInstance instance, string mode = "full")
    {
        _endpoint = $"{instance.BaseUrl.TrimEnd('/')}/mcp?mode={mode}";
        _apiKey = instance.ApiKey;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
    }

    public async Task InitializeAsync()
    {
        var result = await CallAsync("initialize", new { });
        Xunit.Assert.False(result.TryGetProperty("error", out _), "initialize failed");
    }

    public async Task<JsonElement> ToolsListAsync()
    {
        var result = await CallAsync("tools/list", new { });
        Xunit.Assert.True(result.TryGetProperty("result", out var r));
        Xunit.Assert.True(r.TryGetProperty("tools", out var tools));
        return tools.Clone();
    }

    public async Task<JsonElement> ToolsCallAsync(string name, object? arguments = null)
    {
        var result = await CallAsync("tools/call", new
        {
            name,
            arguments = arguments ?? new { }
        });
        return result.Clone();
    }

    private async Task<JsonElement> CallAsync(string method, object parameters)
    {
        var payload = new
        {
            jsonrpc = "2.0",
            id = Interlocked.Increment(ref _id),
            method,
            @params = parameters
        };
        var req = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        var resp = await _http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        Xunit.Assert.True(resp.IsSuccessStatusCode, $"MCP HTTP {(int)resp.StatusCode}: {text[..Math.Min(300, text.Length)]}");
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }
}
