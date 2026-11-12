using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Trowser.ApiTests;

internal sealed class RestClient
{
    private readonly HttpClient _http;
    private readonly string _base;
    private readonly string? _apiKey;

    public RestClient(TrowserInstance instance, string? apiKeyOverride = null)
    {
        _base = instance.BaseUrl.TrimEnd('/');
        _apiKey = apiKeyOverride ?? instance.ApiKey;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
    }

    public async Task<(int Status, JsonDocument Json)> SendAsync(
        HttpMethod method,
        string path,
        object? body = null,
        bool includeAuth = true)
    {
        var req = new HttpRequestMessage(method, _base + path);
        if (includeAuth && _apiKey != null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

        if (body != null)
        {
            req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        }
        else if (method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch)
        {
            req.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        }

        var resp = await _http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
        }
        catch
        {
            throw new InvalidOperationException($"Non-JSON response {resp.StatusCode} for {method} {path}: {text[..Math.Min(200, text.Length)]}");
        }

        return ((int)resp.StatusCode, doc);
    }

    public async Task<JsonElement> ExpectSuccessAsync(HttpMethod method, string path, object? body = null)
    {
        var (status, doc) = await SendAsync(method, path, body);
        try
        {
            Xunit.Assert.True(status is >= 200 and < 300, $"{method} {path} HTTP {status}");
            var root = doc.RootElement;
            Xunit.Assert.True(root.TryGetProperty("success", out var s) && s.GetBoolean(), $"{method} {path} success=false");
            return root.TryGetProperty("data", out var data) ? data.Clone() : default;
        }
        finally
        {
            doc.Dispose();
        }
    }
}
