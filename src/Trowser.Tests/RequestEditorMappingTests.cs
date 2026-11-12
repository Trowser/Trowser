using System.Text.Json;
using Xunit;

namespace Trowser.Tests;

public class RequestEditorMappingTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    [Fact]
    public void ComposeToRawUrl_uses_origin_form_path()
    {
        var url = RequestEditorMapping.ComposeUrl(
            "https://example.com/old",
            "POST /v1/items?x=1 HTTP/1.0");

        Assert.Equal("https://example.com/v1/items?x=1", url);
    }

    [Fact]
    public void ComposeUrl_prefers_absolute_request_target()
    {
        var url = RequestEditorMapping.ComposeUrl(
            "https://example.com/",
            "GET http://other.test/a HTTP/1.1");

        Assert.Equal("http://other.test/a", url);
    }

    [Fact]
    public void Save_compose_omits_raw_fields()
    {
        var saved = RequestEditorMapping.FromCompose(
            "list",
            "https://example.com/items",
            "get",
            new Dictionary<string, string> { ["Accept"] = "application/json" },
            "");

        Assert.Equal("compose", saved.EditorTab);
        Assert.Equal("GET", saved.Method);
        Assert.False(saved.IsRaw);
        Assert.Null(saved.RequestLine);
        Assert.Null(saved.HeaderText);
        Assert.Null(saved.Body);

        var json = JsonSerializer.Serialize(saved, JsonOptions);
        Assert.Contains("\"editorTab\":\"compose\"", json);
        Assert.DoesNotContain("requestLine", json);
        Assert.DoesNotContain("headerText", json);
    }

    [Fact]
    public void Save_raw_keeps_verbatim_line_and_duplicate_headers()
    {
        var headers = "Host: example.com\nX-Test: a\nX-Test: b";
        var saved = RequestEditorMapping.FromRaw(
            "smuggle",
            "https://example.com/api",
            "GET /admin HTTP/1.0",
            headers,
            "raw-body");

        Assert.True(saved.IsRaw);
        Assert.Equal("GET", saved.Method);
        Assert.Equal("https://example.com/api", saved.Url);
        Assert.Equal("GET /admin HTTP/1.0", saved.RequestLine);
        Assert.Equal(headers, saved.HeaderText);
        Assert.Equal("raw-body", saved.Body);
        Assert.Null(saved.Headers);

        var json = JsonSerializer.Serialize(saved, JsonOptions);
        Assert.Contains("\"editorTab\":\"raw\"", json);
        Assert.Contains("GET /admin HTTP/1.0", json);
        Assert.Contains("X-Test: a", json);
        Assert.DoesNotContain("\"headers\"", json);

        var roundTrip = JsonSerializer.Deserialize<SavedHttpRequest>(json, JsonOptions);
        Assert.NotNull(roundTrip);
        Assert.True(roundTrip!.IsRaw);
        Assert.Equal(headers, roundTrip.HeaderText);
    }

    [Fact]
    public void Missing_editor_tab_loads_as_compose()
    {
        var json = """{"name":"old","url":"https://example.com/","method":"POST","body":"{}"}""";
        var saved = JsonSerializer.Deserialize<SavedHttpRequest>(json, JsonOptions);
        Assert.NotNull(saved);
        Assert.False(saved!.IsRaw);
        Assert.Equal("POST", saved.Method);
    }
}
