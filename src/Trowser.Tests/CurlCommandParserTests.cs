using Xunit;

namespace Trowser.Tests;

public class CurlCommandParserTests
{
    [Fact]
    public void round_trip_trowser_bash_get()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "GET",
            "https://example.com/search?q=a&b=2",
            null,
            null);

        var parsed = CurlCommandParser.Parse(cmd);
        Assert.Equal("GET", parsed.Method);
        Assert.Equal("https://example.com/search?q=a&b=2", parsed.Url);
        Assert.Null(parsed.Body);
        Assert.False(parsed.FollowRedirects);
    }

    [Fact]
    public void round_trip_trowser_bash_post_json()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer tok"
        };
        const string body = "{\"name\":\"test\"}";

        var cmd = CurlCommandBuilder.ToCommandLine(
            "POST",
            "https://api.example.com/v1/items",
            headers,
            body);

        var parsed = CurlCommandParser.Parse(cmd);
        Assert.Equal("POST", parsed.Method);
        Assert.Equal("https://api.example.com/v1/items", parsed.Url);
        Assert.Equal(body, parsed.Body);
        Assert.Equal("application/json", parsed.Headers["Content-Type"]);
        Assert.Equal("Bearer tok", parsed.Headers["Authorization"]);
    }

    [Fact]
    public void round_trip_with_location_and_get_body()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "GET",
            "https://example.com/",
            null,
            "{\"x\":1}",
            followRedirects: true);

        var parsed = CurlCommandParser.Parse(cmd);
        Assert.Equal("GET", parsed.Method);
        Assert.Equal("{\"x\":1}", parsed.Body);
        Assert.True(parsed.FollowRedirects);
    }

    [Fact]
    public void chrome_bash_multiline_single_quotes()
    {
        const string cmd = """
            curl 'https://api.example.com/v1/foo' \
              -H 'accept: application/json' \
              -H 'authorization: Bearer x' \
              --data-raw '{"a":1}'
            """;

        var parsed = CurlCommandParser.Parse(cmd);
        Assert.Equal("POST", parsed.Method);
        Assert.Equal("https://api.example.com/v1/foo", parsed.Url);
        Assert.Equal("{\"a\":1}", parsed.Body);
        Assert.Equal("application/json", parsed.Headers["accept"]);
        Assert.Equal("Bearer x", parsed.Headers["authorization"]);
    }

    [Fact]
    public void bash_percent_in_url_round_trip()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "GET",
            "https://example.com/?q=%PATH%",
            null,
            null);

        var parsed = CurlCommandParser.Parse(cmd);
        Assert.Equal("https://example.com/?q=%PATH%", parsed.Url);
    }

    [Fact]
    public void head_flag_sets_method()
    {
        var parsed = CurlCommandParser.Parse("curl -I https://example.com/");
        Assert.Equal("HEAD", parsed.Method);
        Assert.Equal("https://example.com/", parsed.Url);
    }

    [Fact]
    public void cookie_and_user_agent_flags_become_headers()
    {
        var parsed = CurlCommandParser.Parse(
            "curl https://example.com/ -b session=abc -A MyAgent/1.0");

        Assert.Equal("session=abc", parsed.Headers["Cookie"]);
        Assert.Equal("MyAgent/1.0", parsed.Headers["User-Agent"]);
    }

    [Fact]
    public void dash_url_uses_url_flag()
    {
        var parsed = CurlCommandParser.Parse("curl -X QUERY --url \"-odd\"");
        Assert.Equal("QUERY", parsed.Method);
        Assert.Equal("-odd", parsed.Url);
    }

    [Fact]
    public void file_body_reference_throws()
    {
        Assert.Throws<FormatException>(() =>
            CurlCommandParser.Parse("curl https://example.com/ -d @body.json"));
    }
}
