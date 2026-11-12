using System.Net.Http.Headers;
using Trowser;
using Xunit;

namespace Trowser.Tests;

public class BreakpointForwardHttpTests
{
    [Fact]
    public void RequestLooksLikeEventStream_AcceptHeader()
    {
        var headers = new Dictionary<string, string> { ["Accept"] = "text/event-stream" };
        Assert.True(BreakpointForwardHttp.RequestLooksLikeEventStream(headers, "Fetch"));
    }

    [Fact]
    public void RequestLooksLikeEventStream_ResourceType()
    {
        Assert.True(BreakpointForwardHttp.RequestLooksLikeEventStream(
            new Dictionary<string, string>(), "EventSource"));
    }

    [Fact]
    public void ResponseLooksLikeEventStream_ContentType()
    {
        using var response = new HttpResponseMessage();
        response.Content = new StringContent("");
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("text/event-stream");
        Assert.True(BreakpointForwardHttp.ResponseLooksLikeEventStream(response));
    }

    [Fact]
    public void BuildRequest_SkipsHostAndSetsBody()
    {
        var headers = new Dictionary<string, string>
        {
            ["Host"] = "evil.example",
            ["Content-Type"] = "application/json",
            ["X-Test"] = "1"
        };
        using var req = BreakpointForwardHttp.BuildRequest(
            "https://example.com/a", "POST", headers, "{\"a\":1}");
        Assert.Equal("https://example.com/a", req.RequestUri?.ToString());
        Assert.Equal("1", req.Headers.GetValues("X-Test").First());
        Assert.Equal("application/json", req.Content?.Headers.ContentType?.MediaType);
    }
}
