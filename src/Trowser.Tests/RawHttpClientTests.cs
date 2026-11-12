using System.Text;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class RawHttpClientTests
{
    private static readonly Uri Target = new("https://example.com/search?q=1");

    [Fact]
    public void request_line_version_is_preserved()
    {
        var built = RawHttpClient.BuildRequest("POST /search HTTP/1.0", "Host: example.com", null, Target);
        Assert.StartsWith("POST /search HTTP/1.0\r\n", built.RequestSent);
        Assert.False(built.HostWasAdded);
    }

    [Fact]
    public void default_request_line_uses_path_and_http11()
    {
        Assert.Equal("PUT /search?q=1 HTTP/1.1", RawHttpClient.DefaultRequestLine("PUT", Target));
    }

    [Fact]
    public void duplicate_content_length_is_preserved()
    {
        var headers = "Host: example.com\nContent-Length: 4\nContent-Length: 0";
        var built = RawHttpClient.BuildRequest("POST / HTTP/1.1", headers, "abcd", Target);
        Assert.Contains("Content-Length: 4\r\nContent-Length: 0\r\n", built.RequestSent);
    }

    [Fact]
    public void content_length_and_transfer_encoding_both_present()
    {
        var headers = "Host: example.com\nContent-Length: 6\nTransfer-Encoding: chunked";
        var built = RawHttpClient.BuildRequest("POST / HTTP/1.1", headers, "0\r\n\r\n", Target);
        Assert.Contains("Content-Length: 6\r\n", built.RequestSent);
        Assert.Contains("Transfer-Encoding: chunked\r\n", built.RequestSent);
        Assert.EndsWith("0\r\n\r\n", built.RequestSent);
    }

    [Fact]
    public void content_length_is_not_auto_added()
    {
        var built = RawHttpClient.BuildRequest("POST / HTTP/1.1", "Host: example.com", "hello", Target);
        Assert.DoesNotContain("Content-Length", built.RequestSent, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("hello", built.RequestSent);
    }

    [Fact]
    public void host_injected_only_when_missing()
    {
        var missing = RawHttpClient.BuildRequest("GET / HTTP/1.1", "", null, Target);
        Assert.True(missing.HostWasAdded);
        Assert.Contains("Host: example.com\r\n", missing.RequestSent);

        var present = RawHttpClient.BuildRequest("GET / HTTP/1.1", "Host: other.test", null, Target);
        Assert.False(present.HostWasAdded);
        Assert.Contains("Host: other.test\r\n", present.RequestSent);
        Assert.DoesNotContain("Host: example.com", present.RequestSent);
    }

    [Fact]
    public void header_newlines_normalized_to_crlf_body_left_as_is()
    {
        var built = RawHttpClient.BuildRequest(
            "POST / HTTP/1.1",
            "Host: example.com\nX-A: 1",
            "line1\nline2",
            Target);
        Assert.Contains("Host: example.com\r\nX-A: 1\r\n\r\n", built.RequestSent);
        Assert.EndsWith("line1\nline2", built.RequestSent);
        Assert.DoesNotContain("line1\r\nline2", built.RequestSent);
    }

    [Fact]
    public void normalize_headers_false_keeps_lf_only()
    {
        var built = RawHttpClient.BuildRequest(
            "POST / HTTP/1.1",
            "Host: example.com\nX-A: 1",
            "body",
            Target,
            new RawHttpClient.BuildOptions { NormalizeHeaders = false, AddHostIfMissing = false });
        Assert.Contains("POST / HTTP/1.1\nHost: example.com\nX-A: 1\n\nbody", built.RequestSent);
    }

    [Fact]
    public void parse_response_preserves_duplicate_headers()
    {
        var raw = Encoding.UTF8.GetBytes(
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nhello");
        var parsed = RawHttpClient.ParseRawResponse(raw, 12);
        Assert.Equal(200, parsed.Status);
        Assert.Equal("OK", parsed.StatusText);
        Assert.Equal(2, parsed.Headers.Count);
        Assert.Contains("Set-Cookie: a=1", parsed.Headers);
        Assert.Contains("Set-Cookie: b=2", parsed.Headers);
        Assert.Equal("hello", parsed.Body);
        Assert.Equal(12, parsed.DurationMs);
    }

    [Fact]
    public void parse_response_decodes_chunked_body()
    {
        var payload = "{\"error\":\"denied\"}";
        var raw = Encoding.UTF8.GetBytes(
            "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n" +
            $"{payload.Length:X}\r\n{payload}\r\n0\r\n\r\n");
        var parsed = RawHttpClient.ParseRawResponse(raw, 5);
        Assert.Equal(403, parsed.Status);
        Assert.Equal(payload, parsed.Body);
        Assert.True(parsed.BodyWasChunked);
        Assert.NotNull(parsed.BodyRaw);
        Assert.Contains("0\r\n\r\n", parsed.BodyRaw);
    }

    [Fact]
    public void decode_chunked_body_strips_framing()
    {
        var decoded = RawHttpClient.DecodeChunkedBody("B\r\n{\"ok\":true}\r\n0\r\n\r\n");
        Assert.Equal("{\"ok\":true}", decoded);
    }
}
