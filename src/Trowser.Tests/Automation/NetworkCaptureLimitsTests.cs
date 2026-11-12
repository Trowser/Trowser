using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class NetworkCaptureLimitsTests
{
    [Fact]
    public void Response_truncated_at_capture_cap()
    {
        var entry = new NetworkEntry { ResponseBody = new string('x', NetworkCaptureLimits.MaxTextBodyChars) };
        Assert.True(NetworkCaptureLimits.IsResponseBodyTruncated(entry));
    }

    [Fact]
    public void Event_stream_uses_higher_capture_limit()
    {
        var entry = new NetworkEntry
        {
            ResponseHeaders = new Dictionary<string, string> { ["Content-Type"] = "text/event-stream" },
            ResponseBody = new string('x', NetworkCaptureLimits.MaxTextBodyChars + 1)
        };
        Assert.False(NetworkCaptureLimits.IsResponseBodyTruncated(entry));
        Assert.Equal(NetworkCaptureLimits.MaxEventStreamBodyChars,
            NetworkCaptureLimits.ResponseBodyCaptureFields(entry)["bodyCaptureLimitChars"]);
    }

    [Fact]
    public void Response_truncated_when_content_length_exceeds_capture()
    {
        var entry = new NetworkEntry
        {
            ResponseBody = "small",
            ResponseHeaders = new Dictionary<string, string> { ["Content-Length"] = "999999" }
        };
        Assert.True(NetworkCaptureLimits.IsResponseBodyTruncated(entry) != true);
        Assert.True(NetworkCaptureLimits.IsResponseBodySizeMismatch(entry));
    }

    [Fact]
    public void Small_content_length_gap_is_not_truncated()
    {
        var entry = new NetworkEntry
        {
            ResponseBody = new string('x', 1414),
            ResponseHeaders = new Dictionary<string, string> { ["Content-Length"] = "1416" }
        };
        Assert.False(NetworkCaptureLimits.IsResponseBodyTruncated(entry) == true);
        Assert.False(NetworkCaptureLimits.IsResponseBodySizeMismatch(entry) == true);
    }

    [Fact]
    public void Should_capture_script_stylesheet_and_ecmascript_not_images()
    {
        Assert.True(NetworkCaptureLimits.ShouldCaptureResponseBody("Script", ""));
        Assert.True(NetworkCaptureLimits.ShouldCaptureResponseBody("Stylesheet", null));
        Assert.True(NetworkCaptureLimits.ShouldCaptureResponseBody("Other", "application/ecmascript"));
        Assert.False(NetworkCaptureLimits.ShouldCaptureResponseBody("Image", "image/png"));
        Assert.False(NetworkCaptureLimits.ShouldCaptureResponseBody("Other", "application/octet-stream"));
    }

    [Fact]
    public void Missing_request_headers_skip_cookie_and_existing_names()
    {
        var have = new Dictionary<string, string> { ["Accept"] = "text/html", ["X-CSRF"] = "1" };
        var seen = new Dictionary<string, string>
        {
            ["Cookie"] = "session=abc",
            ["x-csrf"] = "1",
            ["X-Requested-With"] = "XMLHttpRequest"
        };

        var missing = NetworkCaptureLimits.MissingRequestHeaders(have, seen);
        Assert.DoesNotContain("Cookie", missing.Keys);
        Assert.DoesNotContain(missing.Keys, k => k.Equals("X-CSRF", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("XMLHttpRequest", missing["X-Requested-With"]);
    }

    [Fact]
    public void Slice_body()
    {
        Assert.Equal("bc", NetworkCaptureLimits.SliceBody("abcd", 1, 2));
        Assert.Equal("", NetworkCaptureLimits.SliceBody("abcd", 4, 10));
    }
}
