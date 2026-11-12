using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class XssReflectionTrappedPayloadTests
{
    [Fact]
    public void IsPayloadTrapped_alert_inside_img_src_url()
    {
        var snippet = "<img src=\"/resources/images/tracker.gif?searchTerms=alert(1)\">";
        Assert.True(XssReflectionAnalyzer.IsPayloadTrappedInNonExecutableHtmlSink(
            "alert(1)", "document.write", snippet));
    }

    [Fact]
    public void IsPayloadTrapped_false_when_onload_breakout_present()
    {
        var snippet = "<img src=\"/x\" onload=\"alert(1)\">";
        Assert.False(XssReflectionAnalyzer.IsPayloadTrappedInNonExecutableHtmlSink(
            "alert(1)", "document.write", snippet));
    }

    [Fact]
    public void SinkHitsLackExecutableContext_for_tracker_only_document_write()
    {
        var sinks = new InputTraceResult.SinkTrace
        {
            PayloadReachedSink = true,
            Hits =
            [
                new InputTraceResult.SinkHit
                {
                    Sink = "document.write",
                    ContainsPayload = true,
                    Snippet = "<img src=\"/t?searchTerms=alert(1)\">"
                }
            ]
        };

        Assert.True(XssReflectionAnalyzer.SinkHitsLackExecutablePayloadContext("alert(1)", sinks));
        Assert.False(XssBypassProbes.IsConfirmedXss(new InputTraceResult
        {
            Payload = "alert(1)",
            Injection = new InputTraceResult.InjectionTrace { SourceType = "url-query" },
            Sinks = sinks,
            Csp = new InputTraceResult.CspTrace { WouldBlock = false }
        }));
    }

    [Fact]
    public void IsBenignAbsoluteUrlAttributeWrite_filters_angular_href_echo()
    {
        Assert.True(XssReflectionAnalyzer.IsBenignAbsoluteUrlAttributeWrite(
            "setAttribute",
            "https://ginandjuice.shop/blog/?search=test&back=https://example.com/",
            "https://example.com/"));
    }
}
