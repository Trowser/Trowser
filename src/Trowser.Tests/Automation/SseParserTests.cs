using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class SseParserTests
{
    [Fact]
    public void Parse_multiline_data_and_crlf()
    {
        const string body = "id: 1\r\nevent: tick\r\ndata: line1\r\ndata: line2\r\n\r\n";
        var events = SseParser.Parse(body);
        Assert.Single(events);
        Assert.Equal("1", events[0].EventId);
        Assert.Equal("tick", events[0].EventName);
        Assert.Equal("line1\nline2", events[0].Data);
    }

    [Fact]
    public void Parse_ignores_comments_and_done()
    {
        const string body = ": comment\ndata: hello\ndata: [DONE]\n\n";
        var text = SseParser.ExtractDataText(body);
        Assert.Equal("hello", text);
    }

    [Fact]
    public void LooksLikeSse_detects_event_prefix()
    {
        Assert.True(SseParser.LooksLikeSse("event: ping\ndata: x\n"));
    }
}
