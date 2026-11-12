using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class SseIncrementalParserTests
{
    [Fact]
    public void Append_emits_event_across_chunks()
    {
        var state = new SseParseState();
        var a = SseIncrementalParser.Append(state, "data: hel");
        Assert.Empty(a);
        var b = SseIncrementalParser.Append(state, "lo\n\n");
        Assert.Single(b);
        Assert.Equal("hello", b[0].Data);
    }

    [Fact]
    public void Append_two_events_in_one_chunk()
    {
        var state = new SseParseState();
        var events = SseIncrementalParser.Append(state, "data: one\n\ndata: two\n\n");
        Assert.Equal(2, events.Count);
    }
}
