using Trowser.Automation;
using Trowser.Security.Sse;
using Xunit;

namespace Trowser.Tests.Security;

public class SseAuditorScopeTests
{
    [Fact]
    public void ScopeNetworkStreams_FiltersToLinkedNetworkEntry()
    {
        var streams = new List<NetworkEntry>
        {
            new() { Id = 1, Url = "https://a.test/s", Method = "GET", ResponseHeaders = new() { ["Content-Type"] = "text/event-stream" } },
            new() { Id = 2, Url = "https://b.test/t", Method = "GET", ResponseHeaders = new() { ["Content-Type"] = "text/event-stream" } },
        };
        var conn = new SseConnection { ConnectionId = 1, Url = "https://a.test/s", Method = "GET", NetworkEntryId = 1 };

        var scoped = SseAuditor.ScopeNetworkStreams(streams, [conn], connectionId: 1);

        Assert.Single(scoped);
        Assert.Equal(1, scoped[0].Id);
    }

    [Fact]
    public void ScopeNetworkStreams_TabWideWhenNoConnectionFilter()
    {
        var streams = new List<NetworkEntry>
        {
            new() { Id = 1, Url = "https://a.test/s", Method = "GET" },
            new() { Id = 2, Url = "https://b.test/t", Method = "GET" },
        };

        var scoped = SseAuditor.ScopeNetworkStreams(streams, [], connectionId: null);
        Assert.Equal(2, scoped.Count);
    }
}
