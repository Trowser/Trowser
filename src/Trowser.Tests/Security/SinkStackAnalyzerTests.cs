using Trowser.Security;
using Trowser.Security.Runtime;
using Xunit;

namespace Trowser.Tests.Security;

public class SinkStackAnalyzerTests
{
    [Fact]
    public void GetPageStack_strips_sensor_frames()
    {
        var stack = """
            at captureSink (trowser-runtime-sensor.js:455:16)
            at HTMLDivElement.set [as innerHTML] (trowser-runtime-sensor.js:155:34)
            at pageCode (https://example.test/app.js:12:5)
            """;

        var page = SinkStackAnalyzer.GetPageStack(stack);
        Assert.Contains("pageCode", page);
        Assert.DoesNotContain("captureSink", page);
    }

    [Fact]
    public void IsToolArtifactSink_keeps_page_attributed_innerHTML()
    {
        var stack = """
            at captureSink (trowser-runtime-sensor.js:1:1)
            at pageCode (https://example.test/app.js:1:1)
            """;
        var pageOnly = SinkStackAnalyzer.GetPageStack(stack);
        Assert.False(RuntimeInstrumentationFilter.IsToolArtifactSink("innerHTML", pageOnly, "<b>x</b>"));
    }

    [Fact]
    public void IsToolArtifactSink_drops_host_bridge_only()
    {
        Assert.True(RuntimeInstrumentationFilter.IsToolArtifactSink("innerHTML", "at tryFunc (<anonymous>)", "x"));
    }
}
