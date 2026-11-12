using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class FrameInspectableExecutionTests
{
    [Fact]
    public void StripFrameLocatorsInJs_removes_action_frame_prefix_from_deepQuery_literals()
    {
        const string js = "var el = deepQuery('@frame:f1|[data-trowser-loc=\"_t_abc\"]');";
        var stripped = AutomationContext.StripFrameLocatorsInJsForInspectableChild(js, "f1");
        Assert.DoesNotContain("@frame:", stripped);
        Assert.Contains("[data-trowser-loc=\"_t_abc\"]", stripped);
    }

    [Fact]
    public void StripFrameLocatorsInJs_leaves_other_frames_unchanged()
    {
        const string js = "deepQuery('@frame:f2|#x')";
        var stripped = AutomationContext.StripFrameLocatorsInJsForInspectableChild(js, "f1");
        Assert.Equal(js, stripped);
    }

    [Fact]
    public void SplitFrameLocator_parses_frame_pipe_inner()
    {
        var (frame, inner) = AutomationContext.SplitFrameLocator("@frame:child|#btn");
        Assert.Equal("child", frame);
        Assert.Equal("#btn", inner);
    }
}
