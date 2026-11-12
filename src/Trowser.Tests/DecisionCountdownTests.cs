using Trowser.Decisions;
using Xunit;

namespace Trowser.Tests;

public class DecisionCountdownTests
{
    [Theory]
    [InlineData(300, 300)]
    [InlineData(241, 240)]
    [InlineData(240, 240)]
    [InlineData(180, 180)]
    [InlineData(61, 60)]
    [InlineData(45, 45)]
    [InlineData(16, 15)]
    [InlineData(10, 15)]
    public void milestone_for_seconds_remaining(int remaining, int expected) =>
        Assert.Equal(expected, DecisionCountdown.MilestoneFor(remaining));

    [Theory]
    [InlineData(300, "5 minutes left")]
    [InlineData(240, "4 minutes left")]
    [InlineData(180, "3 minutes left")]
    [InlineData(120, "2 minutes left")]
    [InlineData(60, "1 minute left")]
    [InlineData(45, "45 seconds left")]
    [InlineData(30, "30 seconds left")]
    [InlineData(15, "15 seconds left")]
    public void format_milestone_text(int seconds, string expected) =>
        Assert.Equal(expected, DecisionCountdown.Format(seconds));
}
