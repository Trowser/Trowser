using Trowser.Api;
using Xunit;

namespace Trowser.Tests;

public class AgentUrlPolicyTests
{
    [Fact]
    public void ForAgent_truncates_data_urls()
    {
        var data = "data:text/html;base64," + new string('A', 2000);
        var shaped = AgentUrlPolicy.ForAgent(data);
        Assert.NotNull(shaped);
        Assert.DoesNotContain(new string('A', 2000), shaped);
        Assert.Contains("data-url omitted", shaped);
    }

    [Fact]
    public void ResolveLogicalPageUrl_prefers_display_override_over_data_source()
    {
        var resolved = AgentUrlPolicy.ResolveLogicalPageUrl(
            "data:text/html;base64,abc",
            "https://trowser-regression.test/");
        Assert.Equal("https://trowser-regression.test/", resolved);
    }
}