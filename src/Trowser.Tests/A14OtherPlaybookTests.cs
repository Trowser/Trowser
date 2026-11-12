using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Playbooks;
using Xunit;

namespace Trowser.Tests;

public class A14OtherPlaybookTests
{
    [Fact]
    public void describe_steps_runs_cache_identify_before_cache_map()
    {
        var playbook = new A14OtherPlaybook();
        var steps = playbook.DescribeSteps(new PlaybookRequest());
        var names = steps.Select(s => s.Name).ToList();

        Assert.Contains("cache-identify", names);
        Assert.True(names.IndexOf("cache-identify") < names.IndexOf("cache-map"),
            "cache-identify should run before cache-map");

        var identify = steps.First(s => s.Name == "cache-identify");
        Assert.False(identify.WritesSideEffects);
        Assert.False(identify.SkippedByCurrentSafetyMode);
        Assert.Equal("none (passive)", identify.HttpVerbs);
    }

    [Fact]
    public void cache_identify_is_not_gated_by_passive_safety()
    {
        var playbook = new A14OtherPlaybook();
        var steps = playbook.DescribeSteps(new PlaybookRequest { SafetyMode = SafetyMode.Passive });
        var identify = Assert.Single(steps, s => s.Name == "cache-identify");
        Assert.False(identify.SkippedByCurrentSafetyMode);
        Assert.Null(identify.SkipReason);

        var map = Assert.Single(steps, s => s.Name == "cache-map");
        Assert.True(map.SkippedByCurrentSafetyMode);
    }
}
