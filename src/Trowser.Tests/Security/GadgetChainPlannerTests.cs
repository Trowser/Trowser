using Trowser.Security.GadgetChains;
using Trowser.Security.Runtime;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class GadgetChainPlannerTests
{
    [Fact]
    public void Plan_SelectsClobberWhenFirstPartyRadarHitsAndActive()
    {
        var hits = new List<GadgetRadarService.GadgetRadarHit>
        {
            new()
            {
                Name = "window.gadgetCfg",
                Key = "gadgetCfg",
                Receiver = "window",
                FirstPartyStack = true,
                Count = 2,
                Discovery = GadgetRadarLeads.DiscoveryTrap,
                ClobberProbeCandidate = true
            }
        };
        var plan = GadgetChainPlanner.Build(hits, surface: null, active: true, requestedProbes: null);
        Assert.Contains("clobber", plan.SelectedProbes);
        Assert.Contains("gadgetCfg", plan.ClobberProbeNames);
        Assert.Contains("gadgetCfg", plan.TargetGlobalNames);
    }

    [Fact]
    public void Plan_SkipsActiveProbesInPassiveMode()
    {
        var hits = new List<GadgetRadarService.GadgetRadarHit>
        {
            new() { Name = "window.x", Key = "x", FirstPartyStack = true }
        };
        var plan = GadgetChainPlanner.Build(hits, surface: null, active: false, requestedProbes: null);
        Assert.DoesNotContain("clobber", plan.SelectedProbes);
        Assert.DoesNotContain("client-pp", plan.SelectedProbes);
    }
}
