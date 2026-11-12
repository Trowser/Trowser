using Trowser.Security.DomFlow;
using Trowser.Security.GadgetChains;
using Trowser.Security.Runtime;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class GadgetRadarLeadsTests
{
    [Fact]
    public void IsClobberProbeCandidate_FalseForDocumentScriptScanBuiltin()
    {
        var hit = new GadgetRadarService.GadgetRadarHit
        {
            Name = "document.navigator",
            Key = "navigator",
            Receiver = "document",
            FirstPartyStack = true,
            Discovery = GadgetRadarLeads.DiscoveryScriptScan
        };
        Assert.False(GadgetRadarLeads.IsClobberProbeCandidate(hit));
    }

    [Fact]
    public void IsClobberProbeCandidate_TrueForWindowTrapRead()
    {
        var hit = new GadgetRadarService.GadgetRadarHit
        {
            Name = "window.gadgetCfg",
            Key = "gadgetCfg",
            Receiver = "window",
            FirstPartyStack = true,
            Discovery = GadgetRadarLeads.DiscoveryTrap
        };
        Assert.True(GadgetRadarLeads.IsClobberProbeCandidate(hit));
    }

    [Fact]
    public void ShouldEmitDomFlowFinding_FalseForInertValueMatch()
    {
        var chain = new DomFlowGraph.DomFlowChain
        {
            Source = "window.name",
            Sink = "innerHTML",
            Tier = "exploitable",
            Consequence = "inert",
            Confidence = "value-match",
            Stack = "at x (https://app.test/main.js:1:1)"
        };
        Assert.False(GadgetRadarLeads.ShouldEmitDomFlowFinding(chain));
        Assert.True(GadgetRadarLeads.IsDomFlowLead(chain));
    }

    [Fact]
    public void ShouldEmitDomFlowFinding_TrueForExecCanary()
    {
        var chain = new DomFlowGraph.DomFlowChain
        {
            Source = "url-query",
            Sink = "innerHTML",
            Tier = "exploitable",
            Consequence = "exec",
            Confidence = "canary"
        };
        Assert.True(GadgetRadarLeads.ShouldEmitDomFlowFinding(chain));
    }
}
