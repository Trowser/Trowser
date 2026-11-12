using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class DomXssAuditRunnerTests
{
    [Fact]
    public void ResolveWallClockSeconds_ExplicitMaxSeconds_Wins()
    {
        var options = new DomXssAuditRunner.DomXssAuditOptions { MaxSeconds = 45, TimeoutMs = 8_000 };
        Assert.Equal(45, DomXssAuditRunner.ResolveWallClockSeconds(options));
    }

    [Fact]
    public void ResolveWallClockSeconds_DerivesBoundedDefault_WhenZero()
    {
        var minimal = new DomXssAuditRunner.DomXssAuditOptions
        {
            RunClientSurface = false,
            RunPassiveXss = false,
            RunDomFlowProbe = false,
            RunTraceInput = true,
            ProbeAllUrlParams = false,
            ProbeUrlHash = true,
            TimeoutMs = 6_000,
            MaxSeconds = 0
        };
        var sec = DomXssAuditRunner.ResolveWallClockSeconds(minimal);
        Assert.InRange(sec, 15, 90);
    }

    [Fact]
    public void PlanScanDepth_Standard_IsMediumCurrentPage()
    {
        var plan = DomXssAuditRunner.PlanScanDepth(null);
        Assert.Equal(SecurityScanDepth.Standard, plan.Depth);
        Assert.False(plan.RunClientSurface);
        Assert.False(plan.ProbeAllUrlParams);
        Assert.True(plan.ProbeUrlHash);
        Assert.True(plan.RunTraceInput);
        Assert.False(plan.RunScriptGatedTraces);
        Assert.Equal(45, plan.MaxSeconds);
    }

    [Fact]
    public void PlanScanDepth_Quick_SkipsTraceInput()
    {
        var plan = DomXssAuditRunner.PlanScanDepth("quick");
        Assert.False(plan.RunTraceInput);
        Assert.False(plan.ProbeUrlHash);
    }

    [Fact]
    public void PlanScanDepth_Deep_FullSweep()
    {
        var plan = DomXssAuditRunner.PlanScanDepth("deep");
        Assert.True(plan.RunClientSurface);
        Assert.True(plan.ProbeAllUrlParams);
        Assert.True(plan.RunScriptGatedTraces);
        Assert.True(plan.ConfirmExecutionUnlessExplicit);
    }

    [Fact]
    public void ResolveOptions_UsesPlanWhenFlagsOmitted()
    {
        var plan = DomXssAuditRunner.PlanScanDepth("standard");
        var options = DomXssAuditRunner.ResolveOptions(plan, confirmExecution: false, maxSecondsOverride: 0,
            null, null, null, null, null, null, null, null, null);
        Assert.False(options.RunClientSurface);
        Assert.False(options.ProbeAllUrlParams);
        Assert.Equal(45, options.MaxSeconds);
    }
}
