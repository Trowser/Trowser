using Trowser.EndpointProbe;
using Trowser.Security;
using Trowser.Security.Orchestration;
using Xunit;

namespace Trowser.Tests.Security;

public class EndpointScopeHelperTests
{
    [Fact]
    public void ApplyToAutoScan_endpoint_scope_disables_site_wide_extras()
    {
        var options = new AutoScanPipeline.AutoScanOptions
        {
            AllowGenericScaffold = true,
            IncludeXssDom = true,
            IncludeSqliLoginSweep = true,
            IncludePassiveNetworkRecall = true,
            MaxEndpointsPerScanner = 5
        };

        EndpointScopeHelper.ApplyToAutoScan(options, new PlaybookScope
        {
            TargetUrl = "https://app.example/api/order",
            TargetMethod = "POST"
        });

        Assert.Equal("https://app.example/api/order", options.TargetUrl);
        Assert.Equal("POST", options.TargetMethod);
        Assert.Equal(1, options.MaxEndpointsPerScanner);
        Assert.False(options.AllowGenericScaffold);
        Assert.False(options.IncludeXssDom);
        Assert.False(options.IncludeSqliLoginSweep);
        Assert.False(options.IncludePassiveNetworkRecall);
        Assert.False(options.IncludeApiEnrichment);
    }

    [Fact]
    public void ApplyToAutoScan_site_wide_leaves_scaffold_enabled()
    {
        var options = new AutoScanPipeline.AutoScanOptions { AllowGenericScaffold = true };

        EndpointScopeHelper.ApplyToAutoScan(options, new PlaybookScope());

        Assert.True(options.AllowGenericScaffold);
        Assert.Null(options.TargetUrl);
    }

    [Theory]
    [InlineData("a05-injection", true)]
    [InlineData("a01-access", true)]
    [InlineData("request-fuzzer", true)]
    [InlineData("auth-control-identifier", true)]
    [InlineData("a04-crypto", false)]
    [InlineData("a07-authn", false)]
    [InlineData("quick", false)]
    public void endpoint_probe_catalog_classifies_run_scope(string probeId, bool endpointPinned) =>
        Assert.Equal(endpointPinned, EndpointProbeCatalog.IsEndpointPinnedProbe(probeId));
}
