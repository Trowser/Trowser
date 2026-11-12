using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class RedirectAnalysisOpenRedirectTests
{
    private static readonly Uri Request = new("https://app.example/redirect");

    [Fact]
    public void ShouldFlag_WhenBaselineAlreadyExternal_ButProbePointsToProbeHost()
    {
        var baseline = new RedirectAnalysis.OpenRedirectResponseSignals(
            "https://allowed.example/path", null, null);
        var probe = new RedirectAnalysis.OpenRedirectResponseSignals(
            $"https://{RedirectAnalysis.DefaultProbeHost}/", null, null);

        Assert.True(RedirectAnalysis.ShouldFlagOpenRedirect(
            Request, RedirectAnalysis.DefaultProbeHost, probe, baseline));
    }

    [Fact]
    public void ShouldNotFlag_WhenProbeRedirectsToSameOriginLogin()
    {
        var request = new Uri("https://app.example/redirect?next=x");
        var baseline = new RedirectAnalysis.OpenRedirectResponseSignals("/dashboard", null, null);
        var probe = new RedirectAnalysis.OpenRedirectResponseSignals("/login?return=/", null, null);

        Assert.False(RedirectAnalysis.ShouldFlagOpenRedirect(
            request, RedirectAnalysis.DefaultProbeHost, probe, baseline));
    }

    [Fact]
    public void ShouldNotFlag_WhenBaselineAndProbeBothStayOnSameExternalHost()
    {
        var baseline = new RedirectAnalysis.OpenRedirectResponseSignals(
            "https://allowed.example/path", null, null);
        var probe = new RedirectAnalysis.OpenRedirectResponseSignals(
            "https://allowed.example/other", null, null);

        Assert.False(RedirectAnalysis.ShouldFlagOpenRedirect(
            Request, RedirectAnalysis.DefaultProbeHost, probe, baseline));
    }

    [Fact]
    public void ShouldFlag_MetaRefreshToProbe_WhenBaselineHadNoRefresh()
    {
        var html = "<html><head><meta http-equiv=\"refresh\" content=\"0;url=https://open-redirect-probe.trowser.test/\"></head></html>";
        var baseline = new RedirectAnalysis.OpenRedirectResponseSignals(null, null, "<html></html>");
        var probe = new RedirectAnalysis.OpenRedirectResponseSignals(null, null, html);

        Assert.True(RedirectAnalysis.ShouldFlagOpenRedirect(
            Request, RedirectAnalysis.DefaultProbeHost, probe, baseline));
    }

    [Fact]
    public void TryExtractRefreshTarget_ParsesRefreshHeader()
    {
        var target = RedirectAnalysis.TryExtractRefreshTarget("0;url=https://evil.example/x", null);
        Assert.Equal("https://evil.example/x", target);
    }

    [Theory]
    [InlineData("redirectTo")]
    [InlineData("redirect_uri")]
    [InlineData("nextUrl")]
    [InlineData("go_to")]
    public void RedirectLike_IncludesCommonParamNames(string name) =>
        Assert.True(UrlLikeParamNames.IsRedirectLikeName(name));

    [Fact]
    public void RedirectLike_ExcludesBareGo()
    {
        Assert.False(UrlLikeParamNames.IsRedirectLikeName("go"));
        Assert.True(UrlLikeParamNames.IsRedirectLikeName("go_to"));
    }

    [Fact]
    public void BuildProbeRequest_UsesJsonBodyForNetworkBodySource()
    {
        var pt = new RedirectParamDiscovery.InjectionPoint
        {
            BaseUri = new Uri("https://app.example/api/redirect"),
            ParamName = "redirectTo",
            OriginalValue = "/home",
            Method = "POST",
            Source = "network-body",
            RequestBodySample = """{"redirectTo":"/home","user":"x"}""",
            RequestContentType = "application/json"
        };

        var req = RedirectParamDiscovery.BuildProbeRequest(pt, "https://open-redirect-probe.trowser.test/");
        Assert.Equal("https://app.example/api/redirect", req.Url);
        Assert.NotNull(req.Body);
        Assert.Contains("open-redirect-probe.trowser.test", req.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(req.Url, "redirectTo=", StringComparison.Ordinal);
    }
}
