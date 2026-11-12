using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class RedirectParamBypassLabelTests
{
    [Fact]
    public void ClassifyBypassTechnique_WithoutFilterEvidence_UsesAbsoluteUrl_NotSubstringBypass()
    {
        var technique = RedirectParamDiscovery.ClassifyBypassTechnique(
            "https://example.com/notes/1",
            "/dashboard",
            "https://example.com/notes/1",
            filterEvidence: false);

        Assert.Equal("absolute-url", technique);
    }

    [Fact]
    public void ClassifyBypassTechnique_WithFilterEvidence_AllowsSubstringBypassLabel()
    {
        var technique = RedirectParamDiscovery.ClassifyBypassTechnique(
            "https://example.com/allowed/evil",
            "/allowed",
            "https://example.com/allowed/evil",
            filterEvidence: true);

        Assert.Equal("substring-filter-bypass", technique);
    }
}
