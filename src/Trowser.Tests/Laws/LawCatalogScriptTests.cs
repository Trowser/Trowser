using Trowser.Laws;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawCatalogScriptTests
{
    [Fact]
    public void TryGetEmbeddedLawSourceKey_maps_quicktests_laws_resource()
    {
        Assert.True(LawCatalogScript.TryGetEmbeddedLawSourceKey(
            "Trowser.Resources.Quicktests.Laws.GenericWebLaws.csx",
            out var key));
        Assert.Equal("embedded:GenericWebLaws.csx", key);
    }

    [Fact]
    public void TryGetEmbeddedLawSourceKey_rejects_non_law_quicktest()
    {
        Assert.False(LawCatalogScript.TryGetEmbeddedLawSourceKey(
            "Trowser.Resources.Quicktests.SiteHealth.csx",
            out _));
    }

    [Fact]
    public void BuildScriptConsoleRunner_uses_source_scoped_check()
    {
        var code = LawCatalogScript.BuildScriptConsoleRunner("embedded:GenericWebLaws.csx");
        Assert.Contains("includeTraffic: true", code);
        Assert.Contains("embedded:GenericWebLaws.csx", code);
        Assert.Contains("sourceFile:", code);
    }

    [Fact]
    public void SourceFileMatches_compares_normalized_paths()
    {
        Assert.True(LawCatalogScript.SourceFileMatches(
            @"C:\Docs\Trowser Quicktests\Laws\site.csx",
            @"c:\docs\trowser quicktests\laws\site.csx"));
        Assert.False(LawCatalogScript.SourceFileMatches(
            "embedded:GenericWebLaws.csx",
            "embedded:WebPhysics.csx"));
    }
}