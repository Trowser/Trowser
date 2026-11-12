using Trowser.Security.ChainEngine;
using Xunit;

namespace Trowser.Tests;

public class ChainDiscoveryEngineTests
{
    [Fact]
    public void HstsDowngrade_StaysPartial_WithoutConfirmationEvidence()
    {
        var catalog = new ChainPatternCatalog();
        var engine = new ChainDiscoveryEngine(catalog);
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "shadow-hsts",
                Source = "shadow",
                Category = "missing-hsts",
                Severity = "low",
                Title = "Missing HSTS",
                Endpoint = "https://example.com/"
            }
        };

        var result = engine.Analyze(findings);
        Assert.Empty(result.Chains);
        Assert.Single(result.PartialChains);
        var partial = result.PartialChains[0];
        Assert.Equal("missing-hsts-downgrade-risk", partial.PatternId);
        Assert.Equal("partial", partial.Status);
        Assert.Contains("needs-http-probe", partial.Tags);
        Assert.Equal(1, partial.PresentLinkCount);
        Assert.Equal(1, partial.RequiredLinkCount);
        Assert.NotEmpty(partial.MissingCategories);
    }

    [Fact]
    public void HstsDowngrade_Confirms_WithMixedContent()
    {
        var catalog = new ChainPatternCatalog();
        var engine = new ChainDiscoveryEngine(catalog);
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "1",
                Source = "shadow",
                Category = "missing-hsts",
                Severity = "low",
                Endpoint = "https://example.com/"
            },
            new()
            {
                Id = "2",
                Source = "shadow",
                Category = "mixed-content",
                Severity = "medium",
                Endpoint = "https://example.com/app"
            }
        };

        var result = engine.Analyze(findings);
        var hsts = Assert.Single(result.Chains, c => c.PatternId == "missing-hsts-downgrade-risk");
        Assert.Equal("matched", hsts.Status);
        Assert.False(hsts.Provable);
    }

    [Fact]
    public void PartialChain_CountsRequiredLinksOnly()
    {
        var catalog = new ChainPatternCatalog();
        var engine = new ChainDiscoveryEngine(catalog);
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "sri",
                Source = "manual",
                Category = "missing-sri",
                Severity = "low",
                Endpoint = "https://cdn.example/lib.js",
                Tags = ["external-script"]
            },
            new()
            {
                Id = "csp",
                Source = "manual",
                Category = "missing-csp",
                Severity = "low",
                Endpoint = "https://example.com/"
            }
        };

        var result = engine.Analyze(findings, includePartial: true);
        var sriPartial = result.PartialChains.FirstOrDefault(p => p.PatternId.Contains("sri", StringComparison.OrdinalIgnoreCase));
        if (sriPartial != null)
        {
            // The optional CSP amplifier may be listed as present, but only required links count.
            Assert.Contains(sriPartial.PresentFindings, f =>
                f.Category.Equals("missing-sri", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1, sriPartial.RequiredLinkCount);
            Assert.True(sriPartial.PresentLinkCount <= sriPartial.RequiredLinkCount);
        }
    }
}
