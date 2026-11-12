using Trowser.Automation;
using Trowser.Laws;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawPathMatchTests
{
    [Fact]
    public void PagePathGlob_matches_query()
    {
        Assert.True(LawPathMatch.PagePathMatches("/cart*", "https://shop.example.com/cart?x=1"));
        Assert.False(LawPathMatch.PagePathMatches("/checkout*", "https://shop.example.com/cart"));
    }

    [Fact]
    public void PagePath_literal_does_not_substring_match_other_paths()
    {
        Assert.True(LawPathMatch.PagePathMatches("/sweets", "https://sweetshop.netlify.app/sweets"));
        Assert.False(LawPathMatch.PagePathMatches("/sweets", "https://sweetshop.netlify.app/about"));
        Assert.False(LawPathMatch.PagePathMatches("/sweets", "https://sweetshop.netlify.app/basket"));
    }

    [Fact]
    public void HostMatch_is_exact_not_substring()
    {
        Assert.True(LawPathMatch.HostMatches("shop.netlify.app", "shop.netlify.app"));
        Assert.False(LawPathMatch.HostMatches("shop.netlify.app", "evilshop.netlify.app"));
    }

    [Fact]
    public void HostMatch_bare_domain_includes_subdomains()
    {
        Assert.True(LawPathMatch.HostMatches("spaceducking.com", "www.spaceducking.com"));
        Assert.True(LawPathMatch.HostMatches("spaceducking.com", "spaceducking.com"));
        Assert.False(LawPathMatch.HostMatches("spaceducking.com", "notspaceducking.com"));
    }

    [Fact]
    public void ResponsePattern_matches_method_and_path()
    {
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://api.example.com/api/cart/items",
            StatusCode = 200
        };
        Assert.True(LawPathMatch.ResponseMatches("GET /api/cart*", entry));
        Assert.False(LawPathMatch.ResponseMatches("POST /api/cart*", entry));
    }
}
