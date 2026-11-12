using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ShadowFindingReportTests
{
    [Theory]
    [InlineData("https://shop.example.com/cart", "shop.example.com")]
    [InlineData("https://shop.example.com:8443/cart", "shop.example.com")]
    [InlineData("http://localhost:3000/api", "localhost")]
    [InlineData("https://api.other.test/v1", "api.other.test")]
    public void try_get_domain_uses_host(string url, string expected)
    {
        Assert.Equal(expected, ShadowFinding.TryGetDomain(url));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-url")]
    [InlineData("/relative/path")]
    public void try_get_domain_ignores_unparseable(string? url)
    {
        Assert.Null(ShadowFinding.TryGetDomain(url));
    }

    [Fact]
    public void collect_seen_on_domains_collapses_pages_on_same_host()
    {
        var domains = ShadowFinding.CollectSeenOnDomains(
        [
            "https://shop.example.com/cart",
            "https://shop.example.com/checkout",
            "https://api.other.test/health",
            "https://shop.example.com/cart"
        ]);

        Assert.Equal(["api.other.test", "shop.example.com"], domains);
    }

    [Fact]
    public void format_findings_lists_unique_domains_not_every_page()
    {
        var shadow = new SecurityShadowManager();
        shadow.AddCustomFinding(Severity.Medium, "Missing CSP", "No Content-Security-Policy header.",
            url: "https://shop.example.com/cart");
        shadow.AddCustomFinding(Severity.Medium, "Missing CSP", "No Content-Security-Policy header.",
            url: "https://shop.example.com/checkout");
        shadow.AddCustomFinding(Severity.Medium, "Missing CSP", "No Content-Security-Policy header.",
            url: "https://api.other.test/health");

        var report = shadow.FormatFindings();

        Assert.Contains("Occurrences: 3", report);
        Assert.Contains("Domains: api.other.test, shop.example.com", report);
        Assert.DoesNotContain("/cart", report);
        Assert.DoesNotContain("/checkout", report);
        Assert.DoesNotContain("/health", report);
    }

    [Fact]
    public void format_findings_omits_domains_for_single_occurrence()
    {
        var shadow = new SecurityShadowManager();
        shadow.AddCustomFinding(Severity.Low, "HTTP 404 on GET /missing", "gone",
            url: "https://shop.example.com/missing");

        var report = shadow.FormatFindings();

        Assert.DoesNotContain("Occurrences:", report);
        Assert.DoesNotContain("Domains:", report);
    }
}
