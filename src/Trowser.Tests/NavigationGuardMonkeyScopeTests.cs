using Trowser;
using Xunit;

namespace Trowser.Tests;

public class NavigationGuardMonkeyScopeTests
{
    [Theory]
    [InlineData("https://www.example.com/app", "https://app.example.com/other")]
    [InlineData("https://shop.example.com/cart", "https://api.example.com/v1")]
    [InlineData("https://example.com/", "https://www.example.com/home")]
    public void temporary_scope_allows_same_registrable_domain(string start, string target)
    {
        Assert.True(NavigationGuard.TryBuildTemporaryScopeFromPageUrl(start, out var scope));
        var guard = new NavigationGuard(scope);
        Assert.True(guard.IsRestricted);
        Assert.True(guard.IsAllowed(target));
    }

    [Fact]
    public void temporary_scope_blocks_other_domains()
    {
        Assert.True(NavigationGuard.TryBuildTemporaryScopeFromPageUrl("https://www.example.com/", out var scope));
        var guard = new NavigationGuard(scope);
        Assert.False(guard.IsAllowed("https://evil.example.org/"));
    }

    [Fact]
    public void localhost_uses_exact_host()
    {
        Assert.True(NavigationGuard.TryBuildTemporaryScopeFromPageUrl("http://localhost:8080/page", out var scope));
        Assert.Equal("http://localhost", scope);
        var guard = new NavigationGuard(scope);
        Assert.True(guard.IsAllowed("http://localhost/other"));
        Assert.False(guard.IsAllowed("http://127.0.0.1/other"));
    }

    [Fact]
    public void non_http_url_fails()
    {
        Assert.False(NavigationGuard.TryBuildTemporaryScopeFromPageUrl("about:blank", out _));
    }
}
