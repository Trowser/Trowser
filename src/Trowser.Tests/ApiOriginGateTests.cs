using Trowser.Api;
using Xunit;

namespace Trowser.Tests;

/// <summary>Web pages must not be able to drive the local API, even when the key is disabled.</summary>
public class ApiOriginGateTests
{
    [Theory]
    [InlineData(null, null, false)]                              // curl, MCP clients, scripts
    [InlineData("http://localhost:3000", null, false)]
    [InlineData("http://127.0.0.1:8080", "same-site", false)]
    [InlineData("http://[::1]:5000", null, false)]
    [InlineData("https://evil.example", null, true)]
    [InlineData("null", null, true)]                             // sandboxed iframe, file://, data:
    [InlineData(null, "cross-site", true)]                       // no-cors navigation-style request
    [InlineData("http://localhost.evil.example", null, true)]
    public void Blocks_non_loopback_browser_origins(string? origin, string? secFetchSite, bool blocked) =>
        Assert.Equal(blocked, TrowserApiServer.IsCrossSiteBrowserRequest(origin, secFetchSite));
}
