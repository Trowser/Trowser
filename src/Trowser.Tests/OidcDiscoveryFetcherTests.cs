using System.Text.Json;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public sealed class OidcDiscoveryFetcherTests
{
    [Fact]
    public void BuildDiscoveryUrls_includes_openid_and_oauth_authorization_server()
    {
        var urls = OidcDiscoveryFetcher.BuildDiscoveryUrls("https://login.example/realms/x");
        Assert.Contains(urls, u => u.Contains("openid-configuration", StringComparison.Ordinal));
        Assert.Contains(urls, u => u.Contains("oauth-authorization-server", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("""{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/auth"}""", true)]
    [InlineData("""{"error":"not found"}""", false)]
    [InlineData("""["not","an","object"]""", false)]
    public void LooksLikeDiscoveryDocument_via_fetch_result_shape(string json, bool expectFound)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var looks = root.ValueKind == JsonValueKind.Object
                    && (root.TryGetProperty("issuer", out _)
                        || root.TryGetProperty("authorization_endpoint", out _)
                        || root.TryGetProperty("token_endpoint", out _));
        Assert.Equal(expectFound, looks);
    }
}
