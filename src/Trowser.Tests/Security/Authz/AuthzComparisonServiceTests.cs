using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AuthzComparisonServiceTests
{
    [Fact]
    public void SanitizeReplayHeaders_StripsCookieAndAuthorization()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "session=abc123",
            ["Authorization"] = "Bearer xyz",
            ["Proxy-Authorization"] = "Basic zzz",
            ["Accept"] = "application/json",
            ["Accept-Encoding"] = "gzip, deflate, br",
            ["If-None-Match"] = "\"abc\""
        };

        var cleaned = AuthzComparisonService.SanitizeReplayHeaders(headers);

        Assert.NotNull(cleaned);
        Assert.False(cleaned!.ContainsKey("Cookie"));
        Assert.False(cleaned.ContainsKey("Authorization"));
        Assert.False(cleaned.ContainsKey("Proxy-Authorization"));
        Assert.False(cleaned.ContainsKey("Accept-Encoding"));
        Assert.False(cleaned.ContainsKey("If-None-Match"));
        Assert.True(cleaned.ContainsKey("Accept"));
    }

    [Fact]
    public void SanitizeReplayHeaders_AllHeadersExcluded_ReturnsNull()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "session=abc123",
            ["Authorization"] = "Bearer xyz"
        };

        var cleaned = AuthzComparisonService.SanitizeReplayHeaders(headers);

        Assert.Null(cleaned);
    }

    [Fact]
    public void AuthzLooksLikeDenialRedirect_LoginUrl_ReturnsTrue()
    {
        Assert.True(AuthzComparisonService.AuthzLooksLikeDenialRedirect(
            "https://app.test/login?returnUrl=/orders/42", ""));
    }

    [Fact]
    public void AuthzLooksLikeDenialRedirect_OrdinaryUrlAndBody_ReturnsFalse()
    {
        Assert.False(AuthzComparisonService.AuthzLooksLikeDenialRedirect(
            "https://app.test/orders/42", "{\"id\":42}"));
    }
}
