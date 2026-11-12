using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class AuthFormDiscoveryTests
{
    [Fact]
    public void PickBetterNetworkEntry_PrefersPostOverGetForSamePath()
    {
        var get = new NetworkEntry
        {
            Method = "GET",
            Url = "http://127.0.0.1/login",
            StatusCode = 200,
            Timestamp = DateTime.UtcNow.AddMinutes(-1)
        };
        var post = new NetworkEntry
        {
            Method = "POST",
            Url = "http://127.0.0.1/login",
            StatusCode = 401,
            RequestBody = "user=x&pass=y",
            Timestamp = DateTime.UtcNow
        };

        var picked = AuthFormDiscovery.PickBetterNetworkEntry(get, post);
        Assert.Equal("POST", picked!.Method);
    }
}
