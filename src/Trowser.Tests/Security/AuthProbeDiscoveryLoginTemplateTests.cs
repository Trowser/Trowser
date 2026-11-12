using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class AuthProbeDiscoveryLoginTemplateTests
{
    [Fact]
    public void InferDefaultLoginTemplate_RespectsExplicitFormContentType_OnLoginPath()
    {
        var surface = new AuthProbeDiscovery.LoginSurface
        {
            Url = "http://127.0.0.1:6903/login",
            ContentType = "application/x-www-form-urlencoded",
            UserField = "username",
            PassField = "password"
        };

        AuthProbeDiscovery.InferDefaultLoginTemplate(surface);

        Assert.Contains("username=", surface.BodyTemplate);
        Assert.DoesNotContain("{", surface.BodyTemplate!);
        Assert.Equal("application/x-www-form-urlencoded", surface.ContentType);
    }

    [Fact]
    public void IsFormUrlEncodedContentType_DetectsFormMime()
    {
        Assert.True(AuthProbeDiscovery.IsFormUrlEncodedContentType("application/x-www-form-urlencoded"));
        Assert.False(AuthProbeDiscovery.IsFormUrlEncodedContentType("application/json"));
    }
}
