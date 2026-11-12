using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class LoginInjectionHelpersTests
{
    [Fact]
    public void ClassifyAuthBypass_SuppressesRedirectWhenBaselineAlreadyAuthed()
    {
        var baseline = new LoginInjectionHelpers.LoginProbeResponse
        {
            Status = 302,
            Location = "/Dashboard"
        };
        var attack = new LoginInjectionHelpers.LoginProbeResponse
        {
            Status = 302,
            Location = "/Dashboard"
        };

        Assert.Null(LoginInjectionHelpers.ClassifyAuthBypass(attack, baseline));
    }

    [Fact]
    public void ClassifyAuthBypass_FlagsRedirectWhenBaselineStaysOnLogin()
    {
        var baseline = new LoginInjectionHelpers.LoginProbeResponse
        {
            Status = 401,
            Location = "/login?failed=1"
        };
        var attack = new LoginInjectionHelpers.LoginProbeResponse
        {
            Status = 302,
            Location = "/Dashboard"
        };

        var result = LoginInjectionHelpers.ClassifyAuthBypass(attack, baseline);
        Assert.NotNull(result);
        Assert.Equal("redirect_to_authed_page", result.Value.Signal);
    }

    [Fact]
    public void RedirectLocationsEquivalent_IgnoresFragment()
    {
        Assert.True(LoginInjectionHelpers.RedirectLocationsEquivalent("/Dashboard", "/Dashboard#tab=1"));
    }
}
