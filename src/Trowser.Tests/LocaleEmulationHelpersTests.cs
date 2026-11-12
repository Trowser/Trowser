using Trowser.Automation;
using Xunit;

namespace Trowser.Tests;

public class LocaleEmulationHelpersTests
{
    [Theory]
    [InlineData("de-DE", "de-DE,de,en")]
    [InlineData("en-US", "en-US,en")]
    [InlineData("sv", "sv,en")]
    public void BuildAcceptLanguageHeader_omits_q_values(string locale, string expected)
    {
        Assert.Equal(expected, LocaleEmulationHelpers.BuildAcceptLanguageHeader(locale));
    }
}
