using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class UrlPayloadInjectorTests
{
    [Fact]
    public void StripToolQueryParams_removes_cache_buster()
    {
        var stripped = UrlPayloadInjector.StripToolQueryParams(
            "https://app.test/t/page.html?_trowser_rc=abc123&next=%2Fhome");
        Assert.DoesNotContain("_trowser_rc", stripped, StringComparison.Ordinal);
        Assert.Contains("next=%2Fhome", stripped, StringComparison.Ordinal);
    }
}
