using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class HeadersResultHstsTests
{
    [Fact]
    public void HasStrictTransportSecurity_true_when_header_present()
    {
        var result = new HeadersResult
        {
            IsHttps = true,
            RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["strict-transport-security"] = "max-age=31536000"
            }
        };
        Assert.True(result.HasStrictTransportSecurity);
    }

    [Fact]
    public void HasStrictTransportSecurity_false_when_missing_despite_finding_text()
    {
        var result = new HeadersResult
        {
            IsHttps = true,
            RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            Findings =
            [
                new HeaderFinding
                {
                    Header = "Strict-Transport-Security",
                    Description = "No HSTS header on HTTPS page."
                }
            ]
        };
        Assert.False(result.HasStrictTransportSecurity);
    }
}
