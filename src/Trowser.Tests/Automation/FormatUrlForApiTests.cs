using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class FormatUrlForApiTests
{
    [Fact]
    public void FormatUrlForApi_PercentEncodesQueryConsistently()
    {
        var raw = "https://example.test/path?a=%3C%3E&b=%3D";
        var formatted = AutomationContext.FormatUrlForApi(raw);
        Assert.Contains("%3C", formatted, StringComparison.Ordinal);
        Assert.Contains("%3D", formatted, StringComparison.Ordinal);
        Assert.DoesNotContain("<", formatted, StringComparison.Ordinal);
    }
}
