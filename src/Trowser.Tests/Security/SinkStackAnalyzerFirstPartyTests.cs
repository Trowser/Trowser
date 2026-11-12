using Trowser.Security.Runtime;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class SinkStackAnalyzerFirstPartyTests
{
    [Fact]
    public void IsFirstPartyStack_MatchesPageOriginInStackUrl()
    {
        var stack = "Error\n    at foo (https://app.example.com/bundle.js:1:2)";
        var ok = SinkStackAnalyzer.IsFirstPartyStack(
            stack,
            "https://app.example.com",
            ["https://cdn.example.com"]);
        Assert.True(ok);
    }

    [Fact]
    public void IsFirstPartyStack_FalseForThirdPartyOnly()
    {
        var stack = "Error\n    at foo (https://evil.example.net/x.js:1:1)";
        var ok = SinkStackAnalyzer.IsFirstPartyStack(stack, "https://app.example.com", null);
        Assert.False(ok);
    }
}
