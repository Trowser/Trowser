using Xunit;

namespace Trowser.Tests;

public class DevToolsWindowProbeTests
{
    [Theory]
    [InlineData("DevTools")]
    [InlineData("DevTools - https://example.com/")]
    [InlineData("devtools - about:blank")]
    [InlineData("example.com — DevTools")]
    [InlineData("Developer Tools")]
    public void recognizes_devtools_window_titles(string title) =>
        Assert.True(DevToolsWindowProbe.IsDevToolsTitle(title));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Trowser")]
    [InlineData("Example Domain")]
    [InlineData("https://example.com/")]
    public void ignores_unrelated_titles(string? title) =>
        Assert.False(DevToolsWindowProbe.IsDevToolsTitle(title));
}
