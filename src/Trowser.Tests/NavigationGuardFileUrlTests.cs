using Trowser;
using Xunit;

namespace Trowser.Tests;

public class NavigationGuardFileUrlTests
{
    [Fact]
    public void file_url_blocked_by_default_even_with_allow_all_scope()
    {
        var guard = new NavigationGuard("*.*");
        Assert.False(guard.IsAllowed("file:///C:/Windows/win.ini"));
    }

    [Fact]
    public void file_url_allowed_when_opt_in()
    {
        var guard = new NavigationGuard("*.*", allowFileUrls: true);
        Assert.True(guard.IsAllowed("file:///C:/Windows/win.ini"));
    }

    [Fact]
    public void https_still_allowed_with_default_file_block()
    {
        var guard = new NavigationGuard("*.*");
        Assert.True(guard.IsAllowed("https://example.com/page"));
    }
}
