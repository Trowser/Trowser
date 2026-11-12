using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class NavWaitSatisfiedTests
{
    [Fact]
    public void SpNavigationSucceededDespiteStaleHref_AcceptsSameOriginPushStateRoute()
    {
        const string before = "https://app.example.test/inbox?page=1";
        const string href = "https://app.example.test/";
        const string after = "https://app.example.test/messageDetail/1538809?page=1";

        Assert.True(AutomationContext.SpNavigationSucceededDespiteStaleHref(before, after, href));
        Assert.True(AutomationContext.NavWaitSatisfied(before, after, href));
    }

    [Fact]
    public void SpNavigationSucceededDespiteStaleHref_RejectsUnchangedUrl()
    {
        const string url = "https://app.example.test/inbox";
        const string href = "https://app.example.test/";

        Assert.False(AutomationContext.SpNavigationSucceededDespiteStaleHref(url, url, href));
    }

    [Fact]
    public void SpNavigationSucceededDespiteStaleHref_RejectsCrossOriginRedirect()
    {
        const string before = "https://app.example.test/inbox";
        const string href = "https://app.example.test/detail";
        const string after = "https://other.example.test/detail";

        Assert.False(AutomationContext.SpNavigationSucceededDespiteStaleHref(before, after, href));
    }

    [Fact]
    public void NavWaitSatisfied_ExactHrefMatchStillWorks()
    {
        const string target = "https://app.example.test/messageDetail/1";
        Assert.True(AutomationContext.NavWaitSatisfied(target, target, target));
    }
}
