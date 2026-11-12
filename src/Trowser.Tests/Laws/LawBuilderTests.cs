using Trowser.Laws;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawBuilderTests
{
    [Fact]
    public void Severity_after_expect_updates_registered_law()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "severity order", null, "test.csx")
            .OnPage("*")
            .Expect((PageFacts _) => true)
            .Severity(Severity.High);

        var law = registry.All.Single();
        Assert.Equal(Severity.High, law.Severity);
    }

    [Fact]
    public void Chained_expect_combines_with_and()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "both", null, "test.csx")
            .OnPage("*")
            .Expect((PageFacts _) => false)
            .Expect((PageFacts _) => true);

        var law = registry.All.Single();
        Assert.False(law.PageExpect!(new PageFacts(new Dictionary<string, object?>(), new HashSet<string>(), "https://x/", "t")));
    }

    [Fact]
    public void OnPage_after_expect_throws()
    {
        var registry = new LawRegistry();
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            new LawBuilder(registry, "bad order", null, "test.csx")
                .OnPage("*")
                .Expect((PageFacts _) => true)
                .OnPage("/other*");
        });
        Assert.Contains("OnPage", ex.Message);
    }

    [Fact]
    public void Site_default_page_pattern_applies_when_onpage_omitted()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "scoped", "example.com", "test.csx", defaultPagePattern: "/mvk/*")
            .Expect((PageFacts _) => true);

        var law = registry.All.Single();
        Assert.Equal("/mvk/*", law.TriggerPattern);
    }

    [Fact]
    public void Expect_and_forbid_both_apply()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "expect forbid", null, "test.csx")
            .OnPage("*")
            .Expect((PageFacts _) => true)
            .Forbid((PageFacts _) => false);

        var law = registry.All.Single();
        var facts = new PageFacts(new Dictionary<string, object?>(), new HashSet<string>(), "https://x/", "t");
        Assert.True(law.PageExpect!(facts));
        Assert.False(law.PageForbid!(facts));
    }
}
