using Trowser.Laws;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawRegistryTests
{
    [Fact]
    public void TryRegister_rejects_duplicate_name_across_sources()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "Same name", null, "a.csx")
            .OnPage("*")
            .Expect(p => !string.IsNullOrWhiteSpace(p.Title));
        var ex = Assert.Throws<InvalidOperationException>(() =>
            new LawBuilder(registry, "Same name", null, "b.csx")
                .OnPage("*")
                .Expect(p => !string.IsNullOrWhiteSpace(p.Title)));
        Assert.Contains("Duplicate Law name", ex.Message);
    }

    [Fact]
    public void FindNameConflict_detects_other_file()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "Title law", null, "a.csx")
            .OnPage("*")
            .Expect(p => !string.IsNullOrWhiteSpace(p.Title));
        var candidate = new LawDefinition
        {
            Id = "b.csx|Title law",
            Name = "Title law",
            Trigger = LawTriggerKind.Page,
            SourceFile = "b.csx"
        };
        Assert.Equal("a.csx", registry.FindNameConflict(candidate, excludeSourceFile: "b.csx"));
    }
}
