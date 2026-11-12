using Trowser.Laws;
using Trowser.Recording;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawCodeGeneratorTests
{
    [Fact]
    public void FromElement_includes_selector_expect()
    {
        var el = new ContextMenuElementInfo
        {
            Selector = "#checkout",
            Tag = "button",
            Text = "Pay now"
        };
        var code = LawCodeGenerator.FromElement(el, new Uri("https://shop.example.com/cart"));
        Assert.Contains("Site(\"shop.example.com\")", code);
        Assert.Contains("#checkout", code);
        Assert.Contains("Pay now", code);
        Assert.Contains("await CheckLaws()", code);
    }

    [Fact]
    public void FromFinding_noopener_scaffold()
    {
        var finding = new ShadowFinding
        {
            Url = "https://shop.example.com/cart",
            Audit = "tabnabbing",
            Title = "Reverse tabnabbing: target=_blank without noopener",
            Description = "16 link(s) open in a new tab without rel=noopener/noreferrer."
        };
        var code = LawCodeGenerator.FromFinding(finding);
        Assert.Contains("noopener", code, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Site(\"shop.example.com\"", code);
        Assert.Contains("/cart*", code);
    }

    [Fact]
    public void StripConsoleRunnerLines_removes_check_and_assert_runners()
    {
        var raw = """
            Law("x").OnPage("*").Expect(p => true);
            await CheckLaws();
            await AssertLaws();
            """;
        var stripped = LawCodeGenerator.StripConsoleRunnerLines(raw);
        Assert.DoesNotContain("CheckLaws", stripped);
        Assert.DoesNotContain("AssertLaws", stripped);
        Assert.Contains("Law(\"x\")", stripped);
    }
}
