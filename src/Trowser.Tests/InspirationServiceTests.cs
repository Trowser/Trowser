using Xunit;

namespace Trowser.Tests;

public class InspirationServiceTests
{
    [Fact]
    public void X_terms_are_the_quality_characteristics()
    {
        Assert.Equal(
        [
            "capability", "reliability", "usability", "charisma", "security",
            "performance", "IT-bility", "compatibility", "standards",
            "supportability", "testability", "maintainability", "portability"
        ], InspirationService.XTerms);
    }

    [Fact]
    public void Y_terms_are_sfdipot_product_elements()
    {
        Assert.Equal(
        [
            "structure", "function", "data", "interfaces", "platform",
            "operations", "time"
        ], InspirationService.YTerms);
    }

    [Fact]
    public void Resolve_xy_equation_is_x_plus_y()
    {
        var seenX = new HashSet<string>();
        var seenY = new HashSet<string>();

        for (var i = 0; i < 400; i++)
        {
            var message = InspirationService.Resolve("XY_EQUATION");
            Assert.EndsWith(" = ?", message);

            var body = message[..^" = ?".Length];
            var plus = body.IndexOf(" + ", StringComparison.Ordinal);
            Assert.True(plus > 0, message);

            var x = body[..plus];
            var y = body[(plus + 3)..];
            Assert.Contains(x, InspirationService.XTerms);
            Assert.Contains(y, InspirationService.YTerms);
            seenX.Add(x);
            seenY.Add(y);
        }

        Assert.Equal(InspirationService.XTerms.Length, seenX.Count);
        Assert.Equal(InspirationService.YTerms.Length, seenY.Count);
    }

    [Fact]
    public void Resolve_po_statement_is_po_plus_a_word()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 800; i++)
        {
            var message = InspirationService.Resolve("PO_STATEMENT");
            Assert.StartsWith("PO: ", message);
            var word = message["PO: ".Length..];
            Assert.Contains(word, InspirationService.PoWords);
            seen.Add(word);
        }

        Assert.Equal(InspirationService.PoWords.Length, seen.Count);
    }

    [Fact]
    public void Resolve_leaves_ordinary_lines_unchanged()
    {
        Assert.Equal("Try it backwards", InspirationService.Resolve("Try it backwards"));
    }

    [Fact]
    public void GetRandom_expands_markers_from_the_message_file()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """
                # comment

                XY_EQUATION
                PO_STATEMENT
                Try it backwards
                """);

            var service = new InspirationService(path);
            var seen = new HashSet<string>();
            for (var i = 0; i < 80; i++)
                seen.Add(service.GetRandom()!);

            Assert.Contains(seen, m => m.Contains(" + ", StringComparison.Ordinal) && m.EndsWith(" = ?", StringComparison.Ordinal));
            Assert.Contains(seen, m => m.StartsWith("PO: ", StringComparison.Ordinal));
            Assert.Contains("Try it backwards", seen);
            Assert.DoesNotContain("XY_EQUATION", seen);
            Assert.DoesNotContain("PO_STATEMENT", seen);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
