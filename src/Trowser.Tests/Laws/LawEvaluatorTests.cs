using System.Globalization;
using Trowser.Automation;
using Trowser.Laws;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawEvaluatorTests
{
    private sealed class CountStubFetcher : IPageFactsFetcher
    {
        public Task<Dictionary<string, object?>> FetchAsync(IReadOnlyList<string> keys, CancellationToken ct)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var k in keys)
                result[k] = k.StartsWith("count\0", StringComparison.Ordinal) ? "1" : "";
            return Task.FromResult(result);
        }
    }

    private sealed class StaticFetcher : IPageFactsFetcher
    {
        private readonly Dictionary<string, object?> _data;

        public StaticFetcher(Dictionary<string, object?> data) => _data = data;

        public Task<Dictionary<string, object?>> FetchAsync(IReadOnlyList<string> keys, CancellationToken ct)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var k in keys)
                if (_data.TryGetValue(k, out var v))
                    result[k] = v;
            return Task.FromResult(result);
        }
    }

    [Fact]
    public async Task PageLaw_passes_when_expectation_holds()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "title present", null, "test")
            .OnPage("*")
            .Expect(p => p.Title == "Hello");

        var law = registry.All[0];
        var key = PageFacts.Key("h1", "text");
        var fetcher = new StaticFetcher(new Dictionary<string, object?> { [key] = "x" });

        var eval = new LawEvaluator();
        var result = await eval.EvaluatePageLawAsync(
            law,
            "https://example.com/",
            "example.com",
            "Hello",
            fetcher,
            CancellationToken.None);

        Assert.Equal(LawVerdict.Pass, result.Verdict);
    }

    [Fact]
    public void ResponseLaw_includes_evidence_and_request_url_on_fail()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "total positive", null, "test")
            .OnResponse("GET /api/cart*")
            .Expect(r => r.Json.Number("total") > 0);

        var law = registry.All[0];
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://example.com/api/cart",
            StatusCode = 200,
            ResponseBody = """{"total": -1}"""
        };

        var eval = new LawEvaluator();
        var result = eval.EvaluateResponseLaw(law, "https://example.com/basket", "example.com", entry);
        Assert.Equal(LawVerdict.Fail, result.Verdict);
        Assert.Equal(entry.Url, result.ContextUrl);
        Assert.Contains("total", result.Evidence ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResponseLaw_fails_on_negative_total()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "non-negative total", null, "test")
            .OnResponse("GET /api/cart*")
            .Expect(r => r.Json.Number("total") >= 0);

        var law = registry.All[0];
        var entry = new NetworkEntry
        {
            Method = "GET",
            Url = "https://example.com/api/cart",
            StatusCode = 200,
            ResponseBody = """{"total": -1}"""
        };

        var eval = new LawEvaluator();
        var result = eval.EvaluateResponseLaw(law, "https://example.com/cart", "example.com", entry);
        Assert.Equal(LawVerdict.Fail, result.Verdict);
    }

    [Fact]
    public void PageLaw_parse_uses_invariant_culture_under_swedish_locale()
    {
        var prev = CultureInfo.CurrentCulture;
        var prevUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("sv-SE");
            CultureInfo.CurrentUICulture = new CultureInfo("sv-SE");

            var registry = new LawRegistry();
            new LawBuilder(registry, "parse dot", null, "test")
                .OnPage("*")
                .Expect((PageFacts _) => double.Parse("17.98") > 0);

            var law = registry.All[0];
            var eval = new LawEvaluator();
            var result = eval.EvaluatePageLaw(
                law,
                "https://example.com/",
                "example.com",
                "Title",
                new StaticFetcher(new Dictionary<string, object?>()),
                CancellationToken.None);

            Assert.NotEqual(LawVerdict.Error, result.Verdict);
            Assert.Equal(LawVerdict.Pass, result.Verdict);
        }
        finally
        {
            CultureInfo.CurrentCulture = prev;
            CultureInfo.CurrentUICulture = prevUi;
        }
    }

    [Fact]
    public void PageLaw_when_guard_blocks_expect_without_error()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "when blocks", null, "test")
            .OnPage("*")
            .When((PageFacts p) => p.Text("h1") == "NO SUCH HEADING")
            .Expect((PageFacts p) => int.Parse(p.Text("h1")) > 0);

        var law = registry.All[0];
        var key = PageFacts.Key("h1", "text");
        var fetcher = new StaticFetcher(new Dictionary<string, object?> { [key] = "Real Title" });

        var eval = new LawEvaluator();
        var result = eval.EvaluatePageLaw(
            law,
            "https://example.com/",
            "example.com",
            "Real Title",
            fetcher,
            CancellationToken.None);

        Assert.Equal(LawVerdict.NotApplicable, result.Verdict);
    }

    [Fact]
    public async Task PageLaw_fetches_many_distinct_dom_facts_in_one_round()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "multi fact", null, "test")
            .OnPage("*")
            .Expect(p => p.Count("h1") >= 0 && p.Count("nav") >= 0 && p.Count("footer") >= 0);

        var law = registry.All[0];
        var fetcher = new CountStubFetcher();

        var eval = new LawEvaluator();
        var result = await eval.EvaluatePageLawAsync(
            law,
            "https://example.com/",
            "example.com",
            "Title",
            fetcher,
            CancellationToken.None);

        Assert.Equal(LawVerdict.Pass, result.Verdict);
    }

    [Fact]
    public void PageLaw_attr_reads_cached_attribute()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "radio value", null, "test")
            .OnPage("*")
            .Expect(p => p.Attr("#x", "value") == "1.99");

        var law = registry.All[0];
        var key = PageFacts.Key("#x", "attr", "value");
        var fetcher = new StaticFetcher(new Dictionary<string, object?> { [key] = "1.99" });

        var eval = new LawEvaluator();
        var result = eval.EvaluatePageLaw(
            law,
            "https://example.com/",
            "example.com",
            "Title",
            fetcher,
            CancellationToken.None);

        Assert.Equal(LawVerdict.Pass, result.Verdict);
    }

    [Fact]
    public void ConsoleLaw_forbid_triggers_on_error_level()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "no errors", null, "test")
            .OnConsole("error")
            .Forbid((ConsoleFacts _) => true);

        var law = registry.All[0];
        var entry = new ConsoleEntry { Level = ConsoleLevel.Error, Message = "boom" };
        var eval = new LawEvaluator();
        var result = eval.EvaluateConsoleLaw(law, "https://example.com/", "example.com", entry);
        Assert.Equal(LawVerdict.Fail, result.Verdict);
    }
}
