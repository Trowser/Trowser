using System.Reflection;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Laws;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawSandboxTests
{
    [Theory]
    [InlineData("var x = global::System.IO.File.Exists(\"c:\\\\\");")]
    [InlineData("#r \"System.Net.Http\"\nLaw(\"x\").OnPage(\"*\").Expect((PageFacts p) => true);")]
    [InlineData("var a = \"\".GetType().Assembly;")]
    [InlineData("var t = typeof(string).Assembly;")]
    [InlineData("System.Threading.Tasks.Task.Run(() => 1);")]
    [InlineData("var e = Environment.GetEnvironmentVariable(\"PATH\");")]
    [InlineData("using IO = System.IO; var b = IO.File.Exists(\"x\");")]
    [InlineData("var c = new System.Net.Http.HttpClient();")]
    [InlineData("Law(\"x\").OnPage(\"*\").Expect((PageFacts p) => System.Diagnostics.Process.GetProcesses().Length > 0);")]
    public async Task Validate_rejects_code_outside_the_allowlist(string code)
    {
        var loader = new LawLoader(new LawRegistry());
        var (ok, errors) = await loader.ValidateAsync(code);
        Assert.False(ok);
        Assert.NotEmpty(errors);
    }

    [Fact]
    public async Task Validate_never_executes_rejected_code()
    {
        var marker = Path.Combine(Path.GetTempPath(), "trowser-law-sandbox-" + Guid.NewGuid().ToString("N"));
        var code = $"global::System.IO.File.WriteAllText(@\"{marker}\", \"pwned\");";
        var loader = new LawLoader(new LawRegistry());

        var (ok, _) = await loader.ValidateAsync(code);

        Assert.False(ok);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public async Task Validate_accepts_typical_law_code()
    {
        const string code = """
            Site("shop.example.com");
            var leak = new Regex(@"\bNaN\b", RegexOptions.None, TimeSpan.FromMilliseconds(100));
            var words = new List<string> { "a", "b" }.Select(w => w.ToUpperInvariant()).ToArray();
            Law("Cart total")
                .OnPage("/cart*")
                .When((PageFacts p) => p.Count(".line") > 0)
                .Expect((PageFacts p) => p.Number(".total").ApproxEquals(p.Numbers(".line"), 0.01) && !leak.IsMatch(p.Text("body")))
                .Severity(Severity.High)
                .Tags("cart")
                .Confirm();
            Law("Api")
                .OnResponse("GET /api/items*")
                .When((ResponseFacts r) => r.Status == 200 && r.Json.IsValid)
                .Expect((ResponseFacts r) => r.Json.Count("items") >= 0 && Math.Abs(r.Json.Number("items[0].price")) >= 0);
            """;
        var loader = new LawLoader(new LawRegistry());
        var (ok, errors) = await loader.ValidateAsync(code);
        Assert.True(ok, string.Join("\n", errors));
    }

    [Fact]
    public async Task Embedded_laws_and_user_seed_load_under_the_sandbox()
    {
        var assembly = typeof(LawService).Assembly;
        var names = assembly.GetManifestResourceNames()
            .Where(n => n.EndsWith(".csx", StringComparison.Ordinal)
                        && (n.StartsWith("Trowser.Resources.Quicktests.Laws.", StringComparison.Ordinal)
                            || n == "Trowser.Resources.UserQuicktests.Laws.ExampleLaw.csx"))
            .ToList();
        Assert.Contains(names, n => n.EndsWith("GenericWebLaws.csx", StringComparison.Ordinal));

        var registry = new LawRegistry();
        var loader = new LawLoader(registry);
        foreach (var name in names)
        {
            using var reader = new StreamReader(assembly.GetManifestResourceStream(name)!);
            var code = await reader.ReadToEndAsync();
            var loaded = await loader.LoadSourceAsync("embedded:" + name, code);
            Assert.True(loaded, name + ": " + string.Join("\n", loader.Diagnostics.Select(d => d.Message)));
        }

        Assert.Empty(loader.Diagnostics);
        Assert.Contains(registry.All, l => l.Name.StartsWith("No rendering leaks", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Order total: NaN kr", LawVerdict.Fail)]
    [InlineData("Hello [object Object]", LawVerdict.Fail)]
    [InlineData("Welcome {{ user.name }}", LawVerdict.Fail)]
    [InlineData("Bananas are nice. NaNa is a name.", LawVerdict.Pass)]
    public async Task Generic_rendering_leak_law_detects_leaks(string bodyText, LawVerdict expected)
    {
        var registry = new LawRegistry();
        var loader = new LawLoader(registry);
        var assembly = typeof(LawService).Assembly;
        using var reader = new StreamReader(assembly.GetManifestResourceStream("Trowser.Resources.Quicktests.Laws.GenericWebLaws.csx")!);
        Assert.True(await loader.LoadSourceAsync("embedded:Generic", await reader.ReadToEndAsync()));

        var law = registry.All.Single(l => l.Name.StartsWith("No rendering leaks", StringComparison.Ordinal));
        var fetcher = new DictFetcher(new() { [PageFacts.Key("body", "text")] = bodyText });
        var result = await new LawEvaluator().EvaluatePageLawAsync(
            law, "https://example.com/", "example.com", "T", fetcher, CancellationToken.None);
        Assert.Equal(expected, result.Verdict);
    }

    [Theory]
    [InlineData(LawTriggerKind.Action)]
    [InlineData(LawTriggerKind.Timer)]
    public async Task Action_and_timer_laws_evaluate_page_facts(LawTriggerKind trigger)
    {
        var registry = new LawRegistry();
        var b = new LawBuilder(registry, "menu visible", null, "test");
        b = trigger == LawTriggerKind.Action ? b.OnAction() : b.OnTimer();
        b.Expect((PageFacts p) => p.Visible("#menu"));

        var law = registry.All[0];
        Assert.True(law.UsesPageFacts);
        var fetcher = new DictFetcher(new() { [PageFacts.Key("#menu", "visible")] = false });
        var result = await new LawEvaluator().EvaluatePageLawAsync(
            law, "https://example.com/anything", "example.com", "T", fetcher, CancellationToken.None);
        Assert.Equal(LawVerdict.Fail, result.Verdict);
    }

    [Fact]
    public async Task Confirm_retry_error_is_not_reported_as_pass()
    {
        var registry = new LawRegistry();
        var calls = 0;
        new LawBuilder(registry, "flaky", null, "test")
            .OnPage("*")
            .Confirm()
            .Expect((PageFacts p) =>
            {
                if (p.Count("h1") < 0) return true;
                return ++calls switch
                {
                    1 => false,
                    _ => throw new InvalidOperationException("boom")
                };
            });

        var fetcher = new DictFetcher(new() { [PageFacts.Key("h1", "count")] = 1 });
        var result = await new LawEvaluator().EvaluatePageLawAsync(
            registry.All[0], "https://example.com/", "example.com", "T", fetcher, CancellationToken.None);
        Assert.NotEqual(LawVerdict.Pass, result.Verdict);
    }

    [Fact]
    public async Task Page_facts_value_and_texts_are_read_from_cache()
    {
        var registry = new LawRegistry();
        new LawBuilder(registry, "qty", null, "test")
            .OnPage("*")
            .Expect((PageFacts p) => p.Value("#qty") == "2" && p.Texts("li").Count == 3 && p.Path == "/cart");

        var fetcher = new DictFetcher(new()
        {
            [PageFacts.Key("#qty", "value")] = "2",
            [PageFacts.Key("li", "texts")] = "a\u001fb\u001fc"
        });
        var result = await new LawEvaluator().EvaluatePageLawAsync(
            registry.All[0], "https://example.com/cart?x=1", "example.com", "T", fetcher, CancellationToken.None);
        Assert.Equal(LawVerdict.Pass, result.Verdict);
    }

    [Fact]
    public void JsonFacts_supports_array_indexes_root_arrays_and_counts()
    {
        var obj = new JsonFacts("""{"items":[{"price":1.5},{"price":"2,50 kr"}],"meta":{"n":2}}""");
        Assert.Equal(1.5, obj.Number("items[0].price"));
        Assert.Equal(1.5, obj.Number("items.0.price"));
        Assert.Equal(2, obj.Count("items"));
        Assert.Equal(2, obj.Numbers("items", "price").Count);
        Assert.True(obj.HasValue("items[-1].price"));
        Assert.False(obj.HasValue("items[5].price"));

        var root = new JsonFacts("""[{"id":"a"},{"id":"b"}]""");
        Assert.Equal("b", root.String("[1].id"));
        Assert.Equal(2, root.Count());
        Assert.True(root.IsValid);
        Assert.False(new JsonFacts("not json").IsValid);
    }

    [Theory]
    [InlineData("https://x.com/api/orders/123?page=2", "/api/orders/*")]
    [InlineData("https://x.com/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6/cart", "/api/users/*/cart")]
    [InlineData("https://x.com/api/products", "/api/products")]
    [InlineData("https://x.com/assets/app.js", "/assets/app.js")]
    public void Miner_normalizes_id_segments_and_drops_query(string url, string expected) =>
        Assert.Equal(expected, LawMiner.NormalizeEndpointPath(url));

    [Fact]
    public async Task Miner_proposals_escape_hostile_paths_and_compile()
    {
        var store = new LawProposalStore();
        var miner = new LawMiner(store);
        for (var i = 0; i < 6; i++)
        {
            miner.ObserveResponse(new NetworkEntry
            {
                Method = "GET",
                Url = "https://x.com/api/a%22);File.Delete(%22x/" + i,
                StatusCode = 200,
                ResponseBody = """{"id":1}""",
                ResponseHeaders = new Dictionary<string, string> { ["content-type"] = "application/json" }
            }, "x.com");
        }

        miner.RankAndPropose(minObservations: 5);
        Assert.NotEmpty(store.Proposals);
        var loader = new LawLoader(new LawRegistry());
        foreach (var p in store.Proposals)
        {
            var (ok, errors) = await loader.ValidateAsync(p.Code);
            Assert.True(ok, p.Code + "\n" + string.Join("\n", errors));
        }
    }

    [Theory]
    [InlineData("list", false)]
    [InlineData("check", false)]
    [InlineData("proposals", false)]
    [InlineData("reject", false)]
    [InlineData("add", true)]
    [InlineData("replace", true)]
    [InlineData("validate", true)]
    [InlineData("author", true)]
    [InlineData("accept", true)]
    [InlineData("delete", true)]
    public void Safe_mode_blocks_law_code_actions_only(string action, bool blocked)
    {
        using var doc = JsonDocument.Parse($$"""{"action":"{{action}}"}""");
        Assert.Equal(blocked, SafeModePolicy.IsToolBlocked("browser_laws", doc.RootElement));
        Assert.False(SafeModePolicy.IsToolAlwaysBlocked("browser_laws"));
    }

    [Theory]
    [InlineData("/api/laws/add", true)]
    [InlineData("/api/laws/validate", true)]
    [InlineData("/api/laws/proposals/accept", true)]
    [InlineData("/api/laws/check", false)]
    [InlineData("/api/laws/proposals/reject", false)]
    public void Safe_mode_blocks_law_code_routes(string path, bool blocked) =>
        Assert.Equal(blocked, SafeModePolicy.IsRouteBlocked(path, "POST", null));

    private sealed class DictFetcher(Dictionary<string, object?> data) : IPageFactsFetcher
    {
        public Task<Dictionary<string, object?>> FetchAsync(IReadOnlyList<string> keys, CancellationToken ct)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var k in keys)
                if (data.TryGetValue(k, out var v))
                    result[k] = v;
            return Task.FromResult(result);
        }
    }
}
