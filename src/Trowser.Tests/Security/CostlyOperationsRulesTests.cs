using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class CostlyOperationsRulesTests
{
    [Fact]
    public void LargeResponse_IgnoresTinyLookupTables()
    {
        var body = "{\"data\":[" + string.Join(",", Enumerable.Range(1, 56).Select(i => i.ToString())) + "]}";
        var findings = CostlyOperationsRules.RunCheck("large-response", Ctx(Entry(
            "https://example.test/api/Quantitys/", body))).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void LargeResponse_FlagsBigListWithRealBytes()
    {
        var pad = new string('x', 400);
        var items = string.Join(",", Enumerable.Range(1, 120).Select(i => $"{{\"id\":{i},\"n\":\"{pad}\"}}"));
        var body = "{\"data\":[" + items + "]}";
        var findings = CostlyOperationsRules.RunCheck("large-response", Ctx(Entry(
            "https://example.test/api/Challenges/", body, id: 95))).ToList();

        var hit = Assert.Single(findings);
        Assert.Equal("high", hit.Severity);
        Assert.Equal("costly-large-response", hit.Category);
        Assert.Equal(95, hit.NetworkEntryId);
    }

    [Fact]
    public void Pagination_SkipsSmallLists_AndScalesSeverity()
    {
        var tiny = CostlyOperationsRules.RunCheck("pagination", Ctx(Entry(
            "https://example.test/rest/languages",
            "[" + string.Join(",", Enumerable.Range(1, 42).Select(i => $"{{\"id\":{i}}}")) + "]"))).ToList();
        Assert.Empty(tiny);

        var catalog = "{\"data\":[" + string.Join(",", Enumerable.Range(1, 46).Select(i =>
            $"{{\"id\":{i},\"name\":\"{new string('p', 80)}\"}}")) + "]}";
        var medium = CostlyOperationsRules.RunCheck("pagination", Ctx(Entry(
            "https://example.test/rest/products/search?q=", catalog))).ToList();
        var page = Assert.Single(medium);
        Assert.Equal("costly-missing-pagination", page.Category);
        Assert.Equal("medium", page.Severity);
    }

    [Fact]
    public void Pagination_DoesNotTreatSkipAsPageSize()
    {
        var candidates = CostlyOperationsRules.PageSizeConfirmCandidates(Ctx(Entry(
            "https://example.test/products?limit=10&skip=0",
            "{\"products\":[" + string.Join(",", Enumerable.Range(1, 10).Select(i => i.ToString())) + "]}"))).ToList();

        Assert.Single(candidates);
        Assert.Equal("limit", candidates[0].ParamName);
        Assert.Equal("step", candidates[0].Kind);
        Assert.Equal("30", candidates[0].ProbeValue);
    }

    [Fact]
    public void PageSizeConfirm_InjectsLimitOnlyForUnpagedLists()
    {
        var body = "{\"data\":[" + string.Join(",", Enumerable.Range(1, 30).Select(i =>
            $"{{\"id\":{i},\"n\":\"{new string('a', 40)}\"}}")) + "]}";
        var candidates = CostlyOperationsRules.PageSizeConfirmCandidates(Ctx(Entry(
            "https://example.test/api/Hints/", body))).ToList();

        var inject = Assert.Single(candidates);
        Assert.Equal("inject", inject.Kind);
        Assert.Contains("limit=50", inject.ProbeUrl, StringComparison.Ordinal);
    }

    [Fact]
    public void ImageConfirm_RequiresAnExistingDimensionParam()
    {
        var plain = CostlyOperationsRules.ImageEdgeConfirmCandidates(Ctx(Entry(
            "https://example.test/products?limit=10", "{\"ok\":true}"))).ToList();
        Assert.Empty(plain);

        var sized = CostlyOperationsRules.ImageEdgeConfirmCandidates(Ctx(Entry(
            "https://example.test/photo?width=64", "{\"ok\":true}"))).ToList();
        var hit = Assert.Single(sized);
        Assert.Equal("width", hit.ParamName);
        Assert.Equal("256", hit.ProbeValue);
    }

    [Fact]
    public void NestedPayload_IgnoresHtmlAndProse_FlagsBase64Field()
    {
        var html = "<html><body>\"" + new string('a', 800) + "\"</body></html>";
        Assert.Empty(CostlyOperationsRules.RunCheck("nested-payload", Ctx(Entry(
            "https://example.test/", html, contentType: "text/html"))));

        var prose = "{\"banner\":\"" + string.Concat(Enumerable.Repeat("Welcome to the shop. ", 40)) + "\"}";
        Assert.Empty(CostlyOperationsRules.RunCheck("nested-payload", Ctx(Entry(
            "https://example.test/config", prose))));

        var b64 = Convert.ToBase64String(Enumerable.Repeat((byte)7, 700).ToArray());
        var findings = CostlyOperationsRules.RunCheck("nested-payload", Ctx(Entry(
            "https://example.test/config", "{\"logo\":\"" + b64 + "\"}"))).ToList();
        var hit = Assert.Single(findings);
        Assert.Equal("$.logo", hit.Parameter);
        Assert.Contains("length=", hit.Evidence);
    }

    [Fact]
    public void TrafficShape_SkipsRepeatedSameUrlAndSocketPolling()
    {
        var config = Enumerable.Range(0, 8).Select(_ => Entry(
            "https://example.test/rest/admin/application-configuration", "{\"ok\":true}")).ToList();
        var surface = Surface(config[0].Url, "/rest/admin/application-configuration", config.Count);
        Assert.Empty(CostlyOperationsRules.RunCheck("traffic-shape", Ctx(config, surface)));

        var polls = Enumerable.Range(0, 8).Select(i => Entry(
            $"https://example.test/socket.io/?EIO=4&transport=polling&t=abc{i}", "2")).ToList();
        var pollSurface = Surface(polls[0].Url, "/socket.io/", polls.Count);
        Assert.Empty(CostlyOperationsRules.RunCheck("traffic-shape", Ctx(polls, pollSurface)));
    }

    [Fact]
    public void TrafficShape_FlagsDistinctResourceUrls()
    {
        var calls = Enumerable.Range(1, 6).Select(i => Entry(
            $"https://example.test/api/orders/{i}", "{\"id\":" + i + "}")).ToList();
        var surface = Surface(calls[0].Url, "/api/orders/{id}", calls.Count);
        var findings = CostlyOperationsRules.RunCheck("traffic-shape", Ctx(calls, surface)).ToList();
        var hit = Assert.Single(findings);
        Assert.Equal("costly-n-plus-one", hit.Category);
        Assert.Contains("distinctUrls=6", hit.Evidence);
    }

    [Fact]
    public void UploadLead_RespectsUrlScope()
    {
        var spa = new SpaRuntimeSurface
        {
            PageUrl = "https://example.test/#/complain",
            InputFields = [new SpaFieldSummary { Tag = "input", Type = "file", Label = "Invoice PDF" }]
        };
        var entry = Entry("https://example.test/api/Hints/", "{\"data\":[1]}");
        var scoped = Ctx([entry], new AttackSurfaceResult(), spa,
            urlScope: ["https://example.test/api/Hints/"]);
        Assert.Empty(CostlyOperationsRules.RunCheck("upload-surface", scoped));

        var open = Ctx([entry], new AttackSurfaceResult(), spa);
        Assert.Single(CostlyOperationsRules.RunCheck("upload-surface", open));
    }

    [Fact]
    public void SpecLimits_UseOperationMethodAndUrl()
    {
        var spec = """
            {
              "openapi": "3.0.0",
              "servers": [{ "url": "/api/v3" }],
              "paths": {
                "/user/createWithList": {
                  "post": {
                    "requestBody": {
                      "content": {
                        "application/json": {
                          "schema": { "type": "array", "items": { "type": "object" } }
                        }
                      }
                    }
                  }
                }
              }
            }
            """;
        var findings = CostlyOperationsSpecAnalyzer.Analyze(
        [
            new CostlyOperationsSpecAnalyzer.SpecDocument
            {
                Url = "https://petstore3.swagger.io/api/v3/openapi.json",
                Body = spec,
                Kind = "openapi"
            }
        ], 10).ToList();

        var hit = Assert.Single(findings);
        Assert.Equal("POST", hit.Method);
        Assert.Equal("https://petstore3.swagger.io/api/v3/user/createWithList", hit.Endpoint);
        Assert.Contains("openapi.json", hit.Evidence);
    }

    private static CostlyOperationsRules.ScanContext Ctx(
        NetworkEntry entry,
        AttackSurfaceResult? surface = null,
        SpaRuntimeSurface? spa = null,
        IReadOnlyList<string>? urlScope = null) =>
        Ctx([entry], surface, spa, urlScope);

    private static CostlyOperationsRules.ScanContext Ctx(
        IReadOnlyList<NetworkEntry> entries,
        AttackSurfaceResult? surface = null,
        SpaRuntimeSurface? spa = null,
        IReadOnlyList<string>? urlScope = null) =>
        new(
            entries.ToList(),
            surface ?? new AttackSurfaceResult(),
            spa,
            "https://example.test",
            slowThresholdMs: 3000,
            maxCandidates: 24,
            urlScope: urlScope);

    private static AttackSurfaceResult Surface(string url, string template, int count) => new()
    {
        Endpoints =
        [
            new AttackSurfaceEndpoint
            {
                Url = url,
                UrlTemplate = template,
                Methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "GET" },
                RequestCount = count
            }
        ]
    };

    private static NetworkEntry Entry(string url, string body, string contentType = "application/json", int id = 0) => new()
    {
        Id = id,
        Method = "GET",
        Url = url,
        StatusCode = 200,
        ResourceType = "Fetch",
        ResponseBody = body,
        ResponseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = contentType
        }
    };
}
