using Trowser.Automation;
using Trowser.Laws;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawMinerTests
{
    private static NetworkEntry JsonGet(string url, string body, int status = 200) => new()
    {
        Method = "GET",
        Url = url,
        StatusCode = status,
        ResponseBody = body,
        ResponseHeaders = new Dictionary<string, string> { ["content-type"] = "application/json" }
    };

    [Fact]
    public void RankAndPropose_emits_http_2xx_with_rationale()
    {
        var store = new LawProposalStore();
        var miner = new LawMiner(store);
        for (var i = 0; i < 6; i++)
            miner.ObserveResponse(JsonGet("https://shop.example.com/api/items", """{"id":1}"""), "shop.example.com");

        miner.RankAndPropose(minObservations: 5);
        var p = store.Proposals.SingleOrDefault(x => x.Kind == "http-2xx");
        Assert.NotNull(p);
        Assert.Contains("2xx", p.Rationale, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(p.Evidence);
    }

    [Fact]
    public void RankAndPropose_emits_json_non_null_proposal()
    {
        var store = new LawProposalStore();
        var miner = new LawMiner(store);
        for (var i = 0; i < 5; i++)
            miner.ObserveResponse(JsonGet("https://app.example.com/api/user", """{"email":"a@b.c"}"""), "app.example.com");

        miner.RankAndPropose(minObservations: 5);
        var p = store.Proposals.SingleOrDefault(x => x.Kind == "json-non-null");
        Assert.NotNull(p);
        Assert.Contains("email", p.Code, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("HasValue", p.Code, StringComparison.Ordinal);
    }

    [Fact]
    public void ObserveResponse_skips_error_json_for_non_null_mining()
    {
        var store = new LawProposalStore();
        var miner = new LawMiner(store);
        for (var i = 0; i < 6; i++)
            miner.ObserveResponse(JsonGet("https://app.example.com/api/x", """{"correlationId":"c","message":"err","path":"/"}""", status: 500), "app.example.com");

        miner.RankAndPropose(minObservations: 5);
        Assert.Null(store.Proposals.SingleOrDefault(x => x.Kind == "json-non-null"));
    }

    [Fact]
    public void Reject_unknown_id_returns_false_without_side_effects()
    {
        var store = new LawProposalStore();
        store.Add(new LawProposal
        {
            Id = "p1",
            Title = "t",
            Code = "// x"
        });

        Assert.True(store.Reject("p1"));
        Assert.False(store.Reject("p1"));
        Assert.False(store.Reject("unknown"));
    }

    [Fact]
    public void RankAndPropose_console_clean_uses_typed_lambda()
    {
        var store = new LawProposalStore();
        var miner = new LawMiner(store);
        for (var i = 0; i < 6; i++)
            miner.ObserveResponse(JsonGet("https://shop.example.com/api/items", """{"id":1}"""), "shop.example.com");

        miner.RankAndPropose(minObservations: 5);
        var p = store.Proposals.SingleOrDefault(x => x.Kind == "console-clean");
        Assert.NotNull(p);
        Assert.Contains("(ConsoleFacts c)", p.Code, StringComparison.Ordinal);
    }
}
