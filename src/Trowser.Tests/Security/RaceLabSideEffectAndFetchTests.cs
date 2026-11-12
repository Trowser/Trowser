using Trowser.Api;
using Trowser.Security;
using Trowser.Security.RaceLab;
using Xunit;

namespace Trowser.Tests.Security;

public class RaceLabSideEffectAndFetchTests
{
    [Fact]
    public void Extract_keeps_order_ids_and_drops_request_ids()
    {
        var ids = SideEffectIds.Extract(
            """{"userId":"u1","orderId":"o9","requestId":"r1","createdAt":"2020-01-01T00:00:00Z"}""");

        Assert.Contains("u1", ids);
        Assert.Contains("o9", ids);
        Assert.DoesNotContain("r1", ids);
        Assert.DoesNotContain("2020-01-01T00:00:00Z", ids);
    }

    [Fact]
    public void Varying_ignores_ids_shared_by_every_response()
    {
        var a = SideEffectIds.Extract("""{"userId":"u1","orderId":"o9","requestId":"r1"}""");
        var b = SideEffectIds.Extract("""{"userId":"u1","orderId":"o10","requestId":"r2"}""");
        var varying = SideEffectIds.Varying([a, b]);

        Assert.Contains("o9", varying);
        Assert.Contains("o10", varying);
        Assert.DoesNotContain("u1", varying);
    }

    [Fact]
    public void Extract_reads_location_when_the_body_is_identical()
    {
        var first = SideEffectIds.Extract("""{"ok":true}""", "https://shop.test/orders/1001");
        var second = SideEffectIds.Extract("""{"ok":true}""", "https://shop.test/orders/1002");
        var varying = SideEffectIds.Varying([first, second]);

        Assert.Contains("1001", varying);
        Assert.Contains("1002", varying);
    }

    [Fact]
    public void Normalize_blanks_request_ids_but_keeps_order_ids()
    {
        var a = SideEffectIds.NormalizeForComparison("""{"ok":true,"requestId":"a"}""");
        var b = SideEffectIds.NormalizeForComparison("""{"ok":true,"requestId":"b"}""");
        Assert.Equal(RaceLabJson.HashBody(a), RaceLabJson.HashBody(b));

        var o1 = SideEffectIds.NormalizeForComparison("""{"ok":true,"orderId":"1"}""");
        var o2 = SideEffectIds.NormalizeForComparison("""{"ok":true,"orderId":"2"}""");
        Assert.NotEqual(RaceLabJson.HashBody(o1), RaceLabJson.HashBody(o2));
    }

    [Fact]
    public void Analyzer_suppresses_identical_mutate_successes()
    {
        var baseline = new[] { Shot("baseline", RaceLabRoles.Mutate, "same") };
        var burst = new[]
        {
            Shot("burst", RaceLabRoles.Mutate, "same"),
            Shot("burst", RaceLabRoles.Mutate, "same")
        };

        var findings = Analyze(baseline, burst);
        Assert.DoesNotContain(findings, f => f.Category == "race-condition");
    }

    [Fact]
    public void Analyzer_flags_distinct_side_effect_ids_even_when_bodies_match()
    {
        var baseline = new[] { Shot("baseline", RaceLabRoles.Mutate, "same", "order-1") };
        var burst = new[]
        {
            Shot("burst", RaceLabRoles.Mutate, "same", "order-1"),
            Shot("burst", RaceLabRoles.Mutate, "same", "order-2")
        };

        var finding = Assert.Single(Analyze(baseline, burst), f => f.Category == "race-condition");
        Assert.Equal(SecurityConfidence.Confirmed, finding.Confidence);
        Assert.Contains("order-2", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Analyzer_flags_check_readback_that_gains_ids()
    {
        var baseline = new[]
        {
            Shot("baseline", RaceLabRoles.Mutate, "ok"),
            Shot("baseline", RaceLabRoles.Check, "list", "order-1")
        };
        var burst = new[]
        {
            Shot("burst", RaceLabRoles.Mutate, "ok"),
            Shot("burst", RaceLabRoles.Mutate, "ok"),
            Shot("burst", RaceLabRoles.Check, "list2", "order-1", "order-2")
        };

        var finding = Assert.Single(Analyze(baseline, burst), f => f.Category == "race-condition");
        Assert.Contains("Readback", finding.Title, StringComparison.Ordinal);
        Assert.Contains("order-2", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_content_type_omits_the_header()
    {
        var empty = RequestContentBuilder.FromText("{}", "", "text/plain");
        Assert.Null(empty.Headers.ContentType);

        var omitted = RequestContentBuilder.FromText("{}", null, "text/plain");
        Assert.Equal("text/plain", omitted.Headers.ContentType?.MediaType);
    }

    [Fact]
    public void Explicit_empty_cookies_mean_anonymous_unless_opted_into_the_jar()
    {
        Assert.True(FetchCookieResolver.ExplicitAnonymous(true, "", false, null, null));
        Assert.True(FetchCookieResolver.ExplicitAnonymous(false, null, true, "  ", null));
        Assert.False(FetchCookieResolver.ExplicitAnonymous(true, "", false, null, true));
        Assert.False(FetchCookieResolver.ExplicitAnonymous(false, null, false, null, null));
    }

    [Fact]
    public void Identity_describes_what_was_actually_sent()
    {
        Assert.Equal("anonymous", FetchIdentity.Describe(true, [], null, false));
        Assert.Equal("browser-session", FetchIdentity.Describe(true, ["sid"], null, false));
        Assert.Equal("caller-cookies", FetchIdentity.Describe(false, ["sid"], "cookies", true));
        Assert.Equal("peer:alice", FetchIdentity.Describe(false, ["sid"], "peer:alice", true));
    }

    private static List<UnifiedSecurityFinding> Analyze(
        IReadOnlyList<RaceLabTimelineEntry> baseline,
        IReadOnlyList<RaceLabTimelineEntry> burst) =>
        RaceLabAnalyzer.Analyze(new RaceLabProfile { Name = "t" }, baseline, burst, null);

    private static RaceLabTimelineEntry Shot(string phase, string role, string hash, params string[] ids) =>
        new()
        {
            Phase = phase,
            Role = role,
            Accepted = true,
            Status = 200,
            Method = role == RaceLabRoles.Check ? "GET" : "POST",
            Url = role == RaceLabRoles.Check ? "https://example.test/orders" : "https://example.test/checkout",
            Session = "driver",
            BodyHash = hash,
            SideEffectIds = ids.ToList(),
            ResourceId = ids.FirstOrDefault()
        };
}
