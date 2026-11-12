using Trowser.Security.XsLeaks;
using Xunit;

namespace Trowser.Tests.Security;

public class XsLeakStatsAndPlannerTests
{
    [Fact]
    public void DeterministicDistinct_ignores_timeout_samples()
    {
        var a = new List<string?> { "load", "timeout" };
        var b = new List<string?> { "error", "timeout" };
        Assert.False(XsLeakStats.DeterministicDistinct(a, b));
    }

    [Fact]
    public void DeterministicDistinct_requires_two_evidence_samples_per_state()
    {
        var a = new List<string?> { "load" };
        var b = new List<string?> { "error", "error" };
        Assert.False(XsLeakStats.DeterministicDistinct(a, b));
    }

    [Fact]
    public void Hypothesis_expands_url_template_with_encoding()
    {
        var h = new XsLeakHypothesis.HypothesisSpec
        {
            Secret = "diagnosis",
            UrlTemplate = "https://example.test/search?q={value}",
            HitValues = ["Ulcerös proktit"],
            MissValues = ["zzzz"]
        };
        var states = XsLeakHypothesis.ExpandStates([], h);
        Assert.Equal(2, states.Count);
        Assert.Contains("Ulcer", states[0].Url, StringComparison.Ordinal);
        Assert.Equal("hit", states[0].Role);
    }

    [Fact]
    public void Planner_selects_status_oracle_for_status_diff()
    {
        var validation = new XsLeakStateValidator.ValidationResult
        {
            CredentialedDiff = "status",
            AnonymousDiff = "status",
            States =
            [
                new() { ContentType = "image/svg+xml", TimingAllowOrigin = false },
                new() { ContentType = "image/svg+xml", TimingAllowOrigin = false }
            ]
        };
        var profile = new XsLeakSessionProfile { AuthMechanism = "unknown", CookieMode = "no-session-cookie" };
        var delivery = new XsLeakCredentialObservation.DeliveryResult { Subresource = "unknown" };
        var plan = XsLeakTechniquePlanner.Build(
            active: false,
            hypothesisMode: true,
            maxSeconds: 60,
            attackerSite: "cross-site",
            validation,
            profile,
            delivery,
            explicitFilter: null,
            fullCatalog: false);
        Assert.Contains(plan.SelectedTechniques, t => t.Id == "status-bucket-oracle" || t.Id == "img-error");
    }

    [Fact]
    public void Confirmation_downgrades_when_control_separates_from_miss()
    {
        var tech = XsLeakTechniques.Catalog.First(t => t.Id == "img-error");
        var values = new Dictionary<string, List<string?>>(StringComparer.OrdinalIgnoreCase)
        {
            ["miss-0"] = ["error", "error"],
            ["control-miss"] = ["load", "load"]
        };
        Assert.True(XsLeakConfirmation.ControlInvalidatesSecret(tech, values, "miss-0", "control-miss"));
        var status = XsLeakConfirmation.ResolveConfirmationStatus(
            hypothesisMode: true,
            screeningVerdict: "distinguishable",
            confirmVerdict: "distinguishable",
            controlFailed: true,
            explainable: true,
            mitigatedExploitable: false,
            sessionHealthy: true,
            ranConfirmation: true);
        Assert.Equal("candidate-control-failed", status);
        Assert.False(XsLeakConfirmation.ShouldEmitFinding(status));
    }

    [Fact]
    public void SameRequestTarget_false_when_post_bodies_differ()
    {
        var url = "https://app.test/api/search";
        var states = new List<XsLeakScanner.StateSpec>
        {
            new() { Label = "hit", Url = url, Method = "POST", Body = "{\"q\":\"a\"}", Role = "hit" },
            new() { Label = "miss", Url = url, Method = "POST", Body = "{\"q\":\"b\"}", Role = "miss" }
        };
        Assert.False(XsLeakScanner.AllStatesShareSameRequestTarget(states));
        Assert.True(XsLeakScanner.AllStatesShareSameUrlPath(states));
    }

    [Fact]
    public void PickCredentialProbeCookie_prefers_session_over_xsrf()
    {
        var auth = new List<XsLeakSessionProfile.AuthCookieCandidate>
        {
            new() { Name = "XSRF-TOKEN", SameSite = "lax", HttpOnly = false },
            new() { Name = "SESSION", SameSite = "none", HttpOnly = true }
        };
        var pick = XsLeakSessionProfile.PickCredentialProbeCookie(auth, "samesite-none-present");
        Assert.Equal("SESSION", pick?.Name);
    }

    [Fact]
    public void ClassifyDiff_uses_length_not_redirect_for_different_endpoints()
    {
        var a = new XsLeakStateValidator.StateFetchSnapshot
        {
            Label = "hit",
            RequestUrl = "https://app.test/api/certificate/aaa",
            FinalUrl = "https://app.test/api/certificate/aaa",
            Status = 200,
            RedirectCount = 0,
            Length = 6000,
            BodyHash = "a"
        };
        var b = new XsLeakStateValidator.StateFetchSnapshot
        {
            Label = "miss",
            RequestUrl = "https://app.test/api/certificate/bbb",
            FinalUrl = "https://app.test/api/certificate/bbb",
            Status = 200,
            RedirectCount = 0,
            Length = 1900,
            BodyHash = "b"
        };
        var states = new List<XsLeakScanner.StateSpec>
        {
            new() { Label = "hit", Role = "hit" },
            new() { Label = "miss", Role = "miss" }
        };
        var diff = typeof(XsLeakStateValidator)
            .GetMethod("ClassifyDiffForStates", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [states, new List<XsLeakStateValidator.StateFetchSnapshot> { a, b }]);
        Assert.Equal("length", diff);
    }

    [Fact]
    public void CanExpandFromHypothesis_requires_template_and_values()
    {
        Assert.True(XsLeakHypothesis.CanExpandFromHypothesis(new XsLeakHypothesis.HypothesisSpec
        {
            UrlTemplate = "https://x/search?q={value}",
            HitValues = ["a"],
            MissValues = ["b"]
        }));
        Assert.False(XsLeakHypothesis.CanExpandFromHypothesis(new XsLeakHypothesis.HypothesisSpec
        {
            UrlTemplate = "https://x/search",
            HitValues = ["a"],
            MissValues = []
        }));
    }

    [Fact]
    public void Latency_gap_accepts_a_few_hundred_milliseconds_on_the_same_body()
    {
        var slow = new List<double> { 580, 610, 640, 590, 620 };
        var fast = new List<double> { 18, 22, 15, 30, 20 };
        Assert.True(XsLeakStateValidator.ClearMedianGap(slow, fast));
        var states = new List<XsLeakScanner.StateSpec>
        {
            new() { Label = "alice", Role = "hit" },
            new() { Label = "guest", Role = "miss" }
        };
        var gap = XsLeakStateValidator.LatencyGapBetweenRoles(states,
        [
            new() { LatencyMs = slow },
            new() { LatencyMs = fast }
        ]);
        Assert.True(gap);
        Assert.False(XsLeakStateValidator.ClearMedianGap(
            [100, 140, 180, 120, 160],
            [110, 150, 170, 130, 145]));
    }

    [Fact]
    public void Confirmation_emits_only_when_confirmed_in_hypothesis_mode()
    {
        var status = XsLeakConfirmation.ResolveConfirmationStatus(
            hypothesisMode: true,
            screeningVerdict: "distinguishable",
            confirmVerdict: "distinguishable",
            controlFailed: false,
            explainable: true,
            mitigatedExploitable: false,
            sessionHealthy: true,
            ranConfirmation: true);
        Assert.Equal("confirmed", status);
        Assert.True(XsLeakConfirmation.ShouldEmitFinding(status));
    }
}
