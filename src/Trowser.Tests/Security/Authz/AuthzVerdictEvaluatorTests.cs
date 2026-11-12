using Trowser.Security;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AuthzVerdictEvaluatorTests
{
    private static DirectFetchHelper.DirectFetchResult Ok(int status, string body, bool redirected = false, string? finalUrl = null) =>
        new() { Ok = status is >= 200 and < 300, Status = status, Body = body, Redirected = redirected, FinalUrl = finalUrl };

    private static DirectFetchHelper.DirectFetchResult Failed(string error) =>
        new() { Error = error };

    [Fact]
    public void Evaluate_OwnerBaselineNotOk_ReturnsInconclusive()
    {
        var owner = Ok(403, "denied");
        var peer = Ok(200, "{}");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.Inconclusive, verdict.Kind);
    }

    [Fact]
    public void Evaluate_PeerFetchErrored_ReturnsInconclusive()
    {
        var owner = Ok(200, "{\"a\":1}");
        var peer = Failed("timed out");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.Inconclusive, verdict.Kind);
    }

    [Theory]
    [InlineData(429)]
    [InlineData(503)]
    public void Evaluate_PeerRateLimited_ReturnsInconclusive(int status)
    {
        var owner = Ok(200, "{\"a\":1}");
        var peer = Ok(status, "");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.Inconclusive, verdict.Kind);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    public void Evaluate_PeerDenied_ReturnsProperlyDenied(int status)
    {
        var owner = Ok(200, "{\"a\":1}");
        var peer = Ok(status, "");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.ProperlyDenied, verdict.Kind);
        Assert.Equal("high", verdict.Confidence);
    }

    [Fact]
    public void Evaluate_PeerRedirectedToLoginPage_ReturnsProperlyDenied()
    {
        var owner = Ok(200, "{\"a\":1}");
        var peer = Ok(200, "please sign in", redirected: true, finalUrl: "https://example.com/login?returnUrl=/x");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.ProperlyDenied, verdict.Kind);
    }

    [Fact]
    public void Evaluate_BothBodiesEmpty_ReturnsNeedsReview()
    {
        var owner = Ok(204, "");
        var peer = Ok(204, "");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.NeedsReview, verdict.Kind);
    }

    [Fact]
    public void Evaluate_OwnerTokenLeakedInPeerBody_ReturnsConfirmedLeak()
    {
        var owner = Ok(200, "{\"id\":1,\"email\":\"alice@example.com\"}");
        var peer = Ok(200, "{\"id\":1,\"email\":\"alice@example.com\"}");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer, ["alice@example.com"]);

        Assert.Equal(AuthzVerdictKind.ConfirmedLeak, verdict.Kind);
        Assert.Equal("high", verdict.Confidence);
    }

    [Fact]
    public void Evaluate_NormalizedJsonMatch_ReturnsBolaSuspected()
    {
        var owner = Ok(200, "{\"id\":1,\"secret\":\"xyz\",\"timestamp\":\"2024-01-01\"}");
        var peer = Ok(200, "{\"id\":1,\"secret\":\"xyz\",\"timestamp\":\"2024-06-06\"}");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.BolaSuspected, verdict.Kind);
    }

    [Fact]
    public void Evaluate_NonJsonBodiesNearIdenticalLength_ReturnsBolaSuspected()
    {
        var owner = Ok(200, new string('a', 1000));
        var peer = Ok(200, new string('b', 1005));

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.BolaSuspected, verdict.Kind);
    }

    [Fact]
    public void Evaluate_StructuralMatchOnly_ReturnsSameShapeDifferentData()
    {
        var owner = Ok(200, "{\"id\":1,\"owner\":\"alice\"}");
        var peer = Ok(200, "{\"id\":2,\"owner\":\"bob\"}");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.SameShapeDifferentData, verdict.Kind);
    }

    [Fact]
    public void Evaluate_RecordIdInTheUrl_IsNotAConfirmedLeak()
    {
        var owner = Ok(200, "{\"id\":\"1001\",\"body\":\"alice note alice@example.test\"}");
        var peer = Ok(200, "{\"id\":\"1001\",\"body\":\"[redacted]\"}");

        var verdict = AuthzVerdictEvaluator.Evaluate(
            owner, peer, ["1001", "alice@example.test"], "https://lab.test/api/notes/1001");

        Assert.NotEqual(AuthzVerdictKind.ConfirmedLeak, verdict.Kind);
    }

    [Fact]
    public void Evaluate_SameShapeWithDifferentEmail_SaysEachIdentityGotItsOwnObject()
    {
        var owner = Ok(200, "{\"email\":\"alice@example.test\",\"name\":\"Alice\"}");
        var peer = Ok(200, "{\"email\":\"bob@example.test\",\"name\":\"Bob\"}");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer, ["alice@example.test"]);

        Assert.Equal(AuthzVerdictKind.SameShapeDifferentData, verdict.Kind);
        Assert.Contains("own object", verdict.Reason);
    }

    [Fact]
    public void Evaluate_DifferentShapeAndContent_ReturnsFilteredResponse()
    {
        var owner = Ok(200, "{\"id\":1,\"owner\":\"alice\"}");
        var peer = Ok(200, "<html>not the same at all</html>");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer);

        Assert.Equal(AuthzVerdictKind.FilteredResponse, verdict.Kind);
        Assert.DoesNotContain("properly scoped", verdict.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_UndecodedPeerBody_ReturnsInconclusiveEvenWhenTokensAreSet()
    {
        var owner = Ok(200, "{\"id\":1,\"owner\":\"alice\"}");
        var peer = Ok(200, "\u001f\u0008\0\0not-text");

        var verdict = AuthzVerdictEvaluator.Evaluate(owner, peer, ["alice"]);

        Assert.Equal(AuthzVerdictKind.Inconclusive, verdict.Kind);
        Assert.Contains("not decoded", verdict.Reason, StringComparison.OrdinalIgnoreCase);
    }
}
