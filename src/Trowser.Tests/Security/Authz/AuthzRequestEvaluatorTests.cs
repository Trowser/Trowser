using Trowser.Security;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class AuthzRequestEvaluatorTests
{
    [Fact]
    public void ClassifyFinding_OwnerOkPeerOkIdenticalBodies_IsBolaSuspected()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: true, peerOk: true, localDenied: false, peerDenied: false, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: true,
            localStatus: 200, peerStatus: 200);

        Assert.Equal("BOLA_SUSPECTED", finding);
    }

    [Fact]
    public void ClassifyFinding_OwnerOkPeerOkDifferentBodies_IsFilteredResponse()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: true, peerOk: true, localDenied: false, peerDenied: false, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 200, peerStatus: 200);

        Assert.Equal("FILTERED_RESPONSE", finding);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    public void ClassifyFinding_OwnerOkPeerDenied_IsProperlyDenied(int peerStatus)
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: true, peerOk: false, localDenied: false, peerDenied: true, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 200, peerStatus: peerStatus);

        Assert.Equal("PROPERLY_DENIED", finding);
    }

    [Fact]
    public void ClassifyFinding_OwnerOkPeerRedirectedToLogin_IsRedirectDenied()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: true, peerOk: true, localDenied: false, peerDenied: false, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: true, bodiesMatch: false,
            localStatus: 200, peerStatus: 200);

        Assert.Equal("REDIRECT_DENIED", finding);
    }

    [Fact]
    public void ClassifyFinding_OwnerOkPeerServerError_IsErrorBeforeAuth()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: true, peerOk: false, localDenied: false, peerDenied: false, peerError: true,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 200, peerStatus: 503);

        Assert.Equal("ERROR_BEFORE_AUTH", finding);
    }

    [Fact]
    public void ClassifyFinding_BothDenied_IsDeniedBoth()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: false, peerOk: false, localDenied: true, peerDenied: true, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 403, peerStatus: 403);

        Assert.Equal("DENIED_BOTH", finding);
    }

    [Fact]
    public void ClassifyFinding_FetchFailedEitherSide_IsError()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: false, peerOk: false, localDenied: false, peerDenied: false, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 0, peerStatus: 200);

        Assert.Equal("ERROR", finding);
    }

    [Fact]
    public void ClassifyFinding_UnrecognizedCombination_IsOther()
    {
        var finding = AuthzRequestEvaluator.ClassifyFinding(
            localOk: false, peerOk: true, localDenied: false, peerDenied: false, peerError: false,
            localRedirectDenied: false, peerRedirectDenied: false, bodiesMatch: false,
            localStatus: 500, peerStatus: 200);

        Assert.Equal("OTHER", finding);
    }

    [Fact]
    public void BuildEntry_LeakTokenInFilteredHtml_PromotesToBolaSuspected()
    {
        var ep = new AuthzEndpoint { Url = "https://app.test/notes/2", Method = "GET" };
        var local = new DirectFetchHelper.DirectFetchResult
        {
            Status = 200,
            Body = "<html><header>Ada</header><main>private phrase here</main></html>"
        };
        var peer = new DirectFetchHelper.DirectFetchResult
        {
            Status = 200,
            Body = "<html><header>Ben</header><main>private phrase here</main></html>"
        };
        var options = new AuthzComparisonOptions { LeakTokens = ["private phrase here"] };

        var entry = AuthzRequestEvaluator.BuildEntry(ep, local, peer, options);

        Assert.Equal("BOLA_SUSPECTED", entry.Finding);
    }

    [Fact]
    public void BuildEntry_PeerBodyContainsOwnerLeakToken_IsFlaggedAsLeak()
    {
        var ep = new AuthzEndpoint { Url = "https://app.test/api/orders/42", Method = "GET" };
        var local = new DirectFetchHelper.DirectFetchResult { Status = 200, Body = "{\"id\":42,\"owner\":\"alice\"}" };
        var peer = new DirectFetchHelper.DirectFetchResult { Status = 200, Body = "{\"id\":42,\"owner\":\"alice\"}" };
        var options = new AuthzComparisonOptions { LeakTokens = ["alice"] };

        var entry = AuthzRequestEvaluator.BuildEntry(ep, local, peer, options);

        Assert.Equal("BOLA_SUSPECTED", entry.Finding);
        Assert.NotNull(entry.Leaks);
        Assert.Contains("alice", entry.Leaks!);
    }

    [Fact]
    public void BuildEntry_FetchErrorOnLocal_TreatsStatusAsZeroAndUsesErrorAsBody()
    {
        var ep = new AuthzEndpoint { Url = "https://app.test/api/orders/42", Method = "GET" };
        var local = new DirectFetchHelper.DirectFetchResult { Error = "timeout" };
        var peer = new DirectFetchHelper.DirectFetchResult { Status = 200, Body = "ok" };
        var options = new AuthzComparisonOptions();

        var entry = AuthzRequestEvaluator.BuildEntry(ep, local, peer, options);

        Assert.Equal(0, entry.Local.Status);
        Assert.Equal("ERROR", entry.Finding);
    }
}
