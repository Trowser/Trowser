using Trowser.Security.DomFlow;
using Xunit;

namespace Trowser.Tests.Security;

public sealed class DomFlowSessionCookieTests
{
    [Fact]
    public void SessionCookieToSameOriginApi_ClassifiesAsHygieneNotExploitable()
    {
        var tier = DomFlowGraph.ClassifyTier(
            source: "document.cookie",
            confidence: "temporal",
            consequence: "request-forgery",
            sinkName: "xhr.open",
            sinkData: "https://app.test/api/session/ping",
            pageOrigin: "https://app.test");

        Assert.Equal("hygiene", tier);
    }
}
