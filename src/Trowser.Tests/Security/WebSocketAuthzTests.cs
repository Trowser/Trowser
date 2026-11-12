using Trowser.Security;
using Trowser.Security.Authz;
using Trowser.Security.WebSocket;
using Xunit;

namespace Trowser.Tests.Security;

public class WebSocketAuthzTests
{
    [Theory]
    [InlineData("{\"type\":\"subscribe\",\"room\":\"1\"}", false)]
    [InlineData("{\"action\":\"query\"}", false)]
    [InlineData("{\"type\":\"ping\"}", false)]
    [InlineData("{\"type\":\"connection_init\"}", false)]
    [InlineData("{\"type\":\"message\",\"text\":\"hi\"}", true)]
    [InlineData("{\"op\":\"create\"}", true)]
    [InlineData("hello", true)]
    [InlineData("", true)]
    public void IsWriteLike_TreatsSubscribeAndQueryAsReads(string message, bool writeLike)
    {
        Assert.Equal(writeLike, WebSocketAuthz.IsWriteLike(message));
    }

    [Fact]
    public void Classify_NoSocket_IsInconclusive()
    {
        var verdict = WebSocketAuthz.Classify("owner", null, "no-socket");
        Assert.Equal(AuthzVerdictKind.Inconclusive, verdict.Kind);
    }

    [Fact]
    public void Classify_Silence_IsLowConfidenceDenial()
    {
        var verdict = WebSocketAuthz.Classify("owner-saw-this", null, "silence");
        Assert.Equal(AuthzVerdictKind.ProperlyDenied, verdict.Kind);
        Assert.Equal("low", verdict.Confidence);
    }

    [Fact]
    public void Classify_ErrorFrame_IsDenial()
    {
        var verdict = WebSocketAuthz.Classify("{\"user\":\"a\"}", "{\"error\":\"unauthorized\"}", "error-frame");
        Assert.Equal(AuthzVerdictKind.ProperlyDenied, verdict.Kind);
        Assert.Equal("high", verdict.Confidence);
    }

    [Fact]
    public void Classify_IdenticalFrames_AreSuspected()
    {
        var body = "{\"room\":\"42\",\"text\":\"secret\"}";
        var verdict = WebSocketAuthz.Classify(body, body, "frames");
        Assert.Equal(AuthzVerdictKind.BolaSuspected, verdict.Kind);
    }

    [Fact]
    public void Classify_OwnerEmailInPeerFrame_IsConfirmedLeak()
    {
        var verdict = WebSocketAuthz.Classify(
            "{\"email\":\"owner@example.com\"}",
            "{\"email\":\"owner@example.com\",\"extra\":1}",
            "frames",
            ["owner@example.com"]);
        Assert.Equal(AuthzVerdictKind.ConfirmedLeak, verdict.Kind);
    }

    [Fact]
    public void DefaultCspProbes_IncludeDataAndBlob_AndOmitNavigation()
    {
        var selected = FirewallCspProbes.Resolve(null, out var unknown);
        Assert.Empty(unknown);
        Assert.Contains("script-src-data", selected);
        Assert.Contains("script-src-blob", selected);
        Assert.DoesNotContain("worker-blob", selected);
        Assert.DoesNotContain("form-action", selected);
    }

    [Fact]
    public void ExplicitCspProbes_ReplaceTheDefaultSet()
    {
        var selected = FirewallCspProbes.Resolve(["worker-blob", "nope"], out var unknown);
        Assert.Equal(["worker-blob"], selected);
        Assert.Equal(["nope"], unknown);
    }
}
