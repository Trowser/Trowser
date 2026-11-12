using System.Text.Json;
using Trowser.Api;
using Trowser.Security.Orchestration;
using Xunit;

namespace Trowser.Tests.Security;

public class SafetyGateTests
{
    [Fact]
    public void RequireAtLeast_includes_requested_and_effective_labels()
    {
        var denial = SafetyGate.RequireAtLeast(
            SafetyMode.Active,
            SafetyMode.Safe,
            SafetyMode.Active,
            "Active OAuth flow probes");

        Assert.NotNull(denial);
        Assert.Equal("active", denial.Value.RequestedSafetyMode);
        Assert.Equal("safe", denial.Value.EffectiveSafetyMode);
        Assert.Contains("requested: 'active'", denial.Value.Message);
        Assert.Contains("effective: 'safe'", denial.Value.Message);
    }

    [Fact]
    public void OAuthFlowTestIsPassiveOnly_accepts_safetyMode_passive()
    {
        using var doc = JsonDocument.Parse("""{"safetyMode":"passive"}""");
        var body = new JsonBody(doc);

        Assert.True(SafetyGate.OAuthFlowTestIsPassiveOnly(body));
    }

    [Fact]
    public void OAuthFlowTestIsPassiveOnly_accepts_passiveOnly_true()
    {
        using var doc = JsonDocument.Parse("""{"passiveOnly":true}""");
        var body = new JsonBody(doc);

        Assert.True(SafetyGate.OAuthFlowTestIsPassiveOnly(body));
    }

    [Fact]
    public void RequireActive_suggests_passiveOnly_when_requested_passive()
    {
        using var doc = JsonDocument.Parse("""{"safetyMode":"passive"}""");
        var body = new JsonBody(doc);

        var denial = SafetyGate.RequireActive(body, "Active OAuth flow probes");

        Assert.NotNull(denial);
        Assert.Contains("passiveOnly", denial.Value.Message);
    }
}
