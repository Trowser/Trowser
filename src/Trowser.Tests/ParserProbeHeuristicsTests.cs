using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ParserProbeHeuristicsTests
{
    [Fact]
    public void anonymous_401_baseline_and_400_stack_is_not_a_differential()
    {
        var match = ParserProbeHeuristics.Evaluate(
            baselineStatus: 401,
            baselineBody: "{\"error\":\"Unauthorized\"}",
            probeStatus: 400,
            probeBody: "System.NullReferenceException\n   at com.example.Api",
            probeKind: "content-type-matrix",
            contentType: "application/xml",
            bodyVariant: "application/xml");

        Assert.Null(match);
    }

    [Fact]
    public void auth_baseline_401_with_probe_200_privileged_field_still_flags()
    {
        var match = ParserProbeHeuristics.Evaluate(
            baselineStatus: 401,
            baselineBody: "{\"error\":\"Unauthorized\"}",
            probeStatus: 200,
            probeBody: "{\"isAdmin\":true}",
            probeKind: "content-type-matrix",
            contentType: "application/xml",
            bodyVariant: "application/xml");

        Assert.NotNull(match);
        Assert.Equal("privileged-field-in-response", match!.Signal);
    }
}
