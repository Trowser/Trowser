using Trowser.Api;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class CsrfTokenHeuristicsTests
{
    [Theory]
    [InlineData("X-CSRF", true)]
    [InlineData("x-csrf-token", true)]
    [InlineData("X-XSRF", true)]
    [InlineData("RequestVerificationToken", true)]
    [InlineData("Accept", false)]
    [InlineData("X-Request-Id", false)]
    [InlineData("Authorization", false)]
    public void Header_name_recognizes_csrf_markers_beyond_the_exact_list(string name, bool expected)
    {
        Assert.Equal(expected, CsrfTokenHeuristics.IsCsrfHeaderName(name));
    }

    [Fact]
    public void Fixed_flag_value_is_not_a_secret_token()
    {
        Assert.False(CsrfTokenHeuristics.LooksLikeCsrfTokenValue("1"));
        Assert.True(CsrfTokenHeuristics.LooksLikeCsrfTokenValue("0123456789abcdef0123456789abcdef"));
    }

    [Theory]
    [InlineData("X-Requested-With", true)]
    [InlineData("X-Feature-Flag", true)]
    [InlineData("X-CSRF", false)]
    [InlineData("X-Request-Id", false)]
    [InlineData("X-Forwarded-For", false)]
    [InlineData("Content-Type", false)]
    [InlineData("Cookie", false)]
    public void Custom_header_candidates_are_non_safelisted_x_headers(string name, bool expected)
    {
        Assert.Equal(expected, CsrfTokenHeuristics.IsCustomHeaderCsrfCandidate(name));
    }

    [Fact]
    public void Replay_rejection_covers_403_and_csrf_language()
    {
        Assert.True(CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(403, "CSRF validation failed"));
        Assert.True(CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(403, ""));
        Assert.True(CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(401, "unauthorized"));
        Assert.False(CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(202, "{\"ok\":true}"));
        Assert.False(CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(400, "missing field"));
    }

    [Theory]
    [InlineData("/api/network/4", true, 4)]
    [InlineData("/api/network/0", true, 0)]
    [InlineData("/api/network/har", false, 0)]
    [InlineData("/api/network/throttle", false, 0)]
    [InlineData("/api/network/", false, 0)]
    [InlineData("/api/network", false, 0)]
    public void Network_entry_path_parses_numeric_ids_only(string path, bool ok, int id)
    {
        Assert.Equal(ok, TrowserApiServer.TryParseNetworkEntryId(path, out var parsed));
        Assert.Equal(id, parsed);
    }
}
