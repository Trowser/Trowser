using System.Text;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class ScannerFalseNegativeFixesTests
{
    [Fact]
    public void JwtProbe_UsesFullToken_NotTruncatedPreview()
    {
        var full = "eyJhbGciOiJSUzI1NiJ9." + new string('b', 40) + "." + new string('c', 40);
        var preview = full[..40] + "…" + full[^20..];
        Assert.Null(JwtProbeHelpers.NormalizeBearerToken(preview));

        var pick = new HttpSecurityProbes.JwtTokenAnalysis
        {
            Source = "sessionStorage.token",
            Raw = preview,
            FullToken = full
        };
        Assert.Equal(full, JwtProbeHelpers.TokenForProbe(pick));
    }

    [Fact]
    public void JwtForge_TopLevelAlgorithmNone_RewritesHeaderAndStripsSignature()
    {
        var token = ToJwt("""{"alg":"RS256","typ":"JWT"}""", """{"user":"alice"}""") + ".sig";
        using var mods = JsonDocument.Parse("""{"payload":{"user":"admin"}}""");
        var applied = HttpSecurityProbes.ApplyTopLevelAlgorithm(mods.RootElement, "none", stripSignature: false, stripSignatureExplicit: false);
        var forged = HttpSecurityProbes.ForgeJwt(token, applied.Modifications, applied.StripSignature);

        using var header = JsonDocument.Parse(forged.HeaderJson);
        Assert.Equal("none", header.RootElement.GetProperty("alg").GetString());
        Assert.True(forged.SignatureStripped);
        Assert.EndsWith(".", forged.Token);
        using var payload = JsonDocument.Parse(forged.PayloadJson);
        Assert.Equal("admin", payload.RootElement.GetProperty("user").GetString());
    }

    [Theory]
    [InlineData(401, "{\"error\":\"no\"}", 200, "{\"id\":1,\"role\":\"admin\"}", true)]
    [InlineData(404, "missing", 200, "{\"id\":1}", true)]
    [InlineData(200, "public page", 200, "{\"email\":\"a@b.c\",\"role\":\"admin\"}", true)]
    [InlineData(200, "{\"email\":\"a@b.c\"}", 200, "{\"email\":\"a@b.c\"}", false)]
    [InlineData(200, "<!doctype html><html></html>", 200, "<!doctype html><html>app</html>", false)]
    public void JwtAcceptance_ClassifiesAlgNone(int anonStatus, string anonBody, int jwtStatus, string jwtBody, bool accept)
    {
        Assert.Equal(accept, JwtAcceptanceSweep.IsAlgNoneAcceptance(anonStatus, anonBody, jwtStatus, jwtBody, "/api/users"));
    }

    [Fact]
    public void Scope_ExcludesGoogleMaps_WhenPageHostIsTheApp()
    {
        Assert.True(SecurityHostScope.IsOutsideApplicationScope(
            "maps.googleapis.com", "brokencrystals.com"));
        Assert.False(SecurityHostScope.IsOutsideApplicationScope(
            "brokencrystals.com", "brokencrystals.com"));
        Assert.True(JwtProbeHelpers.IsStaticAssetUrl(
            "https://maps.googleapis.com/maps/api/js/StaticMapService.GetMapImage?x=1"));
    }

    [Fact]
    public void PathTraversal_DetectsEnvironAndResolvedPathEcho()
    {
        var baseline = "index";
        Assert.Equal("proc-environ", PathTraversalChecker.DetectDisclosure(
            "PATH=/usr/bin\0HOME=/root\0NODE_ENV=production", baseline, "../../../proc/self/environ"));
        Assert.Equal("resolved-path-echo", PathTraversalChecker.DetectDisclosure(
            "Error: ENOENT: no such file or directory, open '/usr/src/app/../../../proc/self/environ'",
            baseline, "../../../proc/self/environ"));
        Assert.Equal("etc-hostname", PathTraversalChecker.DetectDisclosure(
            "bc-web-1", baseline, "../../../etc/hostname"));
        Assert.Null(PathTraversalChecker.DetectDisclosure(baseline, baseline, "../../../etc/passwd"));
    }

    [Fact]
    public void PathTraversal_PhaseEscalation_OnErrorKeyword()
    {
        Assert.True(PathTraversalChecker.ShouldEscalatePathTraversalPayloads(
            200, "ok", 200, "Error: ENOENT: no such file '/etc/passwd'"));
        Assert.False(PathTraversalChecker.ShouldEscalatePathTraversalPayloads(
            200, "ok", 200, "ok"));
    }

    [Fact]
    public void AutoScan_PathTraversal_SkipsWindowsIniLikely()
    {
        var f = new PathTraversalFinding { Indicator = "windows-ini-likely" };
        Assert.False(PathTraversalChecker.ShouldPromoteToAutoScanFinding(f));
    }

    [Fact]
    public void HarvestIds_PrefersLivePathId_OverSwaggerExamples()
    {
        var swaggerIds = string.Join(",", Enumerable.Range(0, 12).Select(i => $"\"id\":{i}"));
        var entries = new List<NetworkEntry>
        {
            new()
            {
                Method = "GET",
                Url = "https://brokencrystals.com/swagger-json",
                StatusCode = 200,
                ResponseBody = "{\"openapi\":\"3.0.0\",\"paths\":{}," + swaggerIds + ",\"operationId\":\"UsersController_get\"}"
            },
            new()
            {
                Method = "GET",
                Url = "https://brokencrystals.com/api/users/id/1",
                StatusCode = 200,
                ResponseBody = "{\"id\":1,\"name\":\"ada\"}"
            },
            new()
            {
                Method = "GET",
                Url = "https://maps.googleapis.com/maps/vt/abcdef0123456789abcdef0123456789",
                StatusCode = 200,
                ResourceType = "Image"
            }
        };

        var result = ObjectIdHarvester.HarvestNetwork(entries, new ObjectIdHarvester.HarvestOptions { MaxIdsPerKind = 12 }, "brokencrystals.com");

        Assert.Contains(result.Ids, id => id.Value == "1" && id.Source == "network-path");
        Assert.DoesNotContain(result.Ids, id => id.Value.Contains("UsersController", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Ids, id => id.ContextUrl != null && id.ContextUrl.Contains("googleapis", StringComparison.Ordinal));
        var suggestion = Assert.Single(result.SuggestedBoundaryTests);
        Assert.Contains("/api/users/id/{id}", suggestion.UrlTemplate, StringComparison.Ordinal);
        Assert.Contains("1", suggestion.AuthorizedValues);
    }

    [Fact]
    public void OpenRedirect_ExplicitUrl_ProbesAllQueryParams_NotOnlyRedirectLikeNames()
    {
        var paramNames = new HashSet<string>(UrlLikeParamNames.RedirectLike, StringComparer.OrdinalIgnoreCase);
        var url = "https://lab.example/challenge/19?xyzzy=https://allowed.test/home";

        var points = RedirectParamDiscovery.FromUrls([url], paramNames).ToList();

        Assert.Contains(points, p =>
            p.ParamName.Equals("xyzzy", StringComparison.OrdinalIgnoreCase)
            && p.Source == "explicit-url"
            && p.BaseUri.GetLeftPart(UriPartial.Path) == "https://lab.example/challenge/19");
    }

    [Fact]
    public void OpenRedirect_EndpointHint_HonorsExplicitParamNames()
    {
        var paramNames = new HashSet<string>(UrlLikeParamNames.RedirectLike, StringComparer.OrdinalIgnoreCase);
        var hints = new List<EndpointParamHint>
        {
            new()
            {
                Url = "https://lab.example/go?xyzzy=/",
                Method = "GET",
                ParamNames = ["xyzzy"]
            }
        };

        var points = RedirectParamDiscovery.FromHints(hints, paramNames).ToList();

        Assert.Single(points);
        Assert.Equal("xyzzy", points[0].ParamName);
        Assert.Equal("/", points[0].OriginalValue);
        Assert.Equal("https://lab.example/go", points[0].BaseUri.GetLeftPart(UriPartial.Path));
    }

    [Fact]
    public void Bfla_RowSeverity_FollowsResult()
    {
        var denied = BflaAdminProbe.Classify("https://app.example/api/admin", "POST", 404, "missing", null, 404);
        Assert.Equal("denied", denied.Result);
        Assert.Equal("info", denied.Severity);

        var shell = BflaAdminProbe.Classify(
            "https://app.example/api/admin", "POST", 200, "<!doctype html><html><app-root></app-root></html>", null, 200);
        Assert.Equal("spa-shell", shell.Result);
        Assert.Equal("info", shell.Severity);

        var hit = BflaAdminProbe.Classify(
            "https://app.example/api/admin/users", "POST", 200, "{\"id\":1,\"name\":\"trowser-bfla-canary\"}", null, 401);
        Assert.Equal("bfla", hit.Result);
        Assert.Equal("critical", hit.Severity);
    }

    private static string ToJwt(string header, string payload) =>
        Base64Url(header) + "." + Base64Url(payload);

    private static string Base64Url(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
