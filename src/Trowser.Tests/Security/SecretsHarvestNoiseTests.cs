using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class SecretsHarvestNoiseTests
{
    [Fact]
    public void StorageAudit_SkipsConsentKeySsnFalsePositive()
    {
        var checker = new StorageAuditChecker();
        var result = checker.Run(
            "https://example.test/",
            localStorage: new Dictionary<string, string>
            {
                ["_sp_user_consent_4595"] = "{\"groups\":\"1,2,3\",\"date\":\"19990101-1234\"}"
            },
            sessionStorage: []);

        Assert.DoesNotContain(result.Findings, f => f.Category == "SsnInStorage");
    }

    [Fact]
    public void StorageAudit_SkipsPortalSessionIdAsAuthToken()
    {
        var checker = new StorageAuditChecker();
        var result = checker.Run(
            "https://www.wikipedia.org/",
            localStorage: new Dictionary<string, string> { ["portal_session_id"] = "9ca89b287643ce52" },
            sessionStorage: []);

        Assert.DoesNotContain(result.Findings, f => f.Category == "AuthTokenInStorage");
    }

    [Fact]
    public void StorageAudit_SkipsNumericUnleashSessionId()
    {
        var checker = new StorageAuditChecker();
        var result = checker.Run(
            "https://example.test/",
            localStorage: new Dictionary<string, string> { ["unleash:repository:sessionId"] = "799480600" },
            sessionStorage: []);

        Assert.DoesNotContain(result.Findings, f => f.Category == "AuthTokenInStorage");
    }

    [Theory]
    [InlineData("000-12-3456", false)]
    [InlineData("666-12-3456", false)]
    [InlineData("900-12-3456", false)]
    [InlineData("123-45-6789", true)]
    public void UsSsnHeuristic_RejectsInvalidAreas(string ssn, bool plausible)
    {
        Assert.Equal(plausible, StorageAuditChecker.TryGetPlausibleSsnMatch(ssn, out _));
    }

    [Fact]
    public void Heuristics_SuppressesChromiumOriginTrialBase64()
    {
        var snippet =
            "{\"origin\":\"https://doubleclick.net:443\",\"feature\":\"WebViewXRequestedWithDeprecation\",\"expiry\":1774310400}";
        var finding = new SecretsHarvestPipeline.SecretFinding
        {
            Category = "base64-decoded-url-or-secret",
            Snippet = snippet
        };

        Assert.True(SecretsHarvestHeuristics.ShouldHardSuppress(finding));
    }

    [Fact]
    public void Heuristics_SuppressesPrebidCurrencyCreditCard()
    {
        var finding = new SecretsHarvestPipeline.SecretFinding
        {
            Category = "credit-card",
            Location = "response:https://cdn.jsdelivr.net/gh/prebid/currency-file@1/latest.json?date=20261003",
            Snippet = "***********4375"
        };

        Assert.True(SecretsHarvestHeuristics.ShouldHardSuppress(finding));
    }

    [Fact]
    public void Heuristics_DowngradesHttpOnlyJwtCookie()
    {
        var finding = new SecretsHarvestPipeline.SecretFinding
        {
            Source = "cookies-storage",
            Category = "jwt-token",
            Severity = "high",
            Location = "httpOnlyCookie:cis-jwt",
            Description = "JWT (HS256): test issue"
        };

        SecretsHarvestHeuristics.CalibrateFinding(finding);

        Assert.Equal("low", finding.Severity);
    }

    private const string SampleJwt =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0cm93c2VyLXRlc3QifQ.b8RpOamNdE-74IqW2Q4kXRDkT8mmhObd3c";

    [Fact]
    public void RequestUrl_FlagsOidcLogoutIdTokenHint()
    {
        var url = "https://idp.example.test/connect/endsession?id_token_hint=" + SampleJwt
                  + "&post_logout_redirect_uri=https%3A%2F%2Fapp.example.test";
        var result = HarvestUrls(
            "https://app.example.test/home",
            new NetworkEntry { Method = "GET", Url = url, ResourceType = "Document", StatusCode = 302 });

        var hit = Assert.Single(result.Findings);
        Assert.Equal("jwt-in-url", hit.Category);
        Assert.Equal("low", hit.Severity);
        Assert.Equal("network-request-url", hit.Source);
        Assert.Contains("id_token_hint", hit.Description, StringComparison.Ordinal);
        Assert.Contains("jwt.io", hit.Description, StringComparison.Ordinal);
        Assert.Contains("/connect/endsession?id_token_hint=", hit.Location, StringComparison.Ordinal);
        Assert.Equal(SampleJwt, hit.Snippet);
        Assert.DoesNotContain(SampleJwt, hit.Location);
        Assert.Equal("credential-exposure", SecretsCategoryMapper.ToVpxCategory(hit.Category));
    }

    [Fact]
    public void RequestUrl_FlagsIdTokenHintWhenLogoutHostIsNotTheApp()
    {
        var url = "https://login.example.test/connect/endsession?id_token_hint=" + SampleJwt;
        var result = HarvestUrls(
            "https://app.example.test/",
            new NetworkEntry { Method = "GET", Url = url, StatusCode = 302 });

        var hit = Assert.Single(result.Findings);
        Assert.Equal("low", hit.Severity);
        Assert.Contains("login.example.test", hit.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void RequestUrl_AccessTokenInQueryIsMedium()
    {
        var url = "https://app.example.test/callback?access_token=" + SampleJwt;
        var result = HarvestUrls(new NetworkEntry { Method = "GET", Url = url, StatusCode = 200 });

        var hit = Assert.Single(result.Findings);
        Assert.Equal("medium", hit.Severity);
        Assert.Contains("access_token", hit.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void RequestUrl_IdTokenInFragmentIsMedium()
    {
        var url = "https://app.example.test/callback#id_token=" + SampleJwt;
        var result = HarvestUrls(new NetworkEntry { Method = "GET", Url = url, StatusCode = 200 });

        var hit = Assert.Single(result.Findings);
        Assert.Equal("medium", hit.Severity);
        Assert.Contains("#id_token=", hit.Location, StringComparison.Ordinal);
    }

    [Fact]
    public void RequestUrl_DecodesPercentEncodedJwt()
    {
        var encoded = SampleJwt.Replace(".", "%2E", StringComparison.Ordinal);
        var url = "https://idp.example.test/connect/endsession?id_token_hint=" + encoded;
        var result = HarvestUrls(new NetworkEntry { Method = "GET", Url = url, StatusCode = 302 });

        var hit = Assert.Single(result.Findings);
        Assert.Equal(SampleJwt, hit.Snippet);
    }

    [Fact]
    public void RequestUrl_IgnoresUrlsWithoutAJwt()
    {
        var result = HarvestUrls(
            new NetworkEntry
            {
                Method = "GET",
                Url = "https://app.example.test/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Fapp.example.test",
                StatusCode = 302
            });

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void RequestUrl_SkipsWellKnownThirdPartyHosts()
    {
        var url = "https://cdnjs.cloudflare.com/ajax/libs/lib.js?token=" + SampleJwt;
        var result = HarvestUrls(new NetworkEntry { Method = "GET", Url = url, StatusCode = 200 });

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void RequestUrl_DedupesTheSameTokenAcrossRedirects()
    {
        var logout = "https://idp.example.test/connect/endsession?id_token_hint=" + SampleJwt;
        var result = HarvestUrls(
            new NetworkEntry { Method = "GET", Url = logout, StatusCode = 302 },
            new NetworkEntry { Method = "GET", Url = logout + "&state=abc", StatusCode = 302 });

        Assert.Single(result.Findings);
    }

    [Fact]
    public void RequestUrl_FlagsJwtOnTheCurrentPageWhenTheLogMissedIt()
    {
        var result = HarvestUrls(
            "https://idp.example.test/connect/endsession?id_token_hint=" + SampleJwt);

        var hit = Assert.Single(result.Findings);
        Assert.Equal("page-url", hit.Source);
        Assert.Equal("low", hit.Severity);
    }

    [Fact]
    public void CalibrateFinding_LeavesJwtInUrlSeverityAlone()
    {
        var finding = new SecretsHarvestPipeline.SecretFinding
        {
            Source = "network-request-url",
            Category = "jwt-in-url",
            Severity = "low",
            Location = "https://idp.example.test/connect/authorize?client_id=app&grant_type=code",
            Description = "JWT in URL query string parameter 'id_token_hint'."
        };

        SecretsHarvestHeuristics.CalibrateFinding(finding);

        Assert.Equal("low", finding.Severity);
        Assert.Equal("jwt-in-url", finding.Category);
    }

    private static SecretsHarvestPipeline.HarvestResult HarvestUrls(params NetworkEntry[] entries)
        => HarvestUrls(pageUrl: null, entries);

    private static SecretsHarvestPipeline.HarvestResult HarvestUrls(string? pageUrl, params NetworkEntry[] entries)
    {
        var result = new SecretsHarvestPipeline.HarvestResult();
        SecretsHarvestPipeline.CollectJwtInUrlFindings(entries, pageUrl, result);
        foreach (var finding in result.Findings)
            SecretsHarvestHeuristics.CalibrateFinding(finding);
        return result;
    }
}
