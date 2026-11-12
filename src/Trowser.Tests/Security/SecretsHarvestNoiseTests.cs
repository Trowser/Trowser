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
}
