using Trowser.Security;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Security.Authz;

public class BacCoverageReportTests
{
    private static AttackSurfaceEndpoint Endpoint(string urlTemplate, string method = "GET", bool authRequired = true, string priority = "high") =>
        new()
        {
            Url = $"https://example.com{urlTemplate}",
            UrlTemplate = $"https://example.com{urlTemplate}",
            Methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { method },
            Auth = new AttackSurfaceAuth { Required = authRequired },
            TestPriority = priority
        };

    private static LiveAuthzShadowResult ShadowResult(
        string method, string urlTemplate, AuthzVerdictKind verdict, bool needsClassification = false) =>
        new()
        {
            Host = "example.com",
            Method = method,
            Url = $"https://example.com{urlTemplate}",
            UrlTemplate = $"https://example.com{urlTemplate}",
            Peer = "peer1",
            Verdict = verdict,
            Confidence = "high",
            Reason = "test",
            NeedsClassification = needsClassification
        };

    [Fact]
    public void Build_UnclassifiedUntestedEndpoint_CountsAsGapNotCoverage()
    {
        var model = new AccessModel { Host = "example.com" };
        var endpoints = new List<AttackSurfaceEndpoint> { Endpoint("/api/orders/{id}") };

        var report = BacCoverageReport.Build(model, endpoints, []);

        Assert.Equal(0, report.CoverageNumerator);
        Assert.Equal(1, report.CoverageDenominator);
        Assert.Single(report.Gaps);
        Assert.True(report.Gaps[0].AuthRequired);
    }

    [Fact]
    public void Build_ClassifiedResource_CountsTowardCoverageAndNotAGap()
    {
        var model = new AccessModel { Host = "example.com" };
        var template = "https://example.com/api/orders/{id}";
        model.Resources[AccessModelResource.KeyOf("GET", template)] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = template,
            Sensitivity = AccessSensitivity.Sensitive,
            Ownership = AccessOwnership.PerUser,
            Source = AccessSource.Human,
            Confidence = 1.0
        };
        var endpoints = new List<AttackSurfaceEndpoint> { Endpoint("/api/orders/{id}") };

        var report = BacCoverageReport.Build(model, endpoints, []);

        Assert.Equal(1, report.CoverageNumerator);
        Assert.Equal(1, report.CoverageDenominator);
        Assert.Empty(report.Gaps);
    }

    [Fact]
    public void Build_ShadowTestedResource_CountsTowardCoverageEvenWithoutClassification()
    {
        var model = new AccessModel { Host = "example.com" };
        var endpoints = new List<AttackSurfaceEndpoint> { Endpoint("/api/orders/{id}") };
        var results = new List<LiveAuthzShadowResult>
        {
            ShadowResult("GET", "/api/orders/{id}", AuthzVerdictKind.ProperlyDenied)
        };

        var report = BacCoverageReport.Build(model, endpoints, results);

        Assert.Equal(1, report.CoverageNumerator);
        Assert.Empty(report.Gaps);
    }

    [Fact]
    public void Build_FindingsGroupedByVerdict()
    {
        var model = new AccessModel { Host = "example.com" };
        var endpoints = new List<AttackSurfaceEndpoint> { Endpoint("/api/orders/{id}") };
        var results = new List<LiveAuthzShadowResult>
        {
            ShadowResult("GET", "/api/orders/{id}", AuthzVerdictKind.ConfirmedLeak),
            ShadowResult("GET", "/api/invoices/{id}", AuthzVerdictKind.BolaSuspected)
        };

        var report = BacCoverageReport.Build(model, endpoints, results);

        Assert.True(report.FindingsByVerdict.ContainsKey("ConfirmedLeak"));
        Assert.True(report.FindingsByVerdict.ContainsKey("BolaSuspected"));
        Assert.Single(report.FindingsByVerdict["ConfirmedLeak"]);
        Assert.Contains("confirmed cross-identity leak", report.NextActions[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_NoGapsOrFindings_ReturnsCleanNextAction()
    {
        var model = new AccessModel { Host = "example.com" };

        var report = BacCoverageReport.Build(model, [], []);

        Assert.Equal(0, report.CoverageDenominator);
        Assert.Empty(report.Gaps);
        Assert.Contains("No replay results for example.com", report.NextActions[0]);
        Assert.DoesNotContain(report.NextActions, a => a.Contains("No outstanding", StringComparison.Ordinal));
    }

    [Fact]
    public void ToMarkdown_ProducesNonEmptyReportWithHostHeading()
    {
        var model = new AccessModel { Host = "example.com" };
        var report = BacCoverageReport.Build(model, [Endpoint("/api/orders/{id}")], []);

        var markdown = report.ToMarkdown();

        Assert.Contains("# BAC Coverage Report — example.com", markdown);
        Assert.Contains("## Coverage", markdown);
        Assert.Contains("## Gaps", markdown);
        Assert.DoesNotContain(",", markdown.Split('\n').First(l => l.Contains('%')));
    }

    [Fact]
    public void Build_UnauthenticatedGap_IsMentionedInNextActions()
    {
        var model = new AccessModel { Host = "example.com" };
        var report = BacCoverageReport.Build(model, [Endpoint("/blog", authRequired: false, priority: "low")], []);

        Assert.Contains(report.NextActions, a => a.Contains("other endpoint", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(report.NextActions, a => a.Contains("No outstanding", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_AllowIntentWithBola_DoesNotAskToInvestigate()
    {
        var model = new AccessModel { Host = "example.com" };
        model.Resources[AccessModelResource.KeyOf("GET", "https://example.com/blog")] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "https://example.com/blog",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Ai,
            Confidence = 1.0
        };
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "GET",
            Url = "https://example.com/blog",
            UrlTemplate = "https://example.com/blog",
            Peer = "peer1",
            Verdict = AuthzVerdictKind.BolaSuspected,
            Confidence = "medium",
            Reason = "same length"
        };

        var report = BacCoverageReport.Build(model, [], [result]);

        Assert.Equal("consistent", report.FindingsByVerdict["BolaSuspected"][0].IntentAlignment);
        Assert.DoesNotContain(report.NextActions, a => a.Contains("Investigate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_DenyIntentWithDifferentContent_IsUnresolved()
    {
        var model = new AccessModel { Host = "example.com" };
        model.Resources[AccessModelResource.KeyOf("GET", "/order/details?orderId={id}")] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/order/details?orderId={id}",
            Sensitivity = AccessSensitivity.Sensitive,
            Ownership = AccessOwnership.PerUser,
            Source = AccessSource.Human,
            Confidence = 1.0
        };
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "GET",
            Url = "https://example.com/order/details?orderId=1",
            UrlTemplate = "/order/details?orderId={id}",
            Peer = "peer1",
            Verdict = AuthzVerdictKind.FilteredResponse,
            Confidence = "low",
            Reason = "different",
            OwnerStatus = 200,
            PeerStatus = 200,
            OwnerBodyLength = 2700,
            PeerBodyLength = 900
        };

        var report = BacCoverageReport.Build(model, [], [result]);

        Assert.Equal("unresolved", report.FindingsByVerdict["FilteredResponse"][0].IntentAlignment);
        Assert.Contains(report.NextActions, a => a.Contains("not proof of scoping", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_SafetySkip_IsNotACriticalUntestedGap()
    {
        var model = new AccessModel { Host = "example.com" };
        var skips = new List<AuthzShadowSkip>
        {
            new()
            {
                Host = "example.com",
                Method = "POST",
                UrlTemplate = "/api/auth/login",
                Kind = "safety"
            }
        };

        var report = BacCoverageReport.Build(
            model,
            [Endpoint("/api/auth/login", "POST", authRequired: true, priority: "critical")],
            [],
            skips);

        Assert.Equal("low", report.Gaps[0].TestPriority);
        Assert.Equal("safety", report.Gaps[0].SkipKind);
        Assert.Contains("safetyMode", report.Gaps[0].Reason);
        Assert.DoesNotContain(report.NextActions, a => a.Contains("authenticated endpoint", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.NextActions, a => a.Contains("safetyMode is safe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_PeerAuthNone_LeadsNextActions()
    {
        var model = new AccessModel { Host = "example.com" };
        var result = ShadowResult("GET", "/api/products", AuthzVerdictKind.Inconclusive);
        result = new LiveAuthzShadowResult
        {
            Host = result.Host,
            Method = result.Method,
            Url = result.Url,
            UrlTemplate = result.UrlTemplate,
            Peer = result.Peer,
            Verdict = result.Verdict,
            Confidence = "low",
            Reason = "Peer replay had no credential (peerAuthApplied: none).",
            PeerAuthApplied = "none"
        };

        var report = BacCoverageReport.Build(model, [], [result]);

        Assert.Contains("peerAuthApplied: none", report.NextActions[0]);
        Assert.Contains("Log the peer in", report.NextActions[0]);
        Assert.DoesNotContain(report.NextActions[0], "storage token", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_NoPeerCredentialAnd200_IsMissingAuthentication()
    {
        var model = new AccessModel { Host = "example.com" };
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "GET",
            Url = "https://example.com/api/message",
            UrlTemplate = "/api/message",
            Peer = "attacker",
            Verdict = AuthzVerdictKind.ConfirmedLeak,
            Confidence = "high",
            Reason = "Peer had no session and received the owner's 200 body.",
            PeerAuthApplied = "none",
            OwnerStatus = 200,
            PeerStatus = 200
        };

        var report = BacCoverageReport.Build(model, [], [result]);
        Assert.Contains(report.NextActions, a => a.Contains("missing authentication", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(report.NextActions, a => a.Contains("Those denials", StringComparison.Ordinal));
    }

    [Fact]
    public void Build_HostWithNoResults_DoesNotSayTheAppIsClean()
    {
        var model = new AccessModel { Host = "localhost" };
        var report = BacCoverageReport.Build(model, [], [], pageHost: "127.0.0.1:8101");
        Assert.Contains("No replay results for localhost", report.NextActions[0]);
        Assert.Contains("The page host is 127.0.0.1:8101", report.NextActions[0]);
        Assert.Contains("different keys", report.NextActions[0]);
        Assert.DoesNotContain(report.NextActions, a => a.Contains("No outstanding", StringComparison.Ordinal));
    }

    [Fact]
    public void Build_ReviewAnswerAfterReplay_UpdatesAlignment()
    {
        var model = new AccessModel { Host = "example.com" };
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "GET",
            Url = "https://example.com/contactList",
            UrlTemplate = "/contactList",
            Peer = "attacker",
            Verdict = AuthzVerdictKind.BolaSuspected,
            Confidence = "low",
            Reason = "Identical public document."
        };

        var before = BacCoverageReport.Build(model, [], [result]);
        Assert.Equal("needs-classification", before.FindingsByVerdict["BolaSuspected"][0].IntentAlignment);

        model.Resources[AccessModelResource.KeyOf("GET", "/contactList")] = new AccessModelResource
        {
            Method = "GET",
            UrlTemplate = "/contactList",
            Sensitivity = AccessSensitivity.Public,
            Ownership = AccessOwnership.Shared,
            Source = AccessSource.Ai,
            Confidence = 1.0
        };

        var after = BacCoverageReport.Build(model, [], [result]);
        var finding = after.FindingsByVerdict["BolaSuspected"][0];
        Assert.Equal("allow", finding.ExpectedOutcome);
        Assert.Equal("consistent", finding.IntentAlignment);
    }

    [Fact]
    public void Build_FilteredResponseWithPeerCredential_IsANextAction()
    {
        var model = new AccessModel { Host = "example.com" };
        var result = ShadowResult("GET", "/contacts", AuthzVerdictKind.FilteredResponse);
        result = new LiveAuthzShadowResult
        {
            Host = result.Host,
            Method = result.Method,
            Url = result.Url,
            UrlTemplate = result.UrlTemplate,
            Peer = result.Peer,
            Verdict = result.Verdict,
            Confidence = "medium",
            Reason = "lengths differ",
            PeerAuthApplied = "both",
            OwnerStatus = 200,
            PeerStatus = 200,
            OwnerBodyLength = 550,
            PeerBodyLength = 306
        };

        var report = BacCoverageReport.Build(model, [], [result]);
        Assert.Contains(report.NextActions, a => a.Contains("peer credential was applied", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Build_ReplayedWrite_SaysPeerWasMutated()
    {
        var model = new AccessModel { Host = "example.com" };
        var result = new LiveAuthzShadowResult
        {
            Host = "example.com",
            Method = "POST",
            Url = "https://example.com/contacts",
            UrlTemplate = "/contacts",
            Peer = "attacker",
            Verdict = AuthzVerdictKind.ReplayedWrite,
            Confidence = "low",
            Reason = "isolated write",
            PeerAuthApplied = "both",
            PeerMutated = true,
            OwnerStatus = 201,
            PeerStatus = 201
        };

        var report = BacCoverageReport.Build(model, [], [result]);
        Assert.Contains(report.NextActions, a => a.Contains("peerMutated", StringComparison.Ordinal));
    }
}
