using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public sealed class PostMessageActiveReconciliationTests
{
    [Fact]
    public void Demotes_hygiene_when_all_active_techniques_blocked()
    {
        var findings = new List<UnifiedSecurityFinding>
        {
            UnifiedSecurityFinding.Create(
                category: "postmessage",
                title: "postMessage listener without origin check",
                severity: "high",
                confidence: SecurityConfidence.Likely,
                tier: SecurityFindingTier.Hygiene,
                id: "pm-abc")
        };

        var techniques = new List<PostMessageTechniqueResult>
        {
            new()
            {
                ListenerId = "pm-abc",
                Topology = "child-iframe",
                Verdict = "blocked",
                Tier = SecurityFindingTier.Hygiene,
                ConfirmationStatus = "none"
            },
            new()
            {
                ListenerId = "pm-abc",
                Topology = "popup-to-opener",
                Verdict = "blocked",
                Tier = SecurityFindingTier.Hygiene,
                ConfirmationStatus = "none"
            }
        };

        PostMessageActiveReconciliation.Apply(findings, techniques);

        Assert.Equal("info", findings[0].Severity);
        Assert.Equal(SecurityConfidence.Tentative, findings[0].Confidence);
        Assert.Contains("(active confirmation blocked)", findings[0].Title);
        Assert.Equal("blocked", findings[0].Extra["activeConfirmation"]);
        Assert.NotNull(findings[0].Extra["caveat"]);
    }

    [Fact]
    public void Runtime_origin_compare_grades_strict()
    {
        var grade = PostMessageOriginGrader.Analyze(
            "function(e){ if (e.origin !== window.location.origin) return; doWork(e.data); }");
        Assert.Equal("strict", grade.Grade);
        Assert.Equal("runtime-origin-compare", grade.CheckKind);
    }
}
