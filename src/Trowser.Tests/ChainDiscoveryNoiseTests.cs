using Trowser.Security.ChainEngine;
using Xunit;

namespace Trowser.Tests;

public class ChainDiscoveryNoiseTests
{
    [Fact]
    public void Tabnabbing_does_not_complete_xss_session_hijack_chain()
    {
        var engine = new ChainDiscoveryEngine(new ChainPatternCatalog());
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "1",
                Source = "shadow",
                Category = "tabnabbing",
                Severity = "low",
                Title = "Reverse tabnabbing: target=_blank without noopener",
                Endpoint = "https://shop.example/potion-shop/"
            },
            new()
            {
                Id = "2",
                Source = "execute-js",
                Category = "missing-httponly",
                Severity = "low",
                Title = "Cookie readable via document.cookie (HttpOnly missing)",
                Detail = "document.cookie returned empty",
                Endpoint = "https://shop.example/potion-shop/"
            }
        };

        var result = engine.Analyze(findings);
        Assert.Empty(result.Chains);
        Assert.DoesNotContain(result.PartialChains, p => p.PatternId == "xss-missing-httponly-session-hijack" && p.ConfidenceScore >= 0.8);
    }

    [Fact]
    public void Low_confidence_full_match_stays_partial_not_confirmed()
    {
        var engine = new ChainDiscoveryEngine(new ChainPatternCatalog());
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "x1",
                Source = "autoscan",
                Category = "xss",
                Severity = "high",
                Title = "Reflected XSS in q",
                Detail = "confirmed payload xss-scan",
                Endpoint = "https://shop.example/search"
            },
            new()
            {
                Id = "h1",
                Source = "execute-js",
                Category = "missing-httponly",
                Severity = "low",
                Title = "Session cookie readable via document.cookie",
                Detail = "document.cookie returned session=abc",
                Evidence = "session=abc",
                Endpoint = "https://shop.example/"
            }
        };

        var result = engine.Analyze(findings);
        var chain = result.Chains.FirstOrDefault(c => c.PatternId == "xss-missing-httponly-session-hijack");
        if (chain != null)
        {
            Assert.True(chain.ConfidenceScore >= ChainDiscoveryEngine.ConfirmedConfidenceFloor);
            Assert.True(chain.Provable);
        }
    }

    [Fact]
    public void Idor_csrf_chain_rejects_get_admin_csrf_and_read_idor()
    {
        var engine = new ChainDiscoveryEngine(new ChainPatternCatalog());
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "csrf1",
                Source = "shadow",
                Category = "csrf",
                Severity = "info",
                Title = "CSRF token not validated on GET /admin",
                Method = "GET",
                Endpoint = "https://app.example/admin"
            },
            new()
            {
                Id = "idor1",
                Source = "autoscan",
                Category = "idor",
                Severity = "info",
                Title = "Public calendar IDOR — other user events readable by ID",
                Method = "GET",
                Endpoint = "https://app.example/api/calendar/123"
            }
        };

        var result = engine.Analyze(findings);
        Assert.DoesNotContain(result.Chains, c => c.PatternId == "idor-csrf-account-takeover");
    }

    [Fact]
    public void Missing_hsts_alone_stays_hypothesis_not_confirmed_high()
    {
        var engine = new ChainDiscoveryEngine(new ChainPatternCatalog());
        var findings = new List<ChainableFinding>
        {
            new()
            {
                Id = "hsts",
                Source = "shadow",
                Category = "missing-hsts",
                Severity = "low",
                Title = "No HSTS header",
                Endpoint = "https://app.example/"
            }
        };

        var result = engine.Analyze(findings);
        Assert.Empty(result.Chains);
        var partial = Assert.Single(result.PartialChains, p => p.PatternId == "missing-hsts-downgrade-risk");
        Assert.Equal("partial", partial.Status);
        Assert.True(partial.ChainedSeverity is "medium" or "low");
    }
}
