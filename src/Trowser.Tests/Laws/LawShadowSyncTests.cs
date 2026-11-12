using Trowser.Automation;
using Trowser.Laws;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Laws;

public class LawShadowSyncTests
{
    [Fact]
    public void ClearLawFailureForUrl_removes_only_matching_url()
    {
        var shadow = new SecurityShadowManager();
        shadow.AddCustomFinding(Severity.Medium, "Law: Demo", "failed", audit: "laws", url: "https://example.com/a");
        Assert.Single(shadow.GetFindings(category: "laws"));

        shadow.ClearLawFailureForUrl("Demo", "https://example.com/b");
        Assert.Single(shadow.GetFindings(category: "laws"));

        shadow.ClearLawFailureForUrl("Demo", "https://example.com/a");
        Assert.Empty(shadow.GetFindings(category: "laws"));
    }

    [Fact]
    public void OnNetworkEntry_reports_fail_and_clears_on_pass_same_url()
    {
        var svc = new LawService();
        var shadow = new SecurityShadowManager();
        shadow.Config.Enabled = true;
        shadow.Config.LawsEnabled = true;
        svc.Wire(null!, shadow);

        new LawBuilder(svc.Registry, "Cart total sane", null, "test.csx")
            .OnResponse("GET /api/cart*")
            .Expect(r => r.Json.Number("total") >= 0);

        svc.OnNetworkEntry(new NetworkEntry
        {
            Method = "GET",
            Url = "https://example.com/api/cart",
            StatusCode = 200,
            ResponseBody = """{"total":-3}""",
            ResponseHeaders = new Dictionary<string, string> { ["content-type"] = "application/json" }
        }, "https://example.com/cart");

        Assert.Single(shadow.GetFindings(category: "laws"));

        svc.OnNetworkEntry(new NetworkEntry
        {
            Method = "GET",
            Url = "https://example.com/api/cart",
            StatusCode = 200,
            ResponseBody = """{"total":10}""",
            ResponseHeaders = new Dictionary<string, string> { ["content-type"] = "application/json" }
        }, "https://example.com/cart");

        Assert.Empty(shadow.GetFindings(category: "laws"));
        Assert.Equal(LawVerdict.Pass, svc.Registry.All[0].LastVerdict);
    }

    [Fact]
    public void OnNetworkEntry_skips_laws_from_inactive_source_file()
    {
        var svc = new LawService();
        var shadow = new SecurityShadowManager();
        shadow.Config.Enabled = true;
        shadow.Config.LawsEnabled = true;
        shadow.Config.ActiveLawSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        svc.Wire(null!, shadow);

        new LawBuilder(svc.Registry, "Cart total sane", null, "test.csx")
            .OnResponse("GET /api/cart*")
            .Expect(r => r.Json.Number("total") >= 0);

        svc.OnNetworkEntry(new NetworkEntry
        {
            Method = "GET",
            Url = "https://example.com/api/cart",
            StatusCode = 200,
            ResponseBody = """{"total":-3}""",
            ResponseHeaders = new Dictionary<string, string> { ["content-type"] = "application/json" }
        }, "https://example.com/cart");

        Assert.Empty(shadow.GetFindings(category: "laws"));
    }
}
