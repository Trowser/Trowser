using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class ShadowNetworkAuditTests
{
    private const string PageUrl = "https://shop.example.com/app";

    [Fact]
    public void network_heuristics_skipped_when_only_retire_js_selected()
    {
        var shadow = new SecurityShadowManager();
        shadow.Configure(
            enabled: true,
            audits: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "retire-js" });

        shadow.OnNetworkEntry(new NetworkEntry
        {
            Method = "GET",
            Url = "https://shop.example.com/api/data?access_token=abc123",
            StatusCode = 200,
            ResourceType = "Fetch"
        }, PageUrl);

        Assert.Equal(0, shadow.FindingsCount);
    }

    [Fact]
    public void sensitive_query_string_reported_when_network_audit_on()
    {
        var shadow = new SecurityShadowManager();
        shadow.Configure(
            enabled: true,
            audits: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "network" });

        shadow.OnNetworkEntry(new NetworkEntry
        {
            Method = "GET",
            Url = "https://shop.example.com/api/data?access_token=abc123",
            StatusCode = 200,
            ResourceType = "Fetch"
        }, PageUrl);

        var findings = shadow.GetFindings(category: "network");
        Assert.Single(findings);
        Assert.Contains("sensitive data in URL", findings[0].Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void duplicate_network_fetch_is_flagged()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js"));
        Report(shadow, Script("https://shop.example.com/app.js"));

        Assert.Single(DuplicateFindings(shadow));
    }

    [Fact]
    public void second_request_served_from_cache_is_not_a_duplicate_fetch()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js"));
        Report(shadow, Script("https://shop.example.com/app.js", servedFromCache: true));

        Assert.Empty(DuplicateFindings(shadow));
    }

    [Fact]
    public void cache_hits_alone_are_not_duplicate_fetches()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js", servedFromCache: true));
        Report(shadow, Script("https://shop.example.com/app.js", servedFromCache: true));

        Assert.Empty(DuplicateFindings(shadow));
    }

    [Fact]
    public void cache_then_one_network_fetch_is_not_a_duplicate()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js", servedFromCache: true));
        Report(shadow, Script("https://shop.example.com/app.js"));

        Assert.Empty(DuplicateFindings(shadow));
    }

    [Fact]
    public void repeated_post_is_flagged_even_when_marked_cached()
    {
        var shadow = NetworkShadow();
        var url = "https://shop.example.com/api/orders";
        Report(shadow, new NetworkEntry { Method = "POST", Url = url, StatusCode = 200, ResourceType = "Fetch", ServedFromCache = true });
        Report(shadow, new NetworkEntry { Method = "POST", Url = url, StatusCode = 200, ResourceType = "Fetch", ServedFromCache = true });

        Assert.Single(DuplicateFindings(shadow));
    }

    [Fact]
    public void static_asset_304_does_not_count_as_a_second_fetch()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js"));
        Report(shadow, Script("https://shop.example.com/app.js", status: 304));
        Report(shadow, Script("https://shop.example.com/app.js", status: 304));

        Assert.Empty(DuplicateFindings(shadow));
    }

    [Fact]
    public void fetch_304_still_counts_as_a_network_fetch()
    {
        var shadow = NetworkShadow();
        var url = "https://shop.example.com/api/cart";
        Report(shadow, new NetworkEntry { Method = "GET", Url = url, StatusCode = 200, ResourceType = "Fetch" });
        Report(shadow, new NetworkEntry { Method = "GET", Url = url, StatusCode = 304, ResourceType = "Fetch" });

        Assert.Single(DuplicateFindings(shadow));
    }

    [Fact]
    public void duplicate_counter_resets_on_the_next_navigation()
    {
        var shadow = NetworkShadow();
        Report(shadow, Script("https://shop.example.com/app.js"));
        shadow.BeginPage();
        Report(shadow, Script("https://shop.example.com/app.js"));

        Assert.Empty(DuplicateFindings(shadow));
    }

    private static SecurityShadowManager NetworkShadow()
    {
        var shadow = new SecurityShadowManager();
        shadow.Configure(
            enabled: true,
            audits: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "network" });
        return shadow;
    }

    private static void Report(SecurityShadowManager shadow, NetworkEntry entry) =>
        shadow.OnNetworkEntry(entry, PageUrl);

    private static List<ShadowFinding> DuplicateFindings(SecurityShadowManager shadow) =>
        shadow.GetFindings(category: "network")
            .Where(f => f.Title.StartsWith("Duplicate ", StringComparison.Ordinal))
            .ToList();

    private static NetworkEntry Script(string url, bool servedFromCache = false, int status = 200) =>
        new()
        {
            Method = "GET",
            Url = url,
            StatusCode = status,
            ResourceType = "Script",
            ServedFromCache = servedFromCache
        };
}
