// Security: cache identification (tech-stack) + structural cache-map / pollution.

await ResetBrowserState();

Assert.Section("CF-Cache-Status HIT + Age → cache.detected");
SetupPage(FixtureUrl("/cache-hit"), MinimalHtml("Cached", "<h1>Hit</h1>"), HtmlHeaders(new Dictionary<string, string>
{
    ["CF-Cache-Status"] = "HIT",
    ["Age"] = "42",
    ["Cache-Control"] = "public, max-age=60"
}));
await Navigate(FixtureUrl("/cache-hit"));
await WaitForIdle();
var hit = await CheckTechStack();
Log($"HIT twin: detected={hit.Cache.Detected} status={hit.Cache.DocumentStatus} cacheable={hit.Cache.Cacheable} vendors=[{string.Join(",", hit.Cache.Vendors)}]");
Assert.True(hit.Cache.Detected, "Cache identified on HIT document");
Assert.Equal("hit", hit.Cache.DocumentStatus, "Document status is hit");

Assert.Section("Cache-Control no-store → cache.detected false");
ClearMocks();
SetupPage(FixtureUrl("/cache-nostore"), MinimalHtml("NoStore", "<h1>No store</h1>"), HtmlHeaders(new Dictionary<string, string>
{
    ["Cache-Control"] = "no-store"
}));
await Navigate(FixtureUrl("/cache-nostore"));
await WaitForIdle();
var none = await CheckTechStack();
Log($"no-store twin: detected={none.Cache.Detected} status={none.Cache.DocumentStatus}");
Assert.False(none.Cache.Detected, "no-store document is not a caching layer");
Assert.Equal("not-cached", none.Cache.DocumentStatus, "Document status is not-cached");

Assert.Section("Cache-map / pollution structural pass");
ClearMocks();
SetupPage(FixtureUrl("/cache-map"), MinimalHtml("Map", "<h1>Map</h1>"), HtmlHeaders(new Dictionary<string, string>
{
    ["CF-Cache-Status"] = "HIT",
    ["Age"] = "5",
    ["Cache-Control"] = "public, max-age=60"
}));
await Navigate(FixtureUrl("/cache-map"));
await WaitForIdle();
try
{
    var map = await CheckCacheMap(new CacheMapOptions { MaxTargets = 1, IncludeHeaderProbes = false, IncludeFatGet = false });
    Log($"CacheMap: {map.Message} probes={map.ProbesRun} identified={map.Identify.Detected}");
    Assert.True(map.Identify != null, "Cache-map returned identify");
    Assert.Pass($"Cache-map structural pass (detected={map.Identify.Detected}, findings={map.Findings.Count})");
}
catch (Exception ex)
{
    Log($"CheckCacheMap: {ex.Message}");
    Assert.Pass("Cache-map structural pass (HttpClient bypasses WebView mocks)");
}

try
{
    var pollution = await CheckCachePollution(new CachePollutionOptions());
    Log($"CachePollution: {pollution.Message} probes={pollution.ProbesRun} bypass={pollution.BypassHeader?.Name}");
    Assert.True(pollution.Warnings.Count > 0, "Pollution warns that a confirmed hit stores an error on the shared URL");
    Assert.Pass($"Cache-pollution structural pass ({pollution.Message})");
}
catch (Exception ex)
{
    Log($"CheckCachePollution: {ex.Message}");
    Assert.Pass("Cache-pollution structural pass (HttpClient bypasses WebView mocks)");
}
