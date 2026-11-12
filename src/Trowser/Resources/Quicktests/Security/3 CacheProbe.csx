// @title 3 Cache Probe
// @shadow never
// @effects mutates
// Cache probe: identify → miss-forcing header → error store → clean GET.
// Indication (cache-map) uses unique query busters and does not poison the live URL.
// Pollution is the live-key confirmation and can store an error other users receive.
//
// Prerequisites: navigate to the target page (logged-in session recommended for map/deception).
// NOTE: cache-pollution and cache-poison send real requests. Pollution requires active probes.

var url = await GetCurrentUrl();
var title = await GetTitle();
Uri.TryCreate(url, UriKind.Absolute, out var uri);
Log($"Cache probe: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Cache map (identify + key indication)");
var map = await PrintCacheMapReport(includeDetails: true);
await AssertCacheMapClean();

if (!map.Identify.Detected)
{
    Assert.Pass("No cache identified — skipping live-key pollution / poison");
    return;
}

Assert.Section("Live-key error pollution (miss-forcing header → error store → clean GET)");
var pollution = await PrintCachePollutionReport(includeDetails: true);
await AssertCachePollutionClean();

if (pollution.BypassHeader != null)
{
    Assert.Section("Unkeyed-header canary poison (same bypass header, live key)");
    var poison = await RunCachePoisonScan(new CachePoisonOptions
    {
        BypassHeader = pollution.BypassHeader.Name,
        BypassHeaderValue = pollution.BypassHeader.Value,
        Headers = map.KeyComponents.Headers.Count > 0 ? map.KeyComponents.Headers : null,
        IncludeHeaderInjectionFuzz = false,
        MaxTargets = 1
    });
    Log(poison.Message);
    foreach (var f in poison.Findings)
        Log($"  [{f.Severity}/{f.Confidence}] {f.Indicator} {f.HeaderName}: {f.CacheHeaders}");
    if (poison.Findings.Any(f => f.Indicator == "cached-persistence"))
        Assert.Fail($"Cache poison persisted: {poison.Message}");
    else
        Assert.Pass(poison.Message);
}

Assert.Section("Cache deception (current path + variants)");
var deception = await RunCacheDeceptionScan(new CacheDeceptionOptions
{
    Paths = uri != null ? [uri.AbsolutePath] : null,
    MaxCandidates = 12,
    RequireSession = true
});
Log(deception.Message);
if (!string.IsNullOrEmpty(deception.SkippedReason))
{
    Assert.Pass($"Skipped cache deception ({deception.SkippedReason})");
}
else
{
    foreach (var f in deception.Findings)
        Log($"  [{f.Severity}/{f.Confidence}] {f.Url} via {f.VariantPath}");
    if (deception.Findings.Count > 0)
        Assert.Fail(deception.Message);
    else
        Assert.Pass(deception.Message);
}
