// @title A00 Specific Scan
// @shadow never
// @effects mutates
// A00 Specific endpoint — active scan on one URL+method from the network log.
// 1. Browse the app and trigger the API call you want tested (or set targetUrl below).
// 2. Re-run: picks the first same-origin POST/PUT/PATCH API call unless targetUrl is set.
// Default: active probes, no crawl-light (includeCrawl=false), depth=quick.
// "aggressive" requires localhost / *.test / *.local or Trowser started with --dangerous-ok.

var pageUrl = await GetCurrentUrl();
var title = await GetTitle();
Log($"Specific endpoint scan: {title}");
Log($"Page: {pageUrl}");
Log("");

// Optional: set explicitly instead of auto-pick from network log
string? targetUrl = null;
string? targetMethod = "POST";

await WaitForIdle(1000, 10000);

var entries = GetNetworkLog();
if (entries.Count == 0)
{
    Log("No network traffic — browse and trigger the target API first, then re-run.");
    Assert.Fail("Network log empty");
    return;
}

if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
{
    Assert.Fail("Current page URL is not absolute");
    return;
}

var pageHost = pageUri.Host;

bool SameHost(NetworkEntry e) =>
    Uri.TryCreate(e.Url, UriKind.Absolute, out var u) &&
    string.Equals(u.Host, pageHost, StringComparison.OrdinalIgnoreCase);

bool IsApiLike(NetworkEntry e) =>
    string.Equals(e.ResourceType, "XHR", StringComparison.OrdinalIgnoreCase)
    || string.Equals(e.ResourceType, "Fetch", StringComparison.OrdinalIgnoreCase)
    || (e.Method is "POST" or "PUT" or "PATCH" or "DELETE" && !string.IsNullOrWhiteSpace(e.RequestBody));

NetworkEntry? seedEntry = null;
if (string.IsNullOrWhiteSpace(targetUrl))
{
    seedEntry = entries
        .Where(SameHost)
        .Where(IsApiLike)
        .Where(e => e.Method is "POST" or "PUT" or "PATCH")
        .OrderByDescending(e => e.Timestamp)
        .FirstOrDefault();

    if (seedEntry == null)
    {
        Log("No POST/PUT/PATCH API call found on this host — set targetUrl at the top of this script.");
        Assert.Fail("No suitable endpoint in network log");
        return;
    }

    targetUrl = seedEntry.Url;
    targetMethod = seedEntry.Method;
}
else
{
    seedEntry = entries
        .Where(SameHost)
        .Where(e => string.Equals(e.Url, targetUrl, StringComparison.OrdinalIgnoreCase))
        .Where(e => targetMethod == null || string.Equals(e.Method, targetMethod, StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(e => e.Timestamp)
        .FirstOrDefault();
}

Dictionary<string, string>? seedHeaders = null;
string? seedBody = null;
if (seedEntry != null)
{
    seedBody = seedEntry.RequestBody;
    if (seedEntry.RequestHeaders.TryGetValue("Content-Type", out var ct) && !string.IsNullOrWhiteSpace(ct))
        seedHeaders = new Dictionary<string, string> { ["Content-Type"] = ct };
}

Log($"Target: {targetMethod} {targetUrl}");
Log("Seeding network log with a baseline request...");
await Fetch(targetUrl, targetMethod ?? "GET", seedHeaders, seedBody);
await WaitForIdle(500, 5000);
Log("");

var result = await PrintPlaybookReport(
    "full",
    safetyMode: "active",
    depth: "quick",
    includeCrawl: false,
    targetUrl: targetUrl,
    targetMethod: targetMethod,
    maxSeconds: 300,
    maxRequests: 1200);

Log("");
Log($"Done: {result.StepsExecuted.Count} steps, safety={result.SafetyMode}, depth={result.Depth}");
var crawl = result.StepsExecuted.FirstOrDefault(s => s.Name == "crawl-light");
if (crawl != null)
    Log($"  crawl-light: {crawl.Status} ({crawl.Reason ?? "ok"})");
