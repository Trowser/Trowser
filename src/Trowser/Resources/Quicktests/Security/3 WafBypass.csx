// @title 3 Waf Bypass
// @shadow never
// @effects mutates
// WAF bypass probe: sends a canonical attack payload, detects WAF block vs baseline,
// then tests encoding / header / path / HPP bypass transforms.
// Discovers a same-origin GET with query params from the network log, or falls back to current URL + param q.
// confirmBackend is implicit in scripting; blocked in --safe mode.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"WAF bypass probe: {title}");
Log($"URL: {url}");
Log("");

await WaitForIdle(500, 5000);

string? probeUrl = null;
string? paramName = null;

if (Uri.TryCreate(url, UriKind.Absolute, out var pageUri))
{
    var pageHost = pageUri.Host;
    foreach (var entry in GetNetworkLog())
    {
        if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase))
            continue;
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var requestUri))
            continue;
        if (!string.Equals(requestUri.Host, pageHost, StringComparison.OrdinalIgnoreCase))
            continue;

        var query = requestUri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(query))
            continue;

        var firstPair = query.Split('&', StringSplitOptions.RemoveEmptyEntries)[0];
        var eq = firstPair.IndexOf('=');
        if (eq <= 0)
            continue;

        paramName = Uri.UnescapeDataString(firstPair[..eq]);
        probeUrl = entry.Url;
        Log($"Discovered injection point from network log: GET {entry.Url} (param: {paramName})");
        break;
    }
}

if (probeUrl == null)
{
    probeUrl = url;
    paramName = "q";
    Log("No same-origin GET with query params in network log — using current URL with paramName 'q'.");
    Log("Tip: browse and trigger search/filter APIs first, then re-run.");
}

Assert.Section("WAF bypass techniques (SQLi probe)");
var result = await PrintWafBypassReport(
    url: probeUrl,
    paramName: paramName,
    category: "sqli",
    includeDetails: true);

if (!result.WafBlockDetected)
{
    Log("Note: No clear WAF block detected — try category xss/lfi, another param, or an explicit probePayload.");
}
else if (result.UsableBypasses.Count > 0)
{
    Log($"Usable bypasses ({result.UsableBypasses.Count}): {string.Join(", ", result.UsableBypasses)}");
    Log("Re-run targeted fuzz/SQLi scans using these transforms on the same injection point.");
}
