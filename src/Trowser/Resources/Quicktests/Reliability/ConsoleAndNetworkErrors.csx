// @title Console And Network Errors
// @shadow light
// @effects none
// Session log review: console errors/warnings, HTTP failures, and investigation
// hints from captured traffic (uncommon status codes, large responses, domains).
// Browse the app first so the network and console logs are populated.

const long LargeResponseBytes = 1_048_576; // 1 MiB -- edit if you want a different bar

// Common status codes for normal browsing and APIs. Anything else is reported
// as uncommon (investigation, not a hard failure). 4xx/5xx that ARE listed here
// still fail the HTTP-errors assert below; this list only controls the "weird code" check.
//
// Intentionally omitted (will warn): 0, 100, 103, 203, 205, 207, 208, 226, 300, 305,
// 402, 406, 407, 408, 409 (conflict / lost update), 410 (gone), 411, 413, 414,
// 415 (unsupported media type), 416-418, 419 (Laravel CSRF), 421, 423-428, 431,
// 451, 499 (nginx), 501, 505-511, 520-530 (Cloudflare), other vendor codes.
// 100 is omitted on purpose: browsers record the *final* status, so a captured
// 100 is an anomaly (not the common on-the-wire Continue handshake).
var commonStatusCodes = new HashSet<int>
{
    101, // WebSocket / protocol upgrade -- expected success, like 200 for HTTP
    200, 201, 202, 204, 206,
    301, 302, 303, 304, 307, 308,
    400, 401, 403, 404, 405, 412, 422, 429,
    500, 502, 503, 504,
};

string TruncUrl(string url, int max = 80) =>
    url.Length > max ? url[..(max - 3)] + "..." : url;

string FormatSize(long bytes) =>
    bytes >= 1_048_576 ? $"{bytes / 1_048_576.0:F1} MB"
    : bytes >= 1024 ? $"{bytes / 1024.0:F1} KB"
    : $"{bytes} B";

bool IsFirstPartyHost(string host, string pageHost)
{
    if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(pageHost))
        return false;
    if (host.Equals(pageHost, StringComparison.OrdinalIgnoreCase))
        return true;
    return host.EndsWith("." + pageHost, StringComparison.OrdinalIgnoreCase);
}

// --- Console ---

Assert.Section("Console");

var errors = GetConsoleErrors();
var warnings = GetConsoleLog().Where(e => e.Level == ConsoleLevel.Warning).ToList();
var all = GetConsoleLog();

Log($"Console Summary");
Log($"  Total messages: {all.Count}");
Log($"  Errors: {errors.Count}");
Log($"  Warnings: {warnings.Count}");
Log("");

if (errors.Count > 0)
{
    Log("ERRORS:");
    foreach (var e in errors)
        Log($"  {e.Message}");
    Log("");
}

if (warnings.Count > 0)
{
    Log("WARNINGS:");
    foreach (var w in warnings)
        Log($"  {w.Message}");
    Log("");
}

Assert.Equal(0, errors.Count, "No console errors");

// --- HTTP errors ---

Assert.Section("HTTP errors");

var pageUrl = await GetCurrentUrl();
var title = await GetTitle();
Log($"Network error check: {title}");
Log("");

var httpErrors = Network.FindErrors();
var allRequests = GetNetworkLog();
var appRequests = allRequests.Where(r => !r.IsTrowserGenerated).ToList();
var skippedSynthetic = allRequests.Count - appRequests.Count;

Log($"Network Summary");
Log($"  Total requests: {allRequests.Count}");
if (skippedSynthetic > 0)
    Log($"  Trowser-generated (excluded from investigation checks): {skippedSynthetic}");
Log($"  Failed requests: {httpErrors.Count}");
Log("");

if (httpErrors.Count > 0)
{
    Log("FAILED REQUESTS:");
    foreach (var req in httpErrors)
        Log($"  {req.Method} {req.StatusCode} {TruncUrl(req.Url)}");
    Log("");
}

var serverErrors = allRequests.Where(r => r.StatusCode >= 500).ToList();
var notFound = allRequests.Where(r => r.StatusCode == 404).ToList();

if (notFound.Count > 0)
    Log($"  404 Not Found: {notFound.Count} request(s)");
if (serverErrors.Count > 0)
    Log($"  5xx Server errors: {serverErrors.Count} request(s)");

Assert.Equal(0, httpErrors.Count, "No HTTP errors");

// --- Uncommon status codes ---

Assert.Section("Uncommon status codes");

var uncommon = appRequests
    .Where(r => !commonStatusCodes.Contains(r.StatusCode))
    .ToList();

if (uncommon.Count == 0)
{
    Log("No uncommon HTTP status codes in session traffic.");
    Log($"Whitelisted: {string.Join(", ", commonStatusCodes.OrderBy(c => c))}.");
}
else
{
    var byCode = uncommon
        .GroupBy(r => r.StatusCode)
        .OrderBy(g => g.Key)
        .ToList();

    Log($"Uncommon status codes: {byCode.Count} distinct ({uncommon.Count} request(s)).");
    Log($"Not in whitelist ({string.Join(", ", commonStatusCodes.OrderBy(c => c))}).");
    Log("");

    foreach (var g in byCode)
    {
        var reason = g.Select(x => x.ReasonPhrase).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s)) ?? "";
        var reasonBit = string.IsNullOrEmpty(reason) ? "" : $" {reason}";
        Log($"  {g.Key}{reasonBit}  ({g.Count()} request(s))");
        foreach (var req in g.Take(5))
            Log($"    {req.Method} {TruncUrl(req.Url, 90)}");
        if (g.Count() > 5)
            Log($"    ... and {g.Count() - 5} more");
    }
}

Log("");

// --- Large responses ---

Assert.Section("Large responses");

var large = appRequests
    .Select(r => (Entry: r, Size: r.ContentLengthBytes))
    .Where(x => x.Size is >= LargeResponseBytes)
    .OrderByDescending(x => x.Size)
    .ToList();

var unsized = appRequests.Count(r => r.ContentLengthBytes == null);

if (large.Count == 0)
{
    Log($"No responses larger than {FormatSize(LargeResponseBytes)} (Content-Length).");
}
else
{
    Log($"Responses larger than {FormatSize(LargeResponseBytes)}: {large.Count}");
    Log("  (Images/media often exceed this legitimately; large Document/Fetch/XHR/Script is more interesting.)");
    Log("");
    Log($"  {"Size",10}  {"Type",-12}  Request");
    Log($"  {"----",10}  {"----",-12}  -------");

    const int maxLarge = 25;
    foreach (var x in large.Take(maxLarge))
        Log($"  {FormatSize(x.Size!.Value),10}  {x.Entry.ResourceType,-12}  {x.Entry.Method} {TruncUrl(x.Entry.Url, 90)}");

    if (large.Count > maxLarge)
        Log($"  ... and {large.Count - maxLarge} more");
}

if (unsized > 0)
    Log($"  {unsized} response(s) had no Content-Length (chunked/HTTP2 -- not sized).");

Log("");

// --- Domains ---

Assert.Section("Domains");

var pageHost = Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri) ? pageUri.Host : "";
var domainGroups = appRequests
    .Select(r => string.IsNullOrEmpty(r.Host) ? "(no host)" : r.Host)
    .GroupBy(h => h, StringComparer.OrdinalIgnoreCase)
    .OrderByDescending(g => g.Count())
    .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
    .ToList();

if (domainGroups.Count == 0)
{
    Log("No request hosts in session traffic.");
}
else
{
    var thirdParty = domainGroups.Count(g => g.Key != "(no host)" && !IsFirstPartyHost(g.Key, pageHost));
    Log($"Hosts contacted: {domainGroups.Count} ({thirdParty} third-party vs current page host '{pageHost}').");
    Log("  First-party = this host or a subdomain of it. Review third-party for trackers, CDNs, unexpected APIs.");
    Log("");
    Log($"  {"Reqs",6}  {"Party",-7}  Host");
    Log($"  {"----",6}  {"-----",-7}  ----");

    foreach (var g in domainGroups)
    {
        var party = g.Key == "(no host)" || string.IsNullOrEmpty(pageHost)
            ? "n/a"
            : IsFirstPartyHost(g.Key, pageHost) ? "first" : "third";
        Log($"  {g.Count(),6}  {party,-7}  {g.Key}");
    }
}

Log("");
Log($"Investigation summary: {uncommon.Select(r => r.StatusCode).Distinct().Count()} uncommon status code(s), {large.Count} large response(s), {domainGroups.Count} host(s).");
