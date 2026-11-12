using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// A discovered endpoint with its HTTP status and metadata.
/// </summary>
public class DiscoveredEndpoint
{
    /// <summary>Absolute request URL that was probed.</summary>
    public string Url { get; init; } = "";

    public string Path { get; init; } = "";

    /// <summary>HTTP method used for the probe (currently always GET).</summary>
    public string Method { get; init; } = "GET";

    public int StatusCode { get; init; }
    public string? ContentType { get; init; }
    public string? Title { get; init; }
    public long? ContentLength { get; init; }
    /// <summary>Normalized redirect target (path and query) for 3xx responses, when a Location header is present.</summary>
    public string? RedirectLocation { get; init; }

    /// <summary>Selected response headers (e.g. Content-Type, Server).</summary>
    public Dictionary<string, string> ResponseHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Short excerpt of the response body (non-404 responses).</summary>
    public string? BodySnippet { get; init; }
}

/// <summary>
/// Fingerprint of the SPA shell response used to filter duplicate &quot;fake&quot; discoveries.
/// </summary>
public sealed class SpaShellFingerprint
{
    public string ProbePath { get; init; } = "";
    public int StatusCode { get; init; }
    /// <summary>Response Content-Type of the probe (e.g. text/html for SPA shells).</summary>
    public string? ContentType { get; init; }
    public string? Title { get; init; }
    public long BodyLength { get; init; }
    public string? RedirectLocation { get; init; }
    /// <summary>Body excerpt of the invalid-path probe. Used to spot identical API echoes; not a finding by itself.</summary>
    public string? BodySnippet { get; init; }
}

/// <summary>
/// Results from an endpoint discovery scan.
/// </summary>
public class DiscoverResult
{
    public string BaseUrl { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public int ScannedCount { get; init; }
    public List<DiscoveredEndpoint> Discovered { get; init; } = new();
    public int DiscoveredCount => Discovered.Count;
    /// <summary>Number of responses excluded because they matched the SPA shell / uniform-redirect fingerprint.</summary>
    public int SpaFilteredCount { get; init; }
    /// <summary>Number of 3xx responses excluded as uniform auth/IdP redirects (subset of <see cref="SpaFilteredCount"/> when baseline matched).</summary>
    public int AuthRedirectFilteredCount { get; init; }
    public SpaShellFingerprint? SpaBaseline { get; init; }
    /// <summary>True when SPA shell / soft-404 duplicates were eligible for exclusion. Default for API and scripting is true.</summary>
    public bool SpaMode { get; init; }
    /// <summary>
    /// Discovered responses that share the invalid-path baseline's status, API content type, and body.
    /// These stay in <see cref="Discovered"/>; <see cref="BaselineNote"/> warns when they dominate the list.
    /// </summary>
    public int ApiEchoCount { get; init; }
    /// <summary>Why some responses were excluded, or why kept responses still look like the invalid-path baseline.</summary>
    public string? BaselineNote { get; init; }
    /// <summary>Wordlist paths probed (same as <see cref="ScannedCount"/>).</summary>
    public int ProbeCount => ScannedCount;
    /// <summary>When <see cref="DiscoveredCount"/> is zero, explains why (SPA filter, errors, etc.).</summary>
    public string? ZeroResultReason { get; init; }

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Endpoint Discovery Scan ===");
        lines.Add($"Base URL: {BaseUrl}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Paths scanned: {ScannedCount}");
        lines.Add($"Discovered: {DiscoveredCount}");
        if (SpaFilteredCount > 0)
            lines.Add($"Filtered as SPA shell / uniform redirect: {SpaFilteredCount}" +
                      (AuthRedirectFilteredCount > 0 ? $" ({AuthRedirectFilteredCount} auth redirects)" : ""));
        if (!string.IsNullOrEmpty(BaselineNote))
            lines.Add(BaselineNote);
        lines.Add("");

        if (DiscoveredCount == 0)
        {
            lines.Add("No interesting endpoints discovered.");
            if (!string.IsNullOrEmpty(ZeroResultReason))
                lines.Add($"Reason: {ZeroResultReason}");
            lines.Add("===============================");
            return string.Join(Environment.NewLine, lines);
        }

        if (includeDetails)
        {
            var grouped = Discovered.GroupBy(d =>
            {
                if (d.StatusCode >= 200 && d.StatusCode < 300) return "Accessible (2xx)";
                if (d.StatusCode == 301 || d.StatusCode == 302) return "Redirects (3xx)";
                if (d.StatusCode == 403) return "Forbidden (403)";
                if (d.StatusCode == 401) return "Auth Required (401)";
                return $"Other ({d.StatusCode})";
            });

            foreach (var group in grouped.OrderBy(g => g.Key))
            {
                lines.Add($"--- {group.Key} ---");
                foreach (var d in group.OrderBy(d => d.Path))
                {
                    var info = d.ContentType != null ? $" [{d.ContentType}]" : "";
                    var title = d.Title != null ? $" \"{d.Title}\"" : "";
                    lines.Add($"  {d.StatusCode} {d.Path}{info}{title}");
                }
                lines.Add("");
            }
        }

        var accessible = Discovered.Count(d => d.StatusCode >= 200 && d.StatusCode < 300);
        var forbidden = Discovered.Count(d => d.StatusCode == 403);
        var authRequired = Discovered.Count(d => d.StatusCode == 401);

        if (accessible > 0)
            lines.Add($"ASSESSMENT: {accessible} accessible endpoint(s) found. Review for sensitive content or unintended exposure.");
        if (forbidden > 0)
            lines.Add($"  {forbidden} path(s) returned 403 Forbidden (exist but are protected).");
        if (authRequired > 0)
            lines.Add($"  {authRequired} path(s) returned 401 Unauthorized (exist but require authentication).");

        lines.Add("===============================");
        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// Scans for common hidden endpoints, admin panels, config files, and API documentation
/// by probing well-known paths. Uses HttpClient from the server side to avoid CORS
/// restrictions and captures cookies from the browser session for authenticated scanning.
/// </summary>
public class EndpointScanner
{
    private readonly AutomationContext _context;
    private static readonly HttpClient SharedClient = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(5)
    };

    /// <summary>Allowed difference in body byte length when comparing SPA shell responses.</summary>
    private const int SpaBodyLengthTolerance = 128;

    public EndpointScanner(AutomationContext context)
    {
        _context = context;
    }

    public async Task<DiscoverResult> RunAsync(string wordlistName = "common", string basePath = "/",
        int delayMs = 0, bool spaMode = true, string? spaProbePath = null)
    {
        var url = await _context.GetCurrentUrl();
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidOperationException("Cannot run endpoint scan: no valid URL loaded.");

        var baseUrl = $"{uri.Scheme}://{uri.Host}" +
                      (uri.IsDefaultPort ? "" : $":{uri.Port}");

        if (!basePath.StartsWith("/")) basePath = "/" + basePath;
        if (!basePath.EndsWith("/")) basePath += "/";
        if (basePath == "//") basePath = "/";

        // Always take an invalid-path baseline. Used for:
        // - spaMode (default): filter SPA shell / soft-404 duplicates (same status, title, similar body length)
        // - always: filter uniform auth redirects (Shibboleth/OIDC/SAML login bounce)
        // A normal site whose probe is HTTP 404 yields no baseline, so the filter is a no-op.
        SpaShellFingerprint? baseline = null;
        {
            var probeRelative = string.IsNullOrWhiteSpace(spaProbePath)
                ? $"{basePath.TrimEnd('/')}/__trowser_spa_probe__/{Guid.NewGuid():N}/"
                : (spaProbePath.StartsWith("/") ? spaProbePath : "/" + spaProbePath);
            if (!probeRelative.StartsWith("/")) probeRelative = "/" + probeRelative;

            var probeUrl = baseUrl + probeRelative;

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, probeUrl);
                request.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} Security Scanner");
                using var response = await SharedClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                var ep = await ParseDiscoveredAsync(response, probeRelative, probeUrl);
                if (ep != null)
                {
                    baseline = new SpaShellFingerprint
                    {
                        ProbePath = ep.Path,
                        StatusCode = ep.StatusCode,
                        ContentType = ep.ContentType,
                        Title = ep.Title,
                        BodyLength = ep.ContentLength ?? 0,
                        RedirectLocation = ep.RedirectLocation,
                        BodySnippet = ep.BodySnippet
                    };
                }
            }
            catch { /* probe failed — continue without baseline */ }
        }

        var paths = GetWordlist(wordlistName);
        var discovered = new List<DiscoveredEndpoint>();
        var scanned = 0;

        var concurrency = delayMs > 0 ? 1 : 10;
        var semaphore = new SemaphoreSlim(concurrency);
        var tasks = paths.Select(async path =>
        {
            await semaphore.WaitAsync();
            try
            {
                if (delayMs > 0)
                    await Task.Delay(delayMs);

                var fullPath = basePath == "/" ? path : basePath.TrimEnd('/') + path;
                var targetUrl = baseUrl + fullPath;
                Interlocked.Increment(ref scanned);

                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                    request.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} Security Scanner");

                    using var response = await SharedClient.SendAsync(request,
                        HttpCompletionOption.ResponseHeadersRead);

                    var ep = await ParseDiscoveredAsync(response, fullPath, targetUrl);
                    if (ep == null) return;

                    lock (discovered)
                    {
                        discovered.Add(ep);
                    }
                }
                catch { /* timeout or connection error -- skip */ }
            }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks);

        // Include interesting same-origin paths already observed as HTTP 200 in the network log
        // (e.g. /nginx.conf, /vendor browsed manually but not in the wordlist probe set).
        MergeObservedNetworkPaths(_context, baseUrl, uri.GetLeftPart(UriPartial.Authority), discovered, ref scanned);

        var raw = discovered.OrderBy(d => d.StatusCode).ThenBy(d => d.Path).ToList();
        var filtered = ApplyBaselineFilter(raw, baseline, spaMode);
        var zeroReason = BuildZeroResultReason(
            filtered.Kept.Count, scanned, filtered.SpaFilteredCount, spaMode || baseline != null, wordlistName);

        return new DiscoverResult
        {
            BaseUrl = baseUrl,
            Timestamp = DateTime.UtcNow,
            ScannedCount = scanned,
            Discovered = filtered.Kept,
            SpaFilteredCount = filtered.SpaFilteredCount,
            AuthRedirectFilteredCount = filtered.AuthRedirectFilteredCount,
            SpaBaseline = baseline,
            SpaMode = spaMode,
            ApiEchoCount = filtered.ApiEchoCount,
            BaselineNote = filtered.BaselineNote,
            ZeroResultReason = zeroReason
        };
    }

    internal sealed class BaselineFilterResult
    {
        public List<DiscoveredEndpoint> Kept { get; init; } = new();
        public int SpaFilteredCount { get; init; }
        public int AuthRedirectFilteredCount { get; init; }
        public int ApiEchoCount { get; init; }
        public string? BaselineNote { get; init; }
    }

    /// <summary>
    /// Drop HTML shell / soft-404 duplicates when <paramref name="spaMode"/> is set, always drop uniform
    /// auth redirects, and note API bodies that are byte-identical to the invalid-path baseline.
    /// </summary>
    internal static BaselineFilterResult ApplyBaselineFilter(
        IReadOnlyList<DiscoveredEndpoint> raw,
        SpaShellFingerprint? baseline,
        bool spaMode)
    {
        var kept = new List<DiscoveredEndpoint>();
        var spaFiltered = 0;
        var authRedirectFiltered = 0;
        var htmlShellFiltered = 0;
        var shellMatchesKept = 0;
        var apiEchoes = 0;

        foreach (var d in raw)
        {
            var htmlShell = baseline != null && MatchesSpaShell(baseline, d);
            var authRedirect = baseline != null && MatchesUniformAuthRedirect(baseline, d);

            if (spaMode && htmlShell)
            {
                spaFiltered++;
                htmlShellFiltered++;
                if (d.StatusCode is >= 300 and < 400)
                    authRedirectFiltered++;
                continue;
            }

            // Shibboleth/OIDC often 302 every unknown path to the IdP with unique SAMLRequest query params.
            if (authRedirect)
            {
                spaFiltered++;
                authRedirectFiltered++;
                continue;
            }

            if (htmlShell)
                shellMatchesKept++;

            if (baseline != null && MatchesApiBaselineEcho(baseline, d))
                apiEchoes++;

            kept.Add(d);
        }

        return new BaselineFilterResult
        {
            Kept = kept,
            SpaFilteredCount = spaFiltered,
            AuthRedirectFilteredCount = authRedirectFiltered,
            ApiEchoCount = apiEchoes,
            BaselineNote = BuildBaselineNote(spaMode, htmlShellFiltered, shellMatchesKept, apiEchoes, kept.Count)
        };
    }

    private static string? BuildBaselineNote(
        bool spaMode, int htmlShellFiltered, int shellMatchesKept, int apiEchoes, int discoveredCount)
    {
        var parts = new List<string>();
        if (spaMode && htmlShellFiltered > 0)
        {
            parts.Add(
                $"{htmlShellFiltered} response(s) matched the invalid-path baseline (same status, title, and body length within {SpaBodyLengthTolerance} bytes) and were excluded as SPA shell or soft-404 duplicates. " +
                "API-shaped responses (json, xml, text/plain) stay in discovered. Set spaMode to false to include the duplicates.");
        }
        else if (!spaMode && shellMatchesKept > 0)
        {
            parts.Add(
                $"{shellMatchesKept} discovered response(s) match the invalid-path baseline (same status, title, and similar body length) and are included because spaMode is false. " +
                "They are likely the site shell or a soft-404 echoed for each guessed path. Set spaMode to true (the default) to exclude them.");
        }

        if (apiEchoes >= 3 && discoveredCount > 0 && apiEchoes * 2 >= discoveredCount)
        {
            parts.Add(
                $"{apiEchoes} of {discoveredCount} discovered response(s) share the invalid-path baseline's status, content type, and body. " +
                "API-shaped bodies stay in discovered. Compare bodies before treating them as distinct endpoints.");
        }

        return parts.Count == 0 ? null : string.Join(" ", parts);
    }

    private static string? BuildZeroResultReason(
        int discoveredCount, int probeCount, int spaFiltered, bool spaMode, string wordlistName)
    {
        if (discoveredCount > 0)
            return null;

        if (probeCount == 0)
            return "No paths were probed (empty wordlist).";

        if (spaFiltered > 0 && spaFiltered >= probeCount - 1)
            return spaMode
                ? $"All {probeCount} probed paths matched the SPA shell fingerprint and were filtered (spaMode). Try spaMode: false or browse to trigger API routes."
                : $"All {probeCount} probed paths returned the same auth/redirect fingerprint and were filtered. Authenticate first, or inspect network log for real endpoints.";

        if (spaFiltered > 0)
            return spaMode
                ? $"No paths remained after SPA filtering ({spaFiltered} of {probeCount} responses looked like the shell). Non-shell responses may all be 404."
                : $"No paths remained after uniform-redirect filtering ({spaFiltered} of {probeCount} responses looked like the auth gate).";

        return $"No non-shell endpoints found for wordlist '{wordlistName}' ({probeCount} paths probed; typical 404 or uniform error responses).";
    }

    private static readonly string[] InterestingObservedPathTokens =
    [
        "nginx.conf", ".env", ".git", "web.config", "vendor", "vendors", "node_modules",
        "phpinfo", "swagger", "actuator", "admin", "backup", ".sql", "config", "server-status"
    ];

    /// <summary>
    /// Promote same-origin network log 2xx responses for sensitive-looking paths into discover results
    /// even when the wordlist did not probe them.
    /// </summary>
    private static void MergeObservedNetworkPaths(
        AutomationContext ctx,
        string baseUrl,
        string origin,
        List<DiscoveredEndpoint> discovered,
        ref int scanned)
    {
        var seen = new HashSet<string>(discovered.Select(d => d.Path), StringComparer.OrdinalIgnoreCase);
        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.StatusCode is < 200 or >= 300) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var u)) continue;
            if (!string.Equals(u.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            var path = u.AbsolutePath;
            if (string.IsNullOrEmpty(path) || path == "/") continue;
            if (!InterestingObservedPathTokens.Any(t => path.Contains(t, StringComparison.OrdinalIgnoreCase)))
                continue;
            if (!seen.Add(path)) continue;

            scanned++;
            lock (discovered)
            {
                discovered.Add(new DiscoveredEndpoint
                {
                    Url = entry.Url,
                    Path = path,
                    Method = entry.Method,
                    StatusCode = entry.StatusCode,
                    ContentType = entry.ContentType,
                    ContentLength = entry.ResponseBody?.Length,
                    BodySnippet = string.IsNullOrEmpty(entry.ResponseBody)
                        ? null
                        : entry.ResponseBody[..Math.Min(entry.ResponseBody.Length, 240)],
                    ResponseHeaders = new Dictionary<string, string>(entry.ResponseHeaders, StringComparer.OrdinalIgnoreCase)
                });
            }
        }
    }

    private static bool MatchesSpaShell(SpaShellFingerprint baseline, DiscoveredEndpoint d)
    {
        // Never treat real API payloads as SPA shell duplicates — even when the invalid-path baseline
        // is also JSON (common behind API gateways), JSON routes must stay visible in discovery.
        if (ResponseLooksLikeApiPayload(d))
            return false;

        if (d.StatusCode != baseline.StatusCode)
            return false;

        var t1 = baseline.Title ?? "";
        var t2 = d.Title ?? "";
        if (!string.Equals(t1, t2, StringComparison.Ordinal))
            return false;

        var len = d.ContentLength ?? 0;
        if (Math.Abs(len - baseline.BodyLength) > SpaBodyLengthTolerance)
            return false;

        // Uniform redirects (e.g. all 302 to the same login or IdP) look like SPA/auth routing.
        if (d.StatusCode is >= 300 and < 400)
            return RedirectFingerprintsMatch(baseline.RedirectLocation, d.RedirectLocation);

        return true;
    }

    /// <summary>
    /// True when an API-shaped response is the same status, content type family, length, and body excerpt
    /// as the invalid-path baseline. These stay in the result; they are only counted for a warning.
    /// </summary>
    private static bool MatchesApiBaselineEcho(SpaShellFingerprint baseline, DiscoveredEndpoint d)
    {
        if (!ResponseLooksLikeApiPayload(d) || !BaselineLooksLikeApi(baseline))
            return false;
        if (d.StatusCode != baseline.StatusCode)
            return false;
        if ((d.ContentLength ?? 0) != baseline.BodyLength)
            return false;
        return string.Equals(baseline.BodySnippet ?? "", d.BodySnippet ?? "", StringComparison.Ordinal);
    }

    private static bool BaselineLooksLikeApi(SpaShellFingerprint b)
    {
        var ct = b.ContentType ?? "";
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.Contains("application/xml", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// True when the probe is a 3xx to the same auth/IdP target as the invalid-path baseline.
    /// Query strings are ignored so SAMLRequest/RelayState/state/nonce variance does not create false hits.
    /// </summary>
    private static bool MatchesUniformAuthRedirect(SpaShellFingerprint baseline, DiscoveredEndpoint d)
    {
        if (baseline.StatusCode is < 300 or >= 400)
            return false;
        if (d.StatusCode is < 300 or >= 400)
            return false;
        if (d.StatusCode != baseline.StatusCode)
            return false;
        return RedirectFingerprintsMatch(baseline.RedirectLocation, d.RedirectLocation);
    }

    private static bool RedirectFingerprintsMatch(string? a, string? b)
    {
        var fa = FingerprintRedirectLocation(a);
        var fb = FingerprintRedirectLocation(b);
        if (fa.Length == 0 && fb.Length == 0)
            return true; // both missing Location — still a uniform redirect pattern
        if (fa.Length == 0 || fb.Length == 0)
            return false;
        return string.Equals(fa, fb, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Stable redirect identity: scheme://host/path (no query/fragment). Relative paths stay as path only.
    /// </summary>
    internal static string FingerprintRedirectLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location))
            return "";

        var raw = location.Trim();
        if (Uri.TryCreate(raw, UriKind.Absolute, out var abs))
            return $"{abs.Scheme}://{abs.Authority}{abs.AbsolutePath}";

        // Path-only or path+query from NormalizeLocation
        var q = raw.IndexOfAny(['?', '#']);
        return q >= 0 ? raw[..q] : raw;
    }

    private static bool BaselineLooksLikeHtmlShell(SpaShellFingerprint b)
    {
        var ct = b.ContentType ?? "";
        if (ct.Contains("text/html", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.Contains("application/xhtml", StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrEmpty(b.Title)) return true;
        return false;
    }

    private static bool ResponseLooksLikeApiPayload(DiscoveredEndpoint d)
    {
        var ct = d.ContentType ?? "";
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.Contains("application/xml", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase)) return true;
        if (ct.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static async Task<DiscoveredEndpoint?> ParseDiscoveredAsync(HttpResponseMessage response,
        string fullPath, string requestUrl)
    {
        var statusCode = (int)response.StatusCode;

        if (statusCode == 404)
            return null;

        var contentType = response.Content.Headers.ContentType?.MediaType;
        byte[] bodyBytes;
        try
        {
            bodyBytes = await response.Content.ReadAsByteArrayAsync();
        }
        catch
        {
            return null;
        }

        var actualLength = (long)bodyBytes.Length;
        var headerLength = response.Content.Headers.ContentLength;

        string? title = null;
        if (contentType != null && contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var body = Encoding.UTF8.GetString(bodyBytes);
                var match = Regex.Match(body, @"<title[^>]*>(.*?)</title>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);
                if (match.Success)
                    title = match.Groups[1].Value.Trim();
            }
            catch { /* ignore */ }
        }

        string? redirectLocation = null;
        if (statusCode is >= 300 and < 400)
            redirectLocation = NormalizeLocation(response, requestUrl);

        var headers = CollectInterestingResponseHeaders(response, contentType);
        var snippet = BuildBodySnippet(bodyBytes, contentType, 500);

        return new DiscoveredEndpoint
        {
            Url = requestUrl,
            Path = fullPath,
            Method = "GET",
            StatusCode = statusCode,
            ContentType = contentType,
            Title = title,
            ContentLength = headerLength ?? actualLength,
            RedirectLocation = redirectLocation,
            ResponseHeaders = headers,
            BodySnippet = snippet
        };
    }

    private static Dictionary<string, string> CollectInterestingResponseHeaders(
        HttpResponseMessage response, string? parsedContentType)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void add(string name, string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (headers.ContainsKey(name)) return;
            headers[name] = value.Trim();
        }

        foreach (var kv in response.Headers)
        {
            if (InterestingResponseHeaderNames.Contains(kv.Key))
            {
                add(kv.Key, kv.Value.FirstOrDefault());
            }
        }

        foreach (var kv in response.Content.Headers)
        {
            if (InterestingResponseHeaderNames.Contains(kv.Key))
                add(kv.Key, kv.Value.FirstOrDefault());
        }

        // Ensure Content-Type appears even if only parsed from ContentType object
        if (!string.IsNullOrEmpty(parsedContentType))
            add("Content-Type", parsedContentType);

        return headers;
    }

    private static readonly HashSet<string> InterestingResponseHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Type", "Server", "X-Powered-By", "X-Framework", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Via", "Cache-Control",
        "Content-Length", "Location"
    };

    private static string? BuildBodySnippet(byte[] bodyBytes, string? contentType, int maxLen)
    {
        if (bodyBytes.Length == 0) return null;

        const int readCap = 32_768;
        var cap = Math.Min(bodyBytes.Length, readCap);
        string s;
        try
        {
            s = Encoding.UTF8.GetString(bodyBytes, 0, cap);
        }
        catch
        {
            return null;
        }

        if (contentType != null &&
            (contentType.Contains("octet-stream", StringComparison.OrdinalIgnoreCase) ||
             contentType.Contains("image/", StringComparison.OrdinalIgnoreCase) ||
             contentType.Contains("font/", StringComparison.OrdinalIgnoreCase)))
        {
            return $"[{contentType} body, {bodyBytes.Length} bytes — snippet omitted]";
        }

        s = Regex.Replace(s, @"[\u0000-\u0008\u000B\u000C\u000E-\u001F]", " ");
        if (s.Length > maxLen)
            s = s[..maxLen] + "…";
        return s.Trim();
    }

    private static string? NormalizeLocation(HttpResponseMessage response, string requestUrl)
    {
        if (!response.Headers.TryGetValues("Location", out var values))
            return null;
        var raw = values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        if (string.IsNullOrEmpty(raw))
            return null;

        raw = raw.Trim();

        // Prefer absolute form so cross-origin IdP redirects keep host identity.
        if (Uri.TryCreate(raw, UriKind.Absolute, out var absDirect))
            return FingerprintRedirectLocation(absDirect.AbsoluteUri);

        if (Uri.TryCreate(requestUrl, UriKind.Absolute, out var baseUri)
            && Uri.TryCreate(baseUri, raw, out var absolute))
            return FingerprintRedirectLocation(absolute.AbsoluteUri);

        return FingerprintRedirectLocation(raw);
    }

    private static List<string> GetWordlist(string name) => name.ToLowerInvariant() switch
    {
        "full" => CommonPaths.Concat(ExtendedPaths).Concat(ApiPaths).Distinct().ToList(),
        "api" => ApiPaths.ToList(),
        _ => CommonPaths.ToList()
    };

    private static readonly string[] CommonPaths =
    [
        // Environment and secret files
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.staging",
        "/.env.bak",
        "/.env.backup",

        // Source control metadata
        "/.git/HEAD",
        "/.git/config",
        "/.gitignore",
        "/.svn/entries",

        // Server configuration
        "/.htaccess",
        "/.htpasswd",
        "/web.config",
        "/nginx.conf",
        "/nginx.conf.bak",
        "/crossdomain.xml",
        "/server-status",
        "/server-info",

        // Vendor / dependency trees (directory listing risk)
        "/vendor",
        "/vendor/",
        "/vendors",
        "/vendors/",
        "/node_modules",
        "/node_modules/",

        // Admin panels
        "/admin",
        "/admin/",
        "/administrator",
        "/wp-admin",
        "/wp-login.php",
        "/wp-config.php",
        "/wp-config.php.bak",
        "/xmlrpc.php",

        // Application config files
        "/config.json",
        "/config.yml",
        "/config.xml",
        "/config.php",
        "/package.json",
        "/composer.json",

        // CI/CD pipeline configs (supply-chain attack surface)
        "/.github/workflows/ci.yml",
        "/.gitlab-ci.yml",
        "/Jenkinsfile",

        // Server-side info disclosure
        "/phpinfo.php",
        "/info.php",

        // Debug and test endpoints
        "/test",
        "/test.html",
        "/debug",
        "/console",

        // Monitoring endpoints (may leak internals)
        "/status",
        "/health",
        "/healthcheck",
        "/metrics",
        "/prometheus",
        "/prometheus/metrics",

        // API documentation (OpenAPI / Swagger variants)
        "/swagger",
        "/swagger/",
        "/swagger-ui.html",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/api-docs/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api",
        "/api/",
        "/graphql",
        "/graphiql",
        "/dashboard",

        // File and data directories
        "/ftp",
        "/ftp/",

        // Admin / configuration APIs (framework-agnostic)
        "/rest/admin",
        "/admin/config",
        "/admin/configuration",
        "/application-configuration",
        "/management",
        "/management/health",
        "/management/info",
        "/internal",
        "/internal/metrics",

        // Database dumps
        "/backup",
        "/dump.sql",
        "/db.sql",
        "/database.sql",
        "/backup.sql",
    ];

    private static readonly string[] ExtendedPaths =
    [
        // OS / editor artifacts
        "/.DS_Store",
        "/.vscode/settings.json",

        // Container and CI/CD config
        "/.dockerenv",
        "/Dockerfile",
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/.github/",
        "/.gitlab-ci.yml",
        "/Jenkinsfile",

        // CMS directories
        "/wp-content/",
        "/wp-includes/",
        "/cgi-bin/",

        // Database management tools
        "/phpmyadmin",
        "/pma",
        "/adminer.php",

        // .NET diagnostic handlers
        "/elmah.axd",
        "/trace.axd",

        // Spring Boot Actuator
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/metrics",
        "/actuator/prometheus",
        "/actuator/info",

        // Cloud-native monitoring / observability (A09)
        "/health",
        "/healthcheck",
        "/healthz",
        "/ready",
        "/readyz",
        "/live",
        "/livez",
        "/metrics",
        "/prometheus",
        "/prometheus/metrics",
        "/grafana",
        "/grafana/",
        "/kibana",
        "/kibana/",
        "/jaeger",
        "/zipkin",
        "/alertmanager",
        "/status",
        "/_status",

        // Audit / logging endpoints (A09 discovery)
        "/actuator/loggers",
        "/api/AuditLogs",
        "/api/auditLogs",
        "/api/SecurityEvents",
        "/api/security/events",
        "/api/logs",
        "/api/audit",
        "/api/admin/logs",
        "/admin/audit",
        "/admin/logs",

        // Java management
        "/jolokia",
        "/jmx-console",
        "/manager/html",
        "/solr/",
        "/jenkins",

        // Go debug endpoints
        "/debug/pprof/",
        "/debug/vars",

        // Symfony / PHP profilers
        "/_profiler/",
        "/__profiler/",

        // Credentials and private keys
        "/.aws/credentials",
        "/.ssh/id_rsa",
        "/id_rsa",
        "/id_rsa.pub",
        "/server.key",
        "/privatekey.pem",
        "/credentials.json",
        "/secrets.json",
        "/.npmrc",

        // Application settings
        "/appsettings.json",
        "/appsettings.Development.json",
        "/configuration.php",
        "/application.properties",
        "/application.yml",

        // Debug / dev tools
        "/_debug",
        "/__debug__",
        "/debug/default/view",
        "/telescope",
        "/horizon",
        "/nova",
        "/filament",

        // Logs and temp directories
        "/log",
        "/logs",
        "/logs/",
        "/temp",
        "/tmp",

        // Upload directories
        "/upload",
        "/uploads",
        "/files",

        // Backups and old files
        "/old",
        "/bak",
        "/backup.zip",
        "/backup.tar.gz",
        "/site.tar.gz",
        "/www.zip",
        "/backup.sql",
        "/db.sqlite3",
        "/database.sqlite",

        // Build tool and dependency files (reveal technology stack)
        "/Makefile",
        "/Gruntfile.js",
        "/gulpfile.js",
        "/webpack.config.js",
        "/tsconfig.json",
        "/yarn.lock",
        "/package-lock.json",
        "/Gemfile",
        "/Gemfile.lock",
        "/requirements.txt",
        "/Pipfile",
        "/go.mod",
        "/go.sum",
        "/Cargo.toml",
    ];

    private static readonly string[] ApiPaths =
    [
        // REST API roots
        "/api",
        "/api/",
        "/api/v1",
        "/api/v1/",
        "/api/v2",
        "/api/v2/",
        "/api/v3",
        "/_api",
        "/_api/",
        "/rest",
        "/rest/",
        "/jsonapi",
        "/odata",
        "/odata/",
        "/v1",
        "/v2",
        "/v3",

        // API info and monitoring
        "/api/health",
        "/api/healthcheck",
        "/api/status",
        "/api/info",
        "/api/version",
        "/api/config",
        "/api/debug",
        "/api/metrics",
        "/api/prometheus",
        "/api/prometheus/metrics",

        // Auth and user endpoints
        "/api/users",
        "/api/Users",
        "/api/user",
        "/api/orders",
        "/api/auth",
        "/api/login",
        "/api/logout",
        "/api/register",
        "/api/token",
        "/api/tokens",
        "/api/admin",
        "/api/admin/configuration",
        "/rest/admin",

        // Audit / security event APIs (A09)
        "/api/AuditLogs",
        "/api/auditLogs",
        "/api/SecurityEvents",
        "/api/security/events",
        "/api/logs",
        "/api/audit",
        "/api/admin/logs",
        "/admin/audit",

        // API documentation
        "/api/docs",
        "/api/swagger.json",
        "/api/swagger/json",
        "/api/openapi.json",
        "/api/openapi.yaml",
        "/swagger",
        "/swagger/",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/swagger-resources",
        "/api-docs",
        "/api-docs/",
        "/redoc",
        "/docs",
        "/docs/",
        "/openapi",
        "/openapi.json",
        "/openapi.yaml",

        // GraphQL
        "/graphql",
        "/graphiql",
        "/playground",
        "/api/graphql",

        // OAuth / OpenID discovery
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/oauth/authorize",
        "/oauth/token",
        "/connect/token",
        "/connect/authorize",

        // CMS-specific APIs
        "/wp-json",
        "/wp-json/wp/v2/users",
    ];
}
