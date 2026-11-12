using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Cookie-isolated HTTP for security probes (JWT acceptance, REST scaffold, path-filter bypass).
/// </summary>
public static class SecurityProbeHttp
{
    public sealed class FetchResult
    {
        public int Status { get; init; }
        public string Body { get; init; } = "";
        public bool Redirected { get; init; }
        public string? FinalUrl { get; init; }
        public IReadOnlyDictionary<string, string> ResponseHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class TimedFetchResult
    {
        public FetchResult Result { get; init; } = new();
        public double ElapsedSeconds { get; init; }
    }

    public static async Task<TimedFetchResult> FetchTimedAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies = false,
        CancellationToken ct = default,
        bool allowSessionTerminationUrls = false)
    {
        var sw = Stopwatch.StartNew();
        var result = await FetchAsync(ctx, url, method, headers, body, timeoutMs, includeBrowserCookies, ct, allowSessionTerminationUrls);
        return new TimedFetchResult { Result = result, ElapsedSeconds = sw.Elapsed.TotalSeconds };
    }

    public static async Task<TimedFetchResult> FetchTimedRawAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        byte[]? bodyBytes,
        int timeoutMs,
        bool includeBrowserCookies = false,
        CancellationToken ct = default,
        bool allowSessionTerminationUrls = false)
    {
        var sw = Stopwatch.StartNew();
        var result = await FetchRawAsync(ctx, url, method, headers, bodyBytes, timeoutMs, includeBrowserCookies, ct, allowSessionTerminationUrls);
        return new TimedFetchResult { Result = result, ElapsedSeconds = sw.Elapsed.TotalSeconds };
    }

    public static async Task<FetchResult> FetchRawAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        byte[]? bodyBytes,
        int timeoutMs,
        bool includeBrowserCookies = false,
        CancellationToken ct = default,
        bool allowSessionTerminationUrls = false)
    {
        if (bodyBytes != null)
            return await FetchRawViaHttpClientAsync(ctx, url, method, headers, bodyBytes, timeoutMs, includeBrowserCookies, ct);

        return await FetchAsync(ctx, url, method, headers, null, timeoutMs, includeBrowserCookies, ct, allowSessionTerminationUrls);
    }

    public static async Task<FetchResult> FetchAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies = false,
        CancellationToken ct = default,
        bool allowSessionTerminationUrls = false)
    {
        if (!allowSessionTerminationUrls && SecurityUrlPolicy.BlockSecurityProbeRequest(url))
        {
            return new FetchResult
            {
                Status = 0,
                Body = "",
                FinalUrl = url,
                Redirected = false
            };
        }

        var mockResult = TryFromActiveTabMock(ctx, url, method);
        if (mockResult != null)
            return mockResult;

        if (RequiresBrowserFetch(url))
            return await FetchViaBrowserAsync(ctx, url, method, headers, body, timeoutMs, ct);

        try
        {
            return await FetchViaHttpClientAsync(ctx, url, method, headers, body, timeoutMs, includeBrowserCookies, ct);
        }
        catch (Exception) when (RequiresBrowserFetch(url) || UrlMayBreakHttpClient(url))
        {
            return await FetchViaBrowserAsync(ctx, url, method, headers, body, timeoutMs, ct);
        }
    }

    /// <summary>WebView mock rules (offline regression, attacker-origin fixtures) — no real DNS/TCP.</summary>
    private static FetchResult? TryFromActiveTabMock(AutomationContext ctx, string url, string method)
    {
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var mock = ctx.FindMatchingMock(url, method);
        if (mock == null && !method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            mock = ctx.FindMatchingMock(url, "HEAD");
        if (mock == null) return null;

        var body = mock.Body ?? "";
        var respHeaders = new Dictionary<string, string>(mock.Headers, StringComparer.OrdinalIgnoreCase);
        return new FetchResult
        {
            Status = mock.StatusCode,
            Body = body,
            FinalUrl = url,
            Redirected = false,
            ResponseHeaders = respHeaders
        };
    }

    private static bool RequiresBrowserFetch(string url) =>
        url.Contains("%00", StringComparison.OrdinalIgnoreCase)
        || url.Contains("%2500", StringComparison.OrdinalIgnoreCase)
        || url.Contains('\0');

    private static bool UrlMayBreakHttpClient(string url) =>
        url.Contains("%00", StringComparison.OrdinalIgnoreCase)
        || url.Contains("%2500", StringComparison.OrdinalIgnoreCase);

    private static async Task<FetchResult> FetchRawViaHttpClientAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        byte[]? bodyBytes,
        int timeoutMs,
        bool includeBrowserCookies,
        CancellationToken ct)
    {
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(Math.Max(timeoutMs, 1000)) };

        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        req.Headers.TryAddWithoutValidation("User-Agent", "Trowser-Probe/1.0");
        req.Headers.TryAddWithoutValidation(ScannerTrafficExclusion.InitiatorHeaderName, ScannerTrafficExclusion.InitiatorHeaderValue);

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    continue;
                req.Headers.TryAddWithoutValidation(kv.Key, CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value));
            }
        }

        if (includeBrowserCookies)
        {
            var cookieHeader = await ctx.GetCookieHeaderForUrl(url);
            if (!string.IsNullOrWhiteSpace(cookieHeader))
                req.Headers.TryAddWithoutValidation("Cookie", CookieHeaderSanitizer.SanitizeCookieHeader(cookieHeader));
        }

        if (bodyBytes != null)
        {
            req.Content = new ByteArrayContent(bodyBytes);
            string? contentType = null;
            var hasContentType = headers != null && headers.TryGetValue("Content-Type", out contentType);
            if (!(hasContentType && RequestContentBuilder.IsExplicitlyEmpty(contentType)))
            {
                if (!hasContentType || string.IsNullOrWhiteSpace(contentType))
                    contentType = "application/octet-stream";
                req.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }
        }

        var bodyTrace = bodyBytes != null ? $"[{bodyBytes.Length} bytes binary]" : null;
        var sw = Stopwatch.StartNew();
        int status = 0;
        string? traceError = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            status = (int)resp.StatusCode;
            var text = await ReadBodySafeAsync(resp, ct);
            var respHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in resp.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);
            foreach (var h in resp.Content.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);

            return new FetchResult
            {
                Status = (int)resp.StatusCode,
                Body = text,
                Redirected = resp.RequestMessage?.RequestUri?.ToString() != url,
                FinalUrl = resp.RequestMessage?.RequestUri?.ToString(),
                ResponseHeaders = respHeaders
            };
        }
        catch (Exception ex)
        {
            traceError = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            ctx.RecordOutboundRequest(method, url, bodyTrace, status, sw.ElapsedMilliseconds, traceError, "httpclient");
        }
    }

    private static async Task<FetchResult> FetchViaHttpClientAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies,
        CancellationToken ct)
    {
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(Math.Max(timeoutMs, 1000)) };

        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        req.Headers.TryAddWithoutValidation("User-Agent", "Trowser-Probe/1.0");
        req.Headers.TryAddWithoutValidation(ScannerTrafficExclusion.InitiatorHeaderName, ScannerTrafficExclusion.InitiatorHeaderValue);

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    continue;
                req.Headers.TryAddWithoutValidation(kv.Key, CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value));
            }
        }

        if (includeBrowserCookies)
        {
            var cookieHeader = await ctx.GetCookieHeaderForUrl(url);
            if (!string.IsNullOrWhiteSpace(cookieHeader))
                req.Headers.TryAddWithoutValidation("Cookie", CookieHeaderSanitizer.SanitizeCookieHeader(cookieHeader));
        }

        if (body != null)
        {
            string? contentType = null;
            var hasContentType = headers != null && headers.TryGetValue("Content-Type", out contentType);
            var trimmed = body.TrimStart();
            var fallback = trimmed.StartsWith('{') || trimmed.StartsWith('[')
                ? "application/json"
                : "application/x-www-form-urlencoded";
            req.Content = RequestContentBuilder.FromText(body, hasContentType ? contentType : null, fallback);
        }

        var sw = Stopwatch.StartNew();
        int status = 0;
        string? traceError = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            status = (int)resp.StatusCode;
            var text = await ReadBodySafeAsync(resp, ct);
            var respHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in resp.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);
            foreach (var h in resp.Content.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);

            return new FetchResult
            {
                Status = (int)resp.StatusCode,
                Body = text,
                Redirected = resp.RequestMessage?.RequestUri?.ToString() != url,
                FinalUrl = resp.RequestMessage?.RequestUri?.ToString(),
                ResponseHeaders = respHeaders
            };
        }
        catch (Exception ex)
        {
            traceError = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            ctx.RecordOutboundRequest(method, url, body, status, sw.ElapsedMilliseconds, traceError, "httpclient");
        }
    }

    private static async Task<FetchResult> FetchViaBrowserAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var headerDict = headers != null
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : null;

        var raw = await ctx.Fetch(url, method, headerDict, body, timeoutMs);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        var status = root.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
        var responseBody = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        var finalUrl = root.TryGetProperty("url", out var u) ? u.GetString() : url;
        var redirected = root.TryGetProperty("redirected", out var rd) && rd.ValueKind == JsonValueKind.True;

        var respHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("headers", out var hEl) && hEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in hEl.EnumerateObject())
                respHeaders[p.Name] = p.Value.GetString() ?? "";
        }

        return new FetchResult
        {
            Status = status,
            Body = responseBody,
            Redirected = redirected,
            FinalUrl = finalUrl,
            ResponseHeaders = respHeaders
        };
    }

    private static async Task<string> ReadBodySafeAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        try
        {
            var text = await ReadBodyCappedAsync(resp, 512_000, ct);
            return TextEncodingFix.FixMojibake(text) ?? text;
        }
        catch
        {
            return "";
        }
    }

    /// <summary>
    /// Reads at most <paramref name="maxChars"/> characters of the response body (appending
    /// <c>...(truncated)</c> when cut), so a hostile or huge response cannot exhaust memory.
    /// </summary>
    internal static async Task<string> ReadBodyCappedAsync(HttpResponseMessage resp, int maxChars, CancellationToken ct = default)
    {
        var encoding = Encoding.UTF8;
        var charset = resp.Content.Headers.ContentType?.CharSet?.Trim('"');
        if (!string.IsNullOrEmpty(charset))
        {
            try { encoding = Encoding.GetEncoding(charset); }
            catch (ArgumentException) { /* unknown charset: keep UTF-8 */ }
        }

        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
        var sb = new StringBuilder();
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer, ct)) > 0)
        {
            sb.Append(buffer, 0, read);
            if (sb.Length >= maxChars)
            {
                sb.Length = maxChars;
                sb.Append("...(truncated)");
                break;
            }
        }
        return sb.ToString();
    }

    public static string ReadBodySafe(string text) => TextEncodingFix.FixMojibake(text) ?? text;

    public static string? GetResponseHeader(FetchResult result, string name)
    {
        foreach (var kv in result.ResponseHeaders)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }

        return null;
    }
}
