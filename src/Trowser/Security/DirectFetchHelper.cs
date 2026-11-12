using System.Net.Http;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Server-side HTTP fetch using the browser cookie jar (includes HttpOnly).
/// Shared by authz comparison, REST /api/fetch-direct, and peer testing.
/// </summary>
public static class DirectFetchHelper
{
    private const int MaxRedirectHops = 20;
    private const int MaxBodyChars = 10_000_000;

    public sealed class DirectFetchResult
    {
        public bool Ok { get; init; }
        public int Status { get; init; }
        public string StatusText { get; init; } = "";
        public string Body { get; init; } = "";
        public bool Redirected { get; init; }
        public string? FinalUrl { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Error { get; init; }
        /// <summary>Cookie names sent on the final request hop (values never included).</summary>
        public List<string> CookiesSent { get; init; } = [];
        public bool IncludedBrowserCookies { get; init; }
        /// <summary>URL passed to the WebView2 cookie manager for the final hop.</summary>
        public string? CookieSourceUrl { get; init; }
        /// <summary>Scopes for cookies on the final hop (names only, with domain/path).</summary>
        public IReadOnlyList<BrowserCookieScope> CookieScopes { get; init; } = [];
        public string Transport { get; init; } = "httpclient";
    }

    /// <summary>
    /// Cookie precedence:
    /// <list type="bullet">
    /// <item><c>includeBrowserCookies: false</c> — only caller-supplied <c>Cookie</c> / <c>Authorization</c> (no jar).</item>
    /// <item><c>includeBrowserCookies: true</c> (default) — browser jar, then overlay caller <c>Cookie</c>
    /// on the first hop only (same-name cookies from the caller win). Caller <c>Cookie</c> is not replayed across redirect hops.</item>
    /// </list>
    /// </summary>
    public static async Task<DirectFetchResult> FetchAsync(
        AutomationContext context,
        string url,
        string method,
        Dictionary<string, string>? headers = null,
        string? body = null,
        int timeoutMs = 30000,
        bool allowAutoRedirect = true,
        bool includeBrowserCookies = true)
    {
        if (string.IsNullOrWhiteSpace(url))
            return new DirectFetchResult { Error = "URL is required." };

        var resolvedStart = await context.ResolveFetchUrlAsync(url);
        if (string.IsNullOrEmpty(resolvedStart))
            return new DirectFetchResult { Error = "Invalid or unresolvable url (relative urls require a loaded page)." };

        try
        {
            string? callerCookie = null;
            if (headers != null)
            {
                foreach (var kv in headers)
                {
                    if (kv.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                    {
                        callerCookie = kv.Value;
                        break;
                    }
                }
            }

            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = System.Net.DecompressionMethods.All,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(timeoutMs)
            };

            var currentUrl = resolvedStart;
            var currentMethod = method.Trim().ToUpperInvariant();
            string? currentBody = body;
            var hop = 0;
            string? lastCookieHeader = null;
            BrowserCookieSnapshot lastSnapshot = new("", resolvedStart, []);
            HttpResponseMessage? resp = null;

            while (hop++ <= MaxRedirectHops)
            {
                lastSnapshot = includeBrowserCookies
                    ? await context.GetBrowserCookieSnapshotForUrl(currentUrl)
                    : new BrowserCookieSnapshot("", currentUrl, []);

                var finalCookie = hop == 1
                    ? (includeBrowserCookies
                        ? CookieHeaderSanitizer.MergeCookieHeaders(lastSnapshot.Header, callerCookie)
                        : callerCookie)
                    : (includeBrowserCookies ? lastSnapshot.Header : null);

                lastCookieHeader = finalCookie;

                var hopHeaders = hop == 1 || IsSameOrigin(currentUrl, resolvedStart)
                    ? headers
                    : WithoutCredentialHeaders(headers);
                using var msg = BuildRequest(currentUrl, currentMethod, hopHeaders, currentBody, finalCookie);
                resp?.Dispose();
                resp = await client.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead);

                if (!allowAutoRedirect || !IsRedirectStatus((int)resp.StatusCode))
                    break;

                if (!resp.Headers.TryGetValues("Location", out var locations))
                    break;

                var location = locations.FirstOrDefault();
                if (string.IsNullOrWhiteSpace(location))
                    break;

                if (!TryResolveRedirectTarget(currentUrl, location, out var nextUrl))
                    break;

                currentUrl = nextUrl;
                if ((int)resp.StatusCode is not (307 or 308))
                {
                    currentMethod = "GET";
                    currentBody = null;
                }
            }

            if (resp == null)
                return new DirectFetchResult { Error = "No response received." };

            if (hop > MaxRedirectHops)
            {
                resp.Dispose();
                return new DirectFetchResult { Error = $"Too many redirects (>{MaxRedirectHops})." };
            }

            using (resp)
            {
                var respBody = await SecurityProbeHttp.ReadBodyCappedAsync(resp, MaxBodyChars);

                var respHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var h in resp.Headers)
                    respHeaders[h.Key] = string.Join(", ", h.Value);
                foreach (var h in resp.Content.Headers)
                    respHeaders[h.Key] = string.Join(", ", h.Value);

                var finalUrl = resp.RequestMessage?.RequestUri?.ToString() ?? currentUrl;
                var redirected = !string.Equals(finalUrl, resolvedStart, StringComparison.OrdinalIgnoreCase);

                return new DirectFetchResult
                {
                    Ok = resp.IsSuccessStatusCode,
                    Status = (int)resp.StatusCode,
                    StatusText = resp.ReasonPhrase ?? "",
                    Body = respBody,
                    Redirected = redirected,
                    FinalUrl = finalUrl,
                    Headers = respHeaders,
                    CookiesSent = CookieHeaderSanitizer.CookieNames(lastCookieHeader),
                    IncludedBrowserCookies = includeBrowserCookies,
                    CookieSourceUrl = lastSnapshot.CookieSourceUrl,
                    CookieScopes = lastSnapshot.Scopes,
                    Transport = "httpclient"
                };
            }
        }
        catch (TaskCanceledException)
        {
            return new DirectFetchResult { Error = $"Request timed out after {timeoutMs}ms." };
        }
        catch (Exception ex)
        {
            return new DirectFetchResult { Error = ex.Message };
        }
    }

    private static HttpRequestMessage BuildRequest(
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        string? cookieHeader)
    {
        var msg = new HttpRequestMessage(new HttpMethod(method), url);

        if (!string.IsNullOrEmpty(cookieHeader))
            msg.Headers.TryAddWithoutValidation("Cookie",
                CookieHeaderSanitizer.SanitizeCookieHeader(cookieHeader));

        if (body != null
            && !method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            && !method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
        {
            string? contentType = null;
            var hasContentType = headers != null && headers.TryGetValue("Content-Type", out contentType);
            msg.Content = RequestContentBuilder.FromText(body, hasContentType ? contentType : null, "text/plain");
        }

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (kv.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!msg.Headers.TryAddWithoutValidation(kv.Key,
                        CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value)))
                {
                    msg.Content?.Headers.TryAddWithoutValidation(kv.Key,
                        CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value));
                }
            }
        }

        return msg;
    }

    private static bool IsRedirectStatus(int status) => status is >= 300 and < 400;

    internal static bool IsSameOrigin(string a, string b) =>
        Uri.TryCreate(a, UriKind.Absolute, out var ua)
        && Uri.TryCreate(b, UriKind.Absolute, out var ub)
        && string.Equals(ua.Scheme, ub.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(ua.IdnHost, ub.IdnHost, StringComparison.OrdinalIgnoreCase)
        && ua.Port == ub.Port;

    /// <summary>
    /// Caller headers to replay after a cross-origin redirect: drops Authorization and anything that
    /// looks like a credential, so a redirect cannot forward the tester's tokens to another host.
    /// </summary>
    internal static Dictionary<string, string>? WithoutCredentialHeaders(Dictionary<string, string>? headers)
    {
        if (headers == null) return null;
        var kept = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
        {
            if (IsCredentialHeader(kv.Key)) continue;
            kept[kv.Key] = kv.Value;
        }
        return kept;
    }

    internal static bool IsCredentialHeader(string name)
    {
        var n = name.ToLowerInvariant();
        return n is "authorization" or "proxy-authorization" or "cookie"
               || n.Contains("token") || n.Contains("api-key") || n.Contains("apikey")
               || n.Contains("secret") || n.Contains("session") || n.Contains("auth")
               || n.Contains("csrf") || n.Contains("xsrf");
    }

    private static bool TryResolveRedirectTarget(string currentUrl, string location, out string absolute)
    {
        absolute = "";
        if (Uri.TryCreate(location, UriKind.Absolute, out var abs)
            && (abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps))
        {
            absolute = abs.ToString();
            return true;
        }

        if (!Uri.TryCreate(currentUrl, UriKind.Absolute, out var baseUri))
            return false;
        if (!Uri.TryCreate(baseUri, location, out var resolved))
            return false;
        if (resolved.Scheme != Uri.UriSchemeHttp && resolved.Scheme != Uri.UriSchemeHttps)
            return false;

        absolute = resolved.ToString();
        return true;
    }
}
