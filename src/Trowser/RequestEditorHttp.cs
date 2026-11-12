using System.Net;
using System.Net.Http;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Shared request-assembly helpers for the HTTP Request Editor (and similar tamper UIs).
/// HttpClient silently drops many headers unless they are applied to the correct collection.
/// </summary>
internal static class RequestEditorHttp
{
    private static readonly HashSet<string> ManagedByHttpClient = new(StringComparer.OrdinalIgnoreCase)
    {
        "Content-Length",
        "Transfer-Encoding"
    };

    private static readonly HashSet<string> BrowserOwnedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Connection", "Content-Length", "Transfer-Encoding",
        "Cookie", "Cookie2", "Keep-Alive", "Upgrade", "Proxy-Connection",
        "Accept-Encoding"
    };

    /// <summary>
    /// Headers safe to overlay on a WebView2 document navigation. Chromium-owned
    /// names (Host, Cookie, Connection, …) can abort the load if SetHeader succeeds.
    /// </summary>
    public static Dictionary<string, string> ForBrowserNavigation(Dictionary<string, string> headers)
    {
        var filtered = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
        {
            if (string.IsNullOrWhiteSpace(kv.Key) || kv.Key.StartsWith(':'))
                continue;
            if (BrowserOwnedHeaders.Contains(kv.Key))
                continue;
            if (kv.Key.StartsWith("Sec-", StringComparison.OrdinalIgnoreCase))
                continue;
            filtered[kv.Key] = kv.Value;
        }
        return filtered;
    }

    /// <summary>
    /// Applies caller-supplied headers to an <see cref="HttpRequestMessage"/>.
    /// Content must already be assigned when sending <c>Content-Type</c> or other entity headers.
    /// Returns header names that could not be applied.
    /// </summary>
    public static List<string> ApplyHeaders(HttpRequestMessage request, Dictionary<string, string> headers)
    {
        var skipped = new List<string>();
        foreach (var kv in headers)
        {
            var name = kv.Key.Trim();
            if (name.Length == 0) continue;

            var value = CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value);

            if (ManagedByHttpClient.Contains(name))
            {
                skipped.Add(name);
                continue;
            }

            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    request.Headers.Host = value;
                    continue;
                }
                catch
                {
                    if (!request.Headers.TryAddWithoutValidation("Host", value))
                        skipped.Add(name);
                    continue;
                }
            }

            if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                if (request.Content == null)
                {
                    skipped.Add(name);
                    continue;
                }

                request.Content.Headers.Remove("Content-Type");
                if (!request.Content.Headers.TryAddWithoutValidation("Content-Type", value))
                    skipped.Add(name);
                continue;
            }

            if (request.Headers.TryAddWithoutValidation(name, value))
                continue;

            if (request.Content != null && request.Content.Headers.TryAddWithoutValidation(name, value))
                continue;

            skipped.Add(name);
        }

        return skipped;
    }

    public static HttpClientHandler CreateHandler(bool allowAutoRedirect, bool automaticDecompression)
    {
        return new HttpClientHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            UseCookies = false,
            // Direct is a raw client: do not inherit WinINET/Fiddler/system proxy.
            UseProxy = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AutomaticDecompression = automaticDecompression ? DecompressionMethods.All : DecompressionMethods.None
        };
    }
}
