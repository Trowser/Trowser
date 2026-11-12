using System.Net;
using System.Net.Http;

namespace Trowser.Security;

/// <summary>
/// Confirms HTTP TRACE / XST — status 200 alone is insufficient (many servers return HTML for unknown verbs).
/// </summary>
public static class TraceMethodAnalyzer
{
    /// <summary>
    /// True when the response body reflects the TRACE request line (Cross-Site Tracing risk).
    /// </summary>
    public static bool BodyIndicatesTraceEcho(string? body, string requestUrl)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length < 12)
            return false;

        if (body.Contains("TRACE /", StringComparison.OrdinalIgnoreCase)
            && body.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase))
            return true;

        if (Uri.TryCreate(requestUrl, UriKind.Absolute, out var uri)
            && body.Contains($"TRACE {uri.AbsolutePath}", StringComparison.OrdinalIgnoreCase))
            return true;

        if (body.Contains("message/http", StringComparison.OrdinalIgnoreCase)
            && body.Contains("TRACE", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    /// <summary>
    /// True when TRACE is genuinely enabled with echo semantics, not a generic 200 HTML fallback.
    /// </summary>
    public static bool IsTraceEnabled(int statusCode, string? body, string requestUrl, string? allowHeader = null)
    {
        if (statusCode == (int)HttpStatusCode.OK && BodyIndicatesTraceEcho(body, requestUrl))
            return true;

        if (!string.IsNullOrWhiteSpace(allowHeader)
            && allowHeader.Contains("TRACE", StringComparison.OrdinalIgnoreCase)
            && BodyIndicatesTraceEcho(body, requestUrl))
            return true;

        return false;
    }

    public static async Task<(int Status, string? Body, string? AllowHeader)> ProbeTraceAsync(
        string url,
        TimeSpan? timeout = null)
    {
        timeout ??= TimeSpan.FromSeconds(10);

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = timeout.Value };

        using var traceMsg = new HttpRequestMessage(new HttpMethod("TRACE"), url);
        using var traceResp = await client.SendAsync(traceMsg);
        var body = traceResp.Content != null
            ? await traceResp.Content.ReadAsStringAsync()
            : null;

        string? allowHeader = null;
        try
        {
            using var optMsg = new HttpRequestMessage(HttpMethod.Options, url);
            using var optResp = await client.SendAsync(optMsg);
            if (optResp.Headers.TryGetValues("Allow", out var allowValues))
                allowHeader = string.Join(", ", allowValues);
        }
        catch
        {
            // OPTIONS is best-effort
        }

        return ((int)traceResp.StatusCode, body, allowHeader);
    }
}
