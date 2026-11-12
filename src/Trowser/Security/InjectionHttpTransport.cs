using System.Net.Http;
using System.Text;

namespace Trowser.Security;

/// <summary>HttpClient request assembly aligned with fetch-direct (no duplicate Content-Type).</summary>
internal static class InjectionHttpTransport
{
    public static void ApplyHeaders(HttpRequestMessage msg, Dictionary<string, string>? headers)
    {
        if (headers == null) return;
        foreach (var kv in headers)
        {
            if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                continue;
            var value = CookieHeaderSanitizer.SanitizeHeaderValue(kv.Value);
            if (!msg.Headers.TryAddWithoutValidation(kv.Key, value))
                msg.Content?.Headers.TryAddWithoutValidation(kv.Key, value);
        }
    }

    public static StringContent? BuildContent(string? body, Dictionary<string, string>? headers, string? formTemplateHint = null)
    {
        // Empty string must not become HttpContent — browsers reject GET/HEAD with a body.
        if (string.IsNullOrEmpty(body)) return null;
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return new StringContent(body, Encoding.UTF8, "application/json");

        if (headers != null && headers.TryGetValue("Content-Type", out var ct)
            && ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

        if (headers != null && headers.TryGetValue("Content-Type", out var ct2)
            && ct2.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");

        return new StringContent(body, Encoding.UTF8);
    }
}
