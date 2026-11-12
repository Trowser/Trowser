using System.Text;
using System.Security.Cryptography;

namespace Trowser.EndpointProbe;

/// <summary>A single HTTP endpoint target for endpoint-scoped security probes.</summary>
public sealed class EndpointProbeItem
{
    public required string Method { get; init; }
    public required string Url { get; init; }
    public string Priority { get; init; } = "low";
    public DateTime? Timestamp { get; init; }
    public Dictionary<string, string> RequestHeaders { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public string? RequestBody { get; init; }
    public int? StatusCode { get; init; }
    public string? ResourceType { get; init; }
    public bool IsImported { get; init; }

    public string Key => ComputeKey(Method, Url, RequestBody);

    /// <summary>Stable key for deduping and merge; POST/PUT/PATCH/DELETE with a body include a body hash.</summary>
    public static string ComputeKey(string method, string url, string? requestBody)
    {
        if (method is "POST" or "PUT" or "PATCH" or "DELETE" && !string.IsNullOrEmpty(requestBody))
            return $"{method}|{url}|{ShortBodyHash(requestBody)}";
        return $"{method}|{url}";
    }

    private static string ShortBodyHash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(bytes[..8]).ToLowerInvariant();
    }

    /// <summary>
    /// Renders the captured request as a raw HTTP-style text block (request line, headers,
    /// then a blank line and the body). Used when handing the request off to the Request
    /// Editor or the AI Assistant chat so that authorization and other headers are retained.
    /// </summary>
    public string ToHttpText()
    {
        var sb = new StringBuilder();
        sb.Append(Method).Append(' ').Append(Url);
        foreach (var kv in RequestHeaders)
            sb.Append('\n').Append(kv.Key).Append(": ").Append(kv.Value);
        if (!string.IsNullOrEmpty(RequestBody))
            sb.Append("\n\n").Append(RequestBody);
        return sb.ToString();
    }

    public EndpointProbeItem Clone() => new()
    {
        Method = Method,
        Url = Url,
        Priority = Priority,
        Timestamp = Timestamp,
        RequestHeaders = new Dictionary<string, string>(RequestHeaders, StringComparer.OrdinalIgnoreCase),
        RequestBody = RequestBody,
        StatusCode = StatusCode,
        ResourceType = ResourceType,
        IsImported = IsImported
    };
}
