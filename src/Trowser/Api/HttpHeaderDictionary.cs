using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// HTTP request header maps (names are case-insensitive per RFC 9110).
/// </summary>
internal static class HttpHeaderDictionary
{
    public static Dictionary<string, string>? Normalize(Dictionary<string, string>? headers)
    {
        if (headers == null || headers.Count == 0)
            return headers;

        if (headers.Comparer.Equals(StringComparer.OrdinalIgnoreCase))
            return headers;

        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
            merged[kv.Key] = kv.Value;
        return merged;
    }

    public static Dictionary<string, string>? FromJsonObject(JsonElement obj)
    {
        if (obj.ValueKind != JsonValueKind.Object)
            return null;

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in obj.EnumerateObject())
            result[prop.Name] = prop.Value.GetString() ?? prop.Value.ToString();
        return result;
    }

    /// <summary>
    /// After resolving a <c>json</c> request body: merge headers case-insensitively and default
    /// <c>Content-Type: application/json</c> only when the caller did not supply one (any casing).
    /// </summary>
    public static Dictionary<string, string> PrepareForJsonBody(Dictionary<string, string>? headers)
    {
        var normalized = Normalize(headers)
            ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!normalized.ContainsKey("Content-Type"))
            normalized["Content-Type"] = "application/json";

        return normalized;
    }
}
