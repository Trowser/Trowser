namespace Trowser.Security;

/// <summary>Case-insensitive HTTP header helpers — avoids duplicate-key crashes when copying header dictionaries.
/// </summary>
internal static class HttpHeaderUtils
{
    public static Dictionary<string, string> CopyCaseInsensitive(IReadOnlyDictionary<string, string>? headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers == null) return result;

        foreach (var (key, value) in headers)
        {
            if (string.IsNullOrEmpty(key)) continue;
            if (result.TryGetValue(key, out var existing) && !string.IsNullOrEmpty(existing))
            {
                if (key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    result[key] = existing + "\n" + value;
                else if (!existing.Contains(value, StringComparison.Ordinal))
                    result[key] = existing + ", " + value;
            }
            else
            {
                result[key] = value;
            }
        }

        return result;
    }

    public static bool TryGetValue(IReadOnlyDictionary<string, string>? headers, string name, out string value)
    {
        value = "";
        if (headers == null) return false;

        foreach (var kv in headers)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                value = kv.Value;
                return true;
            }
        }

        return false;
    }

    public static void SetMerged(Dictionary<string, string> headers, string name, string value)
    {
        if (headers.TryGetValue(name, out var existing) && !string.IsNullOrEmpty(existing))
        {
            if (name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                headers[name] = existing + "\n" + value;
            else if (!existing.Contains(value, StringComparison.Ordinal))
                headers[name] = existing + ", " + value;
        }
        else
        {
            headers[name] = value;
        }
    }
}
