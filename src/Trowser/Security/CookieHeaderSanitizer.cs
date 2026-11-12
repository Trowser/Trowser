using System.Text;

namespace Trowser.Security;

/// <summary>
/// Sanitizes cookie and header values for .NET <see cref="System.Net.Http.HttpClient"/>,
/// which rejects non-ASCII request header values.
/// </summary>
public static class CookieHeaderSanitizer
{
    public static bool IsAsciiHeaderValue(string? value)
    {
        if (string.IsNullOrEmpty(value)) return true;
        foreach (var ch in value)
        {
            if (ch > 127) return false;
        }
        return true;
    }

    public static bool IsAsciiCookieName(string? name) => IsAsciiHeaderValue(name);

    public static bool IsAsciiCookieValue(string? value) => IsAsciiHeaderValue(value);

    /// <summary>Percent-encode non-ASCII bytes so HttpClient accepts the header value.</summary>
    public static string SanitizeHeaderValue(string? value)
    {
        if (string.IsNullOrEmpty(value)) return value ?? "";
        if (IsAsciiHeaderValue(value)) return value;

        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch <= 127)
                sb.Append(ch);
            else
                sb.Append('%').Append(((int)ch).ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Build a Cookie header from name/value pairs, skipping invalid names and encoding values.
    /// </summary>
    public static string BuildCookieHeader(IEnumerable<(string Name, string Value)> cookies)
    {
        var parts = new List<string>();
        foreach (var (name, value) in cookies)
        {
            if (string.IsNullOrEmpty(name) || !IsAsciiCookieName(name))
                continue;
            parts.Add($"{name}={SanitizeHeaderValue(value)}");
        }
        return string.Join("; ", parts);
    }

    /// <summary>Sanitize an existing Cookie header string (name=value pairs separated by ';').</summary>
    public static string SanitizeCookieHeader(string? cookieHeader)
    {
        if (string.IsNullOrWhiteSpace(cookieHeader)) return "";
        if (IsAsciiHeaderValue(cookieHeader)) return cookieHeader;

        return BuildCookieHeader(ParseCookiePairs(cookieHeader));
    }

    /// <summary>
    /// Merge cookie jars. <paramref name="overlay"/> wins on name conflicts
    /// (case-insensitive cookie names).
    /// </summary>
    public static string MergeCookieHeaders(string? @base, string? overlay)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in ParseCookiePairs(@base))
            map[name] = value;
        foreach (var (name, value) in ParseCookiePairs(overlay))
            map[name] = value;
        return BuildCookieHeader(map.Select(kv => (kv.Key, kv.Value)));
    }

    /// <summary>Cookie names only (for audit responses).</summary>
    public static List<string> CookieNames(string? cookieHeader) =>
        ParseCookiePairs(cookieHeader).Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public static List<(string Name, string Value)> ParseCookiePairs(string? cookieHeader)
    {
        var pairs = new List<(string Name, string Value)>();
        if (string.IsNullOrWhiteSpace(cookieHeader)) return pairs;

        foreach (var segment in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = segment.IndexOf('=');
            if (eq <= 0) continue;
            var name = segment[..eq].Trim();
            var value = segment[(eq + 1)..].Trim();
            if (string.IsNullOrEmpty(name)) continue;
            pairs.Add((name, value));
        }

        return pairs;
    }
}
