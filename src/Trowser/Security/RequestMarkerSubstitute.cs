using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Replace §NAME§ and {{NAME}} markers in fuzz-style request templates (same syntax as <see cref="Robustness.RequestFuzzer"/>).
/// </summary>
public static class RequestMarkerSubstitute
{
    private static readonly Regex MarkerRegex = new(@"\u00A7(\w+)\u00A7|\{\{(\w+)\}\}", RegexOptions.Compiled);

    /// <summary>True when <paramref name="value"/> contains a literal injection marker that must stay unescaped in templates.</summary>
    public static bool ContainsMarkerSyntax(string? value) =>
        !string.IsNullOrEmpty(value)
        && (value.Contains('\u00A7') || value.Contains("{{", StringComparison.Ordinal));

    /// <summary>
    /// Percent-encode a query/form value unless it is a marker placeholder.
    /// Discovery templates must keep <c>§NAME§</c> / <c>{{NAME}}</c> literal — encoding them to
    /// <c>%C2%A7…%C2%A7</c> / <c>%7B%7B…%7D%7D</c> prevents later substitution.
    /// </summary>
    public static string EscapeDataStringPreservingMarkers(string value) =>
        ContainsMarkerSyntax(value) ? value : Uri.EscapeDataString(value);

    /// <summary>
    /// True when a built URL/body still contains an unsubstituted marker or a percent-encoded section-sign
    /// marker (<c>%C2%A7</c>) — indicates a discovery/encoding bug rather than a live probe.
    /// </summary>
    public static bool HasUnsubstitutedOrEncodedMarker(string? url, string? body = null)
    {
        if (ListMarkers(url ?? "", body).Count > 0)
            return true;
        if (!string.IsNullOrEmpty(url)
            && url.Contains("%C2%A7", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrEmpty(body)
            && body.Contains("%C2%A7", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static string ReplaceAll(string input, string value) =>
        MarkerRegex.Replace(input, value);

    /// <summary>Replace markers in URL templates with <see cref="Uri.EscapeDataString"/> (required for #, &, %, spaces in query values).</summary>
    public static string ReplaceAllInUrl(string url, string value) =>
        MarkerRegex.Replace(url, _ => Uri.EscapeDataString(value));

    public static string ReplaceNamed(string input, IReadOnlyDictionary<string, string> payloads) =>
        MarkerRegex.Replace(input, match =>
        {
            var name = match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value;
            return payloads.TryGetValue(name, out var v) ? v : match.Value;
        });

    /// <summary>Returns distinct marker names in template order (URL, then body).</summary>
    public static List<string> ListMarkers(string url, string? body) =>
        ListMarkers(url, body, headers: null);

    /// <summary>Returns distinct marker names from URL, body, and header values.</summary>
    public static List<string> ListMarkers(
        string url,
        string? body,
        IEnumerable<KeyValuePair<string, string>>? headers)
    {
        var names = new List<string>();
        void scan(string? s)
        {
            if (string.IsNullOrEmpty(s)) return;
            foreach (Match m in MarkerRegex.Matches(s))
            {
                var name = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
                if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    names.Add(name);
            }
        }
        scan(url);
        scan(body);
        if (headers != null)
        {
            foreach (var kv in headers)
                scan(kv.Value);
        }
        return names;
    }

    /// <summary>Substitute markers in all header values; returns a new dictionary when headers is non-null.</summary>
    public static Dictionary<string, string>? ReplaceAllInHeaders(
        IReadOnlyDictionary<string, string>? headers,
        string value)
    {
        if (headers == null || headers.Count == 0) return headers as Dictionary<string, string> ??
            (headers == null ? null : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase));

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
            result[kv.Key] = ReplaceAll(kv.Value, value);
        return result;
    }

    /// <summary>Substitute named markers in header values.</summary>
    public static Dictionary<string, string>? ReplaceNamedInHeaders(
        IReadOnlyDictionary<string, string>? headers,
        IReadOnlyDictionary<string, string> payloads)
    {
        if (headers == null || headers.Count == 0) return headers as Dictionary<string, string> ??
            (headers == null ? null : new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase));

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
            result[kv.Key] = ReplaceNamed(kv.Value, payloads);
        return result;
    }
}
