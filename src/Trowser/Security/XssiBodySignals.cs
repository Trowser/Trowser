using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Classic cross-site script inclusion shapes: a JavaScript (or sniffed JSON) body that is data,
/// not an application bundle. Missing <c>nosniff</c> matters for JSON; a <c>text/javascript</c>
/// array, assignment, or callback wrapper is includable either way.
/// </summary>
internal static class XssiBodySignals
{
    private static readonly Regex JsonpCallback = new(
        @"[?&](?:callback|jsonp|cb|jsoncallback|_callback)=([^&]*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JsonpBody = new(
        @"^\s*(?:/\*[^*]*\*/\s*)?([A-Za-z_$][\w$]*)\s*\(",
        RegexOptions.Compiled);

    private static readonly Regex AssignmentBody = new(
        @"^\s*(?:/\*[^*]*\*/\s*)?(?:var\s+|let\s+|const\s+)?(?:window\.|[\w$]+\.)?[\w$]+\s*=\s*[\{\[]",
        RegexOptions.Compiled);

    public static bool IsJavaScriptType(string? contentType) =>
        !string.IsNullOrEmpty(contentType)
        && (contentType.Contains("javascript", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("ecmascript", StringComparison.OrdinalIgnoreCase));

    public static bool IsJsonType(string? contentType) =>
        !string.IsNullOrEmpty(contentType)
        && contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
        && !IsJavaScriptType(contentType);

    public static bool HasNosniff(string? xContentTypeOptions) =>
        xContentTypeOptions?.Contains("nosniff", StringComparison.OrdinalIgnoreCase) == true;

    public static bool IsArrayBody(string? body)
    {
        var t = TrimStart(body);
        return t.Length > 0 && t[0] == '[';
    }

    public static bool IsAssignmentBody(string? body)
    {
        var t = TrimStart(body);
        if (t.Length == 0 || t.Length > 8_192) t = t.Length > 8_192 ? t[..8_192] : t;
        return t.Length > 0 && AssignmentBody.IsMatch(t);
    }

    public static bool IsJsonpBody(string? body)
    {
        var t = TrimStart(body);
        return t.Length > 0 && JsonpBody.IsMatch(t);
    }

    /// <summary>Query callback name when the URL has a JSONP-style parameter.</summary>
    public static string? CallbackName(string? url)
    {
        if (string.IsNullOrEmpty(url)) return null;
        var m = JsonpCallback.Match(url);
        if (!m.Success) return null;
        var name = Uri.UnescapeDataString(m.Groups[1].Value).Trim();
        return name.Length is > 0 and <= 64 ? name : null;
    }

    public static bool CallbackReflects(string? url, string? body)
    {
        var name = CallbackName(url);
        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(body)) return false;
        var t = TrimStart(body);
        return t.StartsWith(name + "(", StringComparison.Ordinal)
               || t.Contains(name + "(", StringComparison.Ordinal);
    }

    /// <summary>
    /// True when a script response is data (array, assignment, or callback wrapper),
    /// or a JSON array is served without nosniff.
    /// </summary>
    public static bool IsIncludable(
        string? contentType,
        string? body,
        string? xContentTypeOptions,
        string? url,
        out string shape)
    {
        shape = "";
        if (string.IsNullOrWhiteSpace(body)) return false;
        var script = IsJavaScriptType(contentType);
        var json = IsJsonType(contentType);
        var nosniff = HasNosniff(xContentTypeOptions);
        var reflects = CallbackReflects(url, body);

        if (reflects)
        {
            shape = "callback";
            return true;
        }

        if (script && IsArrayBody(body))
        {
            shape = "array";
            return true;
        }

        if (script && IsJsonpBody(body))
        {
            shape = "jsonp";
            return true;
        }

        if (script && IsAssignmentBody(body))
        {
            shape = "assignment";
            return true;
        }

        if (json && IsArrayBody(body) && !nosniff)
        {
            shape = "json-array";
            return true;
        }

        return false;
    }

    private static string TrimStart(string? body) => body?.TrimStart() ?? "";
}
