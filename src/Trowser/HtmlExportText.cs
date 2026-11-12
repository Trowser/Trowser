using System.Net;
using System.Text.RegularExpressions;

namespace Trowser;

/// <summary>
/// Text and document cleanup for "Show as HTML" and other NavigateToString exports.
/// Embedded NUL (common in base64-decoded binary snippets) truncates at the WebView2 boundary.
/// </summary>
internal static class HtmlExportText
{
    private static readonly Regex C0ControlsExceptNewlineTab =
        new(@"[\u0000-\u0008\u000B\u000C\u000E-\u001F]", RegexOptions.Compiled);

    /// <summary>HTML-encode after removing C0 control characters (keeps tab/LF/CR).</summary>
    public static string Encode(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        var cleaned = C0ControlsExceptNewlineTab.Replace(text, "\uFFFD");
        return WebUtility.HtmlEncode(cleaned);
    }

    /// <summary>Last-chance cleanup before NavigateToString (NUL must not reach native code).</summary>
    public static string PrepareDocument(string html)
    {
        if (string.IsNullOrEmpty(html))
            return html;
        return html.IndexOf('\0') >= 0 ? html.Replace("\0", "\uFFFD") : html;
    }
}
