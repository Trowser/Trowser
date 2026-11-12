using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Extracts anti-CSRF tokens from HTML form pages (used when <c>fetch()</c> probes
/// consume one-time tokens and the live DOM is therefore stale).
/// </summary>
internal static class CsrfHtmlTokenExtractor
{
    private static readonly Regex HiddenInputRegex = new(
        @"<input\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Populate <paramref name="tokens"/> with CSRF field name → value pairs found in HTML.
    /// Returns true when at least one token was found.
    /// </summary>
    public static bool TryExtractAll(string? html, IDictionary<string, string> tokens)
    {
        if (string.IsNullOrWhiteSpace(html) || !html.Contains('<'))
            return false;

        var found = false;
        foreach (Match m in HiddenInputRegex.Matches(html))
        {
            var tag = m.Value;
            var name = ReadAttr(tag, "name");
            var val = ReadAttr(tag, "value");
            var type = ReadAttr(tag, "type");
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(val))
                continue;
            if (!CsrfTokenHeuristics.IsCsrfFieldCandidate(name, type, val)
                && !CsrfTokenHeuristics.IsKnownCsrfFieldName(name))
                continue;

            tokens[name] = val;
            found = true;
        }

        return found;
    }

    private static string ReadAttr(string tag, string attr)
    {
        var match = Regex.Match(tag, attr + @"=[""'](?<v>[^""']*)[""']", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups["v"].Value : "";
    }
}
