using System.Text;

namespace Trowser.Security;

/// <summary>
/// Repairs common UTF-8 mojibake (UTF-8 bytes misread as Windows-1252/Latin-1),
/// e.g. em-dash "—" appearing as "â€"" (\u00e2\u20ac\u201d).
/// </summary>
public static class TextEncodingFix
{
    private static readonly Encoding Windows1252 = Encoding.GetEncoding(1252);

    public static string? FixMojibake(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return text;

        if (!LooksLikeMojibake(text))
            return text;

        try
        {
            var bytes = Windows1252.GetBytes(text);
            var repaired = Encoding.UTF8.GetString(bytes);
            if (repaired.Contains('\uFFFD'))
                return text;
            return repaired;
        }
        catch
        {
            return text;
        }
    }

    private static bool LooksLikeMojibake(string text)
    {
        // Classic UTF-8-as-1252 signature: â (U+00E2) followed by € (U+20AC)
        if (text.Contains('\u00E2') && text.Contains('\u20AC'))
            return true;

        // Other frequent mojibake starters for multi-byte UTF-8
        return text.Contains('\u00C3') || text.Contains('\u00C2') || text.Contains('\u00E2');
    }
}
