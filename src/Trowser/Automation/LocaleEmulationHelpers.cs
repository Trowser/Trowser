namespace Trowser.Automation;

/// <summary>Shared locale / Accept-Language helpers for emulation and tests.</summary>
internal static class LocaleEmulationHelpers
{
    /// <summary>
    /// Accept-Language value for CDP <c>Emulation.setUserAgentOverride</c>.
    /// Omits <c>;q=</c> weights — Chromium can double-apply q-values and emit malformed headers.
    /// </summary>
    internal static string BuildAcceptLanguageHeader(string locale)
    {
        var primary = locale.Trim();
        if (primary.Length == 0)
            return "en";

        var shortLang = primary.Contains('-') ? primary.Split('-')[0] : primary;
        var parts = new List<string> { primary };
        if (!string.Equals(shortLang, primary, StringComparison.OrdinalIgnoreCase))
            parts.Add(shortLang);
        if (!parts.Any(p => p.StartsWith("en", StringComparison.OrdinalIgnoreCase)))
            parts.Add("en");
        return string.Join(',', parts);
    }
}
