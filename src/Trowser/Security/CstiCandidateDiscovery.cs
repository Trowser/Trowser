namespace Trowser.Security;

/// <summary>Filters and deduplicates CSTI probe candidates.</summary>
internal static class CstiCandidateDiscovery
{
    /// <summary>Common client-template query keys (CSTI labs often use short names like <c>tpl</c>).</summary>
    internal static class CstiTemplateParamNames
    {
        internal static readonly string[] Default =
        [
            "tpl", "template", "layout", "partial", "view", "render", "html", "content", "body", "sandbox",
            "theme", "skin", "page", "fragment", "include", "module", "component"
        ];
    }

    internal static readonly HashSet<string> InternalParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "_trowser_rc"
    };

    internal static bool IsProbeableParam(string paramName) =>
        !string.IsNullOrWhiteSpace(paramName)
        && !InternalParamNames.Contains(paramName.Trim());

    /// <summary>Base URL for injection: scheme + host + path (no query/fragment).</summary>
    internal static string CandidateBaseUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return UrlPayloadInjector.StripFragment(url);

        var builder = new UriBuilder(uri) { Query = "", Fragment = "" };
        return builder.Uri.ToString();
    }

    internal static string CandidateKey(string baseUrl, string paramName, CstiProbes.Source source)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
            return $"{source}|{baseUrl}|{paramName}";

        return $"{source}|{uri.Host}|{uri.AbsolutePath}|{paramName}";
    }
}
