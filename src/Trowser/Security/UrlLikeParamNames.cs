namespace Trowser.Security;

/// <summary>
/// Shared parameter names and heuristics for URL-like / redirect parameters used by SSRF,
/// open-redirect, and auto-scan candidate selection.
/// </summary>
public static class UrlLikeParamNames
{
    public static readonly string[] Default =
    [
        "url", "link", "uri", "redirect", "callback", "webhook", "fetch", "src", "href", "target",
        "destination", "dest", "endpoint", "api", "proxy", "feed", "image", "img", "load", "site", "domain",
        "host", "return", "returnurl", "return_url", "returnto", "return_to", "next", "continue", "goto",
        "forward", "referer", "referrer", "request", "source", "path", "file", "document", "page",
        "resource", "import", "export", "download", "preview", "render", "fetch_url", "imageurl",
        "image_url", "avatar", "logo", "banner", "background", "content_url", "media", "video", "audio",
        "rss", "atom", "ping", "track", "beacon", "notify", "hook", "postback", "to", "ref", "out", "redir"
    ];

    /// <summary>Subset most strongly associated with open redirects (CWE-601).</summary>
    public static readonly string[] RedirectLike =
    [
        "redirect", "redirecturl", "redirect_url", "redirect_uri", "redirectto", "redirect_to",
        "redirectpath", "redirect_path",
        "url", "link", "uri", "next", "nexturl", "next_url",
        "continue", "continueurl", "continue_url",
        "return", "returnurl", "return_url", "returnto", "return_to",
        "goto", "gotourl", "go_to",
        "forward", "destination", "destinationurl", "destination_url", "dest",
        "target", "targeturl", "target_url",
        "redir", "out", "to", "ref"
    ];

    public static readonly HashSet<string> DefaultSet =
        new(Default, StringComparer.OrdinalIgnoreCase);

    public static readonly HashSet<string> RedirectLikeSet =
        new(RedirectLike, StringComparer.OrdinalIgnoreCase);

    public static bool IsUrlLikeName(string name) =>
        IsUrlLikeParamName(name);

    /// <summary>
    /// True when the parameter name suggests a URL target (exact list, suffix, or embedded token).
    /// Matches <c>imageUrl</c>, <c>callbackUrl</c>, etc. even without a URL-shaped value.
    /// </summary>
    public static bool IsUrlLikeParamName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (DefaultSet.Contains(name)) return true;

        foreach (var suffix in UrlLikeSuffixes)
        {
            if (name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var token in EmbeddedUrlTokens)
        {
            if (name.Contains(token, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static readonly string[] EmbeddedUrlTokens =
    [
        "_url", "_uri", "_link", "_href", "_src", "_redirect", "_callback", "_webhook", "_endpoint"
    ];

    private static readonly string[] UrlLikeSuffixes =
    [
        "url", "uri", "link", "callback", "webhook", "endpoint", "redirect", "target", "fetch"
    ];

    public static bool IsRedirectLikeName(string name) =>
        RedirectLikeSet.Contains(name);

    /// <summary>
    /// True when the parameter name or value suggests a URL/redirect target.
    /// Name-based match applies even for relative values like <c>info.php?id=1</c>.
    /// </summary>
    public static bool IsUrlLikeParam(string name, string value, ISet<string>? names = null)
    {
        if (IsUrlLikeParamName(name))
            return true;
        if (names != null && names.Contains(name))
            return true;
        return LooksLikeUrlValue(value);
    }

    /// <summary>
    /// True when a DOM form field looks like it accepts a URL (name, type, placeholder, label).
    /// </summary>
    public static bool IsUrlLikeFormField(
        string? name, string? type, string? placeholder, string? label, string? value, ISet<string>? names = null)
    {
        if (!string.IsNullOrWhiteSpace(name) && IsUrlLikeParam(name, value ?? "", names))
            return true;

        if (string.Equals(type, "url", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var hint in new[] { placeholder, label })
        {
            if (string.IsNullOrWhiteSpace(hint)) continue;
            var h = hint.ToLowerInvariant();
            if (h.Contains("http") || h.Contains("url") || h.Contains("link") || h.Contains("website")
                || h.Contains("domain") || h.Contains("webhook") || h.Contains("endpoint"))
                return true;
        }

        return false;
    }

    public static bool LooksLikeUrlValue(string value) =>
        value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("//", StringComparison.Ordinal) ||
        (value.Contains('.') && (value.Contains('/') || value.Contains('\\')));
}

public sealed class EndpointParamHint
{
    public string Url { get; init; } = "";
    public string Method { get; init; } = "GET";
    public List<string> ParamNames { get; init; } = [];
    /// <summary>Captured request body sample for POST/PUT/PATCH injection (form or JSON).</summary>
    public string? RequestBodySample { get; init; }
    public Dictionary<string, string>? Headers { get; init; }
}
