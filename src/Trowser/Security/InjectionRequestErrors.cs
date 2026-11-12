namespace Trowser.Security;

/// <summary>
/// Shared validation text for scans that take a marker template rather than a <c>/api/fetch</c> body.
/// </summary>
internal static class InjectionRequestErrors
{
    public const string RequestExample =
        "{\"safetyMode\":\"active\",\"request\":{\"url\":\"https://example.com/api/items\",\"method\":\"POST\",\"json\":{\"q\":\"§q§\"}}}";

    public const string ShorthandExample =
        "{\"safetyMode\":\"active\",\"url\":\"https://example.com/search?q=1\",\"param\":\"q\"}";

    const string FetchShapeHint =
        "Top-level url plus json/body is the POST /api/fetch shape; wrap that object in request and put §name§ or {{name}} on the value to inject. Markers must stay literal (not percent-encoded).";

    /// <summary>Append a copy-pasteable <c>request</c> template. Used by every marker-based scanner.</summary>
    public static string WithRequestExample(string message) =>
        message.TrimEnd().TrimEnd('.') + ". Example: " + RequestExample + ". " + FetchShapeHint;

    /// <summary>SQLi (and the same shorthand) when neither <c>request</c> nor <c>{ url, param }</c> was provided.</summary>
    public static string MissingSqliTemplate(bool fetchShapedBody)
    {
        var lead = fetchShapedBody
            ? "Top-level url with json or body matches POST /api/fetch, not an injection scan. "
            : "";
        return lead +
            "Provide request with url and a §marker§ or {{marker}} injection point, " +
            "or shorthand { url, param } (optional method). " +
            "Examples: " + ShorthandExample + " or " + RequestExample + ". " +
            FetchShapeHint;
    }
}
