namespace Trowser.Security.XsLeaks;

internal static class XsLeakResourceApplicability
{
    internal enum ResourceKind
    {
        Unknown,
        Html,
        Json,
        OtherNonHtml
    }

    internal sealed record Profile(ResourceKind Kind, string? ContentType);

    internal static Profile FromContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            return new Profile(ResourceKind.Unknown, null);

        var ct = contentType.Split(';')[0].Trim();
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
            return new Profile(ResourceKind.Json, ct);
        if (ct.Contains("html", StringComparison.OrdinalIgnoreCase))
            return new Profile(ResourceKind.Html, ct);
        if (ct.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("application/", StringComparison.OrdinalIgnoreCase))
            return new Profile(ResourceKind.OtherNonHtml, ct);

        return new Profile(ResourceKind.Unknown, ct);
    }

    internal static string? LowApplicabilityReason(string techniqueId, IReadOnlyList<Profile> stateProfiles)
    {
        if (stateProfiles.Count == 0) return null;
        if (stateProfiles.All(p => p.Kind == ResourceKind.Json))
        {
            if (techniqueId is "img-error" or "script-module-error" or "script-error"
                or "link-stylesheet-error" or "iframe-load" or "object-load" or "track-error" or "audio-error")
            {
                return "low — JSON response cannot load as image/script/stylesheet; use resource-transfer-size or cache-timing for API-shaped URLs.";
            }
        }

        return null;
    }

    internal static bool AllStatesJson(IReadOnlyList<Profile> profiles) =>
        profiles.Count > 0 && profiles.All(p => p.Kind == ResourceKind.Json);
}
