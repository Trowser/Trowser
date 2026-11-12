namespace Trowser.Security;

/// <summary>Client-side open redirect detection from final document URL vs injected payload.</summary>
internal static class TraceInputRedirectHelper
{
    public static bool PayloadTargetsOffSiteNavigation(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload)) return false;
        var p = payload.Trim();
        if (p.StartsWith("//", StringComparison.Ordinal))
            return p.Length > 2 && !p[2..].StartsWith('/');
        if (Uri.TryCreate(p, UriKind.Absolute, out var uri))
            return uri.Scheme is "http" or "https" && !string.IsNullOrEmpty(uri.Host);
        return false;
    }

    public static bool DocumentMatchesRedirectPayload(string? documentUrl, string payload, string? pageOrigin = null)
    {
        if (string.IsNullOrWhiteSpace(documentUrl) || string.IsNullOrWhiteSpace(payload))
            return false;

        var target = ResolveTargetUri(documentUrl, payload.Trim(), pageOrigin);
        if (target == null || !Uri.TryCreate(documentUrl, UriKind.Absolute, out var docUri))
            return false;

        if (!string.Equals(docUri.Scheme, target.Scheme, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.Equals(docUri.Host, target.Host, StringComparison.OrdinalIgnoreCase))
            return false;

        var docPath = docUri.AbsolutePath.TrimEnd('/');
        var targetPath = target.AbsolutePath.TrimEnd('/');
        if (docPath.Equals(targetPath, StringComparison.OrdinalIgnoreCase))
            return true;

        return documentUrl.StartsWith(target.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase);
    }

    private static Uri? ResolveTargetUri(string documentUrl, string payload, string? pageOrigin)
    {
        if (payload.StartsWith("//", StringComparison.Ordinal))
        {
            if (Uri.TryCreate(documentUrl, UriKind.Absolute, out var doc))
                return Uri.TryCreate($"{doc.Scheme}:{payload}", UriKind.Absolute, out var u) ? u : null;
            return Uri.TryCreate($"https:{payload}", UriKind.Absolute, out var fb) ? fb : null;
        }

        if (Uri.TryCreate(payload, UriKind.Absolute, out var abs))
            return abs;

        if (pageOrigin != null && Uri.TryCreate(pageOrigin + payload, UriKind.Absolute, out var rel))
            return rel;

        return null;
    }
}
