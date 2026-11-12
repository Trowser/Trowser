namespace Trowser.Security.Authz;

/// <summary>
/// One key for an access model, shadow results, and coverage.
/// <c>example.com</c>, <c>example.com:443</c>, and <c>example.com:80</c> are the same host.
/// A non-default port stays on the key (<c>127.0.0.1:8099</c>).
/// </summary>
public static class AuthzHostKey
{
    public static string Canonical(string? hostOrUrl)
    {
        if (string.IsNullOrWhiteSpace(hostOrUrl)) return "";
        var t = hostOrUrl.Trim();

        if (t.Contains("://", StringComparison.Ordinal)
            && Uri.TryCreate(t, UriKind.Absolute, out var absolute))
            return FromUri(absolute);

        if (t.StartsWith('[') && t.Contains(']', StringComparison.Ordinal))
        {
            var end = t.IndexOf(']');
            if (end > 1)
            {
                var host = t[1..end];
                var rest = end + 1 < t.Length ? t[(end + 1)..] : "";
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var v6Port) && v6Port is not (80 or 443))
                    return host + ":" + v6Port;
                return host;
            }
        }

        var lastColon = t.LastIndexOf(':');
        if (lastColon > 0 && t.IndexOf(':') == lastColon
            && int.TryParse(t.AsSpan(lastColon + 1), out var port))
        {
            if (port is 80 or 443)
                return t[..lastColon];
            return t;
        }

        return t;
    }

    public static string FromUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri) return uri.Host;
        if (uri.Port is 80 or 443 or -1)
            return uri.Host;
        return uri.Host + ":" + uri.Port;
    }
}
