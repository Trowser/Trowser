using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Helpers for analyzing HTTP redirect responses (Location header, external origin checks).
/// </summary>
public static class RedirectAnalysis
{
    public const string DefaultProbeHost = "open-redirect-probe.trowser.test";

    public static bool IsRedirectStatus(int status) =>
        status is 301 or 302 or 303 or 307 or 308;

    public static string? TryGetLocation(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers == null) return null;
        foreach (var kv in headers)
        {
            if (kv.Key.Equals("Location", StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }
        return null;
    }

    public static string? TryGetLocationFromFetchJson(string fetchJson)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(fetchJson);
            if (!doc.RootElement.TryGetProperty("headers", out var hdrs))
                return null;
            foreach (var prop in hdrs.EnumerateObject())
            {
                if (prop.Name.Equals("Location", StringComparison.OrdinalIgnoreCase))
                    return prop.Value.GetString();
            }
        }
        catch { /* ignore */ }
        return null;
    }

    public static Uri? ResolveLocation(string location, Uri requestUri)
    {
        if (string.IsNullOrWhiteSpace(location)) return null;
        location = location.Trim();

        if (Uri.TryCreate(location, UriKind.Absolute, out var abs))
            return abs;

        if (location.StartsWith("//", StringComparison.Ordinal))
        {
            var scheme = requestUri.Scheme;
            if (Uri.TryCreate($"{scheme}:{location}", UriKind.Absolute, out abs))
                return abs;
        }

        if (Uri.TryCreate(requestUri, location, out abs))
            return abs;

        return null;
    }

    public static bool HostMatchesProbe(string host, string probeHost) =>
        host.Equals(probeHost, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + probeHost, StringComparison.OrdinalIgnoreCase);

    public static bool IsExternalRedirect(Uri requestUri, string? location, string? probeHost = null)
    {
        if (string.IsNullOrWhiteSpace(location)) return false;

        var resolved = ResolveLocation(location, requestUri);
        if (resolved == null) return false;

        if (!resolved.IsAbsoluteUri) return false;

        if (probeHost != null && HostMatchesProbe(resolved.Host, probeHost))
            return true;

        return !string.Equals(resolved.Host, requestUri.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when <paramref name="location"/> resolves to the configured probe host (not merely off-site).</summary>
    public static bool LocationPointsToProbe(Uri requestUri, string? location, string probeHost)
    {
        if (string.IsNullOrWhiteSpace(location)) return false;
        var resolved = ResolveLocation(location, requestUri);
        if (resolved == null || !resolved.IsAbsoluteUri) return false;
        return HostMatchesProbe(resolved.Host, probeHost);
    }

    public static bool IsDangerousRedirectScheme(string? location)
    {
        if (string.IsNullOrWhiteSpace(location)) return false;
        var trimmed = location.Trim();
        return trimmed.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ||
               trimmed.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase);
    }

    public static string? TryGetBodyFromFetchJson(string fetchJson)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(fetchJson);
            if (doc.RootElement.TryGetProperty("body", out var body))
                return body.GetString();
        }
        catch { /* ignore */ }
        return null;
    }

    public static string? TryGetRefreshFromFetchJson(string fetchJson)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(fetchJson);
            if (!doc.RootElement.TryGetProperty("headers", out var hdrs))
                return null;
            foreach (var prop in hdrs.EnumerateObject())
            {
                if (prop.Name.Equals("Refresh", StringComparison.OrdinalIgnoreCase))
                    return prop.Value.GetString();
            }
        }
        catch { /* ignore */ }
        return null;
    }

    /// <summary>Signals from one open-redirect probe response (Location, Refresh, HTML body).</summary>
    public readonly record struct OpenRedirectResponseSignals(
        string? Location,
        string? RefreshHeader,
        string? ResponseBody);

    /// <summary>
    /// Whether a probe should be reported vs baseline — includes off-site Location when baseline was already external,
    /// probe-host Location, and HTML/Refresh redirects.
    /// </summary>
    public static bool ShouldFlagOpenRedirect(
        Uri requestUri,
        string probeHost,
        OpenRedirectResponseSignals probe,
        OpenRedirectResponseSignals baseline)
    {
        if (IsDangerousRedirectScheme(probe.Location))
            return true;

        if (IsSuppressedSameOriginLoginRedirect(requestUri, probeHost, probe.Location))
            return false;

        if (IsNewExternalLocation(requestUri, probe.Location, baseline.Location, probeHost))
            return true;

        var probeRefresh = TryExtractRefreshTarget(probe.RefreshHeader, probe.ResponseBody);
        if (!string.IsNullOrWhiteSpace(probeRefresh)
            && IsSuppressedSameOriginLoginRedirect(requestUri, probeHost, probeRefresh))
            return false;

        if (IsNewOffSiteRefresh(requestUri, probe, baseline, probeHost))
            return true;

        return false;
    }

    /// <summary>
    /// Same-origin redirect to login/sign-in after an off-site probe — common WAF/app behavior, not CWE-601.
    /// </summary>
    public static bool IsSuppressedSameOriginLoginRedirect(Uri requestUri, string probeHost, string? location)
    {
        if (string.IsNullOrWhiteSpace(location)) return false;
        if (LocationPointsToProbe(requestUri, location, probeHost)) return false;
        if (IsDangerousRedirectScheme(location)) return false;

        var resolved = ResolveLocation(location, requestUri);
        if (resolved == null || !resolved.IsAbsoluteUri) return false;
        if (!string.Equals(resolved.Host, requestUri.Host, StringComparison.OrdinalIgnoreCase))
            return false;

        return IsLoginLikePath(resolved.AbsolutePath);
    }

    internal static bool IsLoginLikePath(string path)
    {
        var p = path.TrimEnd('/').ToLowerInvariant();
        if (p is "/login" or "/signin" or "/sign-in" or "/auth/login" or "/account/login")
            return true;
        return p.EndsWith("/login", StringComparison.Ordinal)
               || p.EndsWith("/signin", StringComparison.Ordinal)
               || p.EndsWith("/sign-in", StringComparison.Ordinal);
    }

    public static bool IsNewExternalLocation(
        Uri requestUri, string? probeLocation, string? baselineLocation, string probeHost)
    {
        var probeExternal = IsExternalRedirect(requestUri, probeLocation, probeHost);
        var baselineExternal = IsExternalRedirect(requestUri, baselineLocation, probeHost);
        if (probeExternal && !baselineExternal)
            return true;

        var probeProbe = LocationPointsToProbe(requestUri, probeLocation, probeHost);
        var baselineProbe = LocationPointsToProbe(requestUri, baselineLocation, probeHost);
        return probeProbe && !baselineProbe;
    }

    public static bool IsNewOffSiteRefresh(
        Uri requestUri,
        OpenRedirectResponseSignals probe,
        OpenRedirectResponseSignals baseline,
        string probeHost)
    {
        var probeTarget = TryExtractRefreshTarget(probe.RefreshHeader, probe.ResponseBody);
        var baselineTarget = TryExtractRefreshTarget(baseline.RefreshHeader, baseline.ResponseBody);
        if (string.IsNullOrWhiteSpace(probeTarget))
            return false;

        var probeOffSite = IsExternalRedirect(requestUri, probeTarget, probeHost);
        var baselineOffSite = IsExternalRedirect(requestUri, baselineTarget, probeHost);
        if (probeOffSite && !baselineOffSite)
            return true;

        var probeHitsProbe = LocationPointsToProbe(requestUri, probeTarget, probeHost);
        var baselineHitsProbe = LocationPointsToProbe(requestUri, baselineTarget, probeHost);
        return probeHitsProbe && !baselineHitsProbe;
    }

    /// <summary>Parse <c>Refresh</c> header or <c>meta http-equiv=refresh</c> content for a URL target.</summary>
    public static string? TryExtractRefreshTarget(string? refreshHeader, string? htmlBody)
    {
        if (!string.IsNullOrWhiteSpace(refreshHeader))
        {
            var fromHeader = ParseRefreshContent(refreshHeader);
            if (!string.IsNullOrWhiteSpace(fromHeader))
                return fromHeader;
        }

        if (string.IsNullOrWhiteSpace(htmlBody))
            return null;

        var match = MetaRefreshPattern.Match(htmlBody);
        if (!match.Success)
            return null;

        return ParseRefreshContent(match.Groups[1].Value);
    }

    private static string? ParseRefreshContent(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return null;

        var idx = content.IndexOf("url=", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
            return content[(idx + 4)..].Trim().Trim('"', '\'', ';', ' ');

        idx = content.IndexOf("URL=", StringComparison.Ordinal);
        if (idx >= 0)
            return content[(idx + 4)..].Trim().Trim('"', '\'', ';', ' ');

        // Some servers use "0;https://..." without url=
        var semi = content.IndexOf(';');
        if (semi >= 0 && semi + 1 < content.Length)
        {
            var tail = content[(semi + 1)..].Trim();
            if (tail.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                tail.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                tail.StartsWith("//", StringComparison.Ordinal))
                return tail;
        }

        return null;
    }

    private static readonly Regex MetaRefreshPattern = new(
        @"<meta[^>]+http-equiv\s*=\s*[""']?\s*refresh\s*[""']?[^>]*content\s*=\s*[""']([^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static FetchManualParseResult ParseFetchManualResponse(string fetchJson)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(fetchJson);
            var root = doc.RootElement;
            var status = root.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
            return new FetchManualParseResult(
                status,
                TryGetLocationFromFetchJson(fetchJson),
                TryGetRefreshFromFetchJson(fetchJson),
                TryGetBodyFromFetchJson(fetchJson));
        }
        catch
        {
            return new FetchManualParseResult(0, null, null, null);
        }
    }

    public readonly record struct FetchManualParseResult(
        int Status,
        string? Location,
        string? RefreshHeader,
        string? ResponseBody);
}
