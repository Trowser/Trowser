using System.Web;

namespace Trowser.Security;

public enum UrlPayloadEncodeMode
{
    /// <summary>Raw payload — use for hash fragments and some DOM XSS bypasses.</summary>
    None,
    /// <summary><see cref="Uri.EscapeDataString"/> — RFC 3986 component encoding.</summary>
    Component,
    /// <summary><see cref="HttpUtility.UrlEncode"/> — application/x-www-form-urlencoded style.</summary>
    Form
}

public enum UrlInjectionPart
{
    Query,
    Hash,
    Path
}

/// <summary>Structured URL payload placement — avoids fragment/query delimiter issues with string templates.</summary>
public sealed class UrlInjectionSpec
{
    public required UrlInjectionPart Part { get; init; }
    /// <summary>Query or hash parameter name. Omit to use the payload as the entire hash fragment.</summary>
    public string? Param { get; init; }
    public UrlPayloadEncodeMode Encode { get; init; } = UrlPayloadEncodeMode.Component;
    /// <summary>When true and Part is Hash with Param, append <c>#param=value</c> instead of replacing the fragment.</summary>
    public bool Append { get; init; }
}

public static class UrlPayloadInjector
{
    public static string Encode(string value, UrlPayloadEncodeMode mode) => mode switch
    {
        UrlPayloadEncodeMode.None => value,
        UrlPayloadEncodeMode.Form => HttpUtility.UrlEncode(value) ?? value,
        _ => Uri.EscapeDataString(value)
    };

    public static string Build(string baseUrl, UrlInjectionSpec spec, string payload)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("baseUrl is required.", nameof(baseUrl));

        if (!Uri.TryCreate(baseUrl.Trim(), UriKind.Absolute, out var uri))
            throw new ArgumentException($"Invalid base URL: {baseUrl}", nameof(baseUrl));

        var encoded = Encode(payload, spec.Encode);

        return spec.Part switch
        {
            UrlInjectionPart.Query => BuildQuery(uri, spec.Param ?? "q", encoded),
            UrlInjectionPart.Hash => BuildHash(uri, spec.Param, encoded, spec.Append),
            UrlInjectionPart.Path => BuildPath(uri, encoded),
            _ => throw new ArgumentOutOfRangeException(nameof(spec.Part))
        };
    }

    public static UrlInjectionSpec ParsePart(string? partName)
    {
        return partName?.Trim().ToLowerInvariant() switch
        {
            "query" or "url-query" => new UrlInjectionSpec { Part = UrlInjectionPart.Query },
            "hash" or "fragment" or "url-hash" => new UrlInjectionSpec { Part = UrlInjectionPart.Hash },
            "path" or "url-path" => new UrlInjectionSpec { Part = UrlInjectionPart.Path },
            _ => throw new ArgumentException($"Unknown URL injection part: {partName}")
        };
    }

    public static UrlPayloadEncodeMode ParseEncodeMode(string? mode, UrlPayloadEncodeMode defaultMode)
    {
        if (string.IsNullOrWhiteSpace(mode)) return defaultMode;
        return mode.Trim().ToLowerInvariant() switch
        {
            "none" or "raw" => UrlPayloadEncodeMode.None,
            "form" or "urlencode" => UrlPayloadEncodeMode.Form,
            "component" or "uri" or "escaped" => UrlPayloadEncodeMode.Component,
            _ => defaultMode
        };
    }

    /// <summary>Query parameters injected by Trowser tools (not part of the application URL).</summary>
    private static readonly HashSet<string> ToolQueryParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "_trowser_rc"
    };

    /// <summary>
    /// Removes tool-injected query parameters so reported URLs and param lists match what the app saw.
    /// </summary>
    public static string StripToolQueryParams(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url ?? "";
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return url;

        var builder = new UriBuilder(uri);
        var query = ParseQuery(builder.Query);
        var removed = false;
        foreach (var key in ToolQueryParams)
        {
            if (query.Remove(key))
                removed = true;
        }

        if (!removed)
            return url;

        builder.Query = query.Count == 0
            ? ""
            : string.Join("&",
                query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return builder.Uri.ToString();
    }

    /// <summary>
    /// Adds a cache-busting query parameter so hash/fragment changes trigger a full document load.
    /// Hash-only navigation does not re-run inline scripts (e.g. document.write sinks at parse time).
    /// </summary>
    public static string EnsureFullNavigation(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return url;

        var builder = new UriBuilder(uri);
        var query = ParseQuery(builder.Query);
        query["_trowser_rc"] = Guid.NewGuid().ToString("N")[..8];
        builder.Query = string.Join("&",
            query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return builder.Uri.ToString();
    }

    /// <summary>Strip the fragment for baseline page loads (param discovery, clean reload).</summary>
    public static string StripFragment(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return url;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return url;

        var builder = new UriBuilder(uri) { Fragment = "" };
        return builder.Uri.ToString();
    }

    /// <summary>True when the URL fragment looks like an SPA client route (e.g. <c>#/search</c>).</summary>
    public static bool IsSpaHashRoute(string fragment)
    {
        var route = fragment.TrimStart('#');
        return route.StartsWith('/') || route.StartsWith('!');
    }

    private static string BuildQuery(Uri uri, string paramName, string encodedValue)
    {
        var fragment = uri.Fragment.TrimStart('#');
        if (IsSpaHashRoute(fragment))
        {
            var builder = new UriBuilder(uri)
            {
                Fragment = SetHashRouteQuery(fragment, paramName, encodedValue)
            };
            return builder.Uri.ToString();
        }

        var queryBuilder = new UriBuilder(uri);
        var query = ParseQuery(queryBuilder.Query);
        query[paramName] = encodedValue;
        queryBuilder.Query = string.Join("&",
            query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={kv.Value}"));
        return queryBuilder.Uri.ToString();
    }

    private static string BuildHash(Uri uri, string? paramName, string encodedValue, bool append)
    {
        var builder = new UriBuilder(uri);
        if (string.IsNullOrEmpty(paramName))
        {
            builder.Fragment = encodedValue;
            return builder.Uri.ToString();
        }

        var fragment = builder.Fragment.TrimStart('#');
        if (IsSpaHashRoute(fragment))
        {
            builder.Fragment = SetHashRouteQuery(fragment, paramName, encodedValue);
            return builder.Uri.ToString();
        }

        if (append && fragment.Length > 0)
            builder.Fragment = fragment + "&" + $"{paramName}={encodedValue}";
        else
            builder.Fragment = $"{paramName}={encodedValue}";

        return builder.Uri.ToString();
    }

    private static string SetHashRouteQuery(string fragment, string paramName, string encodedValue)
    {
        var qIdx = fragment.IndexOf('?');
        if (qIdx >= 0)
        {
            var path = fragment[..qIdx];
            var query = ParseQuery(fragment[qIdx..]);
            query[paramName] = encodedValue;
            var qs = string.Join("&",
                query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={kv.Value}"));
            return path + "?" + qs;
        }

        return fragment + "?" + $"{paramName}={encodedValue}";
    }

    private static string BuildPath(Uri uri, string encodedSegment)
    {
        var path = uri.AbsolutePath.TrimEnd('/');
        if (!path.EndsWith('/')) path += "/";
        path += encodedSegment;
        var builder = new UriBuilder(uri) { Path = path };
        return builder.Uri.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;
        var q = query.TrimStart('?');
        foreach (var pair in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0)
                result[Uri.UnescapeDataString(pair)] = "";
            else
            {
                var key = Uri.UnescapeDataString(pair[..eq]);
                var val = Uri.UnescapeDataString(pair[(eq + 1)..]);
                result[key] = val;
            }
        }
        return result;
    }
}
