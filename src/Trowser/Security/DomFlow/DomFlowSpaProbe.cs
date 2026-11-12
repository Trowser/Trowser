using System.Web;

namespace Trowser.Security.DomFlow;

/// <summary>
/// Hash-router SPA probe URL builders (Angular, Vue router, Juice Shop <c>#/search?q=</c>).
/// </summary>
internal static class DomFlowSpaProbe
{
    internal static bool IsHashRouterUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        var frag = uri.Fragment;
        return frag.StartsWith("#/", StringComparison.Ordinal)
               || frag.StartsWith("#!/", StringComparison.Ordinal);
    }

    /// <summary>
    /// Probe URLs for attacker-controlled input on hash-router apps.
    /// Mutates query keys already present on the URL (and discovered names) before synthetic fallbacks.
    /// </summary>
    internal static IReadOnlyList<string> BuildQueryProbeUrls(
        string url,
        string payload,
        IReadOnlyList<string>? discoveredParamNames = null)
    {
        var encoded = Uri.EscapeDataString(payload);
        var paramNames = CollectQueryParamNames(url, discoveredParamNames);
        var list = new List<string>();

        if (!IsHashRouterUrl(url))
        {
            foreach (var param in paramNames)
                list.Add(SetDocumentQueryParam(url, param, encoded));
            if (list.Count == 0)
                list.Add(BuildDocumentQueryProbeUrl(url, encoded));
            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        foreach (var param in paramNames)
            list.Add(SetHashRouteQueryParam(url, param, encoded));

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    internal static string BuildDocumentQueryProbeUrl(string url, string encodedPayload)
    {
        return SetDocumentQueryParam(url, "trowser_q", encodedPayload);
    }

    /// <summary>Legacy: entire fragment is the payload (non-router hash sinks).</summary>
    internal static string BuildRawHashPayloadUrl(string url, string encodedPayload)
    {
        var baseUrl = url.Split('#')[0];
        return baseUrl + "#" + encodedPayload;
    }

    internal static List<string> CollectQueryParamNames(string url, IReadOnlyList<string>? discoveredParamNames)
    {
        var ordered = new List<string>();
        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            if (ordered.Any(p => p.Equals(name, StringComparison.OrdinalIgnoreCase))) return;
            ordered.Add(name);
        }

        var fromUrl = ExtractQueryParamNamesFromUrl(url).ToList();
        foreach (var name in fromUrl)
            Add(name);
        if (discoveredParamNames != null)
        {
            foreach (var name in discoveredParamNames)
                Add(name);
        }

        // When the live URL already names query/hash params, avoid spraying unrelated fallback keys
        // (each key is a full navigation during dom-flow probe).
        if (fromUrl.Count == 0 && (discoveredParamNames == null || discoveredParamNames.Count == 0))
        {
            foreach (var fallback in new[]
                     {
                         "q", "search", "query", "trowser_q",
                         "next", "url", "redirect", "return", "returnUrl", "dest", "destination", "continue", "target", "back"
                     })
                Add(fallback);
        }

        return ordered;
    }

    internal static IEnumerable<string> ExtractQueryParamNamesFromUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            foreach (var name in ParseQueryParamNames(uri.Query))
                yield return name;
        }

        var hashIdx = url.IndexOf('#');
        if (hashIdx < 0) yield break;
        var hash = url[hashIdx..];
        var qIdx = hash.IndexOf('?', StringComparison.Ordinal);
        if (qIdx < 0) yield break;
        foreach (var name in ParseQueryParamNames(hash[(qIdx + 1)..]))
            yield return name;
    }

    private static IEnumerable<string> ParseQueryParamNames(string queryPart)
    {
        if (string.IsNullOrWhiteSpace(queryPart)) yield break;
        var q = queryPart.TrimStart('?');
        foreach (var pair in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var raw = eq > 0 ? pair[..eq] : pair;
            if (string.IsNullOrWhiteSpace(raw)) continue;
            yield return HttpUtility.UrlDecode(raw);
        }
    }

    internal static string SetDocumentQueryParam(string url, string param, string encodedValue)
    {
        var hashIdx = url.IndexOf('#');
        var beforeHash = hashIdx >= 0 ? url[..hashIdx] : url;
        var hash = hashIdx >= 0 ? url[hashIdx..] : "";
        return SetQueryOnPath(beforeHash, param, encodedValue) + hash;
    }

    internal static string SetHashRouteQueryParam(string url, string param, string encodedValue)
    {
        var hashIdx = url.IndexOf('#');
        if (hashIdx < 0)
            return SetDocumentQueryParam(url, param, encodedValue);

        var beforeHash = url[..hashIdx];
        var hash = url[hashIdx..];
        var qIdx = hash.IndexOf('?', StringComparison.Ordinal);
        if (qIdx < 0)
            return beforeHash + hash + "?" + param + "=" + encodedValue;

        var route = hash[..qIdx];
        var query = hash[(qIdx + 1)..];
        return beforeHash + route + "?" + MergeQueryParam(query, param, encodedValue);
    }

    private static string SetQueryOnPath(string urlWithoutFragment, string param, string encodedValue)
    {
        var qIdx = urlWithoutFragment.IndexOf('?', StringComparison.Ordinal);
        if (qIdx < 0)
            return urlWithoutFragment + "?" + param + "=" + encodedValue;

        var path = urlWithoutFragment[..qIdx];
        var query = urlWithoutFragment[(qIdx + 1)..];
        return path + "?" + MergeQueryParam(query, param, encodedValue);
    }

    private static string MergeQueryParam(string query, string param, string encodedValue)
    {
        var pairs = new List<string>();
        var replaced = false;
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var key = eq > 0 ? pair[..eq] : pair;
            if (key.Equals(param, StringComparison.OrdinalIgnoreCase))
            {
                pairs.Add(param + "=" + encodedValue);
                replaced = true;
            }
            else
            {
                pairs.Add(pair);
            }
        }

        if (!replaced)
            pairs.Add(param + "=" + encodedValue);

        return string.Join("&", pairs);
    }
}
