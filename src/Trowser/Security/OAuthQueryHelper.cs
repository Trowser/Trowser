namespace Trowser.Security;

internal static class OAuthQueryHelper
{
    internal static string SetQueryParam(string url, string name, string value)
    {
        var uri = new UriBuilder(url);
        var query = ParseQuery(uri.Query);
        query[name] = value;
        uri.Query = query.Count == 0
            ? ""
            : string.Join("&", query.Select(kv =>
                $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        return uri.Uri.ToString();
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var q = query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return dict;
        foreach (var pair in q.Split('&'))
        {
            var eq = pair.IndexOf('=');
            if (eq < 0) continue;
            dict[Uri.UnescapeDataString(pair[..eq])] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }

        return dict;
    }
}
