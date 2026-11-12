using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Discover URL query/hash parameters and storage keys the live app reads (beyond inline-script heuristics).
/// </summary>
public static class DomRuntimeInjectionDiscovery
{
    public sealed record DiscoveryResult(
        IReadOnlyList<string> QueryParams,
        IReadOnlyList<string> HashParams,
        IReadOnlyList<string> StorageKeys,
        string? Notes);

    public static async Task<DiscoveryResult> DiscoverAsync(AutomationContext ctx)
    {
        var hashFromDom = await DomUrlParamDiscovery.DiscoverAsync(ctx);
        var json = await ctx.ExecuteJs("""
            (function(){
                var query = new Set();
                var hash = new Set();
                var storage = new Set();
                try {
                    new URLSearchParams(location.search).forEach(function(v,k){ query.add(k); });
                } catch(e) {}
                try {
                    var frag = (location.hash || '').replace(/^#/, '');
                    var q = frag.indexOf('?');
                    var part = q >= 0 ? frag.slice(q + 1) : frag;
                    if (part.indexOf('=') >= 0) {
                        part.split('&').forEach(function(pair){
                            var eq = pair.indexOf('=');
                            if (eq > 0) hash.add(decodeURIComponent(pair.slice(0, eq)));
                        });
                    }
                } catch(e) {}
                try {
                    for (var i = 0; i < localStorage.length; i++) storage.add(localStorage.key(i));
                } catch(e) {}
                try {
                    for (var i = 0; i < sessionStorage.length; i++) storage.add(sessionStorage.key(i));
                } catch(e) {}
                return JSON.stringify({
                    query: Array.from(query),
                    hash: Array.from(hash),
                    storage: Array.from(storage)
                });
            })()
            """);

        var queryParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hashParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var storageKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (hashFromDom?.PreferredQueryParam != null)
            queryParams.Add(hashFromDom.PreferredQueryParam);
        if (hashFromDom?.PreferredHashParam != null)
            hashParams.Add(hashFromDom.PreferredHashParam);

        try
        {
            using var doc = JsonDocument.Parse(Unquote(json));
            AddStrings(doc.RootElement, "query", queryParams);
            AddStrings(doc.RootElement, "hash", hashParams);
            AddStrings(doc.RootElement, "storage", storageKeys);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        if (queryParams.Count == 0)
            queryParams.Add("q");

        var notes = hashFromDom?.SourceHint;
        return new DiscoveryResult(
            queryParams.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            hashParams.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            storageKeys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            notes);
    }

    private static void AddStrings(JsonElement root, string prop, HashSet<string> into)
    {
        if (!root.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return;
        foreach (var el in arr.EnumerateArray())
        {
            var s = el.GetString();
            if (!string.IsNullOrWhiteSpace(s))
                into.Add(s);
        }
    }

    private static string Unquote(string? json)
    {
        if (string.IsNullOrEmpty(json)) return "{}";
        var s = json.Trim();
        if (s.Length >= 2 && s[0] == '"')
        {
            try { return JsonSerializer.Deserialize<string>(s) ?? "{}"; }
            catch { return "{}"; }
        }
        return s;
    }
}
