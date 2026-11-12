using Trowser.Security;

namespace Trowser.Security.GadgetChains;

/// <summary>Query/form param names for reflected DOM clobber probes (client-surface + runtime discovery).</summary>
internal static class ClobberParamDiscovery
{
    private static readonly string[] FallbackNames =
    [
        "comment", "q", "search", "query", "default", "next", "name", "text", "msg", "message"
    ];

    public static IReadOnlyList<string> Collect(ClientSurfaceResult? surface, DomRuntimeInjectionDiscovery.DiscoveryResult? discovery)
    {
        var ordered = new List<string>();
        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            if (ordered.Any(x => x.Equals(name, StringComparison.OrdinalIgnoreCase))) return;
            ordered.Add(name);
        }

        if (discovery != null)
        {
            foreach (var p in discovery.QueryParams)
                Add(p);
            foreach (var p in discovery.HashParams)
                Add(p);
        }

        if (surface?.Script?.LocationParams is { Count: > 0 } locParams)
        {
            foreach (var p in locParams)
                Add(p);
        }

        foreach (var p in FallbackNames)
            Add(p);

        return ordered.Take(10).ToList();
    }
}
