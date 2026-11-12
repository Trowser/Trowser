namespace Trowser.Security;

/// <summary>
/// CSP probes for <see cref="FirewallTester"/>. The default set is in-page and does not navigate.
/// Opt-in probes can open a worker or attempt a framed navigation, so they run only when named.
/// </summary>
public static class FirewallCspProbes
{
    public static readonly string[] DefaultIds =
    [
        "inline-script",
        "eval",
        "event-handler",
        "nonce-reuse",
        "base-uri-injection",
        "script-src-data",
        "script-src-blob"
    ];

    public static readonly string[] OptInIds =
    [
        "javascript-url",
        "form-action",
        "frame-src",
        "worker-blob"
    ];

    public static IReadOnlyList<string> Resolve(IReadOnlyCollection<string>? requested, out List<string> unknown)
    {
        unknown = [];
        var known = new HashSet<string>(DefaultIds, StringComparer.OrdinalIgnoreCase);
        foreach (var id in OptInIds)
            known.Add(id);

        if (requested == null || requested.Count == 0)
            return DefaultIds;

        var selected = new List<string>();
        foreach (var id in requested)
        {
            if (string.IsNullOrWhiteSpace(id)) continue;
            if (!known.Contains(id))
            {
                unknown.Add(id);
                continue;
            }

            if (selected.Any(s => s.Equals(id, StringComparison.OrdinalIgnoreCase)))
                continue;
            selected.Add(known.First(k => k.Equals(id, StringComparison.OrdinalIgnoreCase)));
        }

        return selected;
    }

    public static bool Includes(IReadOnlyList<string> selected, string id) =>
        selected.Any(s => s.Equals(id, StringComparison.OrdinalIgnoreCase));
}
