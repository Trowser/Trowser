namespace Trowser.Security;

/// <summary>URL-shaped bypass probes for client-side navigation sinks (DOM open redirect).</summary>
internal static class TraceInputRedirectBypassProbes
{
    public static IEnumerable<XssBypassProbes.Probe> GetProbes(int maxAttempts, string? sameOriginPrefix = null)
    {
        var host = RedirectAnalysis.DefaultProbeHost;
        var token = Guid.NewGuid().ToString("N")[..10];
        var path = $"/trowser-or-{token}";

        var candidates = new List<XssBypassProbes.Probe>
        {
            new("dom-or-protocol-relative", $"//{host}{path}", "Protocol-relative off-site navigation"),
            new("dom-or-backslash", $"/\\{host}{path}", "Backslash path bypass toward off-site host"),
            new("dom-or-encoded-slash", $"/%2f%2f{host}{path}", "Encoded slashes toward off-site host"),
            new("dom-or-at-trick", $"/@{host}{path}", "@-trick path toward off-site host"),
            new("dom-or-slash-dot-dot", $"/../{host}{path}", "Dot-dot path segment toward off-site host"),
        };

        if (!string.IsNullOrWhiteSpace(sameOriginPrefix))
        {
            var prefix = sameOriginPrefix.TrimEnd('/');
            candidates.Add(new("dom-or-prefix-protocol-relative", $"{prefix}//{host}{path}",
                "Allowlisted prefix + protocol-relative"));
            candidates.Add(new("dom-or-prefix-at", $"{prefix}@{host}{path}", "Allowlisted prefix + @ trick"));
        }

        foreach (var p in RedirectParamDiscovery.BuildPayloads(host, sameOriginPrefix ?? "/", includeAdaptive: false)
                     .Take(Math.Max(3, maxAttempts)))
        {
            if (p.Contains('<', StringComparison.Ordinal))
                continue;
            candidates.Add(new("dom-or-http-catalog", p, "Shared open-redirect bypass catalog"));
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var count = 0;
        foreach (var probe in candidates)
        {
            if (!seen.Add(probe.Payload)) continue;
            yield return probe;
            if (++count >= maxAttempts) yield break;
        }
    }
}
