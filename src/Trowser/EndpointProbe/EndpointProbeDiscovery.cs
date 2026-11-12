using System.IO;
using Trowser.Automation;
using Trowser.Security;
using Trowser.Security.Orchestration;

namespace Trowser.EndpointProbe;

/// <summary>Builds a prioritized endpoint list from the session network log.</summary>
public static class EndpointProbeDiscovery
{
    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf"
    };

    public static List<EndpointProbeItem> FromNetworkLog(IReadOnlyList<NetworkEntry> entries)
    {
        if (entries.Count == 0)
            return [];

        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(entries.ToList(), includeParameters: false, includeAuth: false,
            includeResponsePatterns: false);

        return entries
            .Where(IsProbeCandidate)
            .GroupBy(e => EndpointProbeItem.ComputeKey(e.Method, e.Url, e.RequestBody), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Timestamp).First())
            .Select(e => ToItem(e, surface))
            .OrderByDescending(i => PriorityRank(i.Priority))
            .ThenBy(i => i.Method, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static List<EndpointProbeItem> Merge(
        IEnumerable<EndpointProbeItem> discovered,
        IEnumerable<EndpointProbeItem> imported)
    {
        var map = new Dictionary<string, EndpointProbeItem>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in discovered)
            map[item.Key] = item;

        foreach (var item in imported)
        {
            if (map.ContainsKey(item.Key))
                continue;
            map[item.Key] = new EndpointProbeItem
            {
                Method = item.Method,
                Url = item.Url,
                Priority = item.Priority,
                RequestHeaders = new Dictionary<string, string>(item.RequestHeaders, StringComparer.OrdinalIgnoreCase),
                RequestBody = item.RequestBody,
                StatusCode = item.StatusCode,
                ResourceType = item.ResourceType,
                IsImported = true
            };
        }

        return map.Values
            .OrderByDescending(i => PriorityRank(i.Priority))
            .ThenBy(i => i.Method, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static EndpointProbeItem ToItem(NetworkEntry entry, AttackSurfaceResult surface)
    {
        var priority = "low";
        foreach (var ep in surface.Endpoints)
        {
            if (PlaybookScopeFilter.EndpointMatches(ep, entry.Url, entry.Method))
            {
                priority = ep.TestPriority;
                break;
            }
        }

        return new EndpointProbeItem
        {
            Method = entry.Method,
            Url = entry.Url,
            Priority = priority,
            Timestamp = entry.Timestamp,
            RequestHeaders = new Dictionary<string, string>(entry.RequestHeaders, StringComparer.OrdinalIgnoreCase),
            RequestBody = entry.RequestBody,
            StatusCode = entry.StatusCode,
            ResourceType = entry.ResourceType
        };
    }

    private static bool IsProbeCandidate(NetworkEntry entry)
    {
        // Exclude Trowser's own probe/fuzzer/replay traffic so scans don't rediscover (and re-fuzz)
        // their own noise — the reason re-opening Endpoint Probe after a run produced mutated bodies.
        if (entry.IsTrowserGenerated)
            return false;
        if (string.IsNullOrEmpty(entry.Url) || entry.StatusCode <= 0)
            return false;
        if (entry.Url.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
            return false;

        var ext = Path.GetExtension(uri.AbsolutePath);
        if (!string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext))
            return false;

        return entry.ResourceType is not ("Image" or "Stylesheet" or "Font" or "Media" or "Script");
    }

    internal static int PriorityRank(string priority) => priority.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1
    };
}
