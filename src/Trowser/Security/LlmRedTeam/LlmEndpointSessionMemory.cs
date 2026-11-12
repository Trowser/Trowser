using System.Collections.Concurrent;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Remembers high-confidence LLM HTTP endpoints for the browser session/host so discovery
/// still works after navigation clears the page network log.
/// </summary>
public static class LlmEndpointSessionMemory
{
    private static readonly ConcurrentDictionary<string, List<LlmEndpointHint>> ByHost = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, List<LlmHttpMcpHint>> McpByHost = new(StringComparer.OrdinalIgnoreCase);

    public static void Remember(string? host, IEnumerable<LlmEndpointHint> endpoints)
    {
        host = NormalizeHost(host);
        if (host == null) return;

        var kept = endpoints
            .Where(e => e.Confidence >= 40 && !string.IsNullOrWhiteSpace(e.Url))
            .GroupBy(e => NormalizeKey(e.Url), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Confidence).First())
            .ToList();
        if (kept.Count == 0) return;

        ByHost.AddOrUpdate(host, _ => kept,
            (_, existing) => MergeEndpoints(existing, kept));
    }

    public static void RememberMcp(string? host, IEnumerable<LlmHttpMcpHint> endpoints)
    {
        host = NormalizeHost(host);
        if (host == null) return;
        var kept = endpoints.Where(e => e.Confidence >= 40).ToList();
        if (kept.Count == 0) return;
        McpByHost.AddOrUpdate(host, _ => kept,
            (_, existing) =>
            {
                var map = existing.ToDictionary(e => NormalizeKey(e.Url), StringComparer.OrdinalIgnoreCase);
                foreach (var e in kept)
                    map[NormalizeKey(e.Url)] = e;
                return map.Values.OrderByDescending(e => e.Confidence).Take(10).ToList();
            });
    }

    public static IReadOnlyList<LlmEndpointHint> GetRemembered(string? host)
    {
        host = NormalizeHost(host);
        if (host == null || !ByHost.TryGetValue(host, out var list))
            return [];
        return list;
    }

    public static IReadOnlyList<LlmHttpMcpHint> GetRememberedMcp(string? host)
    {
        host = NormalizeHost(host);
        if (host == null || !McpByHost.TryGetValue(host, out var list))
            return [];
        return list;
    }

    public static void Clear(string? host = null)
    {
        host = NormalizeHost(host);
        if (host == null)
        {
            ByHost.Clear();
            McpByHost.Clear();
            return;
        }

        ByHost.TryRemove(host, out _);
        McpByHost.TryRemove(host, out _);
    }

    private static List<LlmEndpointHint> MergeEndpoints(List<LlmEndpointHint> existing, List<LlmEndpointHint> incoming)
    {
        var map = existing.ToDictionary(e => NormalizeKey(e.Url), StringComparer.OrdinalIgnoreCase);
        foreach (var e in incoming)
        {
            var key = NormalizeKey(e.Url);
            map.TryGetValue(key, out var prev);
            map[key] = PreferRicherSample(prev, e);
        }
        return map.Values.OrderByDescending(e => e.Confidence).Take(30).ToList();
    }

    private static LlmEndpointHint PreferRicherSample(LlmEndpointHint? prev, LlmEndpointHint next)
    {
        if (prev == null) return next;
        if (string.IsNullOrWhiteSpace(next.SampleRequestBody) && !string.IsNullOrWhiteSpace(prev.SampleRequestBody))
        {
            return new LlmEndpointHint
            {
                Url = prev.Url,
                Method = prev.Method,
                Source = string.IsNullOrEmpty(prev.Source) ? "session" : prev.Source,
                MatchReason = prev.MatchReason,
                ContentType = prev.ContentType,
                IsSse = prev.IsSse,
                Confidence = Math.Max(prev.Confidence, next.Confidence),
                SampleRequestBody = prev.SampleRequestBody
            };
        }
        if (!string.IsNullOrWhiteSpace(next.SampleRequestBody)
            && (string.IsNullOrWhiteSpace(prev.SampleRequestBody)
                || next.SampleRequestBody!.Length >= (prev.SampleRequestBody?.Length ?? 0)))
            return next;
        return next.Confidence >= prev.Confidence ? next : prev;
    }

    private static string? NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return null;
        if (Uri.TryCreate(host, UriKind.Absolute, out var uri))
            return uri.Host.ToLowerInvariant();
        return host.Trim().ToLowerInvariant();
    }

    private static string NormalizeKey(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Trim().ToLowerInvariant();
        return $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}".TrimEnd('/').ToLowerInvariant();
    }
}
