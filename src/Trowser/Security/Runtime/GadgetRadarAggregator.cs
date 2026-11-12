namespace Trowser.Security.Runtime;

internal static class GadgetRadarAggregator
{
    internal static readonly string[] DefaultProtoTrapKeys =
    [
        "src", "href", "url", "data", "html", "template", "policy", "nonce", "innerHTML"
    ];

    public static List<GadgetRadarService.GadgetRadarHit> RankHits(
        IReadOnlyList<RuntimeEvent> events,
        string? pageOrigin,
        IReadOnlyCollection<string> scriptOrigins)
    {
        var grouped = events
            .GroupBy(e => $"{e.Kind}|{e.Name}", StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var first = g.OrderByDescending(e => e.Stack?.Length ?? 0).First();
                first.Extra.TryGetValue("key", out var key);
                first.Extra.TryGetValue("receiver", out var receiver);
                first.Extra.TryGetValue("prop", out var prop);
                var discovery = GadgetChains.GadgetRadarLeads.NormalizeDiscovery(first);
                var fp = g.Any(e => SinkStackAnalyzer.IsFirstPartyStack(e.Stack, pageOrigin, scriptOrigins));
                var stackSample = g.Select(e => e.Stack).FirstOrDefault(s => SinkStackAnalyzer.HasPageFrame(s));
                var count = g.Count();
                if (first.Extra.TryGetValue("count", out var cStr) && int.TryParse(cStr, out var parsed))
                    count = Math.Max(count, parsed);

                var hit = new GadgetRadarService.GadgetRadarHit
                {
                    Name = first.Name,
                    Key = key ?? ExtractKeyFromName(first.Name),
                    Receiver = receiver,
                    Count = count,
                    FirstPartyStack = fp,
                    SampleStack = stackSample?.Length > 400 ? stackSample[..400] : stackSample,
                    Discovery = discovery,
                    Rank = Score(fp, count, first.Kind, discovery),
                    Prop = string.IsNullOrWhiteSpace(prop) ? null : prop
                };
                return new GadgetRadarService.GadgetRadarHit
                {
                    Name = hit.Name,
                    Key = hit.Key,
                    Receiver = hit.Receiver,
                    Count = hit.Count,
                    FirstPartyStack = hit.FirstPartyStack,
                    SampleStack = hit.SampleStack,
                    Discovery = hit.Discovery,
                    Rank = hit.Rank,
                    Prop = hit.Prop,
                    ClobberProbeCandidate = GadgetChains.GadgetRadarLeads.IsClobberProbeCandidate(hit)
                };
            })
            .OrderByDescending(h => h.Rank)
            .ThenByDescending(h => h.Count)
            .Take(40)
            .ToList();

        return grouped;
    }

    private static int Score(bool firstParty, int count, string kind, string discovery)
    {
        var s = firstParty ? 100 : 20;
        s += Math.Min(count, 50);
        if (kind.Equals("proto-read", StringComparison.OrdinalIgnoreCase))
            s += 15;
        if (discovery.Equals(GadgetChains.GadgetRadarLeads.DiscoveryScriptScan, StringComparison.OrdinalIgnoreCase))
            s -= 40;
        else if (discovery.Equals(GadgetChains.GadgetRadarLeads.DiscoveryTrap, StringComparison.OrdinalIgnoreCase))
            s += 25;
        return s;
    }

    private static string? ExtractKeyFromName(string name)
    {
        var dot = name.LastIndexOf('.');
        return dot >= 0 && dot < name.Length - 1 ? name[(dot + 1)..] : name;
    }
}
