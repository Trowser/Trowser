using Trowser.Security.Runtime;

namespace Trowser.Security.GadgetChains;

public static class GadgetChainPlanner
{
    public sealed class Plan
    {
        public List<string> SelectedProbes { get; init; } = [];
        public List<string> SkippedProbes { get; init; } = [];
        public List<string> TargetGlobalNames { get; set; } = [];
        /// <summary>Names eligible for automatic clobber injection probes (subset of radar leads).</summary>
        public List<string> ClobberProbeNames { get; set; } = [];
        public List<string> Notes { get; init; } = [];
    }

    public static Plan Build(
        IReadOnlyList<GadgetRadarService.GadgetRadarHit> radarHits,
        ClientSurfaceResult? surface,
        bool active,
        IReadOnlyList<string>? requestedProbes)
    {
        var plan = new Plan();
        var want = requestedProbes?.Count > 0
            ? requestedProbes.Select(p => p.Trim().ToLowerInvariant()).ToHashSet(StringComparer.Ordinal)
            : null;

        void Select(string probe, bool eligible, string? skipReason = null)
        {
            if (want != null && !want.Contains(probe))
            {
                plan.SkippedProbes.Add($"{probe}: not-requested");
                return;
            }

            if (!eligible)
            {
                if (skipReason != null)
                    plan.SkippedProbes.Add($"{probe}: {skipReason}");
                return;
            }

            plan.SelectedProbes.Add(probe);
        }

        plan.TargetGlobalNames = radarHits
            .Where(h => h.FirstPartyStack && !string.IsNullOrWhiteSpace(h.Key))
            .OrderByDescending(h => h.Rank)
            .Select(h => h.Key!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();

        plan.ClobberProbeNames = GadgetRadarLeads.SelectClobberProbeNames(radarHits);
        if (surface?.Dom.GuardedGlobals is { Count: > 0 })
        {
            foreach (var g in surface.Dom.GuardedGlobals)
            {
                if (g.Length < 2 || g.Length > 64) continue;
                if (plan.ClobberProbeNames.Any(n => n.Equals(g, StringComparison.OrdinalIgnoreCase)))
                    continue;
                plan.ClobberProbeNames.Add(g);
            }

            plan.Notes.Add(
                $"Guarded globals ({string.Join(", ", surface.Dom.GuardedGlobals.Take(4))}) — clobber probes use typeof-guard pattern, not trap-only reads.");
        }

        Select("clobber", active && plan.ClobberProbeNames.Count > 0,
            plan.ClobberProbeNames.Count == 0
                ? "no clobber-eligible radar leads (script-scan/builtin names are hints only)"
                : null);
        Select("client-pp", active, active ? null : "requires safetyMode active");
        Select("dom-flow-probe", active, active ? null : "requires safetyMode active");

        if (surface?.Dom.ClobberCandidates is { Count: > 0 })
            plan.Notes.Add($"Surface inventory: {surface.Dom.ClobberCandidates.Count} clobber candidate(s).");

        if (radarHits.Count == 0)
            plan.Notes.Add("No gadget-read events — browse with Shadow runtime audit or gadget-radar start.");

        return plan;
    }
}
