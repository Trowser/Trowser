using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Race / TOCTOU burst against single-use-looking POSTs discovered from traffic.
/// Flags when concurrent accepts exceed a sequential baseline (not bare multi-2xx on idempotent endpoints).
/// Inspired by PortSwigger race-condition methodology; also influenced by pentest-ai <c>web.race_condition</c>.
/// Highly mutating — active safetyMode only.
/// </summary>
public sealed class RaceConditionScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private const int SequentialBaselineCount = 3;

    public RaceConditionScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class RaceConditionScanOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int BurstSize { get; set; } = 15;
        public int TimeoutMs { get; set; } = 8000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool IncludeRedeemCodeBursts { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class RaceConditionFinding
    {
        public string Category { get; init; } = "race-condition";
        public string Severity { get; init; } = "medium";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string Variant { get; init; } = "concurrent-burst";
        public int AcceptedCount { get; init; }
        public int SequentialAcceptedCount { get; init; }
        public int TotalRequests { get; init; }
        public string MatchReason { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public sealed class RaceConditionScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int BurstsSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<RaceConditionFinding> Findings { get; init; } = [];
        public List<InsecureDesignProbeSupport.ProbeObservation> Observations { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
        public bool HasObservations => Observations.Count > 0;
    }

    public async Task<RaceConditionScanResult> RunAsync(RaceConditionScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running race-condition-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var targets = InsecureDesignDiscovery.DiscoverSingleUsePostTargets(
            _ctx, origin, options.MaxCandidates, options.Urls);

        if (options.IncludeRedeemCodeBursts)
        {
            var redeem = InsecureDesignDiscovery.DiscoverRedeemCodeTargets(_ctx, origin, options.MaxCandidates);
            var seen = new HashSet<string>(targets.Select(t => t.Url), StringComparer.OrdinalIgnoreCase);
            foreach (var t in redeem)
            {
                if (seen.Add(t.Url))
                    targets.Add(t);
            }
        }

        if (targets.Count == 0)
        {
            return new RaceConditionScanResult
            {
                Message = "No single-use POST candidates in network log. Browse workflows (submit, redeem, vote, confirm) first.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var findings = new List<RaceConditionFinding>();
        var observations = new List<InsecureDesignProbeSupport.ProbeObservation>();
        var burstsSent = 0;
        var csrfBlockedBursts = 0;
        var burstSize = Math.Clamp(options.BurstSize, 2, 25);

        _log($"RaceConditionScan: {targets.Count} target(s), sequential={SequentialBaselineCount}, burst={burstSize}", "#888888");

        foreach (var target in targets.Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            var variant = target.MatchReason.Contains("redeem", StringComparison.OrdinalIgnoreCase)
                ? "redeem-code-burst"
                : "concurrent-burst";

            var prepared = await PrepareAsync(target, ct);

            var (seqAccepted, seqResults) = await RunSequentialAsync(
                target, prepared, SequentialBaselineCount, options, ct);
            var (concurrentAccepted, stats, concurrentResults) = await RunBurstAsync(
                target, prepared, burstSize, options, ct);
            burstsSent++;

            if (stats.AllCsrfBlocked)
            {
                csrfBlockedBursts++;
                observations.Add(InsecureDesignProbeSupport.CsrfBlockedObservation(target.Url, stats, prepared));
                continue;
            }

            if (!ExceedsSequentialBaseline(concurrentAccepted, seqAccepted))
                continue;

            var distinctResources = CountDistinctResourceIds(concurrentResults);
            var severity = distinctResources >= 1 ? "high" : "medium";

            var csrfNote = stats.CsrfRejectedCount > 0
                ? $" ({stats.CsrfRejectedCount} CSRF-rejected; remainder accepted — possible race or CSRF single-use side effect.)"
                : "";

            findings.Add(new RaceConditionFinding
            {
                Category = "race-condition",
                Severity = severity,
                Url = target.Url,
                Method = target.Method,
                Variant = variant,
                AcceptedCount = concurrentAccepted,
                SequentialAcceptedCount = seqAccepted,
                TotalRequests = burstSize,
                MatchReason = target.MatchReason,
                Detail =
                    $"Sequential baseline accepted {seqAccepted}/{SequentialBaselineCount}; " +
                    $"concurrent burst accepted {concurrentAccepted}/{burstSize}{csrfNote}. " +
                    (distinctResources >= 1
                        ? $"Varying side-effect ids across concurrent responses: {distinctResources}."
                        : "Uniqueness or rate-limit gate may be non-atomic.")
            });
        }

        var message = findings.Count > 0
            ? $"{findings.Count} race-condition finding(s)."
            : csrfBlockedBursts == burstsSent && burstsSent > 0
                ? $"No race anomalies — all {burstsSent} burst(s) blocked by CSRF validation (inconclusive for race testing)."
                : $"No race anomalies on {burstsSent} burst(s).";

        return new RaceConditionScanResult
        {
            Message = message,
            CandidatesProbed = Math.Min(targets.Count, options.MaxCandidates),
            BurstsSent = burstsSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            Observations = observations
        };
    }

    private static bool ExceedsSequentialBaseline(int concurrentAccepted, int sequentialAccepted) =>
        concurrentAccepted > sequentialAccepted
        || (concurrentAccepted >= 2 && sequentialAccepted <= 1);

    private async Task<InsecureDesignProbeSupport.PreparedRequest> PrepareAsync(
        InsecureDesignDiscovery.PostTarget target,
        CancellationToken ct)
    {
        var bodyTemplate = target.BodyTemplate != null
            ? InsecureDesignDiscovery.NormalizeRaceBody(target.BodyTemplate, 0)
            : null;
        return await InsecureDesignProbeSupport.PrepareRequestAsync(
            _ctx, bodyTemplate, target.Headers, target.Url, injectCsrfIfMissing: true, ct);
    }

    private async Task<(int Accepted, List<SecurityProbeHttp.FetchResult> Results)> RunSequentialAsync(
        InsecureDesignDiscovery.PostTarget target,
        InsecureDesignProbeSupport.PreparedRequest prepared,
        int count,
        RaceConditionScanOptions options,
        CancellationToken ct)
    {
        var results = new List<SecurityProbeHttp.FetchResult>(count);
        for (var i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var result = await SecurityProbeHttp.FetchAsync(
                _ctx,
                target.Url,
                target.Method,
                prepared.Headers,
                prepared.Body,
                options.TimeoutMs,
                options.IncludeBrowserCookies,
                ct);
            results.Add(result);
        }

        var stats = InsecureDesignProbeSupport.SummarizeBurst(results);
        return (stats.AcceptedCount, results);
    }

    private async Task<(int Accepted, InsecureDesignProbeSupport.BurstStats Stats, SecurityProbeHttp.FetchResult[] Results)> RunBurstAsync(
        InsecureDesignDiscovery.PostTarget target,
        InsecureDesignProbeSupport.PreparedRequest prepared,
        int totalRequests,
        RaceConditionScanOptions options,
        CancellationToken ct)
    {
        var tasks = Enumerable.Range(0, totalRequests).Select(_ =>
            SecurityProbeHttp.FetchAsync(
                _ctx,
                target.Url,
                target.Method,
                prepared.Headers,
                prepared.Body,
                options.TimeoutMs,
                options.IncludeBrowserCookies,
                ct)).ToArray();

        var results = await Task.WhenAll(tasks);
        var stats = InsecureDesignProbeSupport.SummarizeBurst(results);
        return (stats.AcceptedCount, stats, results);
    }

    private static int CountDistinctResourceIds(IEnumerable<SecurityProbeHttp.FetchResult> results)
    {
        var sets = new List<IReadOnlyList<string>>();
        foreach (var r in results)
        {
            if (r.Status is < 200 or >= 300)
                continue;
            string? location = null;
            r.ResponseHeaders?.TryGetValue("Location", out location);
            sets.Add(SideEffectIds.Extract(r.Body, location));
        }

        return SideEffectIds.Varying(sets).Count;
    }
}
