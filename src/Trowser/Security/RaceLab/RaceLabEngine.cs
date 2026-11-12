using System.Diagnostics;
using System.Text.RegularExpressions;
using Trowser.Api;
using Trowser.Automation;

namespace Trowser.Security.RaceLab;

public sealed class RaceLabEngine
{
    private readonly AutomationContext _ctx;
    private readonly PeerRegistry? _peers;
    private readonly Action<string, string> _log;
    private readonly Random _random = new();

    public RaceLabEngine(AutomationContext ctx, PeerRegistry? peers, Action<string, string> log)
    {
        _ctx = ctx;
        _peers = peers;
        _log = log;
    }

    public static List<RaceLabRequest> ExpandSessions(
        IReadOnlyList<RaceLabRequest> requests,
        PeerRegistry? peers)
    {
        var peerNames = peers?.GetAll().Select(p => p.Name).ToList() ?? [];
        var list = new List<RaceLabRequest>();
        foreach (var req in requests)
        {
            foreach (var session in RaceLabSessions.Expand(req.Session, peerNames))
            {
                var clone = req.Clone();
                clone.Session = session;
                list.Add(clone);
            }
        }

        return list;
    }

    public async Task<RaceLabSyncResult> SynchronizeAsync(
        IReadOnlyList<RaceLabRequest> requests,
        RaceLabParameters parameters,
        bool ensurePeerOrigin,
        CancellationToken ct = default)
    {
        var expanded = ExpandSessions(requests, _peers);
        if (expanded.Count == 0)
            return new RaceLabSyncResult();

        _log("Race Lab: Synchronizing timing across sessions (latency compensation)...", "#888888");

        var sessions = expanded
            .Select(r => RaceLabSessions.Normalize(r.Session))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var medianRtt = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
        foreach (var session in sessions)
        {
            ct.ThrowIfCancellationRequested();
            var sampleRequest = expanded.First(r =>
                string.Equals(RaceLabSessions.Normalize(r.Session), session, StringComparison.OrdinalIgnoreCase));

            if (ensurePeerOrigin
                && _peers != null
                && !string.Equals(session, RaceLabSessions.Driver, StringComparison.OrdinalIgnoreCase))
            {
                var (_, err) = await _peers.EnsureOriginAsync(session, sampleRequest.Url);
                if (err != null)
                    _log($"Race Lab: peer \"{session}\" origin warning: {err}", "#F44747");
            }

            var probeUrl = RaceLabHttp.ProbeUrlForRequest(sampleRequest);
            var rtt = await RaceLabHttp.ProbeRttAsync(
                _ctx, _peers, session, probeUrl, parameters.TimeoutMs, parameters.IncludeBrowserCookies, ct);
            medianRtt[session] = rtt;
            _log($"Race Lab: session \"{session}\" median RTT {rtt:F1} ms", "#888888");
        }

        var max = medianRtt.Values.DefaultIfEmpty(0).Max();
        var offsets = medianRtt.ToDictionary(
            kv => kv.Key,
            kv => (int)Math.Max(0, Math.Round(max - kv.Value)),
            StringComparer.OrdinalIgnoreCase);

        return new RaceLabSyncResult
        {
            MedianRttMs = medianRtt,
            DispatchOffsetMs = offsets
        };
    }

    public async Task<List<RaceLabTimelineEntry>> RunBaselineAsync(
        RaceLabProfile profile,
        CancellationToken ct = default)
    {
        _log("Race Lab: Running baseline (one soft pass per request)...", "#888888");
        var baseline = new List<RaceLabTimelineEntry>();
        var offset = 0L;

        var requests = ExpandSessions(profile.Requests, _peers);
        foreach (var request in requests)
        {
            ct.ThrowIfCancellationRequested();
            var entry = await FireShotAsync(
                request,
                profile.Parameters,
                batchIndex: 0,
                shotIndex: baseline.Count,
                phase: "baseline",
                dispatchDelayMs: 0,
                batchStartUtc: DateTimeOffset.UtcNow,
                ct);
            baseline.Add(CopyTimelineEntry(entry, offsetMs: offset));
            offset += (long)Math.Max(1, entry.LatencyMs);
        }

        return baseline;
    }

    public async Task<RaceLabRunResult> RunFullAsync(
        RaceLabProfile profile,
        RaceLabRunOptions options,
        IReadOnlyDictionary<string, int>? dispatchOffsets = null,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        if (profile.Requests.Count == 0)
        {
            return new RaceLabRunResult
            {
                Message = "No requests configured.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        RaceLabSyncResult? sync = null;
        if (options.RunSync)
        {
            sync = await SynchronizeAsync(profile.Requests, profile.Parameters, options.EnsurePeerOrigin, ct);
            dispatchOffsets = sync.DispatchOffsetMs;
        }

        List<RaceLabTimelineEntry> baseline = [];
        if (options.RunBaseline)
            baseline = await RunBaselineAsync(profile, ct);

        dispatchOffsets ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        var expandedRequests = ExpandSessions(profile.Requests, _peers);
        var timeline = new List<RaceLabTimelineEntry>();
        var parameters = profile.Parameters.Clamped();
        var batchIndex = 0;
        var runStart = DateTimeOffset.UtcNow;

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (parameters.DurationMs > 0
                && (DateTimeOffset.UtcNow - runStart).TotalMilliseconds >= parameters.DurationMs)
                break;
            if (parameters.DurationMs <= 0 && batchIndex >= Math.Max(1, parameters.TotalBatches))
                break;

            var shots = BuildBatchShots(expandedRequests, parameters);
            if (parameters.RandomizeOrder)
                shots = shots.OrderBy(_ => _random.Next()).ToList();

            _log($"Race Lab: Burst {batchIndex + 1} ({shots.Count} shot(s), mode {parameters.Mode})...", "#569CD6");

            var batchStart = DateTimeOffset.UtcNow;

            if (parameters.Mode == RaceLabMode.Sequential)
            {
                var shotIndex = 0;
                foreach (var shot in shots)
                {
                    if (parameters.DelayPerRequestMs > 0 && shotIndex > 0)
                        await Task.Delay(parameters.DelayPerRequestMs, ct);

                    var entry = await FireShotAsync(
                        shot,
                        parameters,
                        batchIndex,
                        shotIndex,
                        "burst",
                        GetDispatchDelay(dispatchOffsets, shot, parameters),
                        batchStart,
                        ct);
                    timeline.Add(entry);
                    shotIndex++;
                }
            }
            else
            {
                var tasks = shots.Select(async (shot, shotIndex) =>
                {
                    var delay = GetDispatchDelay(dispatchOffsets, shot, parameters);
                    if (delay > 0)
                        await Task.Delay(delay, ct);

                    return await FireShotAsync(
                        shot,
                        parameters,
                        batchIndex,
                        shotIndex,
                        "burst",
                        delay,
                        batchStart,
                        ct);
                }).ToArray();

                var entries = await Task.WhenAll(tasks);
                timeline.AddRange(entries);
            }

            batchIndex++;
            if (parameters.DelayBetweenBatchesMs > 0)
                await Task.Delay(parameters.DelayBetweenBatchesMs, ct);
        }

        sw.Stop();
        var findings = RaceLabAnalyzer.Analyze(profile, baseline, timeline, sync);
        var summary = BuildSummary(findings, timeline);

        var message = findings.Count > 0
            ? $"{findings.Count} Race Lab finding(s)."
            : $"No anomalies in {timeline.Count} burst request(s).";

        return new RaceLabRunResult
        {
            Message = message,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Sync = sync,
            Baseline = baseline,
            Timeline = timeline,
            Findings = findings,
            Summary = summary
        };
    }

    private static List<string> BuildSummary(List<UnifiedSecurityFinding> findings, List<RaceLabTimelineEntry> timeline)
    {
        var summary = new List<string>();
        if (findings.Count > 0)
            summary.Add($"{findings.Count} finding(s) across {timeline.Count} burst request(s).");
        else
            summary.Add($"Clean burst run ({timeline.Count} request(s)).");

        var errors = timeline.Count(e => e.Status >= 500);
        if (errors > 0)
            summary.Add($"{errors} server error response(s) observed.");

        return summary;
    }

    private int GetDispatchDelay(
        IReadOnlyDictionary<string, int> offsets,
        RaceLabRequest shot,
        RaceLabParameters parameters)
    {
        var session = RaceLabSessions.Normalize(shot.Session);
        offsets.TryGetValue(session, out var baseOffset);
        var jitter = parameters.JitterMs > 0 ? _random.Next(0, parameters.JitterMs + 1) : 0;
        return baseOffset + jitter;
    }

    internal static List<RaceLabRequest> BuildBatchShots(
        IReadOnlyList<RaceLabRequest> requests,
        RaceLabParameters parameters)
    {
        if (requests.Count == 0)
            return [];

        return parameters.Mode switch
        {
            RaceLabMode.Spike => requests.Select(r => r.Clone()).ToList(),
            RaceLabMode.Sequential => requests.Select(r => r.Clone()).ToList(),
            _ => ExpandReplicas(requests, Math.Max(1, parameters.RequestsPerBatch))
        };
    }

    private static List<RaceLabRequest> ExpandReplicas(IReadOnlyList<RaceLabRequest> requests, int replicasPerRequest)
    {
        var list = new List<RaceLabRequest>();
        foreach (var req in requests)
        {
            for (var i = 0; i < replicasPerRequest; i++)
                list.Add(req.Clone());
        }

        return list;
    }

    private async Task<RaceLabTimelineEntry> FireShotAsync(
        RaceLabRequest request,
        RaceLabParameters parameters,
        int batchIndex,
        int shotIndex,
        string phase,
        int dispatchDelayMs,
        DateTimeOffset batchStartUtc,
        CancellationToken ct)
    {
        var firedAt = DateTimeOffset.UtcNow;
        var resp = await RaceLabHttp.FetchAsync(_ctx, _peers, request, parameters, ct);
        var offsetMs = (long)(firedAt - batchStartUtc).TotalMilliseconds;

        var body = resp.Body ?? "";
        var snippet = body.Length > 240 ? body[..240] : body;
        var accepted = resp.Error == null
                       && InsecureDesignProbeSupport.ClassifyResponse(resp.Status, body)
                           == InsecureDesignProbeSupport.ProbeResponseKind.Accepted;
        var sideEffectIds = accepted
            ? SideEffectIds.Extract(body, resp.Location).ToList()
            : [];

        var pattern = string.IsNullOrWhiteSpace(request.ResponsePattern) ? null : request.ResponsePattern.Trim();
        bool? patternMatched = null;
        string? patternError = null;
        if (pattern != null)
            (patternMatched, patternError) = EvaluateResponsePattern(pattern, body);

        return new RaceLabTimelineEntry
        {
            OffsetMs = offsetMs,
            BatchIndex = batchIndex,
            ShotIndex = shotIndex,
            RequestName = string.IsNullOrWhiteSpace(request.Name) ? request.Url : request.Name,
            Url = request.Url,
            Method = request.Method,
            Session = RaceLabSessions.Normalize(request.Session),
            Role = RaceLabRoles.Normalize(request.Role),
            Status = resp.Status,
            LatencyMs = resp.LatencyMs,
            BodyHash = RaceLabJson.HashBody(SideEffectIds.NormalizeForComparison(body)),
            BodySnippet = snippet,
            Accepted = accepted,
            Phase = phase,
            ResourceId = sideEffectIds.Count > 0 ? sideEffectIds[0] : null,
            SideEffectIds = sideEffectIds,
            CookiesSent = resp.CookiesSent,
            IdentityUsed = resp.IdentityUsed,
            Error = resp.Error,
            ResponsePattern = pattern,
            ResponsePatternMatched = patternMatched,
            ResponsePatternError = patternError
        };
    }

    private static (bool? matched, string? error) EvaluateResponsePattern(string pattern, string body)
    {
        try
        {
            var regex = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
            return (regex.IsMatch(body ?? ""), null);
        }
        catch (Exception ex)
        {
            return (null, $"Invalid responsePattern: {ex.Message}");
        }
    }

    private static RaceLabTimelineEntry CopyTimelineEntry(RaceLabTimelineEntry entry, long offsetMs) =>
        new()
        {
            OffsetMs = offsetMs,
            BatchIndex = entry.BatchIndex,
            ShotIndex = entry.ShotIndex,
            RequestName = entry.RequestName,
            Url = entry.Url,
            Method = entry.Method,
            Session = entry.Session,
            Role = entry.Role,
            Status = entry.Status,
            LatencyMs = entry.LatencyMs,
            BodyHash = entry.BodyHash,
            BodySnippet = entry.BodySnippet,
            Accepted = entry.Accepted,
            Phase = entry.Phase,
            ResourceId = entry.ResourceId,
            SideEffectIds = entry.SideEffectIds,
            CookiesSent = entry.CookiesSent,
            IdentityUsed = entry.IdentityUsed,
            Error = entry.Error,
            ResponsePattern = entry.ResponsePattern,
            ResponsePatternMatched = entry.ResponsePatternMatched,
            ResponsePatternError = entry.ResponsePatternError
        };
}
