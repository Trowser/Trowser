using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Single-request ReDoS timing oracle — one evil-regex payload per injectable parameter (no fuzz campaigns).
/// </summary>
public sealed class ReDoSScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public ReDoSScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class ReDoSScanOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int MaxPayloadsPerCandidate { get; set; } = 3;
        public double SlowThresholdSeconds { get; set; } = 3.0;
        public int TimeoutMs { get; set; } = 8000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RespectRateLimits { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class ReDoSFinding
    {
        public string Category { get; init; } = "redos-suspected";
        public string Severity { get; init; } = "medium";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Param { get; init; } = "";
        public string Payload { get; init; } = "";
        public double BaselineSeconds { get; init; }
        public double AttackSeconds { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class ReDoSScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public bool RateLimitRespected { get; init; }
        public List<string> SkippedDueTo429 { get; init; } = [];
        public List<ReDoSFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    private static readonly string[] EvilRegexPayloads =
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        "(a+)+$"
    ];

    public async Task<ReDoSScanResult> RunAsync(ReDoSScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running redos-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = AvailabilityDiscovery.DiscoverReDoSCandidates(
            _ctx, origin, options.MaxCandidates, options.Urls);

        if (candidates.Count == 0)
        {
            return new ReDoSScanResult
            {
                Message = "No injectable search/filter/email parameters found in network log.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var respectState = new RateLimitRespectHelper.RespectState();
        var findings = new List<ReDoSFinding>();
        var probesSent = 0;
        var threshold = Math.Clamp(options.SlowThresholdSeconds, 1.0, 10.0);
        var maxPayloads = Math.Clamp(options.MaxPayloadsPerCandidate, 1, 3);

        _log($"ReDoSScan: {candidates.Count} candidate(s)", "#888888");

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(candidate.InjectableParam)) continue;

            var baselineUrl = candidate.Url;
            var baselineBody = candidate.BodyTemplate;
            var baselineTimed = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, baselineUrl, candidate.Method, candidate.Headers, baselineBody,
                options.TimeoutMs, options.IncludeBrowserCookies,
                options.RespectRateLimits, respectState, ct);
            probesSent++;

            if (baselineTimed.Result.Status == 429 && options.RespectRateLimits)
                continue;

            foreach (var payload in EvilRegexPayloads.Take(maxPayloads))
            {
                ct.ThrowIfCancellationRequested();
                var attackUrl = baselineUrl;
                var attackBody = baselineBody;
                if (candidate.ParamLocation == "query")
                {
                    attackUrl = AvailabilityDiscovery.InjectReDoSPayload(
                        baselineUrl, baselineBody, candidate.InjectableParam!, candidate.ParamLocation, payload);
                }
                else
                {
                    attackBody = AvailabilityDiscovery.InjectReDoSPayload(
                        baselineUrl, baselineBody, candidate.InjectableParam!, candidate.ParamLocation, payload);
                }

                var attackTimed = await RateLimitRespectHelper.FetchTimedAsync(
                    _ctx, attackUrl, candidate.Method, candidate.Headers, attackBody,
                    options.TimeoutMs, options.IncludeBrowserCookies,
                    options.RespectRateLimits, respectState, ct);
                probesSent++;

                var delta = attackTimed.ElapsedSeconds - baselineTimed.ElapsedSeconds;
                var initialHit = attackTimed.ElapsedSeconds >= threshold && delta >= threshold * 0.5;
                if (initialHit)
                {
                    var benignControl = SameLengthBenignControl(payload);
                    var confirmControlUrl = candidate.ParamLocation == "query"
                        ? AvailabilityDiscovery.InjectReDoSPayload(
                            baselineUrl, baselineBody, candidate.InjectableParam!, candidate.ParamLocation, benignControl)
                        : baselineUrl;
                    var confirmControlBody = candidate.ParamLocation == "query"
                        ? baselineBody
                        : AvailabilityDiscovery.InjectReDoSPayload(
                            baselineUrl, baselineBody, candidate.InjectableParam!, candidate.ParamLocation, benignControl);

                    var confirmed = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
                        async ct2 => (await RateLimitRespectHelper.FetchTimedAsync(
                            _ctx, confirmControlUrl, candidate.Method, candidate.Headers, confirmControlBody,
                            options.TimeoutMs, options.IncludeBrowserCookies,
                            options.RespectRateLimits, respectState, ct2)).ElapsedSeconds,
                        async ct2 => (await RateLimitRespectHelper.FetchTimedAsync(
                            _ctx, attackUrl, candidate.Method, candidate.Headers, attackBody,
                            options.TimeoutMs, options.IncludeBrowserCookies,
                            options.RespectRateLimits, respectState, ct2)).ElapsedSeconds,
                        (b, a) => a >= threshold && a - b >= threshold * 0.5,
                        ct);
                    probesSent += 2;

                    if (confirmed)
                    {
                        findings.Add(new ReDoSFinding
                        {
                            Url = attackUrl,
                            Method = candidate.Method,
                            Param = candidate.InjectableParam!,
                            Payload = payload,
                            BaselineSeconds = baselineTimed.ElapsedSeconds,
                            AttackSeconds = attackTimed.ElapsedSeconds,
                            Detail =
                                $"Parameter '{candidate.InjectableParam}' triggered slow response " +
                                $"({attackTimed.ElapsedSeconds:F2}s vs baseline {baselineTimed.ElapsedSeconds:F2}s). Possible ReDoS."
                        });
                        break;
                    }
                }
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindings(findings);

        return new ReDoSScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} ReDoS suspect(s) on {candidates.Count} candidate(s)."
                : $"No ReDoS timing signals on {candidates.Count} candidate(s), {probesSent} probe(s).",
            CandidatesProbed = candidates.Count,
            ProbesSent = probesSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            RateLimitRespected = respectState.RateLimitRespected,
            SkippedDueTo429 = respectState.SkippedDueTo429,
            Findings = findings
        };
    }

    internal static string SameLengthBenignControl(string attackPayload) =>
        attackPayload.EndsWith('!')
            ? new string('a', attackPayload.Length)
            : new string('a', Math.Max(attackPayload.Length, 1));

    private void RegisterFindings(IEnumerable<ReDoSFinding> findings)
    {
        foreach (var f in findings)
        {
            _ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"redos-{Math.Abs((f.Url + f.Param).GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = $"ReDoS timing signal on parameter {f.Param}",
                Endpoint = f.Url,
                Method = f.Method,
                Detail = f.Detail
            });
        }
    }
}
