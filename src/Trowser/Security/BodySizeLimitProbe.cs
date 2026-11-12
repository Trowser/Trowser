using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Escalating body-size tiers (1 KB → 64 KB → 256 KB → 1 MB) on POST endpoints — one request per tier.
/// </summary>
public sealed class BodySizeLimitProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public BodySizeLimitProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class BodySizeLimitOptions
    {
        public int MaxCandidates { get; set; } = 6;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RespectRateLimits { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class BodySizeFinding
    {
        public string Category { get; init; } = "body-size-unbounded";
        public string Severity { get; init; } = "medium";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public int LargestAcceptedBytes { get; init; }
        public int LargestTierBytes { get; init; }
        public string Detail { get; init; } = "";
        public List<object> TierResults { get; init; } = [];
    }

    public sealed class BodySizeLimitResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public bool RateLimitRespected { get; init; }
        public List<string> SkippedDueTo429 { get; init; } = [];
        public List<BodySizeFinding> Findings { get; init; } = [];
        public List<BodySizeFinding> LimitPresent { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    private static readonly int[] BodyTiers = [1024, 65536, 262144, 1_048_576];

    public async Task<BodySizeLimitResult> RunAsync(BodySizeLimitOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running body-size-limit-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = AvailabilityDiscovery.DiscoverBodySizeCandidates(
            _ctx, origin, options.MaxCandidates, options.Urls);

        if (candidates.Count == 0)
        {
            return new BodySizeLimitResult
            {
                Message = "No POST/PUT/PATCH endpoints in network log for body-size probing.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var respectState = new RateLimitRespectHelper.RespectState();
        var findings = new List<BodySizeFinding>();
        var limitPresent = new List<BodySizeFinding>();
        var probesSent = 0;

        _log($"BodySizeLimit: {candidates.Count} candidate(s)", "#888888");

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();

            if (candidate.Method is not ("POST" or "PUT" or "PATCH"))
                continue;

            var prepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                _ctx, candidate.BodyTemplate, candidate.Headers, candidate.Url,
                injectCsrfIfMissing: true, ct);

            var tierResults = new List<object>();
            var largestAccepted = 0;
            var saw413 = false;
            var sawTimeout = false;
            var saw2xx = false;
            var allClientRejected = true;

            foreach (var tier in BodyTiers)
            {
                var bodyBytes = AvailabilityDiscovery.BuildTierBody(prepared.Body, tier);
                var headers = prepared.Headers != null
                    ? new Dictionary<string, string>(prepared.Headers, StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                if (!headers.ContainsKey("Content-Type"))
                    headers["Content-Type"] = "application/json";

                var timed = await RateLimitRespectHelper.FetchTimedRawAsync(
                    _ctx, candidate.Url, candidate.Method, headers, bodyBytes,
                    options.TimeoutMs, options.IncludeBrowserCookies,
                    options.RespectRateLimits, respectState, ct);
                probesSent++;

                tierResults.Add(new
                {
                    tierBytes = tier,
                    sentBytes = bodyBytes.Length,
                    status = timed.Result.Status,
                    elapsedMs = (int)(timed.ElapsedSeconds * 1000)
                });

                if (timed.Result.Status == 429 && options.RespectRateLimits)
                    break;

                if (timed.Result.Status == 413)
                {
                    saw413 = true;
                    limitPresent.Add(new BodySizeFinding
                    {
                        Category = "body-size-limit-present",
                        Severity = "info",
                        Url = candidate.Url,
                        Method = candidate.Method,
                        LargestAcceptedBytes = largestAccepted,
                        LargestTierBytes = tier,
                        Detail = $"HTTP 413 at {tier} byte tier — request body limit appears enforced.",
                        TierResults = tierResults
                    });
                    break;
                }

                if (timed.ElapsedSeconds >= options.TimeoutMs / 1000.0 * 0.9 || timed.Result.Status == 0)
                {
                    sawTimeout = true;
                    break;
                }

                if (timed.Result.Status is >= 200 and < 300)
                {
                    saw2xx = true;
                    allClientRejected = false;
                    largestAccepted = Math.Max(largestAccepted, bodyBytes.Length);
                }
                else if (timed.Result.Status is >= 400 and < 500)
                {
                    // Consistent 4xx (except 413) means the body was rejected, not accepted.
                }
                else if (timed.Result.Status >= 500)
                {
                    allClientRejected = false;
                }
            }

            if (saw413) continue;

            if (!saw2xx && allClientRejected)
                continue;

            if (largestAccepted >= BodyTiers[^1] && !sawTimeout)
            {
                findings.Add(new BodySizeFinding
                {
                    Url = candidate.Url,
                    Method = candidate.Method,
                    LargestAcceptedBytes = largestAccepted,
                    LargestTierBytes = BodyTiers[^1],
                    Detail = $"Accepted body up to {BodyTiers[^1]} bytes (HTTP 2xx) without HTTP 413.",
                    TierResults = tierResults
                });
            }
            else if (saw2xx && largestAccepted >= BodyTiers[^2] && largestAccepted < BodyTiers[^1] && !sawTimeout)
            {
                limitPresent.Add(new BodySizeFinding
                {
                    Category = "body-size-no-413",
                    Severity = "info",
                    Url = candidate.Url,
                    Method = candidate.Method,
                    LargestAcceptedBytes = largestAccepted,
                    LargestTierBytes = BodyTiers[^1],
                    Detail = $"Accepted body up to {largestAccepted} bytes (HTTP 2xx) without HTTP 413 at tested tiers.",
                    TierResults = tierResults
                });
            }
            else if (sawTimeout && largestAccepted > 0)
            {
                findings.Add(new BodySizeFinding
                {
                    Category = "body-size-unbounded",
                    Severity = "low",
                    Url = candidate.Url,
                    Method = candidate.Method,
                    LargestAcceptedBytes = largestAccepted,
                    LargestTierBytes = BodyTiers[^1],
                    Detail = "Large payload caused timeout or transport failure after HTTP 2xx acceptance — possible resource exhaustion.",
                    TierResults = tierResults
                });
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindings(findings);

        return new BodySizeLimitResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} body-size finding(s) on {candidates.Count} candidate(s)."
                : limitPresent.Count > 0
                    ? $"Body limits present on {limitPresent.Count} endpoint(s); no unbounded bodies detected."
                    : $"No body-size issues on {candidates.Count} candidate(s), {probesSent} probe(s).",
            CandidatesProbed = candidates.Count,
            ProbesSent = probesSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            RateLimitRespected = respectState.RateLimitRespected,
            SkippedDueTo429 = respectState.SkippedDueTo429,
            Findings = findings,
            LimitPresent = limitPresent
        };
    }

    private void RegisterFindings(IEnumerable<BodySizeFinding> findings)
    {
        foreach (var f in findings.Where(x => x.Category != "body-size-limit-present"))
        {
            _ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"body-size-{Math.Abs(f.Url.GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = "Missing or weak request body size limit",
                Endpoint = f.Url,
                Method = f.Method,
                Detail = f.Detail
            });
        }
    }
}
