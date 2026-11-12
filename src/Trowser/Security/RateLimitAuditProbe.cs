using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Observational rate-limit audit: sequential baseline then small concurrent burst on traffic-derived endpoints.
/// Emits <c>missing-rate-limit</c>, <c>weak-rate-limit</c>, or <c>rate-limit-present</c> findings.
/// </summary>
public sealed class RateLimitAuditProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public RateLimitAuditProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class RateLimitAuditOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int SequentialAttempts { get; set; } = 5;
        public int BurstSize { get; set; } = 8;
        public int DelayMs { get; set; } = 200;
        public int TimeoutMs { get; set; } = 8000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RespectRateLimits { get; set; } = true;
        public bool IncludeOtpTemplates { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class RateLimitFinding
    {
        public string Category { get; init; } = "missing-rate-limit";
        public string Severity { get; init; } = "medium";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Kind { get; init; } = "";
        public string MatchReason { get; init; } = "";
        public string Detail { get; init; } = "";
        public object? Evidence { get; init; }
    }

    public sealed class RateLimitAuditResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int RequestsSent { get; init; }
        public int ElapsedMs { get; init; }
        public bool RateLimitRespected { get; init; }
        /// <summary>HTTP 429 responses observed during the run (any attempt).</summary>
        public int Http429Responses { get; init; }
        public List<string> SkippedDueTo429 { get; init; } = [];
        public int BackoffEvents { get; init; }
        public List<RateLimitFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<RateLimitAuditResult> RunAsync(RateLimitAuditOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running rate-limit-audit.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = AvailabilityDiscovery.DiscoverRateLimitCandidates(
            _ctx, origin, options.MaxCandidates, options.Urls);
        candidates = await EnrichCandidatesFromDomFormsAsync(candidates);

        if (candidates.Count == 0)
        {
            return new RateLimitAuditResult
            {
                Message = "No rate-limit audit candidates in network log. Browse login, search, OTP, or write APIs first.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var respectState = new RateLimitRespectHelper.RespectState();
        var findings = new List<RateLimitFinding>();
        var requestsSent = 0;
        var sequentialCount = Math.Clamp(options.SequentialAttempts, 2, 10);
        var burstTotal = Math.Clamp(options.BurstSize, 2, 15);
        var delayMs = Math.Clamp(options.DelayMs, 50, 2000);

        _log($"RateLimitAudit: {candidates.Count} candidate(s), sequential={sequentialCount}, burst={burstTotal}", "#888888");

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();

            var prepared = candidate.Method is "POST" or "PUT" or "PATCH"
                ? await InsecureDesignProbeSupport.PrepareRequestAsync(
                    _ctx, candidate.BodyTemplate, candidate.Headers, candidate.Url,
                    injectCsrfIfMissing: true, ct)
                : new InsecureDesignProbeSupport.PreparedRequest
                {
                    Body = candidate.BodyTemplate,
                    Headers = candidate.Headers != null
                        ? new Dictionary<string, string>(candidate.Headers, StringComparer.OrdinalIgnoreCase)
                        : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                };

            var body = prepared.Body;
            var headers = prepared.Headers;
            var sequentialStatuses = new List<int>();
            var sequentialTimings = new List<long>();
            var saw429 = false;
            var sawLockoutText = false;
            var abortCandidate = false;
            var csrfRejectedCount = 0;

            var attempts = candidate.Kind == "otp" && options.IncludeOtpTemplates
                ? Math.Min(sequentialCount, 10)
                : sequentialCount;

            for (var i = 0; i < attempts; i++)
            {
                var reqBody = candidate.Kind == "otp" && options.IncludeOtpTemplates
                    ? AvailabilityDiscovery.BuildOtpProbeBody(body, i)
                    : body;

                var timed = await RateLimitRespectHelper.FetchTimedAsync(
                    _ctx, candidate.Url, candidate.Method, headers, reqBody,
                    options.TimeoutMs, options.IncludeBrowserCookies,
                    options.RespectRateLimits, respectState, ct);
                requestsSent++;

                sequentialStatuses.Add(timed.Result.Status);
                sequentialTimings.Add((long)(timed.ElapsedSeconds * 1000));

                var responseKind = InsecureDesignProbeSupport.ClassifyResponse(timed.Result.Status, timed.Result.Body);
                if (responseKind == InsecureDesignProbeSupport.ProbeResponseKind.CsrfRejected)
                    csrfRejectedCount++;

                if (timed.Result.Status == 429)
                {
                    saw429 = true;
                    if (options.RespectRateLimits)
                    {
                        abortCandidate = true;
                        break;
                    }
                }

                if (LooksLikeLockout(timed.Result.Body))
                    sawLockoutText = true;

                if (timed.Result.Status is 502 or 503)
                {
                    abortCandidate = true;
                    break;
                }

                if (i < attempts - 1 && delayMs > 0)
                    await Task.Delay(delayMs, ct);
            }

            if (saw429 || sawLockoutText)
            {
                findings.Add(new RateLimitFinding
                {
                    Category = "rate-limit-present",
                    Severity = "info",
                    Url = candidate.Url,
                    Method = candidate.Method,
                    Kind = candidate.Kind,
                    MatchReason = candidate.MatchReason,
                    Detail = saw429
                        ? "HTTP 429 observed during sequential probe — rate limiting appears active."
                        : "Lockout/throttle language observed during sequential probe.",
                    Evidence = new { sequentialStatuses, sequentialTimings }
                });
                continue;
            }

            if (abortCandidate)
                continue;

            if (IsSensitiveRateLimitKind(candidate.Kind)
                && sequentialStatuses.Count > 0
                && csrfRejectedCount < sequentialStatuses.Count
                && sequentialStatuses.All(IsRejectionWithoutRateLimit)
                && !saw429 && !sawLockoutText)
            {
                findings.Add(BuildMissingRateLimitFinding(
                    candidate,
                    $"No HTTP 429 or throttle signal after {attempts} sequential attempt(s); endpoint consistently returns {FormatStatusSummary(sequentialStatuses)} (request rejected but not rate-limited).",
                    new { sequentialStatuses, sequentialTimings, csrfRefreshed = prepared.CsrfRefreshed }));
                continue;
            }

            var burstTasks = Enumerable.Range(0, burstTotal).Select(_ =>
                RateLimitRespectHelper.FetchAsync(
                    _ctx, candidate.Url, candidate.Method, headers, body,
                    options.TimeoutMs, options.IncludeBrowserCookies,
                    options.RespectRateLimits, respectState, ct)).ToArray();

            var burstResults = await Task.WhenAll(burstTasks);
            requestsSent += burstResults.Length;

            var burstStatuses = burstResults.Select(r => r.Status).ToList();
            var burst429 = burstStatuses.Count(s => s == 429);
            var burst503 = burstStatuses.Count(s => s is 502 or 503);
            var burst2xx = burstStatuses.Count(s => s is >= 200 and < 300);
            var burstCsrfRejected = burstResults.Count(r =>
                InsecureDesignProbeSupport.ClassifyResponse(r.Status, r.Body)
                == InsecureDesignProbeSupport.ProbeResponseKind.CsrfRejected);

            if (burst503 >= burstTotal / 2)
            {
                _log($"RateLimitAudit: stopping {candidate.Url} — server errors during burst", "#CCCC00");
                continue;
            }

            if (burst429 > 0)
            {
                findings.Add(new RateLimitFinding
                {
                    Category = "rate-limit-present",
                    Severity = "info",
                    Url = candidate.Url,
                    Method = candidate.Method,
                    Kind = candidate.Kind,
                    MatchReason = candidate.MatchReason,
                    Detail = $"HTTP 429 on {burst429}/{burstTotal} concurrent requests.",
                    Evidence = new { burstStatuses }
                });
                continue;
            }

            if (IsSensitiveRateLimitKind(candidate.Kind)
                && burstCsrfRejected < burstStatuses.Count
                && burstStatuses.All(IsRejectionWithoutRateLimit)
                && !sawLockoutText)
            {
                findings.Add(BuildMissingRateLimitFinding(
                    candidate,
                    $"No HTTP 429 or throttle signal after {attempts} sequential + {burstTotal} concurrent request(s); endpoint consistently returns {FormatStatusSummary(burstStatuses)} (request rejected but not rate-limited).",
                    new { sequentialStatuses, sequentialTimings, burstStatuses, csrfRefreshed = prepared.CsrfRefreshed }));
                continue;
            }

            var avgSeq = sequentialTimings.Count > 0 ? sequentialTimings.Average() : 0;

            if (burst2xx >= burstTotal - 1 && !sawLockoutText && IsSensitiveRateLimitKind(candidate.Kind))
            {
                var progressiveSlowdown = sequentialTimings.Count >= 3
                    && sequentialTimings[^1] > avgSeq * 2
                    && avgSeq > 50;

                findings.Add(new RateLimitFinding
                {
                    Category = progressiveSlowdown ? "weak-rate-limit" : "missing-rate-limit",
                    Severity = progressiveSlowdown ? "low" : "medium",
                    Url = candidate.Url,
                    Method = candidate.Method,
                    Kind = candidate.Kind,
                    MatchReason = candidate.MatchReason,
                    Detail = progressiveSlowdown
                        ? $"No HTTP 429, but later sequential attempts slowed ({sequentialTimings[^1]}ms vs avg {avgSeq:F0}ms). Backoff may exist without hard limits."
                        : $"No rate-limit signal after {attempts} sequential + {burstTotal} concurrent requests ({burst2xx}×2xx).",
                    Evidence = new { sequentialStatuses, sequentialTimings, burstStatuses }
                });
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindings(findings);

        var domFallbackCount = candidates.Count(c =>
            c.MatchReason.Contains("dom-post-form", StringComparison.OrdinalIgnoreCase));
        var message = findings.Count > 0
            ? $"{findings.Count} rate-limit finding(s) on {candidates.Count} candidate(s)."
            : $"No rate-limit gaps detected on {candidates.Count} candidate(s), {requestsSent} request(s).";
        if (domFallbackCount > 0)
            message += $" {domFallbackCount} candidate(s) used POST method/body from a live form (network log had GET or no POST).";

        return new RateLimitAuditResult
        {
            Message = message,
            CandidatesProbed = candidates.Count,
            RequestsSent = requestsSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            RateLimitRespected = respectState.RateLimitRespected,
            Http429Responses = respectState.Http429Responses,
            SkippedDueTo429 = respectState.SkippedDueTo429,
            BackoffEvents = respectState.BackoffEvents,
            Findings = findings
        };
    }

    private async Task<List<AvailabilityDiscovery.EndpointCandidate>> EnrichCandidatesFromDomFormsAsync(
        List<AvailabilityDiscovery.EndpointCandidate> candidates)
    {
        var enriched = new List<AvailabilityDiscovery.EndpointCandidate>();
        foreach (var c in candidates)
        {
            var dom = await AuthFormDiscovery.FindFormForUrlAsync(_ctx, c.Url, preferPost: true);
            if (dom != null
                && dom.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && !c.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                enriched.Add(new AvailabilityDiscovery.EndpointCandidate
                {
                    Url = c.Url,
                    Method = "POST",
                    BodyTemplate = dom.BodyTemplate,
                    Headers = dom.Headers,
                    Kind = c.Kind,
                    MatchReason = c.MatchReason + "+dom-post-form",
                    InjectableParam = c.InjectableParam,
                    ParamLocation = c.ParamLocation
                });
            }
            else
            {
                enriched.Add(c);
            }
        }

        return enriched;
    }

    private static bool LooksLikeLockout(string body)
    {
        var lower = body.ToLowerInvariant();
        return lower.Contains("too many", StringComparison.Ordinal)
               || lower.Contains("rate limit", StringComparison.Ordinal)
               || lower.Contains("locked", StringComparison.Ordinal)
               || lower.Contains("lockout", StringComparison.Ordinal)
               || lower.Contains("try again later", StringComparison.Ordinal)
               || lower.Contains("captcha", StringComparison.Ordinal);
    }

    private static bool IsSensitiveRateLimitKind(string kind) =>
        kind is "login" or "otp" or "coupon" or "search" or "export" or "write-api";

    private static bool IsRejectionWithoutRateLimit(int status) =>
        status is 400 or 401 or 403 or 422;

    private static string FormatStatusSummary(IReadOnlyList<int> statuses) =>
        string.Join("/", statuses.Distinct().OrderBy(s => s));

    private static RateLimitFinding BuildMissingRateLimitFinding(
        AvailabilityDiscovery.EndpointCandidate candidate,
        string detail,
        object evidence) => new()
    {
        Category = "missing-rate-limit",
        Severity = "medium",
        Url = candidate.Url,
        Method = candidate.Method,
        Kind = candidate.Kind,
        MatchReason = candidate.MatchReason,
        Detail = detail,
        Evidence = evidence
    };

    private void RegisterFindings(IEnumerable<RateLimitFinding> findings)
    {
        foreach (var f in findings.Where(x => x.Category is not "rate-limit-present"))
        {
            _ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"rate-limit-{Math.Abs((f.Url + f.Category).GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Category switch
                {
                    "weak-rate-limit" => $"Weak rate limiting on {f.Kind} endpoint",
                    _ => $"Missing rate limiting on {f.Kind} endpoint"
                },
                Endpoint = f.Url,
                Method = f.Method,
                Detail = f.Detail,
                Tags = string.IsNullOrEmpty(f.Kind) ? [] : [$"endpoint-kind:{f.Kind}"]
            });
        }
    }
}
