using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Captcha replay / broken anti-automation: extract captchaId+answer, accept once, replay.
/// Accepted responses exclude captcha-reject phrases; third-party widgets are observations, not findings.
/// Inspired by OWASP WSTG CAPTCHA / business-logic abuse testing; also influenced by pentest-ai <c>web.captcha_replay</c>.
/// May create duplicate submissions under active mode.
/// </summary>
public sealed class CaptchaReplayScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CaptchaReplayScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class CaptchaReplayScanOptions
    {
        public int MaxSubmitCandidates { get; set; } = 6;
        public int TimeoutMs { get; set; } = 8000;
        public bool IncludeBrowserCookies { get; set; } = true;
    }

    public sealed class CaptchaReplayFinding
    {
        public string Category { get; init; } = "broken-anti-automation";
        public string Severity { get; init; } = "medium";
        public string CaptchaUrl { get; init; } = "";
        public string SubmitUrl { get; init; } = "";
        public string Method { get; init; } = "POST";
        public object? CaptchaId { get; init; }
        public int FirstStatus { get; init; }
        public int ReplayStatus { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class CaptchaReplayScanResult
    {
        public string Message { get; init; } = "";
        public int CaptchaServicesProbed { get; init; }
        public int SubmitEndpointsTested { get; init; }
        public int ElapsedMs { get; init; }
        public List<CaptchaReplayFinding> Findings { get; init; } = [];
        public List<InsecureDesignProbeSupport.ProbeObservation> Observations { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
        public bool HasObservations => Observations.Count > 0;
    }

    public async Task<CaptchaReplayScanResult> RunAsync(CaptchaReplayScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running captcha-replay-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var observations = new List<InsecureDesignProbeSupport.ProbeObservation>();

        foreach (var signal in await InsecureDesignProbeSupport.DetectThirdPartyCaptchaAsync(_ctx))
            observations.Add(InsecureDesignProbeSupport.ThirdPartyCaptchaObservation(signal));

        var captchaUrls = InsecureDesignDiscovery.DiscoverCaptchaServiceUrls(_ctx, origin, 4);
        var submitTargets = InsecureDesignDiscovery.DiscoverCaptchaSubmitTargets(
            _ctx, origin, options.MaxSubmitCandidates);

        object? captchaId = null;
        object? answer = null;
        string? captchaUrlUsed = null;

        foreach (var captchaUrl in captchaUrls)
        {
            ct.ThrowIfCancellationRequested();
            var get = await SecurityProbeHttp.FetchAsync(
                _ctx, captchaUrl, "GET", null, null, options.TimeoutMs,
                options.IncludeBrowserCookies, ct);

            if (!InsecureDesignDiscovery.IsSuccessStatus(get.Status) || string.IsNullOrEmpty(get.Body))
                continue;

            if (InsecureDesignDiscovery.TryExtractCaptchaCredentials(get.Body, out captchaId, out answer))
            {
                captchaUrlUsed = captchaUrl;
                break;
            }
        }

        if (captchaId == null || answer == null)
        {
            var hasThirdParty = observations.Any(o =>
                o.Category.Equals("captcha-present-untestable", StringComparison.OrdinalIgnoreCase));

            return new CaptchaReplayScanResult
            {
                Message = hasThirdParty
                    ? "Third-party CAPTCHA detected in DOM but not programmatically testable. No JSON captchaId+answer service in network log."
                    : "No captcha/challenge service returned captchaId + answer JSON. Browse a captcha-gated form first.",
                CaptchaServicesProbed = captchaUrls.Count,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Observations = observations
            };
        }

        if (submitTargets.Count == 0)
        {
            return new CaptchaReplayScanResult
            {
                Message = "Captcha credentials obtained but no submit endpoints found in network log.",
                CaptchaServicesProbed = captchaUrls.Count,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Observations = observations
            };
        }

        var findings = new List<CaptchaReplayFinding>();
        var tested = 0;
        var csrfBlocked = 0;

        _log($"CaptchaReplayScan: captcha={captchaUrlUsed}, {submitTargets.Count} submit target(s)", "#888888");

        foreach (var target in submitTargets)
        {
            ct.ThrowIfCancellationRequested();
            tested++;

            var firstBody = InsecureDesignDiscovery.BuildCaptchaSubmitBody(
                captchaId, answer, target.BodyTemplate, "first");
            var replayBody = InsecureDesignDiscovery.BuildCaptchaSubmitBody(
                captchaId, answer, target.BodyTemplate, "replay");

            var firstPrepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                _ctx, firstBody.ToJsonString(), target.Headers, target.Url, injectCsrfIfMissing: true, ct);
            var replayPrepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                _ctx, replayBody.ToJsonString(), target.Headers, target.Url, injectCsrfIfMissing: true, ct);

            var first = await SecurityProbeHttp.FetchAsync(
                _ctx, target.Url, target.Method, firstPrepared.Headers,
                firstPrepared.Body, options.TimeoutMs, options.IncludeBrowserCookies, ct);

            var firstKind = InsecureDesignProbeSupport.ClassifyResponse(first.Status, first.Body);
            if (firstKind == InsecureDesignProbeSupport.ProbeResponseKind.CsrfRejected)
            {
                csrfBlocked++;
                observations.Add(InsecureDesignProbeSupport.CsrfBlockedObservation(
                    target.Url,
                    new InsecureDesignProbeSupport.BurstStats
                    {
                        Total = 1, CsrfRejectedCount = 1, AcceptedCount = 0
                    },
                    firstPrepared));
                continue;
            }

            if (firstKind != InsecureDesignProbeSupport.ProbeResponseKind.Accepted
                || LooksLikeCaptchaRejection(first.Body))
                continue;

            var replay = await SecurityProbeHttp.FetchAsync(
                _ctx, target.Url, target.Method, replayPrepared.Headers,
                replayPrepared.Body, options.TimeoutMs, options.IncludeBrowserCookies, ct);

            if (InsecureDesignProbeSupport.ClassifyResponse(replay.Status, replay.Body)
                == InsecureDesignProbeSupport.ProbeResponseKind.CsrfRejected)
            {
                csrfBlocked++;
                observations.Add(new InsecureDesignProbeSupport.ProbeObservation
                {
                    Category = "csrf-blocked",
                    Severity = "info",
                    Url = target.Url,
                    Detail = "Replay request rejected by CSRF validation after first submit succeeded. " +
                             "Refresh CSRF from the form page between attempts."
                });
                continue;
            }

            if (InsecureDesignProbeSupport.ClassifyResponse(replay.Status, replay.Body)
                    != InsecureDesignProbeSupport.ProbeResponseKind.Accepted
                || LooksLikeCaptchaRejection(replay.Body))
                continue;

            findings.Add(new CaptchaReplayFinding
            {
                Category = "broken-anti-automation",
                Severity = "medium",
                CaptchaUrl = captchaUrlUsed ?? "",
                SubmitUrl = target.Url,
                Method = target.Method,
                CaptchaId = captchaId,
                FirstStatus = first.Status,
                ReplayStatus = replay.Status,
                Detail =
                    $"Two consecutive 2xx responses on {target.Url} using the same captcha credentials " +
                    $"(captchaId={JsonSerializer.Serialize(captchaId)}). Token was not single-use."
            });
            break;
        }

        var message = findings.Count > 0
            ? "CAPTCHA token replay accepted (broken anti-automation)."
            : csrfBlocked > 0 && csrfBlocked == tested
                ? "All submit probes blocked by CSRF validation — captcha replay test inconclusive."
                : "Captcha credentials did not replay successfully on probed submit endpoints.";

        return new CaptchaReplayScanResult
        {
            Message = message,
            CaptchaServicesProbed = captchaUrls.Count,
            SubmitEndpointsTested = tested,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            Observations = observations
        };
    }

    private static readonly string[] CaptchaRejectPhrases =
    [
        "invalid captcha", "wrong captcha", "captcha failed", "captcha incorrect",
        "failed captcha", "captcha error", "captcha mismatch", "bad captcha",
        "incorrect captcha", "captcha is invalid", "captcha validation failed"
    ];

    private static bool LooksLikeCaptchaRejection(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var lower = body.ToLowerInvariant();
        return CaptchaRejectPhrases.Any(p => lower.Contains(p, StringComparison.Ordinal));
    }
}
