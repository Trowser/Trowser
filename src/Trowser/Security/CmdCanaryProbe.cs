using System.Diagnostics;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Safe command-injection and RCE indicator probes — error-based, SSTI arithmetic, OOB, and timing tiers.
/// </summary>
public sealed class CmdCanaryProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CmdCanaryProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class CmdCanaryOptions
    {
        public string? UrlTemplate { get; set; }
        public string? Method { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? BodyTemplate { get; set; }
        public string? ParamName { get; set; }
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeSstiTier { get; set; } = true;
        public bool IncludeCallback { get; set; }
        public bool IncludeTiming { get; set; }
        public int TimingThresholdMs { get; set; } = 3500;
        public int CallbackWaitMs { get; set; } = 2000;
        public string? CallbackDomain { get; set; }
        public bool ExcludeTransportEndpoints { get; set; } = true;

        /// <summary>When true, only probe parameters with cmd/exec/shell-like names.</summary>
        public bool RestrictToCmdParams { get; set; }
    }

    public sealed class CmdCanaryFinding
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Tier { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "";
        public string ParamName { get; init; } = "";
        public string Payload { get; init; } = "";
        public int Status { get; init; }
        public string? Indicator { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class CmdCanaryResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int PayloadsSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<CmdCanaryFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
        /// <summary>True when the probe stopped early (budget/cancel) but still returned findings collected so far.</summary>
        public bool Partial { get; init; }
    }

    /// <summary>
    /// Tier-0: bare argv-style canaries (many spawn/execFile sinks do not invoke a shell).
    /// Tier-1: classic shell metacharacter injection forms.
    /// </summary>
    private static readonly string[] ErrorPayloads =
    [
        "id", "whoami", "hostname",
        "`id`", "$(id)", ";id", "|id", "&id", "||id", "\nid"
    ];

    private static readonly string[] ShellOutputIndicators =
    [
        "uid=", "gid=", "groups=", "Windows IP", "Volume Serial Number"
    ];

    private static readonly string[] WeakShellOutputIndicators =
    [
        "/bin/", "/usr/bin/", "TTL=", "Linux", "Darwin", "PING"
    ];

    public async Task<CmdCanaryResult> RunAsync(CmdCanaryOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running cmd-canary.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var points = await BuildInjectionPointsAsync(options, origin, ct);
        if (points.Count == 0)
        {
            return new CmdCanaryResult
            {
                Message = "No injectable parameter candidates found. Browse the app or pass urlTemplate with §INJECT§ marker.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        CallbackDetector? detector = null;
        var callbackStarted = false;
        if (options.IncludeCallback && _ctx.CallbackDetector != null)
        {
            detector = _ctx.CallbackDetector;
            if (!detector.Active)
            {
                detector.Start(options.CallbackDomain);
                callbackStarted = true;
            }
            else if (!string.IsNullOrWhiteSpace(options.CallbackDomain))
            {
                detector.Start(options.CallbackDomain);
            }
        }

        var findings = new List<CmdCanaryFinding>();
        var payloadsSent = 0;
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        _log($"CmdCanary: {points.Count} candidate(s)", "#888888");

        var partial = false;
        int? callbackSinceId = null;
        if (options.IncludeCallback && detector != null)
        {
            var existing = detector.GetInteractions();
            callbackSinceId = existing.Count > 0 ? existing[^1].Id : null;
        }

        try
        {
            foreach (var pt in points)
            {
                ct.ThrowIfCancellationRequested();
                payloadsSent += await ProbePointAsync(pt, options, timeout, detector, findings, ct);
            }

            if (options.IncludeCallback && detector != null && options.CallbackWaitMs > 0)
            {
                await Task.Delay(options.CallbackWaitMs, ct);
                foreach (var hit in detector.GetInteractions(callbackSinceId))
                {
                    if (!IsCmdProbeBrowserCallback(hit.Url)) continue;
                    if (findings.Any(f => f.Tier == "OOB" && f.Indicator == hit.Url)) continue;
                    findings.Add(new CmdCanaryFinding
                    {
                        Category = "callback-browser-hit",
                        Severity = "info",
                        Tier = "OOB",
                        Url = hit.Url,
                        Method = hit.Method ?? "GET",
                        ParamName = "",
                        Payload = hit.CorrelationId ?? "",
                        Status = hit.StatusCode ?? 0,
                        Indicator = hit.Url,
                        Detail = "Callback URL loaded by the browser during cmd-canary — client-side injection signal, not server RCE."
                    });
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Never drop findings already collected — return partial so auto-scan can flush them.
            partial = true;
            _log($"  CmdCanary cancelled — flushing {findings.Count} partial finding(s)", "#CCA700");
        }
        finally
        {
            if (callbackStarted && detector != null)
                detector.Stop();
        }

        return new CmdCanaryResult
        {
            Message = partial
                ? $"Partial: {findings.Count} command/RCE indicator(s) before cancel ({points.Count} candidate(s), {payloadsSent} payload(s))."
                : findings.Count > 0
                    ? $"{findings.Count} command/RCE indicator(s) across {points.Count} injection point(s)."
                    : $"No command injection indicators across {points.Count} point(s), {payloadsSent} payload(s).",
            CandidatesProbed = points.Count,
            PayloadsSent = payloadsSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Partial = partial
        };
    }

    private async Task<List<InjectionPointDiscovery.InjectionPoint>> BuildInjectionPointsAsync(
        CmdCanaryOptions options, string origin, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(options.UrlTemplate))
        {
            var markers = RequestMarkerSubstitute.ListMarkers(options.UrlTemplate, options.BodyTemplate, options.Headers);
            if (markers.Count == 0)
                throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                    "urlTemplate/body/headers must contain §INJECT§ or {{INJECT}} marker."));

            return
            [
                new InjectionPointDiscovery.InjectionPoint
                {
                    Url = options.UrlTemplate,
                    Method = (options.Method ?? "GET").ToUpperInvariant(),
                    ParamName = options.ParamName ?? markers[0],
                    UrlTemplate = options.UrlTemplate,
                    BodyTemplate = options.BodyTemplate,
                    Headers = options.Headers,
                    Source = "explicit"
                }
            ];
        }

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 10;
        var fromNetwork = InjectionPointDiscovery.DiscoverFromNetwork(
                _ctx, origin, max, jsonBodiesOnly: false, prioritizeCmdParams: true,
                restrictToCmdHints: options.RestrictToCmdParams)
            .Where(p => !InjectionProbeFilters.ShouldExcludeTransportEndpoint(
                p.UrlTemplate ?? p.Url, p.ParamName, options.ExcludeTransportEndpoints))
            .ToList();

        // Merge DOM POST forms that were never submitted (absent from network log).
        try
        {
            var fromDom = await InjectionPointDiscovery.DiscoverFromDomFormsAsync(
                _ctx, origin, max, prioritizeCmdParams: true,
                restrictToCmdHints: options.RestrictToCmdParams, ct: ct);
            var seen = new HashSet<string>(
                fromNetwork.Select(p => $"{p.Method}|{p.Url}|{p.ParamName}"),
                StringComparer.OrdinalIgnoreCase);
            foreach (var pt in fromDom)
            {
                var key = $"{pt.Method}|{pt.Url}|{pt.ParamName}";
                if (!seen.Add(key)) continue;
                if (InjectionProbeFilters.ShouldExcludeTransportEndpoint(
                        pt.UrlTemplate ?? pt.Url, pt.ParamName, options.ExcludeTransportEndpoints))
                    continue;
                fromNetwork.Add(pt);
                if (fromNetwork.Count >= max) break;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            /* DOM harvest is best-effort */
        }

        return fromNetwork;
    }

    private async Task<int> ProbePointAsync(
        InjectionPointDiscovery.InjectionPoint pt,
        CmdCanaryOptions options,
        int timeout,
        CallbackDetector? detector,
        List<CmdCanaryFinding> findings,
        CancellationToken ct)
    {
        var urlTemplate = pt.UrlTemplate ?? pt.Url;
        if (InjectionProbeFilters.ShouldExcludeTransportEndpoint(urlTemplate, pt.ParamName, options.ExcludeTransportEndpoints))
            return 0;

        var sent = 0;
        var baselineVal = "trowser-cmd-baseline";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var baseUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, baselineVal);
        var baseBody = SubstituteBody(pt.BodyTemplate, baselineVal);
        var baseHeaders = RequestMarkerSubstitute.ReplaceAllInHeaders(pt.Headers, baselineVal) ?? pt.Headers;
        var baseSw = Stopwatch.StartNew();
        var baseJson = await FetchWithTimeoutAsync(baseUrl, pt.Method, baseHeaders, baseBody, timeout);
        baseSw.Stop();
        ct.ThrowIfCancellationRequested();
        var (_, baseText, _) = HttpSecurityProbes.ParseFetchJson(baseJson);
        var baselineMs = (int)baseSw.ElapsedMilliseconds;

        foreach (var payload in ErrorPayloads)
        {
            ct.ThrowIfCancellationRequested();
            sent++;
            var (status, text, indicator) = await SendPayloadAsync(pt, urlTemplate, payload, timeout);
            if (indicator != null && !IndicatorPresentInBaseline(indicator, baseText)
                && seen.Add($"error|{pt.ParamName}|{payload}"))
            {
                AddFinding(findings, pt, payload, status, "A-error-based", "command-injection",
                    indicator, $"Shell output indicator '{indicator}' in response.");
            }
        }

        if (options.IncludeSstiTier)
        {
            foreach (var payload in SstiScanner.DefaultPayloads.Take(6))
            {
                ct.ThrowIfCancellationRequested();
                sent++;
                var (status, text, _) = await SendPayloadAsync(pt, urlTemplate, payload, timeout);
                if (SstiReflectionHelper.DetectArithmeticReflection(payload, baseText, text)
                    && seen.Add($"ssti|{pt.ParamName}|{payload}"))
                {
                    AddFinding(findings, pt, payload, status, "B-ssti-arithmetic", "ssti-confirmed",
                        "49/56", "Template arithmetic reflection detected (49 or 56).");
                }
            }
        }

        if (options.IncludeCallback && detector != null)
        {
            var probeUrl = detector.GenerateProbeUrl("cmd");
            var callbackPayloads = new[]
            {
                $";curl {probeUrl}",
                $"$(curl {probeUrl})",
                $"|curl {probeUrl}",
                probeUrl
            };

            foreach (var payload in callbackPayloads)
            {
                ct.ThrowIfCancellationRequested();
                sent++;
                var substituted = detector.SubstituteMarkers(
                    payload.Replace(CallbackDetector.MarkerLegacy, probeUrl, StringComparison.Ordinal)
                           .Replace(CallbackDetector.MarkerAscii, probeUrl, StringComparison.Ordinal));
                var (status, text, _) = await SendPayloadAsync(pt, urlTemplate, substituted, timeout);
                if (text.Contains(probeUrl, StringComparison.OrdinalIgnoreCase) &&
                    seen.Add($"oob-reflect|{pt.ParamName}|{payload}"))
                {
                    findings.Add(new CmdCanaryFinding
                    {
                        Category = "callback-reflection",
                        Severity = "info",
                        Tier = "D-oob-reflection",
                        Url = pt.Url,
                        Method = pt.Method,
                        ParamName = pt.ParamName,
                        Payload = substituted,
                        Status = status,
                        Indicator = probeUrl,
                        Detail = "Callback URL reflected in response — not evidence of server-side execution."
                    });
                }
            }
        }

        if (options.IncludeTiming)
        {
            var timingPayloads = new[] { "sleep 5", "$(sleep 5)", ";sleep 5", "|sleep 5" };
            foreach (var payload in timingPayloads)
            {
                ct.ThrowIfCancellationRequested();
                sent++;
                var probeSw = Stopwatch.StartNew();
                var (status, _, _) = await SendPayloadAsync(pt, urlTemplate, payload, timeout);
                probeSw.Stop();
                var delta = (int)probeSw.ElapsedMilliseconds - baselineMs;
                var threshold = options.TimingThresholdMs > 0 ? options.TimingThresholdMs : 3500;
                if (delta >= threshold && seen.Add($"timing|{pt.ParamName}|{payload}"))
                {
                    var confirmed = await SecurityProbeTimingConfirm.ConfirmDeltaAsync(
                        async ct2 =>
                        {
                            var sw = Stopwatch.StartNew();
                            await FetchWithTimeoutAsync(baseUrl, pt.Method, baseHeaders, baseBody, timeout);
                            sw.Stop();
                            return sw.Elapsed.TotalSeconds;
                        },
                        async ct2 =>
                        {
                            var sw = Stopwatch.StartNew();
                            await SendPayloadAsync(pt, urlTemplate, payload, timeout);
                            sw.Stop();
                            return sw.Elapsed.TotalSeconds;
                        },
                        (controlS, attackS) => (attackS - controlS) * 1000 >= threshold,
                        ct);
                    if (!confirmed) continue;

                    AddFinding(findings, pt, payload, status, "E-timing", "rce-indicator",
                        $"{delta}ms", $"Response {delta}ms slower than baseline ({baselineMs}ms) — possible time-based execution.");
                }
            }
        }

        return sent;
    }

    private async Task<(int status, string text, string? indicator)> SendPayloadAsync(
        InjectionPointDiscovery.InjectionPoint pt,
        string urlTemplate,
        string payload,
        int timeout)
    {
        var url = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, payload);
        var body = SubstituteBody(pt.BodyTemplate, payload);
        var hdrs = RequestMarkerSubstitute.ReplaceAllInHeaders(pt.Headers, payload) ?? pt.Headers;
        // Discovery bug guard: encoded/unsubstituted markers never reach the sink.
        if (RequestMarkerSubstitute.HasUnsubstitutedOrEncodedMarker(url, body)
            || (hdrs != null && hdrs.Values.Any(v => RequestMarkerSubstitute.HasUnsubstitutedOrEncodedMarker(v))))
        {
            return (0, "", "marker-not-substituted");
        }

        var json = await FetchWithTimeoutAsync(url, pt.Method, hdrs, body, timeout);
        var (status, text, _) = HttpSecurityProbes.ParseFetchJson(json);
        var indicator = DetectShellOutput(text);
        return (status, text, indicator);
    }

    private static bool IndicatorPresentInBaseline(string indicator, string baselineText) =>
        !string.IsNullOrEmpty(baselineText)
        && baselineText.Contains(indicator, StringComparison.OrdinalIgnoreCase);

    private async Task<string> FetchWithTimeoutAsync(
        string url, string method, Dictionary<string, string>? headers, string? body, int timeoutMs)
    {
        try
        {
            return await _ctx.Fetch(url, method, headers, body, timeoutMs);
        }
        catch (OperationCanceledException)
        {
            // Fetch uses an internal JS timeout — map only that path to TimeoutException.
            // Budget/scan cancellation is thrown between probes via CancellationToken, not here.
            throw new TimeoutException(
                $"Request timed out after {timeoutMs}ms. Increase timeoutMs for slow backends.");
        }
    }

    private static void AddFinding(
        List<CmdCanaryFinding> findings,
        InjectionPointDiscovery.InjectionPoint pt,
        string payload,
        int status,
        string tier,
        string category,
        string indicator,
        string detail)
    {
        var severity = ResolveCmdSeverity(category, indicator);
        findings.Add(new CmdCanaryFinding
        {
            Category = category,
            Severity = severity,
            Tier = tier,
            Url = pt.Url,
            Method = pt.Method,
            ParamName = pt.ParamName,
            Payload = payload,
            Status = status,
            Indicator = indicator,
            Detail = detail
        });
    }

    internal static string ResolveCmdSeverity(string category, string indicator)
    {
        if (category is "ssti-confirmed")
            return "high";

        // Clear RCE output from id/whoami-style canaries.
        if (!string.IsNullOrEmpty(indicator)
            && (indicator.Contains("uid=", StringComparison.OrdinalIgnoreCase)
                || indicator.Equals("root", StringComparison.OrdinalIgnoreCase)
                || indicator.Contains("gid=", StringComparison.OrdinalIgnoreCase)
                || indicator.Contains("groups=", StringComparison.OrdinalIgnoreCase)
                || indicator.Contains("Windows IP", StringComparison.OrdinalIgnoreCase)
                || indicator.Contains("Volume Serial Number", StringComparison.OrdinalIgnoreCase)))
            return "critical";

        if (category is "rce-indicator")
            return "high";

        if (category is "command-injection")
            return "medium";

        return "medium";
    }

    internal static string? DetectShellOutput(string text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        foreach (var sig in ShellOutputIndicators)
        {
            if (text.Contains(sig, StringComparison.OrdinalIgnoreCase))
                return sig;
        }

        foreach (var sig in WeakShellOutputIndicators)
        {
            if (text.Contains(sig, StringComparison.OrdinalIgnoreCase))
                return sig;
        }

        return null;
    }

    private static string? SubstituteBody(string? template, string value)
    {
        if (string.IsNullOrEmpty(template)) return template;
        var trimmed = template.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return InjectionJsonBody.SubstituteMarkers(template, value);
        return RequestMarkerSubstitute.ReplaceAll(template, value);
    }

    private static bool IsCmdProbeBrowserCallback(string url) =>
        url.Contains("/probe-cmd-", StringComparison.OrdinalIgnoreCase);
}
