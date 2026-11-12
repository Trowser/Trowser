using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Reflected XSS probe — injects XSS payloads at marker points and analyzes response reflection context.
/// </summary>
public static class XssScanner
{
    /// <summary>Fallback when no context-driven set is available (no javascript: iframe — too noisy).</summary>
    public static readonly string[] DefaultPayloads =
    [
        XssBypassProbes.DefaultPrimaryPayload,
        "</script><img src=x onerror=window.__xss_proof=1>",
        "<img src=x onerror=window.__xss_proof=1>",
        "\"><img src=x onerror=window.__xss_proof=1>"
    ];

    public sealed class XssRow
    {
        public string Payload { get; init; } = "";
        public int Status { get; init; }
        public string Context { get; init; } = "";
        public bool Encoded { get; init; }
        public bool Dangerous { get; init; }
        public string? Reason { get; init; }
        public string? Surrounding { get; init; }
        public bool DomVerified { get; init; }
        /// <summary>Scanner severity aligned with InputTracer verdict (critical/high/medium/low).</summary>
        public string Severity { get; init; } = "high";
        /// <summary>Meets xss-scan reporting bar (execution, causal DOM, or dangerous reflection — not sink-only noise).</summary>
        public bool ConfirmedDomXss { get; init; }
    }

    public sealed class XssScanResult
    {
        public List<XssRow> Rows { get; init; } = [];
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public XssPayloadStrategy.CharSurvival? CharSurvival { get; init; }
        public string Depth { get; init; } = SecurityScanDepth.Standard;
        public bool HasFindings => Rows.Any(r => r.Dangerous);
    }

    public static async Task<XssScanResult> RunAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        int timeoutMs = 15000,
        IReadOnlyList<string>? payloads = null,
        string? depth = null,
        PayloadProfile payloadProfile = PayloadProfile.Small,
        bool runCharSurvival = true,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate, headers);
        if (markers.Count == 0)
            throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                "Template must contain §marker§ or {{marker}} injection point in url, body, or headers."));

        var resolved = InjectionScanDepth.Resolve(depth);
        XssPayloadStrategy.CharSurvival? survival = null;
        if (runCharSurvival && resolved.RunCharSurvivalProbe)
        {
            survival = await XssPayloadStrategy.ProbeCharSurvivalAsync(
                ctx, urlTemplate, method, headers, bodyTemplate, timeoutMs, ct);
        }

        var baselineVal = "trowser-xss-baseline";
        var baseUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, baselineVal);
        var baseBody = SubstituteBody(bodyTemplate, baselineVal);
        var baseHeaders = RequestMarkerSubstitute.ReplaceAllInHeaders(headers, baselineVal) ?? headers;
        var baseJson = await ctx.Fetch(baseUrl, method, baseHeaders, baseBody, timeoutMs);
        ct.ThrowIfCancellationRequested();
        HttpSecurityProbes.ParseFetchJson(baseJson);

        var probePayloads = payloads is { Count: > 0 }
            ? payloads
            : XssPayloadStrategy.SelectPayloads(survival, resolved.Name, payloadProfile);

        var rows = new List<XssRow>();
        foreach (var payload in probePayloads)
        {
            ct.ThrowIfCancellationRequested();
            var subUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, payload);
            var subBody = SubstituteBody(bodyTemplate, payload);
            var subHeaders = RequestMarkerSubstitute.ReplaceAllInHeaders(headers, payload) ?? headers;
            var json = await ctx.Fetch(subUrl, method, subHeaders, subBody, timeoutMs);
            var (status, text, _) = HttpSecurityProbes.ParseFetchJson(json);
            if (string.IsNullOrEmpty(text)) continue;

            foreach (var variant in XssReflectionAnalyzer.GetPayloadReflectionVariants(payload))
            {
                if (!text.Contains(variant, StringComparison.OrdinalIgnoreCase)) continue;

                var analysis = XssReflectionAnalyzer.AnalyzeReflection(
                    text, payload, variant,
                    encoded: !string.Equals(variant, payload, StringComparison.Ordinal),
                    contentType: null);

                if (!analysis.Dangerous) continue;

                rows.Add(new XssRow
                {
                    Payload = payload,
                    Status = status,
                    Context = analysis.Context,
                    Encoded = analysis.Encoded,
                    Dangerous = analysis.Dangerous,
                    Reason = analysis.Reason,
                    Surrounding = analysis.Surrounding
                });
                break;
            }
        }

        return new XssScanResult
        {
            Rows = rows,
            CandidatesProbed = 1,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            CharSurvival = survival,
            Depth = resolved.Name
        };
    }

    public static async Task<XssScanResult> RunDomProbeAsync(
        AutomationContext ctx,
        string baseUrl,
        TraceSourceType source,
        string paramName,
        int timeoutMs = 10000,
        int maxBypassAttempts = 6,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var tracer = new InputTracer(ctx);
        var traceSource = source switch
        {
            TraceSourceType.UrlHash => TraceSourceType.UrlHash,
            TraceSourceType.UrlPath => TraceSourceType.UrlPath,
            _ => TraceSourceType.UrlQuery
        };

        var options = new TraceInputOptions
        {
            Source = traceSource,
            BaseUrl = baseUrl,
            QueryParam = paramName,
            HashParam = paramName,
            Payload = XssBypassProbes.DefaultPrimaryPayload,
            AutoBypass = true,
            MaxBypassAttempts = maxBypassAttempts,
            MonitorSinks = true,
            ConfirmExecution = true,
            CheckCsp = true,
            TimeoutMs = timeoutMs,
            QueryEncode = UrlPayloadEncodeMode.None,
            FragmentEncode = UrlPayloadEncodeMode.None
        };

        var result = await tracer.TraceWithAutoBypassAsync(options);
        ct.ThrowIfCancellationRequested();

        var effective = result.SuccessfulBypass ?? result.PrimaryTrace;
        if (!XssBypassProbes.IsConfirmedDomXssForScan(effective))
        {
            return new XssScanResult
            {
                CandidatesProbed = 1,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var context = effective.Dom?.Context
            ?? effective.ServerResponse?.Reflections.FirstOrDefault(r => r.Dangerous)?.Context
            ?? effective.Injection.SourceType;

        // Align severity with the tracer verdict — never claim CRITICAL when the summary says
        // the payload was not rendered as active DOM content (reflected-only / medium).
        var severity = MapVerdictSeverity(effective.Verdict.Severity, effective);
        var effectObserved = effective.Sinks?.ExecutionConfirmed == true
                             || effective.Sinks?.DialogEffectConfirmed == true;
        if (!effectObserved && severity is "critical")
            severity = "high";

        var activeDom = effectObserved
                        || (effective.Dom is { PayloadRendered: true, Dangerous: true }
                            && XssReflectionAnalyzer.DomEvidenceIsPayloadCausal(effective.Payload, effective.Dom)
                            && effectObserved);

        return new XssScanResult
        {
            Rows =
            [
                new XssRow
                {
                    Payload = effective.Payload,
                    Status = effective.ServerResponse?.Status ?? 200,
                    Context = context,
                    Dangerous = true,
                    DomVerified = activeDom,
                    Reason = effective.Verdict.Summary,
                    Surrounding = effective.Dom?.Reason,
                    Severity = severity,
                    ConfirmedDomXss = true
                }
            ],
            CandidatesProbed = 1,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private static string MapVerdictSeverity(Severity verdict, InputTraceResult trace)
    {
        // Cap when evidence contradicts active DOM execution.
        var summary = trace.Verdict.Summary ?? "";
        if (summary.Contains("not rendered as active content", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("safe rendering context", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("markup was not parsed as active HTML", StringComparison.OrdinalIgnoreCase))
        {
            return "medium";
        }

        return verdict switch
        {
            Severity.Critical => "critical",
            Severity.High => "high",
            Severity.Medium => "medium",
            Severity.Low => "low",
            _ => "info"
        };
    }

    private static string? SubstituteBody(string? template, string value)
    {
        if (string.IsNullOrEmpty(template)) return template;
        var trimmed = template.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return InjectionJsonBody.SubstituteMarkers(template, value);
        return RequestMarkerSubstitute.ReplaceAll(template, value);
    }
}
