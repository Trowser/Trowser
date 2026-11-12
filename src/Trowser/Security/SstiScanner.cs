using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Lightweight server-side template injection probe — arithmetic reflection and common error signatures.
/// </summary>
public static class SstiScanner
{
    public static readonly string[] DefaultPayloads =
    [
        "{{7*7}}",
        "{{=7*7}}",      // doT / similar interpolate-print forms
        "{{= 7*7 }}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "${{7*7}}",
        "@(7*7)",
        "{{config}}",
        "${7*8}",
        "{{7*8}}"
    ];

    private static readonly string[] ErrorIndicators =
    [
        "jinja2", "TemplateNotFound", "UndefinedError", "freemarker", "VelocityException",
        "twig", "Handlebars", "mustache", "Thymeleaf", "pebble", "smarty",
        "TemplateSyntaxError", "eval()", "liquid error"
        // Note: bare "SyntaxError" removed — too generic (JS/runtime noise).
    ];

    private static readonly (string Engine, string Payload, string Marker)[] EngineCanaries =
    [
        ("jinja2", "{{config.items()}}", "config"),
        ("twig", "{{_self.env}}", "_self"),
        ("freemarker", "${.data_model}", "data_model"),
        ("smarty", "{php}echo 'trowser';{/php}", "trowser")
    ];

    public sealed class SstiRow
    {
        public string Payload { get; init; } = "";
        public int Status { get; init; }
        public bool ReflectedArithmetic { get; init; }
        public bool TemplateError { get; init; }
        public string? Indicator { get; init; }
        public string? ContentType { get; init; }
    }

    public sealed class SstiScanResult
    {
        public List<SstiRow> Rows { get; init; } = [];
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public string Depth { get; init; } = SecurityScanDepth.Standard;
        public bool HasFindings => Findings.Count > 0;

        public SecurityScanResult ToSecurityScanResult(string? message = null) => new()
        {
            Message = message ?? (HasFindings ? $"{Findings.Count} SSTI finding(s)." : "No SSTI indicators."),
            Depth = Depth,
            CandidatesProbed = CandidatesProbed,
            PayloadsSent = Rows.Count,
            ElapsedMs = ElapsedMs,
            Findings = Findings,
            Details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["rows"] = Rows
            }
        };
    }

    public static async Task<SstiScanResult> RunAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        string paramName,
        int timeoutMs = 15000,
        CancellationToken ct = default,
        string? depth = null,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        var sw = Stopwatch.StartNew();
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate, headers);
        if (markers.Count == 0)
            throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                "Template must contain §marker§ or {{marker}} injection point in url, body, or headers."));

        var depthProfile = InjectionScanDepth.Resolve(depth);
        var contentTypeVariants = depthProfile.TryContentTypeMatrix
            ? BuildContentTypeVariants(method, headers, bodyTemplate)
            : [null];
        var baselineVal = "trowser-ssti-baseline";
        var rows = new List<SstiRow>();
        var arithmeticHits = new List<(string Payload, int Status, string? Ct, string Endpoint)>();
        var errorFindings = new List<UnifiedSecurityFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var param = string.IsNullOrWhiteSpace(paramName) ? markers[0] : paramName;

        foreach (var ctVariant in contentTypeVariants)
        {
            ct.ThrowIfCancellationRequested();
            var baseHeaders = MergeHeaders(
                RequestMarkerSubstitute.ReplaceAllInHeaders(headers, baselineVal),
                ctVariant);
            var baseUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, baselineVal);
            var baseBody = SubstituteBody(bodyTemplate, baselineVal);
            var baseJson = await ctx.Fetch(baseUrl, method, baseHeaders, baseBody, timeoutMs);
            ct.ThrowIfCancellationRequested();
            var (_, baseText, _) = HttpSecurityProbes.ParseFetchJson(baseJson);

            var payloads = PayloadCatalog.ResolveWithFallback("ssti", DefaultPayloads, payloadProfile);
            if (depthProfile.Name == SecurityScanDepth.Quick)
                payloads = payloads.Take(5).ToArray();

            foreach (var payload in payloads)
            {
                ct.ThrowIfCancellationRequested();
                var subHeaders = MergeHeaders(
                    RequestMarkerSubstitute.ReplaceAllInHeaders(headers, payload),
                    ctVariant);
                var subUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, payload);
                var subBody = SubstituteBody(bodyTemplate, payload);
                var json = await ctx.Fetch(subUrl, method, subHeaders, subBody, timeoutMs);
                var (status, text, _) = HttpSecurityProbes.ParseFetchJson(json);

                var reflected = SstiReflectionHelper.DetectArithmeticReflection(payload, baseText, text);
                var err = DetectTemplateError(baseText, text, out var indicator);
                if (!reflected && !err) continue;

                rows.Add(new SstiRow
                {
                    Payload = payload,
                    Status = status,
                    ReflectedArithmetic = reflected,
                    TemplateError = err,
                    Indicator = indicator,
                    ContentType = ctVariant
                });

                if (reflected)
                {
                    arithmeticHits.Add((payload, status, ctVariant, subUrl));
                    continue;
                }

                var key = $"{payload}|{ctVariant}|err|{indicator}";
                if (!seen.Add(key)) continue;

                errorFindings.Add(UnifiedSecurityFinding.Create(
                    category: "ssti",
                    title: "Server-side template injection (error signature)",
                    severity: "high",
                    confidence: SecurityConfidence.Tentative,
                    endpoint: subUrl,
                    method: method,
                    param: param,
                    payload: payload,
                    evidence: indicator,
                    proofHint: $"Template engine error signature: {indicator}",
                    nextActions:
                    [
                        SecurityNextActions.SstiConfirmSecondExpression,
                        SecurityNextActions.VerifyWorkflow
                    ],
                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["indicator"] = indicator,
                        ["contentType"] = ctVariant
                    }));
            }

            if (depthProfile.IncludeEngineCanary && arithmeticHits.Count > 0)
            {
                foreach (var (engine, canaryPayload, marker) in EngineCanaries)
                {
                    ct.ThrowIfCancellationRequested();
                    var subHeaders = MergeHeaders(
                        RequestMarkerSubstitute.ReplaceAllInHeaders(headers, canaryPayload),
                        ctVariant);
                    var subUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, canaryPayload);
                    var subBody = SubstituteBody(bodyTemplate, canaryPayload);
                    var json = await ctx.Fetch(subUrl, method, subHeaders, subBody, timeoutMs);
                    var (status, text, _) = HttpSecurityProbes.ParseFetchJson(json);
                    if (string.IsNullOrEmpty(text) || !text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (baseText.Contains(marker, StringComparison.OrdinalIgnoreCase))
                        continue;

                    rows.Add(new SstiRow
                    {
                        Payload = canaryPayload,
                        Status = status,
                        ReflectedArithmetic = false,
                        TemplateError = false,
                        Indicator = $"engine-canary:{engine}",
                        ContentType = ctVariant
                    });

                    errorFindings.Add(UnifiedSecurityFinding.Create(
                        category: "ssti",
                        title: $"SSTI engine canary ({engine})",
                        severity: "critical",
                        confidence: SecurityConfidence.Likely,
                        endpoint: subUrl,
                        method: method,
                        param: param,
                        payload: canaryPayload,
                        evidence: marker,
                        proofHint: $"Safe engine canary for {engine} reflected marker '{marker}'.",
                        nextActions: [SecurityNextActions.VerifyWorkflow],
                        extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["engine"] = engine,
                            ["contentType"] = ctVariant
                        }));
                    break;
                }
            }
        }

        var findings = new List<UnifiedSecurityFinding>();
        findings.AddRange(errorFindings);

        // Dual-expression confirm: need both 49 and 56 (or two distinct arithmetic hits) for critical.
        var has49 = arithmeticHits.Any(h =>
            h.Payload.Contains("7*7", StringComparison.Ordinal) || h.Payload.Contains("7*'7'", StringComparison.Ordinal));
        var has56 = arithmeticHits.Any(h => h.Payload.Contains("7*8", StringComparison.Ordinal));
        var dualConfirmed = !depthProfile.RequireDualArithmeticConfirm || (has49 && has56)
                            || arithmeticHits.Select(h => h.Payload).Distinct(StringComparer.Ordinal).Count() >= 2;

        foreach (var hit in arithmeticHits)
        {
            var key = $"{hit.Payload}|{hit.Ct}|arith";
            if (!seen.Add(key)) continue;

            var severity = dualConfirmed ? "critical" : "high";
            var confidence = dualConfirmed ? SecurityConfidence.Confirmed : SecurityConfidence.Likely;
            var proof = dualConfirmed
                ? "Template arithmetic evaluated (dual-expression confirm)."
                : "Template arithmetic evaluated — confirm with a second expression (e.g. 7*8→56).";

            findings.Add(UnifiedSecurityFinding.Create(
                category: "ssti",
                title: "Server-side template injection",
                severity: severity,
                confidence: confidence,
                endpoint: hit.Endpoint,
                method: method,
                param: param,
                payload: hit.Payload,
                evidence: hit.Payload.Contains("7*8", StringComparison.Ordinal) ? "56" : "49",
                proofHint: proof,
                nextActions: dualConfirmed
                    ? [SecurityNextActions.VerifyWorkflow]
                    : [SecurityNextActions.SstiConfirmSecondExpression, SecurityNextActions.VerifyWorkflow],
                extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["indicator"] = "reflectedArithmetic",
                    ["contentType"] = hit.Ct,
                    ["dualConfirmed"] = dualConfirmed
                }));
        }

        return new SstiScanResult
        {
            Rows = rows,
            Findings = findings,
            CandidatesProbed = 1,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Depth = depthProfile.Name
        };
    }

    /// <summary>
    /// For POST/PUT/PATCH with a body marker, also try text/plain and application/json when Content-Type is unset
    /// (some engines only evaluate templates for specific content types).
    /// </summary>
    private static List<string?> BuildContentTypeVariants(
        string method, Dictionary<string, string>? headers, string? bodyTemplate)
    {
        var mutating = method is "POST" or "PUT" or "PATCH";
        var hasBodyMarker = !string.IsNullOrEmpty(bodyTemplate)
            && RequestMarkerSubstitute.ListMarkers("", bodyTemplate).Count > 0;
        if (!mutating || !hasBodyMarker)
            return [null];

        string? existing = null;
        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(kv.Value))
                {
                    existing = kv.Value.Trim();
                    break;
                }
            }
        }

        // Even when a CT is already set (e.g. JSON-only captured traffic), also try the sibling
        // types that template engines commonly evaluate — JSON-only misses many SSTI sinks.
        if (existing != null)
        {
            var variants = new List<string?> { existing };
            void Add(string ct)
            {
                if (!variants.Any(v => string.Equals(v, ct, StringComparison.OrdinalIgnoreCase)))
                    variants.Add(ct);
            }

            if (existing.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                Add("text/plain");
                Add("application/x-www-form-urlencoded");
            }
            else if (existing.Contains("text/plain", StringComparison.OrdinalIgnoreCase))
            {
                Add("application/json");
                Add("application/x-www-form-urlencoded");
            }
            else if (existing.Contains("urlencoded", StringComparison.OrdinalIgnoreCase)
                     || existing.Contains("form", StringComparison.OrdinalIgnoreCase))
            {
                Add("text/plain");
                Add("application/json");
            }

            return variants;
        }

        // Default matrix: plain text first (doT / many labs), then JSON, then form.
        return ["text/plain", "application/json", "application/x-www-form-urlencoded"];
    }

    private static Dictionary<string, string>? MergeHeaders(
        Dictionary<string, string>? headers, string? contentType)
    {
        if (contentType == null) return headers;
        var result = headers != null
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        result["Content-Type"] = contentType;
        return result;
    }

    internal static bool DetectTemplateError(string baselineText, string probeText, out string? indicator)
    {
        indicator = null;
        if (string.IsNullOrEmpty(probeText)) return false;
        foreach (var sig in ErrorIndicators)
        {
            if (baselineText.Contains(sig, StringComparison.OrdinalIgnoreCase))
                continue;
            if (probeText.Contains(sig, StringComparison.OrdinalIgnoreCase))
            {
                indicator = sig;
                return true;
            }
        }

        return false;
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
