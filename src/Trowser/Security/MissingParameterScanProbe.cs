using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Omits each top-level JSON field on traffic-derived POST bodies and classifies
/// crash vs proper validation responses (OWASP A10 / CWE-234).
/// </summary>
public sealed class MissingParameterScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public MissingParameterScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class ScanOptions
    {
        public IReadOnlyList<string>? Urls { get; set; }
        public int MaxEndpoints { get; set; } = 8;
        public int MaxFieldsPerEndpoint { get; set; } = 8;
        public int TimeoutMs { get; set; } = 12_000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Category { get; init; } = "missing-parameter-crash";
        public string Severity { get; init; } = "medium";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string OmittedField { get; init; } = "";
        public string Signal { get; init; } = "";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int ProbeStatus { get; init; }
        public List<string> NpeHints { get; init; } = [];
        public string? BodySnippet { get; init; }
    }

    public sealed class ScanResult
    {
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int EndpointsProbed { get; init; }
        public int FieldsProbed { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running missing-parameter-scan.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var targets = ExceptionalConditionDiscovery.DiscoverJsonPostTargets(
            _ctx, origin, Math.Clamp(options.MaxEndpoints, 1, 20), options.Urls);

        if (targets.Count == 0)
            throw new InvalidOperationException(
                "No JSON POST endpoints in network log. Browse and submit forms/API calls first, or pass urls[].");

        var findings = new List<ScanFinding>();
        var fieldsProbed = 0;
        var maxFields = Math.Clamp(options.MaxFieldsPerEndpoint, 1, 15);

        _log($"MissingParameterScan: {targets.Count} endpoint(s)", "#888888");

        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();

            var baseline = await SecurityProbeHttp.FetchAsync(
                _ctx, target.Url, target.Method, target.Headers, target.BodyTemplate,
                options.TimeoutMs, includeBrowserCookies: true, ct);

            foreach (var field in target.TopLevelFields.Take(maxFields))
            {
                ct.ThrowIfCancellationRequested();
                fieldsProbed++;

                var omittedBody = ExceptionalConditionDiscovery.OmitTopLevelField(target.BodyTemplate, field);
                var probe = await SecurityProbeHttp.FetchAsync(
                    _ctx, target.Url, target.Method, target.Headers, omittedBody,
                    options.TimeoutMs, includeBrowserCookies: true, ct);

                var finding = Classify(target, field, baseline.Status, baseline.Body ?? "", probe.Status, probe.Body ?? "");
                if (finding != null)
                    findings.Add(finding);
            }
        }

        if (options.RegisterChainFindings)
        {
            foreach (var f in findings)
                AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Detail, f.Url, f.Method, f.Detail);
        }

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add("No crash/stack-trace signals when omitting top-level JSON fields.");
        else
            summary.Add($"{findings.Count} missing-parameter mishandling finding(s) — review validation vs uncaught exceptions.");
        summary.Add($"Endpoints: {targets.Count}, field omissions probed: {fieldsProbed}.");

        return new ScanResult
        {
            Findings = findings,
            Summary = summary,
            EndpointsProbed = targets.Count,
            FieldsProbed = fieldsProbed
        };
    }

    private static ScanFinding? Classify(
        ExceptionalConditionDiscovery.JsonPostTarget target,
        string omittedField,
        int baselineStatus,
        string baselineBody,
        int probeStatus,
        string probeBody)
    {
        var npeHints = ExceptionalConditionHeuristics.ExtractNullFieldHints(probeBody);
        var hasStack = ExceptionalConditionHeuristics.HasCrashPattern(probeBody)
                       && !ExceptionalConditionHeuristics.HasCrashPattern(baselineBody);

        if (probeStatus >= 500 && hasStack)
        {
            var hintText = npeHints.Count > 0
                ? $" NPE chain hint: try supplying field(s) {string.Join(", ", npeHints)} next."
                : "";
            return new ScanFinding
            {
                Category = "missing-parameter-crash",
                Severity = "high",
                Url = target.Url,
                Method = target.Method,
                OmittedField = omittedField,
                Signal = "500-stack-trace",
                Title = $"Missing parameter '{omittedField}' causes stack trace on {target.Url}",
                Detail = $"Omitting '{omittedField}' returned HTTP {probeStatus} with stack/crash markers vs baseline HTTP {baselineStatus}.{hintText}",
                BaselineStatus = baselineStatus,
                ProbeStatus = probeStatus,
                NpeHints = npeHints,
                BodySnippet = ExceptionalConditionHeuristics.Truncate(
                    probeBody.Replace('\r', ' ').Replace('\n', ' '), 200)
            };
        }

        if (probeStatus >= 500)
        {
            return new ScanFinding
            {
                Category = "missing-parameter-error",
                Severity = "medium",
                Url = target.Url,
                Method = target.Method,
                OmittedField = omittedField,
                Signal = "500-without-validation",
                Title = $"Missing parameter '{omittedField}' causes HTTP 500 on {target.Url}",
                Detail = $"Omitting '{omittedField}' returned HTTP {probeStatus} (server error) vs baseline HTTP {baselineStatus}.",
                BaselineStatus = baselineStatus,
                ProbeStatus = probeStatus,
                NpeHints = npeHints,
                BodySnippet = ExceptionalConditionHeuristics.Truncate(
                    probeBody.Replace('\r', ' ').Replace('\n', ' '), 200)
            };
        }

        if (npeHints.Count > 0 && probeStatus is >= 200 and < 300)
        {
            return new ScanFinding
            {
                Category = "missing-parameter-npe-hint",
                Severity = "low",
                Url = target.Url,
                Method = target.Method,
                OmittedField = omittedField,
                Signal = "npe-field-hint",
                Title = $"Missing '{omittedField}' reveals null-field hint on {target.Url}",
                Detail = $"Response mentions field(s) {string.Join(", ", npeHints)} — progressive NPE chain may apply.",
                BaselineStatus = baselineStatus,
                ProbeStatus = probeStatus,
                NpeHints = npeHints,
                BodySnippet = ExceptionalConditionHeuristics.Truncate(
                    probeBody.Replace('\r', ' ').Replace('\n', ' '), 200)
            };
        }

        return null;
    }
}
