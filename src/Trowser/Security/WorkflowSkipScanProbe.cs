using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Multi-step workflow skip — POST directly to late-stage endpoints without earlier steps.
/// Traffic-driven path staging heuristics (not vertical-specific).
/// </summary>
public sealed class WorkflowSkipScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public WorkflowSkipScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class WorkflowSkipScanOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int TimeoutMs { get; set; } = 10000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool TryMinimalBody { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class WorkflowSkipFinding
    {
        public string Category { get; init; } = "workflow-step-skip";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public int StageRank { get; init; }
        public string PathPrefix { get; init; } = "";
        public int Status { get; init; }
        public string BodyVariant { get; init; } = "captured";
        public string Detail { get; init; } = "";
    }

    public sealed class WorkflowSkipScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<WorkflowSkipFinding> Findings { get; init; } = [];
        public List<object> ProperlyGated { get; init; } = [];
        public List<InsecureDesignProbeSupport.ProbeObservation> Observations { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
        public bool HasObservations => Observations.Count > 0;
    }

    public async Task<WorkflowSkipScanResult> RunAsync(WorkflowSkipScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running workflow-skip-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = InsecureDesignDiscovery.DiscoverWorkflowSkipCandidates(
            _ctx, origin, options.MaxCandidates, options.Urls);

        if (candidates.Count == 0)
        {
            return new WorkflowSkipScanResult
            {
                Message = "No late-stage POST endpoints in network log. Browse multi-step flows (confirm, complete, submit, redeem) first.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var findings = new List<WorkflowSkipFinding>();
        var properlyGated = new List<object>();
        var observations = new List<InsecureDesignProbeSupport.ProbeObservation>();
        var probesSent = 0;
        var endpointHadCsrf = false;

        _log($"WorkflowSkipScan: {candidates.Count} late-stage candidate(s)", "#888888");

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            endpointHadCsrf = InsecureDesignDiscovery.EndpointTemplateHadCsrf(candidate.BodyTemplate);

            var capturedBody = candidate.BodyTemplate ?? "{}";
            probesSent++;
            var capturedPrepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                _ctx, capturedBody, candidate.Headers, candidate.Url,
                injectCsrfIfMissing: true, ct);
            var capturedResponse = await SecurityProbeHttp.FetchAsync(
                _ctx,
                candidate.Url,
                candidate.Method,
                capturedPrepared.Headers,
                capturedPrepared.Body,
                options.TimeoutMs,
                options.IncludeBrowserCookies,
                ct);

            var capturedGate = ClassifyGate(
                capturedResponse.Status, capturedResponse.Body, capturedPrepared.Body, endpointHadCsrf);
            if (capturedGate == null
                && InsecureDesignDiscovery.LooksLikeWorkflowSkipAccepted(capturedResponse.Status, capturedResponse.Body))
            {
                observations.Add(new InsecureDesignProbeSupport.ProbeObservation
                {
                    Category = "workflow-replay-accepted",
                    Severity = "info",
                    Url = candidate.Url,
                    Detail =
                        $"Late-stage {candidate.Method} accepted the captured request body in the current browser session " +
                        $"(HTTP {capturedResponse.Status}) — replayable, not evidence of step skip without a fresh session."
                });
            }

            if (options.TryMinimalBody)
            {
                probesSent++;
                var minimalPrepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                    _ctx, "{}", candidate.Headers, candidate.Url,
                    injectCsrfIfMissing: false, ct);
                var minimalResponse = await SecurityProbeHttp.FetchAsync(
                    _ctx,
                    candidate.Url,
                    candidate.Method,
                    minimalPrepared.Headers,
                    minimalPrepared.Body,
                    options.TimeoutMs,
                    options.IncludeBrowserCookies,
                    ct);

                var minimalGate = ClassifyGate(
                    minimalResponse.Status, minimalResponse.Body, minimalPrepared.Body, endpointHadCsrf);
                if (minimalGate != null)
                {
                    properlyGated.Add(new
                    {
                        url = candidate.Url,
                        status = minimalResponse.Status,
                        bodyVariant = "minimal",
                        stageRank = candidate.StageRank,
                        gateType = minimalGate
                    });
                }
                else if (InsecureDesignDiscovery.LooksLikeWorkflowSkipAccepted(minimalResponse.Status, minimalResponse.Body))
                {
                    findings.Add(new WorkflowSkipFinding
                    {
                        Category = "workflow-step-skip",
                        Severity = "medium",
                        Url = candidate.Url,
                        Method = candidate.Method,
                        StageRank = candidate.StageRank,
                        PathPrefix = candidate.PathPrefix,
                        Status = minimalResponse.Status,
                        BodyVariant = "minimal",
                        Detail =
                            $"Direct {candidate.Method} to late-stage endpoint returned HTTP {minimalResponse.Status} " +
                            $"with minimal body {{}} (stageRank={candidate.StageRank}, prefix={candidate.PathPrefix}). " +
                            "This session may have already completed earlier steps — confirm with a fresh session before treating as high."
                    });
                }
            }
        }

        return new WorkflowSkipScanResult
        {
            Message = findings.Count == 0
                ? $"No workflow step-skip on {candidates.Count} late-stage endpoint(s); {properlyGated.Count} properly gated."
                : $"{findings.Count} workflow step-skip finding(s).",
            CandidatesProbed = candidates.Count,
            ProbesSent = probesSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            ProperlyGated = properlyGated,
            Observations = observations
        };
    }

    private static string? ClassifyGate(int status, string? responseBody, string? requestBody, bool endpointHadCsrf)
    {
        if (InsecureDesignProbeSupport.LooksLikeCsrfRejection(status, responseBody)
            || InsecureDesignProbeSupport.InferCsrfGate(status, responseBody, requestBody, endpointHadCsrf))
            return "csrf-validation";

        if (InsecureDesignDiscovery.LooksLikeProperRejection(status, responseBody ?? ""))
            return "business-rejection";

        return null;
    }
}
