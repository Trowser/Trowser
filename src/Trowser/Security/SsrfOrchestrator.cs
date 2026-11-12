using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// One-call SSRF assessment: scaffold + ssrf-scan + open-redirect escalation + JWT jku/x5u + callback poll + chain analysis.
/// </summary>
public sealed class SsrfOrchestrator
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SsrfOrchestrator(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class OrchestratorOptions
    {
        public int MaxCandidates { get; init; } = 10;
        public int TimeoutMs { get; init; } = 15000;
        public int CallbackWaitMs { get; init; } = 2000;
        public bool IncludeScaffoldPaths { get; init; } = true;
        public bool IncludeImdsV2Pivot { get; init; } = true;
        public bool IncludeCloudMetadataHeaders { get; init; } = true;
        public bool IncludeXxe { get; init; } = true;
        public bool IncludeUploadXxe { get; init; }
        public bool IncludeOpenRedirect { get; init; } = true;
        public bool IncludeJwtHeaderAbuse { get; init; } = true;
        public bool IncludeCallbackProbes { get; init; } = true;
        public bool IncludeChainAnalysis { get; init; } = true;
        public bool RegisterChainFindings { get; init; } = true;
        public string? CallbackDomain { get; init; }
        public string? MinConfidence { get; init; }
        public bool UseBackendFetch { get; init; }
        public bool IncludeBrowserCookies { get; init; }
        public List<string>? ExplicitUrls { get; init; }
        public List<EndpointParamHint>? EndpointHints { get; init; }
    }

    public sealed class OrchestratorResult
    {
        public string Message { get; init; } = "";
        public SsrfResult? Ssrf { get; init; }
        public OpenRedirectResult? OpenRedirect { get; init; }
        public JwtHeaderAbuseProbe.ProbeResult? JwtHeaderAbuse { get; init; }
        public int CallbackInteractions { get; init; }
        public object? ChainAnalysis { get; init; }
        public int TotalFindings { get; init; }
        public List<string> StepsRun { get; init; } = [];
        public List<string> Errors { get; init; } = [];
    }

    public async Task<OrchestratorResult> RunAsync(
        OrchestratorOptions options,
        ChainPatternCatalog? chainCatalog = null,
        CancellationToken ct = default)
    {
        var steps = new List<string>();
        var errors = new List<string>();
        var totalFindings = 0;

        if (options.IncludeCallbackProbes && _ctx.CallbackDetector != null && !_ctx.CallbackDetector.Active)
            _ctx.CallbackDetector.Start(options.CallbackDomain);

        SsrfResult? ssrfResult = null;
        try
        {
            ssrfResult = await _ctx.RunSsrfScan(new SsrfOptions
            {
                ExplicitUrls = options.ExplicitUrls,
                EndpointHints = options.EndpointHints,
                MaxCandidates = options.MaxCandidates,
                TimeoutMs = options.TimeoutMs,
                CallbackWaitMs = options.CallbackWaitMs,
                IncludeScaffoldPaths = options.IncludeScaffoldPaths,
                IncludeImdsV2Pivot = options.IncludeImdsV2Pivot,
                IncludeCloudMetadataHeaders = options.IncludeCloudMetadataHeaders,
                IncludeXxe = options.IncludeXxe,
                IncludeUploadXxe = options.IncludeUploadXxe,
                IncludeCallbackProbes = options.IncludeCallbackProbes,
                CallbackDomain = options.CallbackDomain,
                MinConfidence = options.MinConfidence,
                UseBackendFetch = options.UseBackendFetch,
                IncludeBrowserCookies = options.IncludeBrowserCookies
            });
            steps.Add("ssrf-scan");
            totalFindings += ssrfResult.Findings.Count;

            if (options.RegisterChainFindings)
                RegisterSsrfFindings(ssrfResult.Findings);
        }
        catch (Exception ex)
        {
            errors.Add($"ssrf-scan: {ex.Message}");
        }

        OpenRedirectResult? openRedirect = null;
        if (options.IncludeOpenRedirect)
        {
            try
            {
                openRedirect = await _ctx.RunOpenRedirectScan(new OpenRedirectOptions
                {
                    ExplicitUrls = options.ExplicitUrls,
                    EndpointHints = options.EndpointHints,
                    MaxCandidates = Math.Min(options.MaxCandidates, 12),
                    TimeoutMs = options.TimeoutMs,
                    IncludeSsrfEscalationProbes = true
                });
                steps.Add("open-redirect-scan");
                totalFindings += openRedirect.Findings.Count;

                if (options.RegisterChainFindings)
                {
                    foreach (var f in openRedirect.Findings)
                    {
                        AuthProbeDiscovery.RegisterChainFinding(_ctx, "open-redirect", f.Severity,
                            $"Open redirect: {f.Indicator}", f.Url, f.Method, f.Snippet);
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Add($"open-redirect-scan: {ex.Message}");
            }
        }

        JwtHeaderAbuseProbe.ProbeResult? jwtAbuse = null;
        if (options.IncludeJwtHeaderAbuse)
        {
            try
            {
                jwtAbuse = await JwtHeaderAbuseProbe.RunAsync(_ctx, new JwtHeaderAbuseProbe.ProbeOptions
                {
                    MaxEndpoints = options.MaxCandidates,
                    TimeoutMs = options.TimeoutMs,
                    RegisterChainFindings = options.RegisterChainFindings
                }, ct);
                steps.Add("jwt-header-abuse");
                totalFindings += jwtAbuse.Findings.Count;
            }
            catch (Exception ex)
            {
                errors.Add($"jwt-header-abuse: {ex.Message}");
            }
        }

        var callbackCount = 0;
        if (options.IncludeCallbackProbes && _ctx.CallbackDetector?.Active == true)
        {
            if (options.CallbackWaitMs > 0)
                await Task.Delay(options.CallbackWaitMs, ct);
            callbackCount = _ctx.CallbackDetector.GetInteractions().Count;
            steps.Add("callback-poll");
        }

        object? chainAnalysis = null;
        if (options.IncludeChainAnalysis && chainCatalog != null)
        {
            try
            {
                var chainFindings = ChainAnalysisService.CollectFindings(_ctx);
                var analyzed = ChainAnalysisService.Analyze(chainCatalog, chainFindings,
                    new ChainAnalysisService.AnalyzeOptions(MinChainedSeverity: "high", IncludePartial: true));
                chainAnalysis = ChainAnalysisService.BuildAnalyzePayload(analyzed);
                steps.Add("chain-analyze");
            }
            catch (Exception ex)
            {
                errors.Add($"chain-analyze: {ex.Message}");
            }
        }

        var msg = totalFindings > 0
            ? $"SSRF orchestrator: {totalFindings} finding(s) across {string.Join(", ", steps)}."
            : $"SSRF orchestrator complete ({string.Join(", ", steps)}); no SSRF indicators detected.";

        return new OrchestratorResult
        {
            Message = msg,
            Ssrf = ssrfResult,
            OpenRedirect = openRedirect,
            JwtHeaderAbuse = jwtAbuse,
            CallbackInteractions = callbackCount,
            ChainAnalysis = chainAnalysis,
            TotalFindings = totalFindings,
            StepsRun = steps,
            Errors = errors
        };
    }

    private void RegisterSsrfFindings(IReadOnlyList<SsrfFinding> findings)
    {
        foreach (var f in findings)
        {
            _ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"ssrf-{Math.Abs((f.Url + f.ParamName + f.Indicator).GetHashCode(StringComparison.Ordinal))}",
                Source = "ssrf-scan",
                Category = "ssrf",
                Severity = f.Severity,
                Title = $"SSRF ({f.Indicator}): {f.ParamName}",
                Endpoint = f.Url,
                Method = f.Method,
                Parameter = f.ParamName,
                Detail = $"{f.Confidence}: {f.Snippet}"
            });
        }
    }
}
