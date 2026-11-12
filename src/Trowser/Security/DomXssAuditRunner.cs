using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.DomFlow;
using Trowser.XssAudit;

namespace Trowser.Security;

/// <summary>
/// First-class DOM XSS pass: client surface + optional dom-flow probe + trace-input on discovered URL vectors.
/// </summary>
public sealed class DomXssAuditRunner
{
    private readonly AutomationContext _ctx;

    public DomXssAuditRunner(AutomationContext ctx) => _ctx = ctx;

    public sealed class DomXssAuditOptions
    {
        public string ScanDepth { get; init; } = SecurityScanDepth.Standard;
        public bool ConfirmExecution { get; init; }
        /// <summary>Medium default: false — use <c>depth: deep</c> or explicit true for full client-surface map.</summary>
        public bool RunClientSurface { get; init; }
        public bool RunPassiveXss { get; init; } = true;
        public bool RunDomFlowProbe { get; init; } = true;
        public bool RunTraceInput { get; init; } = true;
        /// <summary>Medium default: false — single query trace (<c>q</c>) on current URL; deep enables all keys.</summary>
        public bool ProbeAllUrlParams { get; init; }
        public bool ProbeUrlHash { get; init; } = true;
        /// <summary>Extra trace-input legs from inline script hints (redirect params, location-driven). Deep default only.</summary>
        public bool RunScriptGatedTraces { get; init; }
        public bool FireEvents { get; init; }
        public int TimeoutMs { get; init; } = 6_000;
        /// <summary>Orchestrator wall clock (seconds). 0 = derived from enabled phases and <see cref="TimeoutMs"/>.</summary>
        public int MaxSeconds { get; init; }
    }

    public async Task<DomXssAuditResult> RunAsync(DomXssAuditOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var pageUrl = await _ctx.GetCurrentUrl();
        var restoreUrl = await ProbeNavigationRestore.CaptureBaselineUrlAsync(_ctx);
        var findings = new List<UnifiedSecurityFinding>();
        ClientSurfaceResult? surface = null;
        DomFlowGraph.DomFlowResult? flows = null;
        XssResult? passiveXss = null;
        var traces = new List<InputTraceResult>();
        var partial = false;
        var budgetExhausted = false;

        var wallSeconds = ResolveWallClockSeconds(options);
        CancellationTokenSource? wallCts = null;
        var effectiveCt = ct;
        if (wallSeconds > 0)
        {
            wallCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            ScanTimeout.CancelAfterSeconds(wallCts, wallSeconds);
            effectiveCt = wallCts.Token;
        }

        try
        {
            if (options.RunClientSurface)
            {
                effectiveCt.ThrowIfCancellationRequested();
                surface = await new ClientSurfaceMapper(_ctx).MapAsync(installSensor: true, waitMs: 350);
                foreach (var cell in surface.Cells.Where(c => c.Status is "confirmed" or "correlated").Take(6))
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "dom-xss-surface",
                        title: $"Client surface map: {cell.Source} → {cell.Sink} ({cell.Status})",
                        severity: "medium",
                        confidence: SecurityConfidence.Likely,
                        tier: SecurityFindingTier.Hygiene,
                        evidence: $"{cell.Source}→{cell.Sink} cell status={cell.Status} (runtime correlation — not a proven exploit chain)",
                        proofHint: "Correlation only — confirm with trace-input (monitorSinks) or confirmExecution before filing as exploitable XSS.",
                        nextActions: [SecurityNextActions.TraceInputMonitorSinks, "POST /api/security/dom-flows mode=probe"],
                        extra: new Dictionary<string, object?>
                        {
                            ["surfaceStatus"] = cell.Status,
                            ["clientSurfaceCell"] = true
                        }));
                }
            }

            if (options.RunPassiveXss)
            {
                effectiveCt.ThrowIfCancellationRequested();
                passiveXss = await _ctx.CheckXss(probeDomOpenRedirects: true);
                foreach (var f in passiveXss.Findings.Take(20))
                {
                    var isStaticJsUrl = f.Category.Equals("javascript-url", StringComparison.OrdinalIgnoreCase)
                                        && f.Severity <= XssSeverity.Low;
                    var sev = f.Severity switch
                    {
                        XssSeverity.High => isStaticJsUrl ? "low" : "high",
                        XssSeverity.Medium => "medium",
                        XssSeverity.Low => "low",
                        _ => "info"
                    };
                    var tier = isStaticJsUrl || f.Severity == XssSeverity.Info
                        ? SecurityFindingTier.Hygiene
                        : SecurityFindingTier.Exploitable;
                    var confidence = isStaticJsUrl
                        ? SecurityConfidence.Tentative
                        : SecurityConfidence.Normalize(f.Confidence);
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: string.IsNullOrEmpty(f.Category) ? "xss" : f.Category,
                        title: string.IsNullOrEmpty(f.Category) ? "DOM XSS pattern" : f.Category,
                        severity: sev,
                        confidence: confidence,
                        tier: tier,
                        evidence: string.IsNullOrEmpty(f.Location)
                            ? f.Description
                            : $"{f.Description} ({f.Location})",
                        proofHint: f.Recommendation,
                        nextActions: [SecurityNextActions.TraceInputMonitorSinks]));
                }
            }

            if (options.RunDomFlowProbe)
            {
                effectiveCt.ThrowIfCancellationRequested();
                flows = await new DomFlowGraph(_ctx).ProbeAsync(
                    sources: ["url-query", "url-hash", "storage", "post-message"],
                    restoreUrl: true);
                foreach (var chain in flows.Chains.Where(c => c.Tier == "exploitable").Take(15))
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "dom-xss-flow",
                        title: $"DOM flow: {chain.Source} → {chain.Sink} ({chain.Consequence})",
                        severity: chain.Consequence == "exec" ? "critical" : "high",
                        confidence: chain.Confidence == "canary" ? SecurityConfidence.Confirmed : SecurityConfidence.Likely,
                        evidence: chain.SinkData,
                        proofHint: chain.Stack,
                        nextActions: [SecurityNextActions.VerifyWorkflow, SecurityNextActions.TraceInputMonitorSinks],
                        extra: new Dictionary<string, object?>
                        {
                            ["consequence"] = chain.Consequence,
                            ["tier"] = chain.Tier,
                            ["framework"] = chain.Framework
                        }));
                }
            }

            if (options.RunTraceInput)
            {
                effectiveCt.ThrowIfCancellationRequested();
                var traceTemplate = new TraceInputOptions
                {
                    BaseUrl = pageUrl,
                    MonitorSinks = true,
                    TwoPhase = true,
                    ConfirmExecution = options.ConfirmExecution,
                    AutoBypass = false,
                    ProbeUrlSources = false,
                    FireEvents = options.FireEvents,
                    TimeoutMs = options.TimeoutMs
                };

                if (options.ProbeAllUrlParams)
                {
                    var q = await new InputTracer(_ctx).TraceAsync(traceTemplate with
                    {
                        Source = TraceSourceType.UrlQuery,
                        ProbeAllUrlParams = true
                    }, effectiveCt);
                    traces.Add(q);
                    AddTraceFinding(findings, q, "url-query (all params)");
                }
                else
                {
                    effectiveCt.ThrowIfCancellationRequested();
                    var q = await new InputTracer(_ctx).TraceAsync(traceTemplate with
                    {
                        Source = TraceSourceType.UrlQuery,
                        QueryParam = "q"
                    }, effectiveCt);
                    traces.Add(q);
                    AddTraceFinding(findings, q, "url-query");
                }

                if (options.ProbeUrlHash)
                {
                    effectiveCt.ThrowIfCancellationRequested();
                    var h = await new InputTracer(_ctx).TraceAsync(traceTemplate with
                    {
                        Source = TraceSourceType.UrlHash,
                        HashParam = null,
                        FragmentEncode = UrlPayloadEncodeMode.None
                    }, effectiveCt);
                    traces.Add(h);
                    AddTraceFinding(findings, h, "url-hash");
                }

            if (options.RunScriptGatedTraces && surface?.Script is { } script)
                await TraceScriptGatedVectorsAsync(script, traceTemplate, traces, findings, effectiveCt);
            }
        }
        catch (OperationCanceledException)
        {
            partial = true;
            budgetExhausted = wallCts?.IsCancellationRequested == true && !ct.IsCancellationRequested;
        }
        finally
        {
            wallCts?.Dispose();
            await ProbeNavigationRestore.TryRestoreAsync(_ctx, restoreUrl);
        }

        sw.Stop();
        return BuildResult(pageUrl, sw, options, findings, surface, flows, passiveXss, traces, partial, budgetExhausted);
    }

    /// <summary>Default phase profile when REST/MCP omit explicit phase flags (lazy agents get medium current-page, not deep sweep).</summary>
    public static DomXssAuditDepthPlan PlanScanDepth(string? depth) =>
        DomXssAuditDepthPlan.ForDepth(SecurityScanDepth.Normalize(depth));

    public readonly record struct DomXssAuditDepthPlan(
        string Depth,
        bool RunClientSurface,
        bool RunPassiveXss,
        bool RunDomFlowProbe,
        bool RunTraceInput,
        bool ProbeAllUrlParams,
        bool ProbeUrlHash,
        bool RunScriptGatedTraces,
        bool ConfirmExecutionUnlessExplicit,
        int TimeoutMs,
        int MaxSeconds)
    {
        public static DomXssAuditDepthPlan ForDepth(string normalized) => normalized switch
        {
            SecurityScanDepth.Quick => new(
                Depth: SecurityScanDepth.Quick,
                RunClientSurface: false,
                RunPassiveXss: true,
                RunDomFlowProbe: true,
                RunTraceInput: false,
                ProbeAllUrlParams: false,
                ProbeUrlHash: false,
                RunScriptGatedTraces: false,
                ConfirmExecutionUnlessExplicit: false,
                TimeoutMs: 5_000,
                MaxSeconds: 25),
            SecurityScanDepth.Deep => new(
                Depth: SecurityScanDepth.Deep,
                RunClientSurface: true,
                RunPassiveXss: true,
                RunDomFlowProbe: true,
                RunTraceInput: true,
                ProbeAllUrlParams: true,
                ProbeUrlHash: true,
                RunScriptGatedTraces: true,
                ConfirmExecutionUnlessExplicit: true,
                TimeoutMs: 8_000,
                MaxSeconds: 90),
            _ => new(
                Depth: SecurityScanDepth.Standard,
                RunClientSurface: false,
                RunPassiveXss: true,
                RunDomFlowProbe: true,
                RunTraceInput: true,
                ProbeAllUrlParams: false,
                ProbeUrlHash: true,
                RunScriptGatedTraces: false,
                ConfirmExecutionUnlessExplicit: false,
                TimeoutMs: 6_000,
                MaxSeconds: 45)
        };
    }

    public static DomXssAuditOptions ResolveOptions(
        DomXssAuditDepthPlan plan,
        bool confirmExecution,
        int maxSecondsOverride,
        bool? runClientSurface,
        bool? runPassiveXss,
        bool? runDomFlowProbe,
        bool? runTraceInput,
        bool? probeAllUrlParams,
        bool? probeUrlHash,
        bool? runScriptGatedTraces,
        bool? fireEvents,
        int? timeoutMs) =>
        new()
        {
            ScanDepth = plan.Depth,
            ConfirmExecution = confirmExecution,
            RunClientSurface = runClientSurface ?? plan.RunClientSurface,
            RunPassiveXss = runPassiveXss ?? plan.RunPassiveXss,
            RunDomFlowProbe = runDomFlowProbe ?? plan.RunDomFlowProbe,
            RunTraceInput = runTraceInput ?? plan.RunTraceInput,
            ProbeAllUrlParams = probeAllUrlParams ?? plan.ProbeAllUrlParams,
            ProbeUrlHash = probeUrlHash ?? plan.ProbeUrlHash,
            RunScriptGatedTraces = runScriptGatedTraces ?? plan.RunScriptGatedTraces,
            FireEvents = fireEvents ?? false,
            TimeoutMs = timeoutMs ?? plan.TimeoutMs,
            MaxSeconds = maxSecondsOverride > 0 ? maxSecondsOverride : plan.MaxSeconds
        };

    internal static int ResolveWallClockSeconds(DomXssAuditOptions options)
    {
        if (options.MaxSeconds > 0)
            return ScanTimeout.ClampBudgetSeconds(options.MaxSeconds);

        var perTraceSec = Math.Clamp(options.TimeoutMs, 2000, 30_000) / 1000.0;
        var total = 4.0;
        if (options.RunClientSurface) total += 8;
        if (options.RunPassiveXss) total += 4;
        if (options.RunDomFlowProbe) total += 12;
        if (options.RunTraceInput)
        {
            var legs = (options.ProbeAllUrlParams ? 6 : 1) + (options.ProbeUrlHash ? 2 : 0);
            total += perTraceSec * legs;
            total += perTraceSec * 1.5;
        }

        return ScanTimeout.ClampBudgetSeconds(Math.Clamp((int)Math.Ceiling(total), 15, 90));
    }

    private async Task TraceScriptGatedVectorsAsync(
        ClientScriptTextFacts script,
        TraceInputOptions traceTemplate,
        List<InputTraceResult> traces,
        List<UnifiedSecurityFinding> findings,
        CancellationToken ct)
    {
        var tracer = new InputTracer(_ctx);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var extra = script.ReadsAutoFlag
            ? new Dictionary<string, string> { ["auto"] = "1" }
            : null;
        var budget = 4;

        if (script.NavSinks.Count > 0)
        {
            foreach (var param in script.LocationParams.Where(ClientScriptTextScanner.IsRedirectParam))
            {
                if (budget <= 0 || !seen.Add(param)) continue;
                budget--;
                ct.ThrowIfCancellationRequested();
                var traced = await tracer.TraceAsync(traceTemplate with
                {
                    Source = TraceSourceType.UrlQuery,
                    QueryParam = param,
                    ProbeAllUrlParams = false,
                    ExtraQuery = extra,
                    FireEvents = true
                }, ct);
                traces.Add(traced);
                AddTraceFinding(findings, traced, $"url-query {param}");
            }
        }

        if (script.LocationDrivenRequest)
        {
            var source = script.ReadsLocationHash && !script.ReadsLocationSearch
                ? TraceSourceType.UrlHash
                : TraceSourceType.UrlQuery;
            var names = script.LocationParams.Take(3).ToList();
            if (names.Count == 0 && source == TraceSourceType.UrlHash && budget > 0)
            {
                ct.ThrowIfCancellationRequested();
                var traced = await tracer.TraceAsync(traceTemplate with
                {
                    Source = TraceSourceType.UrlHash,
                    HashParam = null,
                    ProbeAllUrlParams = false,
                    FragmentEncode = UrlPayloadEncodeMode.None
                }, ct);
                traces.Add(traced);
                AddTraceFinding(findings, traced, "url-hash location");
                return;
            }

            foreach (var param in names)
            {
                if (budget <= 0 || !seen.Add(param)) continue;
                budget--;
                ct.ThrowIfCancellationRequested();
                var traced = await tracer.TraceAsync(traceTemplate with
                {
                    Source = source,
                    QueryParam = source == TraceSourceType.UrlQuery ? param : null,
                    HashParam = source == TraceSourceType.UrlHash ? param : null,
                    ProbeAllUrlParams = false,
                    FragmentEncode = UrlPayloadEncodeMode.None
                }, ct);
                traces.Add(traced);
                AddTraceFinding(findings, traced, $"{TraceInputOptions.SourceTypeName(source)} {param}");
            }
        }
    }

    private static DomXssAuditResult BuildResult(
        string pageUrl,
        Stopwatch sw,
        DomXssAuditOptions options,
        List<UnifiedSecurityFinding> findings,
        ClientSurfaceResult? surface,
        DomFlowGraph.DomFlowResult? flows,
        XssResult? passiveXss,
        List<InputTraceResult> traces,
        bool partial,
        bool budgetExhausted)
    {
        var worst = traces.Count > 0
            ? traces.Max(t => t.Verdict.Severity)
            : findings.Count > 0 ? Severity.Medium : Severity.Info;

        var nextActions = new List<string>
        {
            SecurityNextActions.TraceInputMonitorSinks,
            "POST /api/security/dom-flows {\"mode\":\"observe\"} after browsing key flows",
            "POST /api/security/postmessage {\"safetyMode\":\"active\"} when listeners exist"
        };
        if (!options.ConfirmExecution)
            nextActions.Insert(0, "Re-run dom-xss-audit or trace-input with confirmExecution:true for execution proof");
        if (partial && budgetExhausted)
            nextActions.Insert(0, "Re-run with budget.maxSeconds raised or disable phases (runClientSurface, probeAllUrlParams) for full coverage");
        if (options.ScanDepth == SecurityScanDepth.Standard && !options.ProbeAllUrlParams && !options.RunClientSurface)
            nextActions.Add("For full query-key sweep + client-surface: re-run with depth:deep or probeAllUrlParams:true and runClientSurface:true");

        var execConfirmed = traces.Any(t => t.Sinks?.ExecutionConfirmed == true)
                            || flows?.Chains.Any(c => c.Consequence == "exec" && c.Tier == "exploitable") == true;

        var summary = BuildSummary(traces, flows, execConfirmed, options.ConfirmExecution);
        if (partial && budgetExhausted)
            summary = $"Partial DOM XSS audit (wall-clock budget exhausted): {summary}";

        return new DomXssAuditResult
        {
            Url = pageUrl,
            ElapsedMs = sw.ElapsedMilliseconds,
            WorstSeverity = worst,
            ExecutionConfirmed = execConfirmed,
            Applied = DomXssAuditApplied.FromOptions(options),
            ClientSurface = surface,
            DomFlows = flows,
            PassiveXss = passiveXss,
            Traces = traces,
            Findings = findings,
            Summary = summary,
            NextActions = nextActions.Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToList(),
            Partial = partial,
            BudgetExhausted = budgetExhausted
        };
    }

    private static void AddTraceFinding(List<UnifiedSecurityFinding> findings, InputTraceResult trace, string vector)
    {
        if (trace.Verdict.Severity <= Severity.Info && trace.Sinks?.PayloadReachedSink != true)
            return;

        var sev = trace.Verdict.Severity switch
        {
            Severity.Critical => "critical",
            Severity.High => "high",
            Severity.Medium => "medium",
            _ => "low"
        };
        var execConfirmed = trace.Sinks?.ExecutionConfirmed == true;
        var tier = execConfirmed
            ? SecurityFindingTier.Exploitable
            : trace.Sinks?.PayloadReachedSink == true && trace.Verdict.Severity >= Severity.Medium
                ? SecurityFindingTier.Exploitable
                : SecurityFindingTier.Hygiene;
        findings.Add(UnifiedSecurityFinding.Create(
            category: "dom-xss-trace",
            title: $"trace-input ({vector}): {trace.Verdict.Summary}",
            severity: sev,
            confidence: execConfirmed
                ? SecurityConfidence.Confirmed
                : trace.Sinks?.PayloadReachedSink == true
                    ? SecurityConfidence.Likely
                    : SecurityConfidence.Tentative,
            tier: tier,
            payload: trace.Payload.Length > 120 ? trace.Payload[..120] + "…" : trace.Payload,
            evidence: trace.Sinks?.MostDangerousSink ?? trace.Dom?.Context,
            proofHint: trace.Verdict.Recommendation,
            nextActions: execConfirmed
                ? [SecurityNextActions.VerifyWorkflow]
                : [SecurityNextActions.TraceInputMonitorSinks],
            extra: new Dictionary<string, object?>
            {
                ["vector"] = vector,
                ["executionConfirmed"] = execConfirmed,
                ["payloadReachedSink"] = trace.Sinks?.PayloadReachedSink == true,
                ["reachMapCount"] = trace.ReachMap?.Count ?? 0,
                ["confirmedXss"] = XssBypassProbes.IsConfirmedXss(trace)
            }));
    }

    private static string BuildSummary(
        List<InputTraceResult> traces,
        DomFlowGraph.DomFlowResult? flows,
        bool execConfirmed,
        bool confirmExecution)
    {
        var reach = traces.Sum(t => t.ReachMap?.Count ?? t.Sinks?.HitCount ?? 0);
        var exploitableFlows = flows?.ExploitableChainCount ?? 0;
        if (execConfirmed)
            return $"DOM XSS: execution confirmed ({traces.Count} trace(s), {exploitableFlows} exploitable dom-flow chain(s)).";
        if (reach > 0 || exploitableFlows > 0)
            return confirmExecution
                ? $"DOM XSS: {reach} sink reach signal(s), {exploitableFlows} exploitable flow(s); execution oracle did not fire."
                : $"DOM XSS: {reach} reach signal(s), {exploitableFlows} exploitable flow(s) (reach-only — confirmExecution was false).";
        return "DOM XSS audit: no confirmed reach or exploitable client-side flows on probed vectors.";
    }
}

public sealed class DomXssAuditApplied
{
    public string Scope { get; init; } = "current-page";
    public string ScanDepth { get; init; } = SecurityScanDepth.Standard;
    public bool ConfirmExecution { get; init; }
    public bool RunClientSurface { get; init; }
    public bool RunPassiveXss { get; init; }
    public bool RunDomFlowProbe { get; init; }
    public bool RunTraceInput { get; init; }
    public bool ProbeAllUrlParams { get; init; }
    public bool ProbeUrlHash { get; init; }
    public bool RunScriptGatedTraces { get; init; }
    public bool FireEvents { get; init; }
    public int TimeoutMs { get; init; }
    public int MaxSeconds { get; init; }

    public static DomXssAuditApplied FromOptions(DomXssAuditRunner.DomXssAuditOptions o) => new()
    {
        ScanDepth = o.ScanDepth,
        ConfirmExecution = o.ConfirmExecution,
        RunClientSurface = o.RunClientSurface,
        RunPassiveXss = o.RunPassiveXss,
        RunDomFlowProbe = o.RunDomFlowProbe,
        RunTraceInput = o.RunTraceInput,
        ProbeAllUrlParams = o.ProbeAllUrlParams,
        ProbeUrlHash = o.ProbeUrlHash,
        RunScriptGatedTraces = o.RunScriptGatedTraces,
        FireEvents = o.FireEvents,
        TimeoutMs = o.TimeoutMs,
        MaxSeconds = o.MaxSeconds
    };
}

public sealed class DomXssAuditResult
{
    public string Url { get; init; } = "";
    public long ElapsedMs { get; init; }
    public Severity WorstSeverity { get; init; }
    public bool ExecutionConfirmed { get; init; }
    public bool Partial { get; init; }
    public bool BudgetExhausted { get; init; }
    public DomXssAuditApplied Applied { get; init; } = new();
    public ClientSurfaceResult? ClientSurface { get; init; }
    public DomFlowGraph.DomFlowResult? DomFlows { get; init; }
    public XssResult? PassiveXss { get; init; }
    public List<InputTraceResult> Traces { get; init; } = [];
    public List<UnifiedSecurityFinding> Findings { get; init; } = [];
    public string Summary { get; init; } = "";
    public List<string> NextActions { get; init; } = [];

    public object ToApiResponse() => new
    {
        url = Url,
        scope = Applied.Scope,
        scanDepth = Applied.ScanDepth,
        applied = new
        {
            scope = Applied.Scope,
            scanDepth = Applied.ScanDepth,
            confirmExecution = Applied.ConfirmExecution,
            runClientSurface = Applied.RunClientSurface,
            runPassiveXss = Applied.RunPassiveXss,
            runDomFlowProbe = Applied.RunDomFlowProbe,
            runTraceInput = Applied.RunTraceInput,
            probeAllUrlParams = Applied.ProbeAllUrlParams,
            probeUrlHash = Applied.ProbeUrlHash,
            runScriptGatedTraces = Applied.RunScriptGatedTraces,
            fireEvents = Applied.FireEvents,
            timeoutMs = Applied.TimeoutMs,
            maxSeconds = Applied.MaxSeconds
        },
        elapsedMs = ElapsedMs,
        worstSeverity = WorstSeverity.ToString().ToLowerInvariant(),
        executionConfirmed = ExecutionConfirmed,
        partial = Partial ? true : (bool?)null,
        budgetExhausted = BudgetExhausted ? true : (bool?)null,
        summary = Summary,
        nextActions = NextActions,
        findingCount = Findings.Count,
        findings = Findings.Select(SecurityScanResult.ToApiFinding).ToList(),
        clientSurface = ClientSurface != null
            ? new { sinks = ClientSurface.Sinks.Count, listeners = ClientSurface.Listeners.Count, cells = ClientSurface.Cells.Count }
            : null,
        domFlows = DomFlows != null
            ? new
            {
                exploitableChainCount = DomFlows.ExploitableChainCount,
                chainCount = DomFlows.Chains.Count,
                summary = DomFlows.Summary
            }
            : null,
        passiveXssFindings = PassiveXss?.FindingCount ?? 0,
        traces = Traces.Select(t => new
        {
            payload = t.Payload,
            sourceType = t.Injection.SourceType,
            verdict = t.Verdict.Severity.ToString().ToLowerInvariant(),
            summary = t.Verdict.Summary,
            executionConfirmed = t.Sinks?.ExecutionConfirmed == true,
            payloadReachedSink = t.Sinks?.PayloadReachedSink == true,
            reachMapCount = t.ReachMap?.Count ?? 0,
            sinksSeen = t.Sinks?.SinksSeen ?? []
        }).ToList()
    };
}
