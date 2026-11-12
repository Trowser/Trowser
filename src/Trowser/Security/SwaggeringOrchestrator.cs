using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;

namespace Trowser.Security;

/// <summary>
/// Full Swaggering pipeline: discover OpenAPI, inventory, costly spec hints, active lanes, shadow paths, auto-scan.
/// </summary>
public sealed class SwaggeringOrchestrator
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SwaggeringOrchestrator(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SwaggeringOptions
    {
        public SafetyMode SafetyMode { get; set; } = SafetyMode.Active;
        public string Depth { get; set; } = SwaggeringDepthProfile.Thorough;
        public int? MaxStepSeconds { get; set; }
        public IReadOnlyList<string>? SpecUrls { get; set; }
        public bool IncludeSpecsFromNetwork { get; set; } = true;
        public bool IncludeOpenApiProbes { get; set; } = true;
        public string? PathPrefix { get; set; }
        public bool IncludeDeprecated { get; set; }
        public bool IncludeDeleteMethods { get; set; }
        public int TimeoutMs { get; set; } = 12_000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public bool IncludeCostlySpecLimits { get; set; } = true;
    }

    public sealed class SwaggeringResult
    {
        public string Message { get; init; } = "";
        public string SafetyMode { get; init; } = "active";
        public string Depth { get; init; } = SwaggeringDepthProfile.Thorough;
        public int ElapsedMs { get; init; }
        public bool Partial { get; init; }
        public bool BudgetExhausted { get; init; }
        public List<string> SpecSources { get; init; } = [];
        public int OperationsInCatalog { get; init; }
        public List<SwaggeringProbe.OperationResult> Operations { get; init; } = [];
        public SwaggeringProbe.CoverageSummary Coverage { get; init; } = new();
        public ApiInventoryAnalyzer.InventorySummary? InventorySummary { get; init; }
        public List<string> ShadowPaths { get; init; } = [];
        public List<SwaggeringProbe.SwaggeringFinding> Findings { get; init; } = [];
        public List<CostlyOperationsProbe.CostlyFinding> CostlyFindings { get; init; } = [];
        public AutoScanPipeline.AutoScanResult? AutoScan { get; init; }
        public List<string> PhasesCompleted { get; init; } = [];
        public List<string> Warnings { get; init; } = [];
        public int RequestsSent { get; init; }
    }

    public async Task<SwaggeringResult> RunAsync(SwaggeringOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var profile = SwaggeringDepthProfile.Resolve(options.Depth, options.MaxStepSeconds);
        var phases = new List<string>();
        var warnings = new List<string>();
        var allFindings = new List<SwaggeringProbe.SwaggeringFinding>();

        var currentUrl = await _ctx.GetCurrentUrl().ConfigureAwait(false);
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running Swaggering.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var entries = _ctx.Network.Entries;
        var budget = new BudgetTracker(maxRequests: profile.MaxRequestsTotal, maxSeconds: profile.MaxStepSeconds);
        bool BudgetDone() => budget.IsExhausted;

        // --- Discover specs ---
        phases.Add("discover");
        var specLoad = await OpenApiSpecLoader.LoadAsync(
            _ctx, origin, currentUrl, entries, options.SpecUrls,
            options.IncludeSpecsFromNetwork, options.IncludeOpenApiProbes,
            options.TimeoutMs, ct).ConfigureAwait(false);

        warnings.AddRange(specLoad.Errors);

        if (specLoad.Documents.Count == 0)
        {
            return new SwaggeringResult
            {
                Message = OpenApiSpecHeuristics.DescribeMissingSpec(warnings),
                SafetyMode = options.SafetyMode.ToLabel(),
                Depth = profile.Name,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Warnings = warnings.Count > 0 ? warnings : ["no-spec"],
                PhasesCompleted = phases
            };
        }

        var (operations, parseErrors) = OpenApiOperationCatalog.ParseAll(specLoad.Documents, origin);
        warnings.AddRange(parseErrors);

        if (operations.Count == 0)
        {
            return new SwaggeringResult
            {
                Message = "OpenAPI document(s) loaded but no operations could be parsed.",
                SafetyMode = options.SafetyMode.ToLabel(),
                Depth = profile.Name,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                SpecSources = specLoad.Documents.Select(d => d.Url).ToList(),
                Warnings = warnings,
                PhasesCompleted = phases
            };
        }
        if (!string.IsNullOrWhiteSpace(options.PathPrefix))
        {
            operations = operations
                .Where(o => o.PathTemplate.StartsWith(options.PathPrefix, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        if (!options.IncludeDeleteMethods)
            operations = operations.Where(o => !string.Equals(o.Method, "DELETE", StringComparison.OrdinalIgnoreCase)).ToList();

        // --- Attack surface + inventory ---
        phases.Add("inventory");
        var mapper = new AttackSurfaceMapper();
        AttackSurfaceResult mergedSurface;
        if (entries.Count > 0)
        {
            mergedSurface = mapper.Analyze(entries, true, true, true);
            await AttackSurfaceEnrichment.RunAsync(
                mergedSurface, _ctx, entries, currentUrl, new AttackSurfaceEnrichment.Options(), ct)
                .ConfigureAwait(false);
        }
        else
        {
            mergedSurface = new AttackSurfaceResult { Endpoints = [] };
        }

        var catalogSurface = OpenApiOperationCatalog.BuildSurfaceFromOperations(operations);
        foreach (var ep in catalogSurface.Endpoints)
        {
            var key = AttackSurfaceMapper.EndpointMergeKeyFromUrl(ep.Url);
            var existing = mergedSurface.Endpoints.FirstOrDefault(e =>
                string.Equals(AttackSurfaceMapper.EndpointMergeKeyFromUrl(e.Url), key, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                foreach (var m in ep.Methods) existing.Methods.Add(m);
                foreach (var q in ep.Parameters.Query)
                    if (!existing.Parameters.Query.Contains(q, StringComparer.OrdinalIgnoreCase))
                        existing.Parameters.Query.Add(q);
                foreach (var b in ep.Parameters.Body)
                    if (!existing.Parameters.Body.Contains(b, StringComparer.OrdinalIgnoreCase))
                        existing.Parameters.Body.Add(b);
                existing.DiscoveredVia.Add("swaggering-catalog");
            }
            else
                mergedSurface.Endpoints.Add(ep);
        }

        mapper.AttachRefreshedSummary(mergedSurface, entries);

        var inventory = await ApiInventoryAnalyzer.AnalyzeAsync(
            mergedSurface, _ctx,
            new ApiInventoryAnalyzer.AnalyzeOptions
            {
                IncludeAuthDeltaProbes = options.SafetyMode.AllowsProbes() && profile.IncludeAuthDelta,
                MaxAuthDeltaProbes = 24
            }, ct).ConfigureAwait(false);

        // --- Passive costly spec limits ---
        var costlyFindings = new List<CostlyOperationsProbe.CostlyFinding>();
        if (options.IncludeCostlySpecLimits)
        {
            phases.Add("spec-limits");
            var internalDocs = CostlyOperationsSpecAnalyzer.CollectFromNetwork(
                entries, origin, options.SpecUrls, options.IncludeSpecsFromNetwork);
            MergeLoadedSpecs(internalDocs, specLoad.Documents);
            foreach (var f in CostlyOperationsSpecAnalyzer.Analyze(internalDocs, 48))
            {
                costlyFindings.Add(f);
                if (options.RegisterChainFindings)
                    RegisterCostlyAsSwaggering(f);
            }
        }

        // --- Active probe lanes ---
        var probeRequests = 0;
        List<SwaggeringProbe.OperationResult> operationResults;
        if (options.SafetyMode.AllowsProbes())
        {
            phases.Add("swaggering-probe");
            var replay = BuildReplayHeaderMap(entries);
            var probe = new SwaggeringProbe(_ctx, _log);
            var probeResult = await probe.RunAsync(
                operations, profile, options.SafetyMode, options.TimeoutMs,
                options.IncludeBrowserCookies, replay, ct, BudgetDone).ConfigureAwait(false);
            allFindings.AddRange(probeResult.Findings);
            probeRequests = probeResult.RequestsSent;
            operationResults = probeResult.Operations;
            budget.AddRequests(probeResult.RequestsSent);
        }
        else
        {
            warnings.Add("passive-only — set safetyMode active for HTTP operation probes");
            operationResults = operations.Select(op => new SwaggeringProbe.OperationResult
            {
                Method = op.Method,
                Path = op.PathTemplate,
                OperationId = op.OperationId,
                RequiresSecurity = op.RequiresSecurity,
                Outcome = "not-probed",
                SkipReason = "passive mode does not send operation requests"
            }).ToList();
        }

        // --- Shadow paths (spec documents and Swagger UI assets are not shadow APIs) ---
        var shadowEntries = inventory.SpecVsObserved
            .Where(e => e.Tag == "shadow" && !IsSpecDocumentPath(e))
            .Take(24)
            .ToList();
        var inventorySummary = AdjustInventorySummary(inventory.Summary, inventory.SpecVsObserved);
        if (profile.IncludeShadowPaths && options.SafetyMode.AllowsProbes() && !BudgetDone())
        {
            phases.Add("shadow-paths");
            foreach (var sh in shadowEntries.Where(e => e.SampleUrl != null))
            {
                if (BudgetDone()) break;
                ct.ThrowIfCancellationRequested();
                var url = sh.SampleUrl!;
                var resp = await SecurityProbeHttp.FetchAsync(
                    _ctx, url, "GET", null, null, options.TimeoutMs,
                    options.IncludeBrowserCookies, ct).ConfigureAwait(false);
                budget.AddRequests(1);
                probeRequests++;
                if (resp.Status is >= 200 and < 300)
                {
                    allFindings.Add(new SwaggeringProbe.SwaggeringFinding
                    {
                        Category = "swaggering-shadow-exposed",
                        Severity = "medium",
                        Phase = "shadow-paths",
                        Title = "Shadow API path reachable (not in OpenAPI spec)",
                        Detail = sh.PathKey,
                        Url = url,
                        Method = "GET",
                        Status = resp.Status,
                        Evidence = SwaggeringProbe.ResponseExcerpt(resp.Body)
                    });
                }
            }
        }

        // --- Auto-scan on merged surface ---
        AutoScanPipeline.AutoScanResult? autoScan = null;
        if (profile.IncludeAutoScan && options.SafetyMode.AllowsWriteVerbs() && !BudgetDone())
        {
            phases.Add("auto-scan");
            var remaining = budget.RemainingSeconds;
            var autoOpts = new AutoScanPipeline.AutoScanOptions
            {
                PreDiscoveredSurface = mergedSurface,
                IncludeApiEnrichment = false,
                AllowGenericScaffold = false,
                AllowAutoRestScaffoldOnSparseSurface = false,
                ScanDepth = profile.AutoScanDepth,
                MaxStepSeconds = profile.AutoScanMaxStepSeconds > 0
                    ? Math.Min(profile.AutoScanMaxStepSeconds, remaining)
                    : remaining,
                ConfirmBackend = true,
                Host = pageUri.Host
            };
            autoScan = await AutoScanPipeline.RunAsync(_ctx, autoOpts, ct).ConfigureAwait(false);
        }

        if (options.RegisterChainFindings)
            RegisterSwaggeringFindings(allFindings);

        var exhausted = BudgetDone();
        var autoCount = autoScan?.FindingsCount ?? 0;
        var bits = new List<string>();
        if (allFindings.Count > 0)
            bits.Add($"{allFindings.Count} swaggering finding(s)");
        if (costlyFindings.Count > 0)
            bits.Add($"{costlyFindings.Count} spec-cost hint(s)");
        if (autoCount > 0)
            bits.Add($"{autoCount} auto-scan finding(s) on the catalog surface");
        var msg = bits.Count == 0
            ? $"Swaggering complete — no issues flagged across {operations.Count} catalog operation(s)."
            : "Swaggering complete — " + string.Join(", ", bits) + ".";

        if (exhausted)
            msg += " Budget exhausted — partial coverage. See operations[] for what was not reached.";

        return new SwaggeringResult
        {
            Message = msg,
            SafetyMode = options.SafetyMode.ToLabel(),
            Depth = profile.Name,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Partial = exhausted || autoScan?.Partial == true,
            BudgetExhausted = exhausted,
            SpecSources = specLoad.Documents.Select(d => d.Url).ToList(),
            OperationsInCatalog = operations.Count,
            Operations = operationResults,
            Coverage = SummarizeCoverage(operationResults),
            InventorySummary = inventorySummary,
            ShadowPaths = shadowEntries.Select(e => e.PathKey).Where(p => !string.IsNullOrWhiteSpace(p)).ToList(),
            Findings = allFindings,
            CostlyFindings = costlyFindings,
            AutoScan = autoScan,
            PhasesCompleted = phases,
            Warnings = warnings,
            RequestsSent = probeRequests
        };
    }

    private static void MergeLoadedSpecs(
        List<CostlyOperationsSpecAnalyzer.SpecDocument> docs,
        IReadOnlyList<OpenApiOperationCatalog.SpecDocument> loaded)
    {
        foreach (var doc in loaded)
        {
            if (string.IsNullOrWhiteSpace(doc.Body)) continue;
            var index = docs.FindIndex(d => string.Equals(d.Url, doc.Url, StringComparison.OrdinalIgnoreCase));
            var spec = new CostlyOperationsSpecAnalyzer.SpecDocument
            {
                Url = doc.Url,
                Body = doc.Body,
                Kind = "openapi"
            };
            if (index < 0)
                docs.Add(spec);
            else if (OpenApiSpecHeuristics.IsLikelyTruncatedJson(docs[index].Body)
                     && !OpenApiSpecHeuristics.IsLikelyTruncatedJson(doc.Body))
                docs[index] = spec;
        }
    }

    private static bool IsSpecDocumentPath(ApiInventoryAnalyzer.SpecVsObservedEntry entry)
    {
        if (OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(entry.PathKey))
            return true;
        return entry.SampleUrl != null && OpenApiSpecHeuristics.UrlLooksLikeSpecDocument(entry.SampleUrl);
    }

    private static ApiInventoryAnalyzer.InventorySummary AdjustInventorySummary(
        ApiInventoryAnalyzer.InventorySummary summary,
        IReadOnlyList<ApiInventoryAnalyzer.SpecVsObservedEntry> entries)
    {
        var suppressed = entries.Count(e => e.Tag == "shadow" && IsSpecDocumentPath(e));
        if (suppressed == 0) return summary;
        return new ApiInventoryAnalyzer.InventorySummary
        {
            DocumentedCount = summary.DocumentedCount,
            ShadowCount = Math.Max(0, summary.ShadowCount - suppressed),
            ZombieCandidateCount = summary.ZombieCandidateCount,
            ParallelVersionClusters = summary.ParallelVersionClusters,
            AuthGatedCount = summary.AuthGatedCount,
            OpenApiPathCount = summary.OpenApiPathCount,
            ObservedPathCount = summary.ObservedPathCount
        };
    }

    private static SwaggeringProbe.CoverageSummary SummarizeCoverage(
        IReadOnlyList<SwaggeringProbe.OperationResult> operations)
    {
        var http2 = 0;
        var http4 = 0;
        var http5 = 0;
        foreach (var op in operations)
        {
            if (op.Status is >= 200 and < 300) http2++;
            else if (op.Status is >= 400 and < 500) http4++;
            else if (op.Status is >= 500 and < 600) http5++;
        }

        return new SwaggeringProbe.CoverageSummary
        {
            Probed = operations.Count(o => o.Outcome == "probed"),
            Skipped = operations.Count(o => o.Outcome == "skipped"),
            NotProbed = operations.Count(o => o.Outcome == "not-probed"),
            NotReached = operations.Count(o => o.Outcome == "not-reached"),
            Http2xx = http2,
            Http4xx = http4,
            Http5xx = http5
        };
    }

    private static Dictionary<string, (Dictionary<string, string> Headers, string? Body)> BuildReplayHeaderMap(
        IReadOnlyList<NetworkEntry> entries)
    {
        var map = new Dictionary<string, (Dictionary<string, string>, string?)>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries.Where(x => x is { StatusCode: >= 200 and < 300 }))
        {
            if (e.RequestHeaders == null || e.RequestHeaders.Count == 0) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)) continue;
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in e.RequestHeaders)
            {
                if (h.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) continue;
                if (h.Key.StartsWith("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                headers[h.Key] = h.Value;
            }

            if (headers.Count > 0)
                map[u.AbsolutePath] = (headers, e.RequestBody);
        }

        return map;
    }

    private void RegisterSwaggeringFindings(IEnumerable<SwaggeringProbe.SwaggeringFinding> findings)
    {
        foreach (var f in findings)
        {
            if (!FindingNormalizer.IsKnownCategory(f.Category))
                continue;
            AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Title, f.Url, f.Method, f.Detail);
        }
    }

    private void RegisterCostlyAsSwaggering(CostlyOperationsProbe.CostlyFinding f)
    {
        AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Title, f.Endpoint, f.Method, f.Detail);
    }
}
