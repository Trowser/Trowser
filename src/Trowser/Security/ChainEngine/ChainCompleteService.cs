using Trowser.Automation;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Autonomously completes partial attack chains by running the suggested scanner
/// for each missing category, then re-analyzing until chains are fully confirmed
/// or iteration budget is exhausted.
///
/// Loop:
/// 1. Collect all findings → run chain analysis → find partial chains
/// 2. For each partial chain with a SuggestedAction, parse the scanner endpoint
/// 3. Run the scanner via internal API
/// 4. Re-analyze with new findings
/// 5. Repeat until no more progress or MaxIterations reached
/// </summary>
public sealed class ChainCompleteService
{
    /// <summary>Delegate for invoking a Trowser scanner endpoint.</summary>
    public delegate Task<string> ScannerInvoker(string method, string endpoint, string? body, int timeoutMs);

    private readonly AutomationContext _ctx;
    private readonly ChainPatternCatalog _catalog;
    private readonly Action<string, string> _log;
    private readonly ScannerInvoker? _invoker;

    public ChainCompleteService(
        AutomationContext context,
        ChainPatternCatalog catalog,
        Action<string, string> log,
        ScannerInvoker? invoker = null)
    {
        _ctx = context;
        _catalog = catalog;
        _log = log;
        _invoker = invoker;
    }

    public sealed class ChainCompleteOptions
    {
        /// <summary>Maximum iterations of the complete loop.</summary>
        public int MaxIterations { get; set; } = 3;

        /// <summary>Maximum total scanners to invoke across all iterations.</summary>
        public int MaxScannerInvocations { get; set; } = 10;

        /// <summary>Per-scanner timeout in milliseconds.</summary>
        public int ScannerTimeoutMs { get; set; } = 30000;

        /// <summary>Safety mode for scanner invocations.</summary>
        public string SafetyMode { get; set; } = "safe";

        /// <summary>Host filter for scanner scope.</summary>
        public string? Host { get; set; }

        /// <summary>Additional findings from playbook context to include in analysis.</summary>
        public List<ChainableFinding>? AdditionalFindings { get; set; }
    }

    public sealed class ChainCompleteResult
    {
        public string Message { get; init; } = "";
        public int IterationsRun { get; init; }
        public int ScannersInvoked { get; init; }
        public int NewFindingsDiscovered { get; init; }
        public int ChainsCompletedThisRun { get; init; }
        public int RemainingPartials { get; init; }
        public List<CompletedChainInfo> CompletedChains { get; init; } = [];
        public List<AttemptedScannerInfo> ScannerLog { get; init; } = [];
    }

    public sealed class CompletedChainInfo
    {
        public string PatternId { get; init; } = "";
        public string PatternName { get; init; } = "";
        public string ChainedSeverity { get; init; } = "";
        public string Impact { get; init; } = "";
        public int LinkCount { get; init; }
    }

    public sealed class AttemptedScannerInfo
    {
        public int Iteration { get; init; }
        public string PatternId { get; init; } = "";
        public string MissingCategory { get; init; } = "";
        public string ScannerEndpoint { get; init; } = "";
        public bool Success { get; init; }
        public int FindingsProduced { get; init; }
        public string? Error { get; init; }
    }

    public async Task<ChainCompleteResult> RunAsync(ChainCompleteOptions options, CancellationToken ct = default)
    {
        var scannerLog = new List<AttemptedScannerInfo>();
        var completedChains = new List<CompletedChainInfo>();
        int totalScannersInvoked = 0;
        int totalNewFindings = 0;

        // Track attempted (patternId, missingCategory) tuples to avoid re-running same scanner
        var attemptedTuples = new HashSet<(string patternId, string missingCategory)>();

        // Track which pattern IDs were already full chains before we started
        var initialFullChainIds = new HashSet<string>();

        for (int iteration = 0; iteration < options.MaxIterations; iteration++)
        {
            ct.ThrowIfCancellationRequested();

            // Collect findings from ALL sources
            var allFindings = ChainAnalysisService.CollectFindings(_ctx, null);
            if (options.AdditionalFindings != null)
            {
                allFindings = allFindings.Concat(options.AdditionalFindings).ToList();
            }

            // Run chain analysis
            var analysisResult = ChainAnalysisService.Analyze(
                _catalog, allFindings,
                new ChainAnalysisService.AnalyzeOptions(
                    MinChainedSeverity: null,
                    IncludePartial: true,
                    IdentityStore: null,
                    PageUrl: await _ctx.GetCurrentUrl()));

            // Track initial full chains on first iteration
            if (iteration == 0)
            {
                foreach (var chain in analysisResult.Chains)
                    initialFullChainIds.Add(chain.PatternId);
            }

            // Find newly completed chains (weren't full before)
            foreach (var chain in analysisResult.Chains)
            {
                if (!initialFullChainIds.Contains(chain.PatternId) &&
                    !completedChains.Any(c => c.PatternId == chain.PatternId))
                {
                    completedChains.Add(new CompletedChainInfo
                    {
                        PatternId = chain.PatternId,
                        PatternName = chain.PatternName,
                        ChainedSeverity = chain.ChainedSeverity,
                        Impact = chain.Impact,
                        LinkCount = chain.MatchedFindings.Count
                    });
                    _log($"Chain-complete: ✓ Completed chain '{chain.PatternName}' ({chain.ChainedSeverity})", "#4EC9B0");
                }
            }

            // Find actionable partial chains
            var actionablePartials = analysisResult.PartialChains
                .Where(p => p.SuggestedAction != null &&
                            p.MissingCategories.Any(mc => !attemptedTuples.Contains((p.PatternId, mc))))
                .ToList();

            if (actionablePartials.Count == 0)
            {
                _log($"Chain-complete: no more actionable partials after iteration {iteration + 1}", "#CE9178");
                return BuildResult(iteration + 1, totalScannersInvoked, totalNewFindings,
                    completedChains, scannerLog, analysisResult.PartialChains.Count);
            }

            // For each actionable partial, run the suggested scanner
            bool madeProgress = false;
            foreach (var partial in actionablePartials)
            {
                if (totalScannersInvoked >= options.MaxScannerInvocations)
                {
                    _log("Chain-complete: scanner invocation budget exhausted", "#CE9178");
                    return BuildResult(iteration + 1, totalScannersInvoked, totalNewFindings,
                        completedChains, scannerLog, analysisResult.PartialChains.Count);
                }

                ct.ThrowIfCancellationRequested();

                var missingCategory = partial.MissingCategories
                    .FirstOrDefault(mc => !attemptedTuples.Contains((partial.PatternId, mc)));
                if (missingCategory == null) continue;

                attemptedTuples.Add((partial.PatternId, missingCategory));

                // Parse the scanner endpoint from SuggestedAction
                var (method, endpoint, body) = ParseSuggestedAction(partial.SuggestedAction!);
                if (endpoint == null)
                {
                    scannerLog.Add(new AttemptedScannerInfo
                    {
                        Iteration = iteration,
                        PatternId = partial.PatternId,
                        MissingCategory = missingCategory,
                        ScannerEndpoint = partial.SuggestedAction ?? "(unparseable)",
                        Success = false,
                        Error = "Could not parse SuggestedAction into method/endpoint"
                    });
                    continue;
                }

                _log($"Chain-complete: running {method} {endpoint} for '{partial.PatternName}' (missing: {missingCategory})", "#569CD6");

                // Invoke the scanner via internal API (or skip if no invoker)
                var findingsBefore = ChainAnalysisService.CollectFindings(_ctx, null).Count;
                try
                {
                    if (_invoker == null)
                    {
                        scannerLog.Add(new AttemptedScannerInfo
                        {
                            Iteration = iteration,
                            PatternId = partial.PatternId,
                            MissingCategory = missingCategory,
                            ScannerEndpoint = $"{method} {endpoint}",
                            Success = false,
                            Error = "No scanner invoker configured"
                        });
                        continue;
                    }

                    await _invoker(method ?? "POST", endpoint, body, options.ScannerTimeoutMs);

                    var findingsAfter = ChainAnalysisService.CollectFindings(_ctx, null).Count;
                    var newFindings = findingsAfter - findingsBefore;
                    totalNewFindings += Math.Max(0, newFindings);
                    totalScannersInvoked++;

                    if (newFindings > 0) madeProgress = true;

                    scannerLog.Add(new AttemptedScannerInfo
                    {
                        Iteration = iteration,
                        PatternId = partial.PatternId,
                        MissingCategory = missingCategory,
                        ScannerEndpoint = $"{method} {endpoint}",
                        Success = true,
                        FindingsProduced = Math.Max(0, newFindings)
                    });
                }
                catch (Exception ex)
                {
                    totalScannersInvoked++;
                    scannerLog.Add(new AttemptedScannerInfo
                    {
                        Iteration = iteration,
                        PatternId = partial.PatternId,
                        MissingCategory = missingCategory,
                        ScannerEndpoint = $"{method} {endpoint}",
                        Success = false,
                        Error = ex.Message
                    });
                }
            }

            if (!madeProgress)
            {
                _log($"Chain-complete: no new findings after iteration {iteration + 1}, stopping", "#CE9178");
                return BuildResult(iteration + 1, totalScannersInvoked, totalNewFindings,
                    completedChains, scannerLog,
                    actionablePartials.Count);
            }
        }

        // Final analysis after all iterations
        var finalFindings = ChainAnalysisService.CollectFindings(_ctx, null);
        if (options.AdditionalFindings != null)
            finalFindings = finalFindings.Concat(options.AdditionalFindings).ToList();

        var finalResult = ChainAnalysisService.Analyze(
            _catalog, finalFindings,
            new ChainAnalysisService.AnalyzeOptions(null, true, null, await _ctx.GetCurrentUrl()));

        // Capture any newly completed chains from final analysis
        foreach (var chain in finalResult.Chains)
        {
            if (!initialFullChainIds.Contains(chain.PatternId) &&
                !completedChains.Any(c => c.PatternId == chain.PatternId))
            {
                completedChains.Add(new CompletedChainInfo
                {
                    PatternId = chain.PatternId,
                    PatternName = chain.PatternName,
                    ChainedSeverity = chain.ChainedSeverity,
                    Impact = chain.Impact,
                    LinkCount = chain.MatchedFindings.Count
                });
            }
        }

        return BuildResult(options.MaxIterations, totalScannersInvoked, totalNewFindings,
            completedChains, scannerLog, finalResult.PartialChains.Count);
    }

    /// <summary>
    /// Parse a SuggestedAction string like "POST /api/security/xss — description"
    /// into (method, endpoint, bodyJson).
    /// </summary>
    private static (string? method, string? endpoint, string? body) ParseSuggestedAction(string action)
    {
        // Format: "METHOD /api/path {json} — description"
        // or:     "METHOD /api/path — description"
        var dashIndex = action.IndexOf(" — ", StringComparison.Ordinal);
        var actionPart = dashIndex >= 0 ? action[..dashIndex].Trim() : action.Trim();

        var parts = actionPart.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return (null, null, null);

        var method = parts[0].ToUpperInvariant();
        if (method is not ("POST" or "GET" or "PUT" or "DELETE" or "PATCH"))
            return (null, null, null);

        var rest = parts[1];

        // Check if there's a JSON body embedded: "/api/path {json}"
        var braceIndex = rest.IndexOf('{');
        if (braceIndex > 0)
        {
            var endpoint = rest[..braceIndex].Trim();
            var body = rest[braceIndex..].Trim();
            return (method, endpoint, body);
        }

        return (method, rest.Trim(), null);
    }

    private static ChainCompleteResult BuildResult(
        int iterations, int scannersInvoked, int newFindings,
        List<CompletedChainInfo> completedChains, List<AttemptedScannerInfo> scannerLog,
        int remainingPartials)
    {
        var message = completedChains.Count > 0
            ? $"Completed {completedChains.Count} attack chain(s) across {iterations} iteration(s). " +
              $"Invoked {scannersInvoked} scanner(s), discovered {newFindings} new finding(s)."
            : $"Ran {iterations} iteration(s), invoked {scannersInvoked} scanner(s). " +
              $"No partial chains could be fully completed. {remainingPartials} partial chain(s) remain.";

        return new ChainCompleteResult
        {
            Message = message,
            IterationsRun = iterations,
            ScannersInvoked = scannersInvoked,
            NewFindingsDiscovered = newFindings,
            ChainsCompletedThisRun = completedChains.Count,
            RemainingPartials = remainingPartials,
            CompletedChains = completedChains,
            ScannerLog = scannerLog
        };
    }
}
