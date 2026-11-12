using System.Diagnostics;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.SessionLog;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Shared services passed to every playbook step: browser context, identity store,
/// attack-surface cache, chain catalog, budget tracking, journal, and step recording.
/// </summary>
public sealed class PlaybookContext
{
    public AutomationContext Automation { get; }
    public IdentityStore IdentityStore { get; }
    public ChainPatternCatalog ChainCatalog { get; }
    public BudgetTracker Budget { get; }
    public PlaybookDepthProfile DepthProfile { get; }
    public SafetyMode SafetyMode { get; }
    public SessionLogger? SessionLogger { get; }
    public PeerRegistry? PeerRegistry { get; set; }

    /// <summary>Delegate for invoking internal scanner endpoints (e.g., POST /api/security/xss).</summary>
    public ChainEngine.ChainCompleteService.ScannerInvoker? ScannerInvoker { get; set; }

    /// <summary>The run ID for this playbook execution.</summary>
    public string RunId { get; }

    /// <summary>Tags from the request, propagated to findings.</summary>
    public List<string> Tags { get; }

    /// <summary>Warnings accumulated during the run (safety downgrades, skipped steps, etc.).</summary>
    public List<string> Warnings { get; } = [];

    /// <summary>Assertions registered during the run.</summary>
    public int AssertionsAdded { get; set; }

    /// <summary>Recorded step results.</summary>
    public List<PlaybookStepResult> Steps { get; } = [];

    /// <summary>Aggregated findings from all steps.</summary>
    public FindingAggregator Findings { get; } = new();

    /// <summary>Suggested next actions accumulated across steps.</summary>
    public List<NextAction> NextActions { get; } = [];

    /// <summary>Whether the shared crawl-light step runs at playbook start.</summary>
    public bool IncludeCrawl { get; }

    /// <summary>Request scope (host, path include/exclude, logout denylist, target URL).</summary>
    public PlaybookScope Scope { get; }

    private readonly IPlaybookRunProgress? _runProgress;

    public PlaybookContext(
        AutomationContext automation,
        IdentityStore identityStore,
        ChainPatternCatalog chainCatalog,
        PlaybookRequest request,
        string? runId = null,
        IPlaybookRunProgress? runProgress = null)
    {
        Automation = automation;
        IdentityStore = identityStore;
        ChainCatalog = chainCatalog;
        RunId = string.IsNullOrWhiteSpace(runId) ? Guid.NewGuid().ToString("N")[..12] : runId.Trim();
        _runProgress = runProgress;
        Tags = request.Tags;
        IncludeCrawl = request.IncludeCrawl;
        Scope = request.Scope;

        SafetyMode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        DepthProfile = PlaybookDepthProfile.Resolve(request.Depth);

        var effectiveBudget = request.Budget;
        Budget = new BudgetTracker(
            effectiveBudget.MaxRequests,
            effectiveBudget.MaxSeconds,
            effectiveBudget.Adaptive);

        if (SafetyMode != request.SafetyMode)
            Warnings.Add($"Safety mode downgraded from '{request.SafetyMode.ToLabel()}' to '{SafetyMode.ToLabel()}' " +
                          $"due to host/CLI constraints.");

        Findings.SeedDedup(automation.GetManualChainFindingsSnapshot());
    }

    /// <summary>Set the session logger after construction (it may not be available at construction time).</summary>
    public PlaybookContext WithSessionLogger(SessionLogger? logger)
    {
        return new PlaybookContext(this, logger);
    }

    /// <summary>Set the peer registry for cross-identity testing (authz-diff, authz-boundary).</summary>
    public PlaybookContext WithPeerRegistry(PeerRegistry? registry)
    {
        PeerRegistry = registry;
        return this;
    }

    /// <summary>Set the scanner invoker for chain-complete auto-loop.</summary>
    public PlaybookContext WithScannerInvoker(ChainEngine.ChainCompleteService.ScannerInvoker? invoker)
    {
        ScannerInvoker = invoker;
        return this;
    }

    private PlaybookContext(PlaybookContext other, SessionLogger? logger)
    {
        Automation = other.Automation;
        IdentityStore = other.IdentityStore;
        ChainCatalog = other.ChainCatalog;
        Budget = other.Budget;
        DepthProfile = other.DepthProfile;
        SafetyMode = other.SafetyMode;
        SessionLogger = logger;
        PeerRegistry = other.PeerRegistry;
        ScannerInvoker = other.ScannerInvoker;
        IncludeCrawl = other.IncludeCrawl;
        Scope = other.Scope;
        RunId = other.RunId;
        _runProgress = other._runProgress;
        Tags = other.Tags;
        Warnings = other.Warnings;
        AssertionsAdded = other.AssertionsAdded;
        Steps = other.Steps;
        Findings = other.Findings;
        NextActions = other.NextActions;
    }

    /// <summary>Map network log to attack surface and apply scope target/path filters.</summary>
    public AttackSurfaceResult AnalyzeNetworkSurface(string host, PlaybookScope scope, bool includeAuth = true)
    {
        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(
            Automation.Network.Entries,
            includeAuth: includeAuth,
            hostFilter: host);
        return PlaybookScopeFilter.Apply(surface, scope);
    }

    /// <summary>Copy <see cref="PlaybookScope.TargetUrl"/> / <see cref="PlaybookScope.TargetMethod"/> into auto-scan options.</summary>
    public static void ApplyTargetScope(AutoScanPipeline.AutoScanOptions options, PlaybookScope scope)
    {
        EndpointScopeHelper.ApplyToAutoScan(options, scope);
    }

    /// <summary>Resolve scope host from request or current page.</summary>
    public async Task<string> ResolveHostAsync(PlaybookScope scope)
    {
        if (!string.IsNullOrWhiteSpace(scope.Host))
            return scope.Host;

        var pageUrl = await Automation.GetCurrentUrl();
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
            return uri.Host;

        return "unknown";
    }

    public async Task<string> GetCurrentUrlAsync() => await Automation.GetCurrentUrl();

    /// <summary>
    /// Run a light BFS crawl to populate the network log before security scans.
    /// Shared across all playbooks. Respects depth.MaxCrawlPages and budget.
    /// </summary>
    public async Task<PlaybookStepResult> RunCrawlStepAsync(string host, CancellationToken ct)
    {
        if (!IncludeCrawl)
            return SkipStep("crawl-light", "crawl=false");
        if (DepthProfile.MaxCrawlPages <= 0)
            return SkipStep("crawl-light", "Crawl disabled (maxCrawlPages=0)");

        return await RunStepAsync("crawl-light", async innerCt =>
        {
            Budget.ThrowIfExhausted(innerCt);

            const double crawlTimeFraction = 0.6;
            const double scanReserveFraction = 0.25;
            var maxCrawlSeconds = Math.Max(30, (int)(Budget.MaxSeconds * crawlTimeFraction));
            var scanReserveSeconds = Math.Max(60, (int)(Budget.MaxSeconds * scanReserveFraction));
            maxCrawlSeconds = Math.Min(maxCrawlSeconds, Math.Max(30, Budget.RemainingSeconds - scanReserveSeconds));

            using var crawlCts = CancellationTokenSource.CreateLinkedTokenSource(innerCt);
            if (maxCrawlSeconds > 0)
                ScanTimeout.CancelAfterSeconds(crawlCts, maxCrawlSeconds);

            var options = new LightSiteCrawler.CrawlOptions
            {
                AllowedHost = host,
                MaxPages = DepthProfile.MaxCrawlPages,
                MaxDepth = DepthProfile.Depth == PlaybookDepth.Quick ? 1 : 2,
                SpaMode = true,
                FollowLinks = true,
                EnumerateForms = true,
                VisitFormActions = SafetyMode.AllowsProbes(),
                DelayMs = 150,
                MaxInteractionsPerPage = DepthProfile.Depth == PlaybookDepth.Deep ? 30 : 15,
                WaitAfterInteractionMs = 300,
                IncludePaths = Scope.IncludePaths,
                ExcludePaths = Scope.ExcludePaths,
                ExcludeUrlPatterns = Scope.ExcludeUrlPatterns,
                ExcludeLogout = Scope.ExcludeLogout
            };

            var result = await LightSiteCrawler.RunAsync(Automation, options, crawlCts.Token);
            if (result.StoppedEarly)
            {
                Warnings.Add(
                    $"Crawl stopped after {maxCrawlSeconds}s time cap ({(int)(crawlTimeFraction * 100)}% of playbook budget, " +
                    $"{scanReserveSeconds}s reserved for security steps).");
            }

            if (result.SkippedUrls.Count > 0)
            {
                Warnings.Add(
                    $"Crawl skipped {result.SkippedUrls.Count} URL(s) (excludePaths/excludeLogout)" +
                    (Scope.ExcludeLogout ? "; logout denylist on" : "") + ".");
            }

            Budget.AddRequests(result.PagesVisited);
            return new Dictionary<string, object?>
            {
                ["pagesVisited"] = result.PagesVisited,
                ["linksDiscovered"] = result.LinksDiscovered,
                ["formsDiscovered"] = result.FormActionsDiscovered,
                ["networkEntries"] = result.NetworkEntriesAfter,
                ["elapsedMs"] = result.ElapsedMs,
                ["crawlCapped"] = result.StoppedEarly,
                ["maxCrawlSeconds"] = maxCrawlSeconds,
                ["skippedUrls"] = result.SkippedUrls.Take(40).ToList(),
                ["skippedCount"] = result.SkippedUrls.Count,
                ["excludeLogout"] = result.ExcludeLogout
            };
        }, ct);
    }

    /// <summary>Execute and record a named step, catching exceptions as step errors.</summary>
    public async Task<PlaybookStepResult> RunStepAsync(
        string name,
        Func<CancellationToken, Task<Dictionary<string, object?>>> action,
        CancellationToken ct)
    {
        if (Budget.IsExhausted)
        {
            if (Budget.Adaptive &&
                Budget.TryExtendForProgress($"Step '{name}' waiting to start", Steps.Count(s => s.Status == "ok")))
            {
                Warnings.Add(
                    $"Budget extended (adaptive): now {Budget.MaxSeconds}s / {Budget.MaxRequests} requests " +
                    $"before step '{name}'.");
            }
            else
            {
                var skipped = new PlaybookStepResult
                {
                    Name = name,
                    Status = "budget-exhausted",
                    DurationMs = 0,
                    Reason = "Budget exhausted before step started"
                };
                Steps.Add(skipped);
                _runProgress?.StepCompleted(skipped);
                Warnings.Add($"Step '{name}' skipped — budget exhausted ({Budget.RequestCount}/{Budget.MaxRequests} requests, {Budget.ElapsedSeconds}/{Budget.MaxSeconds}s).");
                LogStep(name, "budget-exhausted");
                return skipped;
            }
        }
        ct.ThrowIfCancellationRequested();

        _runProgress?.StepStarting(name);
        Automation.Log($"  ▶ {name}...");

        var sw = Stopwatch.StartNew();
        try
        {
            var metrics = await action(ct);
            sw.Stop();
            var status = "ok";
            string? reason = null;
            if (metrics.TryGetValue("_stepStatus", out var statusObj)
                && statusObj is string statusStr
                && !string.IsNullOrWhiteSpace(statusStr))
            {
                status = statusStr.Trim().ToLowerInvariant();
                metrics.Remove("_stepStatus");
            }
            if (metrics.TryGetValue("_stepReason", out var reasonObj)
                && reasonObj is string reasonStr
                && !string.IsNullOrWhiteSpace(reasonStr))
            {
                reason = reasonStr;
                metrics.Remove("_stepReason");
            }

            var step = new PlaybookStepResult
            {
                Name = name,
                Status = status,
                DurationMs = (int)sw.ElapsedMilliseconds,
                Reason = reason,
                Metrics = metrics
            };
            Steps.Add(step);
            _runProgress?.StepCompleted(step);
            LogStep(name, status, reason);
            return step;
        }
        catch (BudgetExhaustedException)
        {
            sw.Stop();
            var step = new PlaybookStepResult
            {
                Name = name,
                Status = "budget-exhausted",
                DurationMs = (int)sw.ElapsedMilliseconds,
                Reason = "Budget exhausted before step completed"
            };
            Steps.Add(step);
            _runProgress?.StepCompleted(step);
            LogStep(name, "budget-exhausted");
            return step;
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            var step = new PlaybookStepResult
            {
                Name = name,
                Status = "cancelled",
                DurationMs = (int)sw.ElapsedMilliseconds,
                Reason = "Operation was cancelled"
            };
            Steps.Add(step);
            _runProgress?.StepCompleted(step);
            LogStep(name, "cancelled");
            return step;
        }
        catch (Exception ex)
        {
            sw.Stop();
            var step = new PlaybookStepResult
            {
                Name = name,
                Status = "error",
                DurationMs = (int)sw.ElapsedMilliseconds,
                Reason = ex.Message
            };
            Steps.Add(step);
            _runProgress?.StepCompleted(step);
            LogStep(name, "error", ex.Message);
            return step;
        }
    }

    /// <summary>Record a step that was skipped due to safety mode or missing preconditions.</summary>
    public PlaybookStepResult SkipStep(string name, string reason)
    {
        var step = new PlaybookStepResult
        {
            Name = name,
            Status = "skipped",
            Reason = reason
        };
        Steps.Add(step);
        _runProgress?.StepCompleted(step);
        LogStep(name, "skipped", reason);
        return step;
    }

    private void LogStep(string step, string status, string? detail = null)
    {
        var suffix = detail != null ? $": {detail}" : "";
        Automation.Log($"  [{status}] {step}{suffix}");
        SessionLogger?.LogLlmNote(
            $"[orchestrate] Step '{step}' {status}{suffix}",
            tags: ["orchestrate", step, status]);
    }
}
