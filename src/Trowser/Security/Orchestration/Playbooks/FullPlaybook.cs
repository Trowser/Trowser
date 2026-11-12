using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// Full Site Security: runs all playbooks in optimized order, correlates findings
/// across categories to produce attack-chain candidates, and suggests proof workflows.
///
/// Execution order (per plan §3):
///   Passive tier:  A02 (misconfig) → A04 (crypto) → A03 (supply chain)
///   Core tier:     A01 (access) → A07 (authn) → A11 (ssrf) → A14 (other)
///   Extended tier: A05 (injection) → A06 (design) → A09 (opsec) → A12 (availability) → A13 (llm)
///
/// The extended tier is skipped in quick depth or when budget is insufficient.
/// Cross-category chain correlation runs after all playbooks complete.
/// </summary>
public sealed class FullPlaybook : IPlaybook
{
    public string Id => "full";
    public string Title => "Full Site Security";
    public string Category => "full-assessment";

    private static readonly string[] PassiveTier = ["a02-misconfig", "a04-crypto", "a03-supplychain"];
    private static readonly string[] CoreTier = ["a01-access", "a07-authn", "a11-ssrf", "a14-other"];
    private static readonly string[] ExtendedTier = ["a05-injection", "a06-design", "a09-opsec", "a12-availability", "a13-llm"];

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var includeExtended = request.Depth != PlaybookDepth.Quick;
        var steps = new List<DryRunStep>
        {
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages, shared: true)
        };

        foreach (var id in PassiveTier)
            steps.Add(PlaybookStep(id, "Passive tier — mostly observation-based"));

        foreach (var id in CoreTier)
            steps.Add(PlaybookStep(id, "Core tier — primary security assessment"));

        if (includeExtended)
        {
            foreach (var id in ExtendedTier)
                steps.Add(PlaybookStep(id, "Extended tier — deep analysis (skipped in quick depth)"));
        }
        else
        {
            foreach (var id in ExtendedTier)
                steps.Add(new DryRunStep
                {
                    Name = $"playbook-{id}",
                    Description = $"Extended tier: {id}",
                    HttpVerbs = "various",
                    WritesSideEffects = true,
                    SkippedByCurrentSafetyMode = true,
                    SkipReason = "Extended tier skipped in quick depth"
                });
        }

        steps.Add(new DryRunStep
        {
            Name = "chain-correlate",
            Description = "Cross-category attack chain correlation and proof template matching",
            HttpVerbs = "none (passive)",
            WritesSideEffects = false
        });

        steps.Add(new DryRunStep
        {
            Name = "chain-complete",
            Description = "Auto-loop: run suggested scanners to complete partial attack chains",
            HttpVerbs = "varies (per scanner)",
            WritesSideEffects = true,
            SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
            SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
        });

        return steps;
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var includeExtended = ctx.DepthProfile.Depth != PlaybookDepth.Quick;

        await ctx.RunCrawlStepAsync(host, ct);

        var registry = new PlaybookRegistry();
        var childResults = new Dictionary<string, PlaybookResponse>();

        await RunTier(ctx, registry, request, PassiveTier, "passive", childResults, ct);
        await RunTier(ctx, registry, request, CoreTier, "core", childResults, ct);

        if (includeExtended && !ctx.Budget.IsExhausted)
        {
            await RunTier(ctx, registry, request, ExtendedTier, "extended", childResults, ct);
        }
        else if (!includeExtended)
        {
            foreach (var id in ExtendedTier)
                ctx.SkipStep($"playbook-{id}", "Extended tier skipped in quick depth");
        }

        // Cross-category chain correlation
        ChainAnalysisResult? chainResult = null;
        await ctx.RunStepAsync("chain-correlate", async _ =>
        {
            var allFindings = ChainAnalysisService.CollectFindings(ctx.Automation, ctx.SessionLogger);
            chainResult = ChainAnalysisService.Analyze(
                ctx.ChainCatalog,
                allFindings,
                new ChainAnalysisService.AnalyzeOptions(
                    MinChainedSeverity: null,
                    IncludePartial: true,
                    IdentityStore: ctx.IdentityStore,
                    PageUrl: await ctx.GetCurrentUrlAsync()));

            return new Dictionary<string, object?>
            {
                ["findingsAnalyzed"] = chainResult.FindingsAnalyzed,
                ["findingsFromAggregator"] = ctx.Findings.Count,
                ["findingsSuppressed"] = ctx.Findings.SuppressedCount,
                ["chainsDiscovered"] = chainResult.ChainsDiscovered,
                ["partialChains"] = chainResult.PartialChains.Count
            };
        }, ct);

        // Chain-complete auto-loop: autonomously fill partial chains
        if (chainResult?.PartialChains.Count > 0 && ctx.SafetyMode.AllowsProbes() && !ctx.Budget.IsExhausted)
        {
            await ctx.RunStepAsync("chain-complete", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var service = new ChainCompleteService(ctx.Automation, ctx.ChainCatalog, (msg, _) => ctx.Warnings.Add(msg),
                    invoker: ctx.ScannerInvoker);
                var result = await service.RunAsync(new ChainCompleteService.ChainCompleteOptions
                {
                    MaxIterations = 3,
                    MaxScannerInvocations = Math.Min(10, ctx.Budget.RemainingRequests / 50),
                    ScannerTimeoutMs = Math.Min(30000, ctx.Budget.RemainingSeconds * 1000),
                    SafetyMode = ctx.SafetyMode.ToLabel(),
                    Host = request.Scope.Host ?? (Uri.TryCreate(await ctx.GetCurrentUrlAsync(), UriKind.Absolute, out var u) ? u.Host : null),
                    AdditionalFindings = ctx.Findings.All.ToList()
                }, innerCt);

                // Re-run chain analysis with any new findings
                if (result.NewFindingsDiscovered > 0)
                {
                    var allFindings = ChainAnalysisService.CollectFindings(ctx.Automation, ctx.SessionLogger);
                    chainResult = ChainAnalysisService.Analyze(
                        ctx.ChainCatalog, allFindings,
                        new ChainAnalysisService.AnalyzeOptions(null, true, ctx.IdentityStore, await ctx.GetCurrentUrlAsync()));
                }

                return new Dictionary<string, object?>
                {
                    ["iterationsRun"] = result.IterationsRun,
                    ["scannersInvoked"] = result.ScannersInvoked,
                    ["newFindings"] = result.NewFindingsDiscovered,
                    ["chainsCompleted"] = result.ChainsCompletedThisRun,
                    ["remainingPartials"] = result.RemainingPartials
                };
            }, ct);
        }
        else if (chainResult?.PartialChains.Count == 0)
        {
            ctx.SkipStep("chain-complete", "No partial chains to complete");
        }
        else
        {
            ctx.SkipStep("chain-complete", ctx.Budget.IsExhausted
                ? "Budget exhausted"
                : $"Requires safe mode or above (current: {ctx.SafetyMode.ToLabel()})");
        }

        var nextActions = BuildNextActions(ctx, chainResult, childResults);

        return new PlaybookResponse
        {
            PlaybookId = Id,
            RunId = ctx.RunId,
            Scope = request.Scope,
            SafetyMode = ctx.SafetyMode.ToLabel(),
            Depth = ctx.DepthProfile.ToLabel(),
            StartedAt = startedAt.ToString("o"),
            FinishedAt = DateTime.UtcNow.ToString("o"),
            StepsExecuted = ctx.Steps,
            BudgetUsed = ctx.Budget.ToSummary(),
            Warnings = ctx.Warnings,
            AssertionsAdded = ctx.AssertionsAdded,
            NextActions = nextActions,
            CorrelatedChains = chainResult != null
                ? ChainAnalysisService.BuildAnalyzePayload(chainResult, "No cross-category chains discovered.")
                : null
        };
    }

    private async Task RunTier(
        PlaybookContext ctx,
        PlaybookRegistry registry,
        PlaybookRequest request,
        string[] playbookIds,
        string tierName,
        Dictionary<string, PlaybookResponse> results,
        CancellationToken ct)
    {
        foreach (var id in playbookIds)
        {
            if (ctx.Budget.IsExhausted)
            {
                ctx.SkipStep($"playbook-{id}", "Budget exhausted");
                continue;
            }

            var playbook = registry.Get(id);
            if (playbook == null)
            {
                ctx.SkipStep($"playbook-{id}", $"Playbook '{id}' not found in registry");
                continue;
            }

            await ctx.RunStepAsync($"playbook-{id}", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var childResponse = await playbook.RunAsync(ctx, request.WithCrawlDisabled(), innerCt);
                results[id] = childResponse;

                var findingCount = ctx.Findings.Count;
                var stepCount = childResponse.StepsExecuted?.Count ?? 0;

                return new Dictionary<string, object?>
                {
                    ["tier"] = tierName,
                    ["playbookId"] = id,
                    ["findings"] = findingCount,
                    ["steps"] = stepCount,
                    ["warnings"] = childResponse.Warnings?.Count ?? 0
                };
            }, ct);
        }
    }

    private static List<NextAction> BuildNextActions(
        PlaybookContext ctx,
        ChainAnalysisResult? chainResult,
        Dictionary<string, PlaybookResponse> childResults)
    {
        var actions = new List<NextAction>();

        if (chainResult is { ChainsDiscovered: > 0 })
        {
            foreach (var chain in chainResult.Chains.Take(5))
            {
                if (chain.Provable)
                {
                    actions.Add(new NextAction
                    {
                        Action = "chain-prove",
                        WorkflowId = chain.PatternId,
                        Rationale = $"Prove chain: {chain.PatternName} ({chain.ChainedSeverity})"
                    });
                }
            }
        }

        if (chainResult is { PartialChains.Count: > 0 })
        {
            var topPartials = chainResult.PartialChains
                .Where(p => p.SuggestedAction is { Length: > 0 })
                .Take(3);

            foreach (var partial in topPartials)
            {
                actions.Add(new NextAction
                {
                    Action = "investigate",
                    Rationale = $"Partial chain ({partial.PatternName}): {partial.SuggestedAction}"
                });
            }
        }

        var skippedTiers = ctx.Steps
            .Where(s => s.Status == "skipped" && s.Name.StartsWith("playbook-"))
            .Select(s => s.Name.Replace("playbook-", ""))
            .ToList();

        if (skippedTiers.Count > 0)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = skippedTiers.First(),
                Rationale = $"Skipped playbooks ({string.Join(", ", skippedTiers)}) may reveal additional findings. Run individually or increase budget/depth."
            });
        }

        return actions;
    }

    private static DryRunStep PlaybookStep(string id, string tierDescription) => new()
    {
        Name = $"playbook-{id}",
        Description = $"{tierDescription}: {id}",
        HttpVerbs = "various",
        WritesSideEffects = true
    };
}
