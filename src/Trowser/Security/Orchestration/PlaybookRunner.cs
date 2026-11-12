using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Vpx;
using Trowser.SessionLog;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Runs a playbook end-to-end: preflight → execute → build VPX → render → persist.
/// Shared by both the sync and async API endpoints.
/// </summary>
public sealed class PlaybookRunner
{
    private readonly AutomationContext _automation;
    private readonly IdentityStore _identityStore;
    private readonly ChainPatternCatalog _chainCatalog;
    private readonly SessionLogger? _sessionLogger;
    private readonly PeerRegistry? _peerRegistry;
    private readonly ChainEngine.ChainCompleteService.ScannerInvoker? _scannerInvoker;

    public PlaybookRunner(
        AutomationContext automation,
        IdentityStore identityStore,
        ChainPatternCatalog chainCatalog,
        SessionLogger? sessionLogger = null,
        PeerRegistry? peerRegistry = null,
        ChainEngine.ChainCompleteService.ScannerInvoker? scannerInvoker = null)
    {
        _automation = automation;
        _identityStore = identityStore;
        _chainCatalog = chainCatalog;
        _sessionLogger = sessionLogger;
        _peerRegistry = peerRegistry;
        _scannerInvoker = scannerInvoker;
    }

    /// <summary>Execute a playbook and return the formatted response.</summary>
    public async Task<PlaybookResponse> RunAsync(
        IPlaybook playbook,
        PlaybookRequest request,
        CancellationToken ct = default,
        string? runId = null,
        IPlaybookRunProgress? runProgress = null)
    {
        var host = await ResolveHostAsync(request.Scope);
        var surface = PlaybookBudgetPlanner.AnalyzeSurface(_automation.Network.Entries, host, request.Scope);
        var steps = playbook.DescribeSteps(request);
        var plan = PlaybookBudgetPlanner.BuildPlan(playbook.Id, request.Depth, request, steps, surface);

        var effectiveRequest = ApplyBudgetFloor(request, plan);
        var context = new PlaybookContext(_automation, _identityStore, _chainCatalog, effectiveRequest, runId, runProgress)
            .WithSessionLogger(_sessionLogger)
            .WithPeerRegistry(_peerRegistry)
            .WithScannerInvoker(_scannerInvoker);

        if (request.Budget.HonorRequested
            && (request.Budget.MaxSeconds < plan.AdjustedRecommended.MaxSeconds
                || request.Budget.MaxRequests < plan.AdjustedRecommended.MaxRequests))
        {
            if (effectiveRequest.Depth == PlaybookDepth.Llm)
            {
                context.Warnings.Add(
                    $"depth=llm with budget {request.Budget.MaxSeconds}s / {request.Budget.MaxRequests} req " +
                    $"(full-depth recommend {plan.AdjustedRecommended.MaxSeconds}s / {plan.AdjustedRecommended.MaxRequests}). " +
                    "Agent profile intentionally short — expect partial coverage; see nextActions / scannersSkipped. " +
                    $"suggestedClientTimeoutSeconds={plan.SuggestedClientTimeoutSeconds}.");
            }
            else
            {
                context.Warnings.Add(
                    $"Requested budget ({request.Budget.MaxSeconds}s / {request.Budget.MaxRequests} requests) is below " +
                    $"recommended minimum ({plan.AdjustedRecommended.MaxSeconds}s / {plan.AdjustedRecommended.MaxRequests}). " +
                    $"Honoring requested budget — coverage may be partial. " +
                    $"suggestedClientTimeoutSeconds={plan.SuggestedClientTimeoutSeconds}. " +
                    $"Set budget.honorRequested=false to raise to recommended, or raise budget to the recommended minimum. " +
                    "For agent sessions prefer depth=llm or playbook a05a-injection-core.");
            }
            foreach (var note in plan.Notes)
                context.Warnings.Add(note);
        }
        else if (effectiveRequest.Budget.MaxSeconds != request.Budget.MaxSeconds ||
            effectiveRequest.Budget.MaxRequests != request.Budget.MaxRequests)
        {
            context.Warnings.Add(
                $"Budget raised to recommended minimum: {effectiveRequest.Budget.MaxSeconds}s / {effectiveRequest.Budget.MaxRequests} requests " +
                $"(requested: {request.Budget.MaxSeconds}s / {request.Budget.MaxRequests}). " +
                $"suggestedClientTimeoutSeconds={plan.SuggestedClientTimeoutSeconds}.");
            foreach (var note in plan.Notes)
                context.Warnings.Add(note);
        }

        if (surface.NetworkLogEmpty && !effectiveRequest.IncludeCrawl)
        {
            context.Warnings.Add(
                "Network log is empty and crawl=false — browse key flows (login, search, CRUD) to populate traffic, " +
                "or set crawl=true to auto-discover endpoints.");
        }

        if (EndpointScopeHelper.IsProbeHeavyPlaybook(playbook.Id)
            && !EndpointScopeHelper.IsEndpointScoped(effectiveRequest.Scope)
            && effectiveRequest.Depth != PlaybookDepth.Deep)
        {
            var probeCap = EndpointScopeHelper.CapProbeEndpoints(effectiveRequest.Scope, context.DepthProfile);
            context.Warnings.Add(
                $"Probe-heavy steps scan at most {probeCap} endpoint(s) at depth={context.DepthProfile.ToLabel()}. " +
                "Set scope.targetUrl for one endpoint, or depth=deep for broader coverage.");
        }

        var refusal = SecurityPreflight.AssertAllowed(playbook.Id, request.SafetyMode, host);
        if (refusal != null)
        {
            return BuildRefusalResponse(playbook, request, context, refusal, plan);
        }

        if (request.SafetyMode == SafetyMode.Aggressive &&
            !SecurityPreflight.IsLabHost(host) &&
            App.Api.DangerousSecurityProbesOk)
        {
            context.Warnings.Add(
                $"Aggressive mode allowed for '{host}' because --dangerous-ok is set. " +
                $"This enables destructive probes that may modify server state.");
        }

        _sessionLogger?.LogLlmNote(
            $"[orchestrate] Starting playbook '{playbook.Id}' (safety={context.SafetyMode.ToLabel()}, depth={context.DepthProfile.ToLabel()})",
            tags: ["orchestrate", playbook.Id, "start"]);

        PlaybookResponse response;
        try
        {
            response = await playbook.RunAsync(context, effectiveRequest, ct);
        }
        catch (BudgetExhaustedException)
        {
            context.Warnings.Add(
                $"Budget exhausted: {context.Budget.RequestCount}/{effectiveRequest.Budget.MaxRequests} requests, " +
                $"{context.Budget.ElapsedSeconds}/{effectiveRequest.Budget.MaxSeconds}s. " +
                $"Returning partial results ({context.Findings.Count} findings from {context.Steps.Count} steps).");

            response = new PlaybookResponse
            {
                PlaybookId = playbook.Id,
                RunId = context.RunId,
                Scope = effectiveRequest.Scope,
                SafetyMode = context.SafetyMode.ToLabel(),
                Depth = context.DepthProfile.ToLabel(),
                StartedAt = context.Steps.FirstOrDefault()?.Name != null
                    ? DateTime.UtcNow.AddMilliseconds(-context.Budget.ElapsedMs).ToString("o")
                    : DateTime.UtcNow.ToString("o"),
                FinishedAt = DateTime.UtcNow.ToString("o"),
                StepsExecuted = context.Steps,
                BudgetUsed = context.Budget.ToSummary(),
                Warnings = context.Warnings,
                AssertionsAdded = context.AssertionsAdded,
                NextActions = context.NextActions,
                CoverageIncomplete = true,
                AgentInstruction =
                    $"coverageIncomplete: budget exhausted mid-run — " +
                    $"raise to recommendedBudget ({plan.AdjustedRecommended.MaxSeconds}s / {plan.AdjustedRecommended.MaxRequests} req) before treating results as complete."
            };
        }

        AttachTimingEstimates(response, plan);

        // LLM contract: top-level findings[] + severity histogram (VPX remains the export detail).
        response.Findings = context.Findings.GetSorted();
        response.SeverityHistogram = context.Findings.CountBySeverity();

        var skippedProbeSteps = context.Steps.Count(s =>
            s.Status == "budget-exhausted"
            || (s.Status == "skipped"
                && s.Reason?.Contains("budget", StringComparison.OrdinalIgnoreCase) == true));
        if (skippedProbeSteps > 0)
        {
            response.CoverageIncomplete = true;
            // Never recommend a smaller budget than the run that already exhausted.
            var usedSeconds = Math.Max(effectiveRequest.Budget.MaxSeconds, context.Budget.ElapsedSeconds);
            var recommendSeconds = Math.Max(plan.AdjustedRecommended.MaxSeconds, (int)(usedSeconds * 1.5));
            var recommendRequests = Math.Max(plan.AdjustedRecommended.MaxRequests, effectiveRequest.Budget.MaxRequests);
            response.AgentInstruction ??=
                $"coverageIncomplete: {skippedProbeSteps} step(s) skipped/exhausted under budget " +
                $"({effectiveRequest.Budget.MaxSeconds}s / {effectiveRequest.Budget.MaxRequests} req). " +
                $"Re-run with recommendedBudget ({recommendSeconds}s / {recommendRequests} req) " +
                "before treating results as complete.";
            if (!response.Warnings.Any(w => w.Contains("coverageIncomplete", StringComparison.OrdinalIgnoreCase)))
                response.Warnings.Add(response.AgentInstruction);

            // Surface copy-paste follow-ups even when playbook nextActions were empty.
            if (response.NextActions.Count == 0)
            {
                foreach (var step in context.Steps.Where(s =>
                             s.Status is "skipped" or "budget-exhausted" or "degraded"))
                {
                    response.NextActions.Add(new NextAction
                    {
                        Action = "manual-check",
                        Rationale =
                            $"Step '{step.Name}' was {step.Status}. Raise budget to ≥{recommendSeconds}s or run the step's dedicated API."
                    });
                }
            }
        }

        var vpxDoc = await BuildVpxAsync(context, request);
        EnrichVpxWithScanMetadata(vpxDoc, response, playbook.Title);
        response.VpxFull = vpxDoc;

        var suppressedCount = context.Findings.SuppressedCount;
        if (suppressedCount > 0)
        {
            response.SuppressedFindings = context.Findings.SuppressedFindings.ToList();
            response.Warnings.Add(
                $"{suppressedCount} finding(s) suppressed by cross-playbook deduplication " +
                $"(see suppressedFindings[] for ids/titles).");
        }

        ApplyFormat(response, request, playbook.Title, suppressedCount);

        if (request.PersistVpx)
            PersistVpx(context, vpxDoc);

        _sessionLogger?.LogLlmNote(
            $"[orchestrate] Completed playbook '{playbook.Id}': {context.Findings.Count} findings " +
            $"({context.Findings.SuppressedCount} deduped), " +
            $"{context.Steps.Count} steps, {context.Budget.ElapsedMs}ms",
            tags: ["orchestrate", playbook.Id, "complete"]);

        return response;
    }

    /// <summary>Generate a dry-run plan without executing any probes.</summary>
    public async Task<DryRunResponse> DryRunAsync(IPlaybook playbook, PlaybookRequest request)
    {
        var host = await ResolveHostAsync(request.Scope);
        var surface = PlaybookBudgetPlanner.AnalyzeSurface(_automation.Network.Entries, host, request.Scope);
        var steps = playbook.DescribeSteps(request);
        var plan = PlaybookBudgetPlanner.BuildPlan(playbook.Id, request.Depth, request, steps, surface);
        var enrichedSteps = PlaybookBudgetPlanner.EnrichSteps(steps, plan.StepEstimates, request.Budget);

        var skippedByBudget = enrichedSteps.Count(s => s.SkippedByBudget);
        var notes = new List<string>(plan.Notes);
        string? agentInstruction = null;
        if (skippedByBudget > 0)
        {
            var skippedNames = string.Join(", ",
                enrichedSteps.Where(s => s.SkippedByBudget).Select(s => s.Name).Take(8));
            var needSeconds = Math.Max(plan.AdjustedRecommended.MaxSeconds, plan.EstimatedCompletionSeconds);
            notes.Add(
                $"{skippedByBudget} step(s) would likely be omitted at the requested budget " +
                $"({request.Budget.MaxSeconds}s / {request.Budget.MaxRequests} req): {skippedNames}. " +
                $"Use recommendedBudget ({needSeconds}s / {plan.AdjustedRecommended.MaxRequests} req).");
            agentInstruction =
                needSeconds > request.Budget.MaxSeconds
                    ? $"coverageIncomplete: raise budget.maxSeconds to at least {needSeconds} " +
                      $"(estimatedCompletionSeconds={plan.EstimatedCompletionSeconds}, suggestedClientTimeoutSeconds={plan.SuggestedClientTimeoutSeconds}) " +
                      $"— skipped steps: {skippedNames}."
                    : $"coverageIncomplete: raise budget.maxRequests or reduce skipped steps ({skippedNames}) — " +
                      $"time budget {request.Budget.MaxSeconds}s is below estimate {plan.EstimatedCompletionSeconds}s.";
        }

        return new DryRunResponse
        {
            PlaybookId = playbook.Id,
            SafetyMode = request.SafetyMode.ToLabel(),
            Depth = PlaybookDepthProfile.Resolve(request.Depth).ToLabel(),
            Steps = enrichedSteps,
            Budget = request.Budget,
            BaseRecommendedBudget = plan.BaseRecommended,
            RecommendedBudget = plan.AdjustedRecommended,
            EstimatedCompletionSeconds = plan.EstimatedCompletionSeconds,
            SuggestedClientTimeoutSeconds = plan.SuggestedClientTimeoutSeconds,
            Surface = plan.Surface,
            BudgetNotes = notes,
            CoverageIncomplete = skippedByBudget > 0,
            AgentInstruction = agentInstruction
        };
    }

    private async Task<string> ResolveHostAsync(PlaybookScope scope)
    {
        if (!string.IsNullOrWhiteSpace(scope.Host))
            return scope.Host;

        var pageUrl = await _automation.GetCurrentUrl();
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
            return uri.Host;

        return "unknown";
    }

    private static PlaybookRequest ApplyBudgetFloor(PlaybookRequest request, PlaybookBudgetPlanner.BudgetPlan plan)
    {
        var recommended = plan.AdjustedRecommended;

        // Default: honor caller budget so LLM/client timeouts remain predictable.
        if (request.Budget.HonorRequested)
        {
            if (request.Budget.Adaptive == recommended.Adaptive)
                return request;

            return CloneRequest(request, new BudgetLimits
            {
                MaxSeconds = request.Budget.MaxSeconds,
                MaxRequests = request.Budget.MaxRequests,
                Adaptive = request.Budget.Adaptive,
                HonorRequested = true
            });
        }

        if (request.Budget.MaxSeconds >= recommended.MaxSeconds &&
            request.Budget.MaxRequests >= recommended.MaxRequests)
        {
            if (request.Budget.Adaptive == recommended.Adaptive)
                return request;

            return CloneRequest(request, new BudgetLimits
            {
                MaxSeconds = request.Budget.MaxSeconds,
                MaxRequests = request.Budget.MaxRequests,
                Adaptive = request.Budget.Adaptive,
                HonorRequested = false
            });
        }

        return CloneRequest(request, new BudgetLimits
        {
            MaxSeconds = Math.Max(request.Budget.MaxSeconds, recommended.MaxSeconds),
            MaxRequests = Math.Max(request.Budget.MaxRequests, recommended.MaxRequests),
            Adaptive = request.Budget.Adaptive,
            HonorRequested = false
        });
    }

    private static PlaybookRequest CloneRequest(PlaybookRequest request, BudgetLimits budget) =>
        new()
        {
            Scope = request.Scope,
            SafetyMode = request.SafetyMode,
            Depth = request.Depth,
            PayloadProfile = request.PayloadProfile,
            IncludeCrawl = request.IncludeCrawl,
            Budget = budget,
            Evidence = request.Evidence,
            EmitSuggestedProofs = request.EmitSuggestedProofs,
            Tags = request.Tags,
            Format = request.Format,
            EmbedVpx = request.EmbedVpx,
            PersistVpx = request.PersistVpx,
            ResumeRunId = request.ResumeRunId
        };

    private static void AttachTimingEstimates(PlaybookResponse response, PlaybookBudgetPlanner.BudgetPlan plan)
    {
        response.EstimatedCompletionSeconds = plan.EstimatedCompletionSeconds;
        response.SuggestedClientTimeoutSeconds = plan.SuggestedClientTimeoutSeconds;
    }

    private async Task<object> BuildVpxAsync(PlaybookContext context, PlaybookRequest request)
    {
        var findings = context.Findings.GetSorted();

        foreach (var f in findings)
            context.Automation.AddManualChainFinding(f);

        var input = new VpxExportService.ExportInput
        {
            Findings = findings,
            Proofs = context.Automation.GetVpxProofsSnapshot(),
            Verdicts = context.Automation.GetVpxVerdictsSnapshot(),
            ImportedSurfaces = context.Automation.GetVpxSurfacesSnapshot(),
            ImportedRuns = context.Automation.GetVpxRunsSnapshot(),
            ImportedAssessments = context.Automation.GetVpxAssessmentsSnapshot(),
            ImportedArtifacts = context.Automation.GetVpxArtifactsSnapshot(),
            BaseUrl = await context.GetCurrentUrlAsync(),
            Profile = request.Evidence == "full" ? "full" : "compact",
            DocumentId = context.RunId
        };

        var vpxDoc = VpxExportService.BuildDocument(input);

        if (request.EmitSuggestedProofs && vpxDoc is Dictionary<string, object?> doc)
            EnrichWithSuggestedProofs(doc, findings);

        return vpxDoc;
    }

    private static void EnrichWithSuggestedProofs(
        Dictionary<string, object?> vpxDoc,
        IReadOnlyList<ChainableFinding> findings)
    {
        if (!vpxDoc.TryGetValue("findings", out var findingsObj) || findingsObj == null)
            return;

        var findingDicts = findingsObj switch
        {
            IEnumerable<Dictionary<string, object?>> typed => typed.ToList(),
            List<object> list => list.OfType<Dictionary<string, object?>>().ToList(),
            _ => []
        };

        var suggestedProofs = new List<object>();

        foreach (var fd in findingDicts)
        {
            if (!fd.TryGetValue("id", out var idObj) || idObj is not string findingId)
                continue;

            var category = fd.TryGetValue("kind", out var kindObj) && kindObj is string k ? k : "unknown";
            var oracle = SuggestedOracle(category);
            var workflowId = $"suggest-{findingId}";

            fd["suggestedProof"] = new Dictionary<string, object?>
            {
                ["workflowId"] = workflowId,
                ["oracleType"] = oracle
            };

            string? surfaceId = fd.TryGetValue("surfaceId", out var sid) && sid is string s ? s : null;
            string? param = fd.TryGetValue("param", out var p) && p is string ps ? ps : null;

            suggestedProofs.Add(new Dictionary<string, object?>
            {
                ["id"] = workflowId,
                ["findingId"] = findingId,
                ["runId"] = VpxExportService.SessionRunId,
                ["executedAt"] = DateTime.UtcNow.ToString("o"),
                ["status"] = "suggested",
                ["outcome"] = "inconclusive",
                ["workflowType"] = "verify-workflow",
                ["oracle"] = new Dictionary<string, object?>
                {
                    ["type"] = oracle,
                    ["observed"] = false
                },
                ["injection"] = surfaceId != null ? new Dictionary<string, object?>
                {
                    ["surfaceId"] = surfaceId,
                    ["param"] = param
                } : null
            });
        }

        if (suggestedProofs.Count > 0)
        {
            if (vpxDoc.TryGetValue("proofs", out var existingObj) && existingObj is List<object> existing)
                existing.AddRange(suggestedProofs);
            else
                vpxDoc["proofs"] = suggestedProofs;
        }
    }

    private static string SuggestedOracle(string kind) => kind switch
    {
        "sqli" => "error-or-timing",
        "xss" => "reflection",
        "csrf" => "status-code",
        "idor" or "bfla" => "status-code",
        "ssrf" => "network-match",
        "open-redirect" => "status-code",
        "path-traversal" => "status-code",
        "misconfiguration" => "fetch",
        "cors-misconfig" => "fetch",
        "dangerous-methods" => "fetch",
        "missing-sri" or "source-maps" => "expression",
        _ => "network-match"
    };

    private static void EnrichVpxWithScanMetadata(object vpxDoc, PlaybookResponse response, string playbookTitle)
    {
        if (vpxDoc is not Dictionary<string, object?> doc) return;

        var steps = response.StepsExecuted;
        var completed = steps.Count(s => s.Status.Equals("ok", StringComparison.OrdinalIgnoreCase));

        doc["scan"] = new Dictionary<string, object?>
        {
            ["playbookId"] = response.PlaybookId,
            ["playbookTitle"] = playbookTitle,
            ["runId"] = response.RunId,
            ["startedAt"] = response.StartedAt,
            ["finishedAt"] = response.FinishedAt,
            ["safetyMode"] = response.SafetyMode,
            ["depth"] = response.Depth,
            ["scope"] = response.Scope,
            ["stepsExecuted"] = steps.Select(s => new Dictionary<string, object?>
            {
                ["name"] = s.Name,
                ["status"] = s.Status,
                ["durationMs"] = s.DurationMs,
                ["reason"] = s.Reason
            }).Cast<object>().ToList(),
            ["coverageCompleted"] = completed,
            ["coverageTotal"] = steps.Count,
            ["budgetUsed"] = response.BudgetUsed
        };
    }

    private static void ApplyFormat(PlaybookResponse response, PlaybookRequest request, string title, int suppressedCount = 0)
    {
        var vpx = response.VpxFull;
        if (vpx == null) return;

        switch (request.Format.ToLowerInvariant())
        {
            case "vpx":
                response.Vpx = vpx;
                break;

            case "vpx-summary":
                response.Vpx = VpxRenderer.ToSummary(vpx, response.NextActions);
                break;

            case "markdown":
                response.Markdown = VpxRenderer.ToMarkdown(vpx, title, suppressedCount);
                if (request.EmbedVpx)
                    response.VpxAttached = VpxRenderer.ToCompact(vpx);
                break;

            case "sarif":
                response.Sarif = VpxRenderer.ToSarif(vpx, response.PlaybookId, suppressedCount);
                break;

            case "vpx-compact":
            default:
                response.Vpx = VpxRenderer.ToCompact(vpx);
                break;
        }
    }

    private void PersistVpx(PlaybookContext context, object vpxDoc)
    {
        if (vpxDoc is not Dictionary<string, object?> doc) return;

        if (doc.TryGetValue("findings", out var findingsObj) && findingsObj is List<object> findings)
        {
            foreach (var f in findings.OfType<Dictionary<string, object?>>())
            {
                if (f.TryGetValue("surfaceId", out var sid) && sid is string surfaceId)
                {
                    var surface = new Dictionary<string, object?> { ["id"] = surfaceId };
                    if (f.TryGetValue("param", out var p)) surface["params"] = p;
                    context.Automation.UpsertVpxSurface(surfaceId, surface);
                }
            }
        }
    }

    private static PlaybookResponse BuildRefusalResponse(
        IPlaybook playbook,
        PlaybookRequest request,
        PlaybookContext context,
        string refusal,
        PlaybookBudgetPlanner.BudgetPlan plan)
    {
        var response = new PlaybookResponse
        {
            PlaybookId = playbook.Id,
            RunId = context.RunId,
            Scope = request.Scope,
            SafetyMode = request.SafetyMode.ToLabel(),
            Depth = PlaybookDepthProfile.Resolve(request.Depth).ToLabel(),
            StartedAt = DateTime.UtcNow.ToString("o"),
            FinishedAt = DateTime.UtcNow.ToString("o"),
            StepsExecuted = [],
            BudgetUsed = new Dictionary<string, object?> { ["requests"] = 0, ["seconds"] = 0 },
            Warnings = [refusal],
            Markdown = $"## {playbook.Title}\n\n**Blocked**: {refusal}",
            Findings = [],
            SeverityHistogram = new Dictionary<string, int>
            {
                ["critical"] = 0,
                ["high"] = 0,
                ["medium"] = 0,
                ["low"] = 0,
                ["info"] = 0
            }
        };
        AttachTimingEstimates(response, plan);
        return response;
    }
}
