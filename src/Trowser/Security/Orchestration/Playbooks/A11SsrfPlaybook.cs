using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A11 SSRF: wraps SsrfOrchestrator + open-redirect + JWT jku/x5u + callback probes +
/// cloud-metadata payload set + chain analysis.
/// </summary>
public sealed class A11SsrfPlaybook : IPlaybook
{
    public string Id => "a11-ssrf";
    public string Title => "A11 SSRF";
    public string Category => "server-side-request-forgery";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "ssrf-orchestrator",
                Description = "Full SSRF assessment: probe URL parameters with internal IPs, cloud metadata, DNS rebinding, and callback probes",
                HttpVerbs = mode.AllowsWriteVerbs() ? "GET, POST, PUT" : "GET",
                WritesSideEffects = mode.AllowsWriteVerbs(),
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "open-redirect",
                Description = "Scan for open redirect endpoints (SSRF escalation vector)",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "security-headers-ssrf",
                Description = "Check headers relevant to SSRF prevention (CSP connect-src, CORS)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: SSRF orchestrator (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("ssrf-orchestrator", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new SsrfOrchestrator.OrchestratorOptions
                {
                    MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    ExplicitUrls = EndpointScopeHelper.IsEndpointScoped(request.Scope)
                        ? [request.Scope.TargetUrl!]
                        : null,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 30000),
                    CallbackWaitMs = depth.Depth == PlaybookDepth.Deep ? 5000 : 2000,
                    IncludeScaffoldPaths = true,
                    IncludeImdsV2Pivot = ctx.SafetyMode.AllowsWriteVerbs(),
                    IncludeCloudMetadataHeaders = true,
                    IncludeXxe = ctx.SafetyMode.AllowsWriteVerbs(),
                    IncludeUploadXxe = false,
                    IncludeOpenRedirect = false,
                    IncludeJwtHeaderAbuse = true,
                    IncludeCallbackProbes = true,
                    IncludeChainAnalysis = true,
                    RegisterChainFindings = false,
                    IncludeBrowserCookies = true
                };

                var result = await ctx.Automation.RunSsrfOrchestrator(options, ctx.ChainCatalog, innerCt);
                int findingCount = 0;

                if (result.Ssrf?.Findings is { Count: > 0 })
                {
                    foreach (var f in result.Ssrf.Findings)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a11-ssrf-{findingCount}",
                            Source = "orchestrate-a11",
                            Category = "ssrf",
                            Severity = f.Severity.ToLowerInvariant(),
                            Title = $"SSRF ({f.Confidence}): {f.Indicator}",
                            Endpoint = f.Url,
                            Method = f.Method,
                            Parameter = f.ParamName,
                            Detail = $"Payload: {f.Payload}. Status: {f.Status} (baseline: {f.BaselineStatus}). Type: {f.Type}",
                            Evidence = f.Snippet,
                            Remediation = "Validate and whitelist allowed URLs server-side. Block internal/private IP ranges.",
                            Reference = "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
                        });
                        findingCount++;
                    }
                }

                if (result.JwtHeaderAbuse?.Findings is { Count: > 0 })
                {
                    foreach (var f in result.JwtHeaderAbuse.Findings)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a11-jwt-ssrf-{findingCount}",
                            Source = "orchestrate-a11",
                            Category = "ssrf",
                            Severity = f.Severity.ToLowerInvariant(),
                            Title = f.Title,
                            Endpoint = f.Url,
                            Detail = f.Detail,
                            Remediation = "Do not fetch URLs from JWT headers (jku, x5u) without strict allowlisting.",
                            Reference = "https://portswigger.net/web-security/jwt"
                        });
                        findingCount++;
                    }
                }

                ctx.Budget.AddRequests(result.Ssrf?.PayloadsSent ?? 0);

                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["stepsRun"] = result.StepsRun,
                    ["callbackInteractions"] = result.CallbackInteractions,
                    ["totalFindings"] = result.TotalFindings
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("ssrf-orchestrator",
                $"SSRF probing requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 2: Open redirect scan (SSRF escalation)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("open-redirect", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new OpenRedirectOptions
                {
                    MaxCandidates = EndpointScopeHelper.CapRedirectCandidates(request.Scope, depth),
                    ExplicitUrls = EndpointScopeHelper.IsEndpointScoped(request.Scope)
                        ? [request.Scope.TargetUrl!]
                        : null,
                    IncludeDomDiscovery = !EndpointScopeHelper.IsEndpointScoped(request.Scope),
                    // Keep /api/goto scaffolds even when other urls are listed — llm top-N needs them.
                    IncludeScaffoldWithExplicit = !EndpointScopeHelper.IsEndpointScoped(request.Scope)
                        || depth.Depth == PlaybookDepth.Llm,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await ctx.Automation.RunOpenRedirectScan(options, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a11-redir-{findingCount}",
                        Source = "orchestrate-a11",
                        Category = "open-redirect",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Open redirect via {f.ParamName}: {f.Indicator}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Parameter = f.ParamName,
                        Detail = $"Payload: {f.Payload}. Location: {f.Location}. Bypass: {f.BypassTechnique ?? "none"}",
                        Evidence = f.Snippet,
                        Remediation = "Validate redirect targets against an allowlist. Avoid user-controlled redirect URLs.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.PayloadsSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("open-redirect",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3: Security headers relevant to SSRF (passive)
        await ctx.RunStepAsync("security-headers-ssrf", async _ =>
        {
            var result = await ctx.Automation.CheckSecurityHeaders();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings.Where(h => IsSsrfRelevantHeader(h.Header)))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a11-header-{findingCount}",
                        Source = "orchestrate-a11",
                        Category = NormalizeHeaderCategory(f.Header),
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Missing/weak: {f.Header}",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = f.Description,
                        Remediation = f.Recommendation,
                        Reference = f.Reference
                    });
                    findingCount++;
                }
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        var nextActions = BuildNextActions(ctx);

        return new PlaybookResponse
        {
            PlaybookId = Id,
            RunId = ctx.RunId,
            Scope = request.Scope,
            SafetyMode = ctx.SafetyMode.ToLabel(),
            Depth = depth.ToLabel(),
            StartedAt = startedAt.ToString("o"),
            FinishedAt = DateTime.UtcNow.ToString("o"),
            StepsExecuted = ctx.Steps,
            BudgetUsed = ctx.Budget.ToSummary(),
            Warnings = ctx.Warnings,
            AssertionsAdded = ctx.AssertionsAdded,
            NextActions = nextActions
        };
    }

    private static List<NextAction> BuildNextActions(PlaybookContext ctx)
    {
        var actions = new List<NextAction>();

        bool hasSsrf = ctx.Findings.All.Any(f => f.Category == "ssrf");
        bool hasOpenRedirect = ctx.Findings.All.Any(f => f.Category == "open-redirect");

        if (hasSsrf)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "SSRF can bypass access controls to reach internal APIs - test authorization."
            });
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "SSRF to cloud metadata can expose secrets and credentials."
            });
        }

        if (hasOpenRedirect)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Open redirects can be chained with OAuth flows for token theft."
            });
        }

        return actions;
    }

    private static bool IsSsrfRelevantHeader(string? header) =>
        (header ?? "").ToLowerInvariant() is "content-security-policy" or "csp";

    private static string NormalizeHeaderCategory(string? header) => (header ?? "").ToLowerInvariant() switch
    {
        "content-security-policy" or "csp" => "missing-csp",
        _ => "weak-headers"
    };
}
