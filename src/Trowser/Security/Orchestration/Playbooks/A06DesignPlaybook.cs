using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A06 Insecure Design: race-condition → fail-open → missing-parameter → mass-assignment (price/role).
/// Tests business-logic flaws that generic injection scanners miss.
/// </summary>
public sealed class A06DesignPlaybook : IPlaybook
{
    public string Id => "a06-design";
    public string Title => "A06 Insecure Design";
    public string Category => "insecure-design";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "attack-surface",
                Description = "Analyze network log to discover POST/PUT/PATCH endpoints for design flaw testing",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "workflow-step-skip",
                Description = "Detect multi-step workflows and test if intermediate steps can be bypassed",
                HttpVerbs = "POST, PUT, PATCH (replay)",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Workflow skip probes require active mode" : null
            },
            new DryRunStep
            {
                Name = "race-condition",
                Description = "Concurrent POST burst on single-use endpoints (coupons, transfers, votes)",
                HttpVerbs = "POST (burst)",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Race condition probes require active mode" : null
            },
            new DryRunStep
            {
                Name = "fail-open",
                Description = "Test endpoints with missing/invalid auth tokens and after error conditions",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "missing-parameter",
                Description = "Omit required JSON fields to test crash vs graceful validation",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode for POST probes" : null
            },
            new DryRunStep
            {
                Name = "mass-assignment-design",
                Description = "Mass-assignment with price/role/status fields targeting business logic",
                HttpVerbs = "POST, PUT, PATCH",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode for write verbs" : null
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: Attack surface analysis (passive — discovers POST endpoints for downstream steps)
        AttackSurfaceResult? surface = null;
        List<string> postEndpointUrls = [];
        await ctx.RunStepAsync("attack-surface", async _ =>
        {
            surface = ctx.AnalyzeNetworkSurface(host, request.Scope);

            postEndpointUrls = EndpointScopeHelper.PostWriteUrls(surface, request.Scope);

            return new Dictionary<string, object?>
            {
                ["endpointsDiscovered"] = surface.Endpoints.Count,
                ["postEndpoints"] = postEndpointUrls.Count
            };
        }, ct);

        // Step: Workflow step-skip detection (active — replays final step without intermediates)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            var skipWorkflow = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "workflow-step-skip");
            if (skipWorkflow != null)
            {
                ctx.SkipStep("workflow-step-skip", skipWorkflow);
            }
            else
            await ctx.RunStepAsync("workflow-step-skip", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var probe = new WorkflowSkipProbe(ctx.Automation, (msg, _) => ctx.Warnings.Add(msg));
                var result = await probe.RunAsync(new WorkflowSkipProbe.WorkflowSkipOptions
                {
                    MaxWorkflows = Math.Min(depth.MaxEndpointsPerScanner, 5),
                    MinSteps = 3,
                    MaxStepGapSeconds = 60,
                    IncludeBrowserCookies = true,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 10000)
                }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a06-workflow-skip-{findingCount}",
                        Source = "orchestrate-a06",
                        Category = "workflow-skip",
                        Severity = f.Severity,
                        Title = $"Workflow step-skip ({f.SkipVariant}): {f.WorkflowName}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence,
                        Remediation = "Enforce server-side state machine for multi-step workflows. Validate that all prerequisite steps completed before allowing final action.",
                        Reference = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["workflowsDetected"] = result.WorkflowsDetected,
                    ["workflowsTested"] = result.WorkflowsTested,
                    ["probesSent"] = result.ProbesSent
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("workflow-step-skip", $"Workflow skip probes require active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 2: Race condition scan (active — sends concurrent POST bursts)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("race-condition", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var raceUrls = EndpointScopeHelper.ScopedUrlList(request.Scope, postEndpointUrls);
                var result = await ctx.Automation.RunRaceConditionScan(
                    new RaceConditionScanProbe.RaceConditionScanOptions
                    {
                        MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        BurstSize = ctx.SafetyMode.AllowsStress() ? 25 : 15,
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                        IncludeBrowserCookies = true,
                        IncludeRedeemCodeBursts = true,
                        Urls = raceUrls?.Count > 0 ? raceUrls : null
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a06-race-{findingCount}",
                        Source = "orchestrate-a06",
                        Category = "race-condition",
                        Severity = f.Severity,
                        Title = $"Race condition ({f.Variant}): {f.AcceptedCount}/{f.TotalRequests} accepted",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.MatchReason,
                        Remediation = "Use database-level locking (SELECT FOR UPDATE) or idempotency keys for single-use operations.",
                        Reference = "https://portswigger.net/web-security/race-conditions"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.BurstsSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("race-condition", $"Race condition probes require active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 2: Fail-open scan (safe — GET with missing/invalid tokens)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("fail-open", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var failOpenUrls = EndpointScopeHelper.ScopedUrlList(request.Scope, postEndpointUrls);
                var result = await ctx.Automation.RunFailOpenScan(
                    new FailOpenScanProbe.ScanOptions
                    {
                        Urls = failOpenUrls,
                        MaxEndpoints = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 12000),
                        IncludeUnauthenticated = true,
                        IncludeInvalidToken = true,
                        IncludeAfterError = true,
                        RegisterChainFindings = false
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a06-failopen-{findingCount}",
                        Source = "orchestrate-a06",
                        Category = f.Category is { Length: > 0 } ? f.Category : "fail-open",
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.BodySnippet,
                        Remediation = "Implement defense-in-depth: deny by default, fail closed on auth errors, validate tokens server-side.",
                        Reference = "https://owasp.org/Top10/A04_2021-Insecure_Design/"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsProbed);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["endpointsProbed"] = result.EndpointsProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("fail-open", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3: Missing parameter crash test (active)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("missing-parameter", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunMissingParameterScan(
                    new MissingParameterScanProbe.ScanOptions
                    {
                        MaxEndpoints = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        MaxFieldsPerEndpoint = 8,
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 12000),
                        RegisterChainFindings = false,
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope, postEndpointUrls)
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a06-missingparam-{findingCount}",
                        Source = "orchestrate-a06",
                        Category = "missing-parameter-crash",
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Method = f.Method,
                        Parameter = f.OmittedField,
                        Detail = f.Detail,
                        Evidence = f.BodySnippet,
                        Remediation = "Validate all required fields before processing. Return 400 with clear error messages, never 500/stack traces.",
                        Reference = "https://owasp.org/Top10/A04_2021-Insecure_Design/"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.FieldsProbed);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["fieldsProbed"] = result.FieldsProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("missing-parameter", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 4: Mass-assignment with business-logic fields (active)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("mass-assignment-design", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new AutoScanPipeline.AutoScanOptions
                {
                    Host = host,
                    MaxEndpointsPerScanner = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 30000),
                    ConfirmBackend = true,
                    ScanDepth = depth.AutoScanDepthName,
                    PayloadProfile = request.PayloadProfile,

                    SummarizeFindings = false,
                    IncludeChainAnalysis = false,
                    FindingsMode = "append"
                };
                options.DisableAllScanners();
                options.IncludeMassAssignment = true;
                options.MassAssignmentVerifyPersistence = true;
                options.IncludeMassAssignmentPatch = true;
                EndpointScopeHelper.ApplyToAutoScan(options, request.Scope, surface);

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a06-massassign-{findingCount}",
                        Source = "orchestrate-a06",
                        Category = "mass-assignment",
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence,
                        Remediation = "Use allowlists for bindable properties. Reject unexpected fields in API requests.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsScanned);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["endpointsScanned"] = result.EndpointsScanned
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("mass-assignment-design", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

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

        if (ctx.Findings.All.Any(f => f.Category == "race-condition"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a12-availability",
                Rationale = "Race conditions suggest weak concurrency controls — test rate limiting and availability."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category is "fail-open" or "fail-open-unauthenticated" or "fail-open-invalid-token"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "Fail-open behavior may expose protected resources to unauthorized access."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category == "mass-assignment"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Mass-assignment with role/privilege fields may escalate to account takeover."
            });
        }

        return actions;
    }
}
