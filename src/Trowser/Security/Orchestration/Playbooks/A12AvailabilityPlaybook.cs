using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A12 Availability: crawl → costly-operations (passive) → rate-limit audit → body-size limit → ReDoS scan →
/// GraphQL query-cost analysis. Focused on denial-of-service resilience
/// without actually exhausting the target (unless aggressive mode).
/// </summary>
public sealed class A12AvailabilityPlaybook : IPlaybook
{
    public string Id => "a12-availability";
    public string Title => "A12 Availability";
    public string Category => "availability";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "costly-operations",
                Description = "Passive single-request cost risks from traffic/DOM (paging, heavy routes, bulk input)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = false
            },
            new DryRunStep
            {
                Name = "rate-limit-audit",
                Description = "Sequential baseline then concurrent burst to detect missing/weak rate limits",
                HttpVerbs = "GET, POST (burst)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode for probe requests" : null
            },
            new DryRunStep
            {
                Name = "body-size-limit",
                Description = "Escalating body sizes (1KB→1MB) on POST endpoints to detect unbounded acceptance",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode for POST payloads" : null
            },
            new DryRunStep
            {
                Name = "redos-scan",
                Description = "Single-request ReDoS timing oracle on injectable parameters",
                HttpVerbs = "GET, POST",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "graphql-cost",
                Description = "GraphQL depth/complexity/batching probes to detect query-cost DoS vectors",
                HttpVerbs = "POST",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        await ctx.RunStepAsync("costly-operations", async innerCt =>
        {
            var result = await ctx.Automation.RunCostlyOperations(
                new CostlyOperationsProbe.CostlyOperationsOptions
                {
                    SafetyMode = SafetyMode.Passive,
                    MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    Urls = EndpointScopeHelper.ScopedUrlList(request.Scope),
                    IncludeSpaDom = true,
                    RegisterChainFindings = false
                }, innerCt);

            var findingCount = 0;
            foreach (var f in result.Findings.Concat(result.InferredLeads))
            {
                var tags = new List<string> { $"confidence:{f.Confidence}" };
                if (!string.IsNullOrEmpty(f.RelatedProbe))
                    tags.Add($"related:{f.RelatedProbe}");

                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a12-costly-{findingCount}",
                    Source = "orchestrate-a12",
                    Category = f.Category,
                    Severity = f.Severity,
                    Title = f.Title,
                    Endpoint = f.Endpoint,
                    Method = f.Method,
                    Parameter = f.Parameter,
                    Detail = f.Detail,
                    Evidence = f.Evidence,
                    Remediation = f.Remediation,
                    Tags = tags
                });
                findingCount++;
            }

            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["observed"] = result.Findings.Count,
                ["inferredLeads"] = result.InferredLeads.Count,
                ["entriesExamined"] = result.EntriesExamined
            };
        }, ct);

        // Step 1: Rate limit audit (safe — uses small burst, respects 429)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("rate-limit-audit", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunRateLimitAudit(
                    new RateLimitAuditProbe.RateLimitAuditOptions
                    {
                        MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope),
                        SequentialAttempts = 5,
                        BurstSize = ctx.SafetyMode.AllowsStress() ? 15 : 8,
                        DelayMs = 200,
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                        IncludeBrowserCookies = true,
                        RespectRateLimits = !ctx.SafetyMode.AllowsStress(),
                        IncludeOtpTemplates = true,
                        RegisterChainFindings = false
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a12-ratelimit-{findingCount}",
                        Source = "orchestrate-a12",
                        Category = f.Category,
                        Severity = f.Severity,
                        Title = $"Rate limit: {f.Kind} on {f.Method} {TruncateUrl(f.Url)}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.MatchReason,
                        Remediation = "Implement rate limiting (e.g., 100 req/min per IP). Use 429 Too Many Requests with Retry-After header.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.RequestsSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed,
                    ["requestsSent"] = result.RequestsSent,
                    ["backoffEvents"] = result.BackoffEvents
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("rate-limit-audit", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 2: Body size limit (active — sends escalating POST bodies)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("body-size-limit", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunBodySizeLimitScan(
                    new BodySizeLimitProbe.BodySizeLimitOptions
                    {
                        MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope),
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                        IncludeBrowserCookies = true,
                        RespectRateLimits = true,
                        RegisterChainFindings = false
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a12-bodysize-{findingCount}",
                        Source = "orchestrate-a12",
                        Category = "body-size-unbounded",
                        Severity = f.Severity,
                        Title = $"Unbounded body: {f.LargestAcceptedBytes / 1024}KB accepted on {TruncateUrl(f.Url)}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Remediation = "Enforce server-side body size limits (e.g., 1MB max). Use Content-Length validation and streaming parsers.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("body-size-limit", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3: ReDoS scan (safe — single request per parameter, timing-based)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("redos-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunReDoSScan(
                    new ReDoSScanProbe.ReDoSScanOptions
                    {
                        MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope),
                        MaxPayloadsPerCandidate = depth.Depth == PlaybookDepth.Deep ? 5 : 3,
                        SlowThresholdSeconds = 3.0,
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                        IncludeBrowserCookies = true,
                        RespectRateLimits = true,
                        RegisterChainFindings = false
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a12-redos-{findingCount}",
                        Source = "orchestrate-a12",
                        Category = "redos-suspected",
                        Severity = f.Severity,
                        Title = $"ReDoS: {f.AttackSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)}s vs {f.BaselineSeconds.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)}s baseline on {f.Param}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Parameter = f.Param,
                        Detail = f.Detail,
                        Evidence = $"Payload: {f.Payload}",
                        Remediation = "Audit server-side regex for catastrophic backtracking. Use RE2 or other linear-time regex engines.",
                        Reference = "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("redos-scan", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 4: GraphQL query cost analysis
        if (ctx.SafetyMode.AllowsProbes())
        {
            var skipGraphql = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "graphql-cost");
            if (skipGraphql != null)
                ctx.SkipStep("graphql-cost", skipGraphql);
            else
            await ctx.RunStepAsync("graphql-cost", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunGraphqlAnalysis(
                    autoDetect: true,
                    timeoutMs: Math.Min(ctx.Budget.RemainingSeconds * 1000, 20000),
                    skipIntrospection: false,
                    skipBatching: false,
                    skipAmplification: false,
                    skipDepthProbe: false,
                    skipLimitProbe: false,
                    includeCostAnalysis: ctx.SafetyMode.AllowsWriteVerbs());

                if (result.Errors.Count > 0 && string.IsNullOrEmpty(result.Url))
                {
                    return new Dictionary<string, object?>
                    {
                        ["findings"] = 0,
                        ["note"] = "No GraphQL endpoint detected"
                    };
                }

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a12-graphql-{findingCount}",
                        Source = "orchestrate-a12",
                        Category = NormalizeGraphqlCategory(f.Category),
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = result.Url,
                        Detail = f.Description,
                        Remediation = RemediationForGraphql(f.Category),
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["graphqlUrl"] = result.Url
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("graphql-cost", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
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

        if (ctx.Findings.All.Any(f => f.Category is "missing-rate-limit" or "weak-rate-limit"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Missing rate limits on auth endpoints enable brute-force attacks."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category.StartsWith("costly-", StringComparison.OrdinalIgnoreCase)
                                        && f.Severity is "high" or "critical"))
        {
            actions.Add(new NextAction
            {
                Action = "manual-check",
                Rationale = "High single-request cost signals — run POST /api/security/costly-operations with safetyMode active and confirm-* checks."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category.StartsWith("graphql", StringComparison.OrdinalIgnoreCase)))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05-injection",
                Rationale = "GraphQL endpoints with weak controls may be vulnerable to injection via query variables."
            });
        }

        return actions;
    }

    private static string NormalizeGraphqlCategory(string category) => category.ToLowerInvariant() switch
    {
        string c when c.Contains("batch") => "graphql-batching",
        string c when c.Contains("depth") => "graphql-depth-unlimited",
        string c when c.Contains("amplification") || c.Contains("alias") => "graphql-amplification",
        string c when c.Contains("introspection") => "graphql-introspection",
        string c when c.Contains("limit") => "graphql-no-limit",
        string c when c.Contains("field-suggestion") => "graphql-field-suggestion",
        _ => "graphql-misconfiguration"
    };

    private static string RemediationForGraphql(string category) => category.ToLowerInvariant() switch
    {
        string c when c.Contains("batch") =>
            "Disable query batching or limit batch size. Implement per-operation rate limiting.",
        string c when c.Contains("depth") =>
            "Set max query depth (recommended: 5-10). Use query complexity analysis.",
        string c when c.Contains("amplification") =>
            "Limit alias count per query. Implement query complexity scoring.",
        string c when c.Contains("introspection") =>
            "Disable introspection in production (Apollo: introspection: false).",
        _ => "Implement query cost analysis with depth, complexity, and rate limits."
    };

    private static string TruncateUrl(string url) =>
        url.Length > 60 ? url[..57] + "..." : url;
}
