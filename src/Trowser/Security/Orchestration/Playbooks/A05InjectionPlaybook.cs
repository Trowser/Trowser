using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A05 Injection: crawl → attack-surface → injection scan (SQLi, XSS, SSTI, NoSQL,
/// LDAP, cmd-canary, parser-probe, prototype-pollution, deserialization) via AutoScanPipeline.
/// Focused entirely on injection vulnerabilities; IDOR/CSRF/SSRF are handled by their own playbooks.
/// Prefer <c>a05a</c>/<c>a05b</c>/<c>a05c</c> for agent sessions with short budgets.
/// </summary>
public class A05InjectionPlaybook : IPlaybook
{
    private readonly A05ScanProfile _profile;

    public A05InjectionPlaybook() : this(A05ScanProfile.Full, "a05-injection", "A05 Injection")
    {
    }

    protected A05InjectionPlaybook(A05ScanProfile profile, string id, string title)
    {
        _profile = profile;
        Id = id;
        Title = title;
    }

    public string Id { get; }
    public string Title { get; }
    public string Category => "injection";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        var steps = new List<DryRunStep>
        {
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "attack-surface",
                Description = "Analyze network log to discover injectable endpoints and classify by parameter type",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "injection-scan",
                Description = InjectionScanDescription(),
                HttpVerbs = "GET, POST, PUT, PATCH",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode for probe requests" : null
            }
        };

        if (_profile is A05ScanProfile.Full or A05ScanProfile.Core)
        {
            steps.Add(new DryRunStep
            {
                Name = "dom-flows",
                Description = "Runtime sensor DOM XSS flow graph: attacker input → sink → consequence (observe; probe when active)",
                HttpVerbs = "none (observe) / GET (probe)",
                WritesSideEffects = false
            });
        }

        if (_profile is A05ScanProfile.Full or A05ScanProfile.Advanced)
        {
            steps.Add(new DryRunStep
            {
                Name = "sqli-login-sweep",
                Description = "SQL injection bypass on common login endpoints",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Login bypass requires active mode" : null
            });
            steps.Add(new DryRunStep
            {
                Name = "deserialization-scan",
                Description = "Insecure deserialization and file upload validation bypass",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode for POST payloads" : null
            });
        }

        return steps;
    }

    private string InjectionScanDescription() => _profile switch
    {
        A05ScanProfile.Core =>
            "cmd-canary + XSS + SQLi on top endpoints (core / LLM-friendly slice)",
        A05ScanProfile.Templates =>
            "SSTI, SSTI-polyglot, CSTI, NoSQL, LDAP, path-traversal (template / query-language slice)",
        A05ScanProfile.Advanced =>
            "parser-probe + prototype-pollution (advanced slice; login/deser run as separate steps)",
        _ =>
            "SQLi, XSS (reflected + DOM), SSTI, NoSQL, LDAP, cmd-canary, parser-probe, prototype-pollution via AutoScanPipeline"
    };

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: Attack surface analysis (passive)
        AttackSurfaceResult? surface = null;
        await ctx.RunStepAsync("attack-surface", async _ =>
        {
            surface = ctx.AnalyzeNetworkSurface(host, request.Scope);
            if (!string.IsNullOrWhiteSpace(request.Scope.TargetUrl) && surface.Endpoints.Count == 0)
            {
                // Still probe the pinned URL — merge same-path traffic or synthesize (POST text/plain for /render).
                surface = new AttackSurfaceResult
                {
                    Endpoints =
                    [
                        PlaybookScopeFilter.ResolveTargetEndpoint(
                            surface, request.Scope.TargetUrl!, request.Scope.TargetMethod)
                    ],
                    Source = surface.Source,
                    Summary = surface.Summary,
                    SpaRuntime = surface.SpaRuntime,
                    NetworkLogEmpty = surface.NetworkLogEmpty
                };
                ctx.Warnings.Add(
                    $"scope.targetUrl was not in captured traffic — synthesizing probe surface for {request.Scope.TargetUrl}");
            }
            return new Dictionary<string, object?>
            {
                ["endpointsDiscovered"] = surface.Endpoints.Count,
                ["injectableEndpoints"] = surface.Endpoints.Count(IsInjectableEndpoint)
            };
        }, ct);

        // Step 2: Injection scan via AutoScanPipeline (injection-only flags)
        // Capture before the step so post-steps can defer when we started in LLM-fast mode.
        var depthIsLlm = depth.Depth == PlaybookDepth.Llm;
        var injectionFast = ctx.Budget.RemainingSeconds <= 180
                            || depthIsLlm
                            || _profile == A05ScanProfile.Core;
        if (ctx.SafetyMode.AllowsProbes())
        {
            // Never reserve more than ~25% of remaining budget for post-steps (90s budgets were
            // leaving injection with 30s while still attempting a full scanner matrix → hangs).
            // LLM-fast (≤180s) / depth=llm / a05a: skip post-steps so cmd/xss/sqli get the window.
            var tightBudget = injectionFast && _profile is A05ScanProfile.Full or A05ScanProfile.Core;
            var reservedSeconds = 0;
            if (!tightBudget
                && _profile is A05ScanProfile.Full or A05ScanProfile.Advanced
                && ctx.SafetyMode.AllowsWriteVerbs())
                reservedSeconds = Math.Clamp(ctx.Budget.RemainingSeconds / 4, 15, 120);
            await ctx.RunStepAsync("injection-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var maxStepSeconds = Math.Max(20, ctx.Budget.RemainingSeconds - reservedSeconds);
                var options = BuildAutoScanOptions(
                    host, surface, request, depth, ctx, maxStepSeconds, tightBudget);
                if (tightBudget && _profile == A05ScanProfile.Full)
                {
                    ctx.Warnings.Add(
                        $"LLM-fast / tight budget ({ctx.Budget.RemainingSeconds}s remaining) — injection-fast profile " +
                        $"(cmd-canary + xss + sqli on top endpoints, depth=quick, maxStepSeconds={maxStepSeconds}; " +
                        "deferred SSTI-polyglot / path-traversal / deserialization / login-sweep). " +
                        "Prefer playbooks a05a-injection-core → a05b-injection-templates → a05c-injection-advanced, " +
                        "or depth=llm on a05a, or raise budget.maxSeconds (>180) for full A05.");
                }
                else if (depthIsLlm)
                {
                    ctx.Warnings.Add(
                        $"depth=llm — short agent profile (maxStepSeconds={maxStepSeconds}, top endpoints only). " +
                        "See scannersSkipped / nextActions for what was not covered.");
                }

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    if (string.Equals(f.Scanner, "cache-map", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.Findings.Add(CacheMapPresentation.FromAutoScanCacheMap(
                            f, $"a05-inject-{findingCount}", "orchestrate-a05"));
                    }
                    else
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a05-inject-{findingCount}",
                            Source = "orchestrate-a05",
                            Category = NormalizeInjectionCategory(f.Scanner),
                            Severity = f.Severity,
                            Title = f.Title,
                            Endpoint = f.Endpoint,
                            Method = f.Method,
                            Parameter = ChainFindingDedup.ExtractParameter(f.Title, f.Detail, f.Evidence),
                            Detail = f.Detail,
                            Evidence = f.Evidence,
                            Remediation = RemediationForCategory(f.Scanner),
                            Reference = ReferenceForCategory(f.Scanner)
                        });
                    }
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsScanned);
                if (result.BudgetExhausted || result.Partial)
                {
                    ctx.Warnings.Add(
                        $"injection-scan stopped early after {result.ScannersRun.Count} scanner(s) " +
                        $"(budget cap {maxStepSeconds}s; partial={result.Partial}; {result.Findings.Count} finding(s) flushed). " +
                        "Increase budget or use depth=quick for full step coverage.");
                }

                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["endpointsDiscovered"] = result.EndpointsDiscovered,
                    ["injectableEndpoints"] = result.InjectableEndpointsDiscovered,
                    ["endpointsScanned"] = result.EndpointsScanned,
                    ["scannersRun"] = result.ScannersRun,
                    ["budgetExhausted"] = result.BudgetExhausted,
                    ["partial"] = result.Partial,
                    ["maxStepSeconds"] = maxStepSeconds,
                    ["profile"] = _profile switch
                    {
                        A05ScanProfile.Core => "a05a-core",
                        A05ScanProfile.Templates => "a05b-templates",
                        A05ScanProfile.Advanced => "a05c-advanced",
                        _ => tightBudget ? "injection-fast" : "standard"
                    }
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("injection-scan", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3/4: only on Full/Advanced; deferred on LLM-fast Full — leave budget for cmd/xss/sqli.
        var llmFast = injectionFast && _profile == A05ScanProfile.Full;
        var runPostSteps = _profile is A05ScanProfile.Full or A05ScanProfile.Advanced;

        // Step 3: SQLi login sweep (active only)
        if (!runPostSteps)
        {
            // Step not in DescribeSteps for Core/Templates — nothing to skip.
        }
        else if (llmFast)
        {
            ctx.SkipStep("sqli-login-sweep", "Deferred by injection-fast profile (budget ≤180s) — run a05c-injection-advanced or raise budget.maxSeconds.");
        }
        else if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("sqli-login-sweep", async innerCt =>
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
                    Budget = ctx.Budget,
                    SummarizeFindings = false,
                    IncludeChainAnalysis = false,
                    FindingsMode = "append"
                };
                options.DisableAllScanners();
                options.IncludeSqliLoginSweep = true;
                EndpointScopeHelper.ApplyToAutoScan(options, request.Scope, surface);

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    // Only promote true login-sweep hits — never re-label passive/SQL noise.
                    if (!string.Equals(f.Scanner, "sqli-login-sweep", StringComparison.OrdinalIgnoreCase)
                        && !f.Title.Contains("login bypass", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var path = "";
                    if (Uri.TryCreate(f.Endpoint, UriKind.Absolute, out var epUri))
                        path = epUri.AbsolutePath;
                    else if (!string.IsNullOrEmpty(f.Endpoint))
                        path = f.Endpoint;
                    if (!SqliLoginSweep.LooksLikeLoginPath(path))
                        continue;

                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a05-sqli-login-{findingCount}",
                        Source = "orchestrate-a05",
                        Category = "sqli-login-bypass",
                        Severity = f.Severity is { Length: > 0 } ? f.Severity : "critical",
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence,
                        Remediation = "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(Math.Max(result.EndpointsScanned, findingCount > 0 ? 1 : 0));
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("sqli-login-sweep", $"Login bypass requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 4: Deserialization + file upload (active only)
        if (!runPostSteps)
        {
        }
        else if (llmFast)
        {
            ctx.SkipStep("deserialization-scan", "Deferred by injection-fast profile (budget ≤180s) — run a05c-injection-advanced or raise budget.maxSeconds.");
        }
        else if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("deserialization-scan", async innerCt =>
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
                    Budget = ctx.Budget,
                    SummarizeFindings = false,
                    IncludeChainAnalysis = false,
                    FindingsMode = "append"
                };
                options.DisableAllScanners();
                options.IncludeDeserializationScan = true;
                options.IncludeFileUploadScan = true;
                EndpointScopeHelper.ApplyToAutoScan(options, request.Scope, surface);

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a05-deser-{findingCount}",
                        Source = "orchestrate-a05",
                        Category = NormalizeInjectionCategory(f.Scanner),
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence,
                        Remediation = RemediationForCategory(f.Scanner),
                        Reference = ReferenceForCategory(f.Scanner)
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsScanned);
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("deserialization-scan", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // DOM XSS flow graph — observe always; probe when Full + active.
        if (_profile is A05ScanProfile.Full or A05ScanProfile.Core)
        {
            var skipDom = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "dom-flows");
            if (skipDom != null)
            {
                ctx.SkipStep("dom-flows", skipDom);
            }
            else await ctx.RunStepAsync("dom-flows", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var probe = _profile == A05ScanProfile.Full && ctx.SafetyMode.AllowsWriteVerbs() && !injectionFast;
                var result = await ctx.Automation.RunDomFlowsAsync(probe ? "probe" : "observe");
                int findingCount = 0;
                foreach (var c in result.Chains)
                {
                    if (c.Tier is "hygiene" or "noise" or "probe-artifact")
                        continue;
                    if (c.Consequence is "inert" && c.Confidence is "temporal" or null)
                        continue;
                    var severity = c.Consequence == "exec" ? "high"
                        : c.Consequence is "nav-hijack" or "request-forgery" or "executable-markup" ? "medium"
                        : "low";
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a05-domflow-{findingCount}",
                        Source = "orchestrate-a05",
                        Category = "xss",
                        Severity = severity,
                        Title = $"DOM flow: {c.Source} → {c.Sink} ({c.Consequence})",
                        Endpoint = result.Url,
                        Detail = $"{c.Confidence}; mutation={c.Mutation}; {c.SinkData}",
                        Evidence = c.Stack,
                        Remediation = "Sanitize attacker-controlled data before DOM sinks (innerHTML, eval, location, script). Prefer textContent and Trusted Types.",
                        Reference = "https://owasp.org/www-community/attacks/DOM_Based_XSS"
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["chains"] = result.Chains.Count,
                    ["mode"] = result.Mode,
                    ["summary"] = result.Summary
                };
            }, ct);
        }

        var nextActions = BuildNextActions(ctx, surface, request);

        var budgetSkipped = ctx.Steps
            .Where(s => s.Status == "budget-exhausted")
            .Select(s => s.Name)
            .ToList();
        if (budgetSkipped.Count > 0)
        {
            var recommended = PlaybookBudgetPlanner.GetBaseRecommended(Id, depth.Depth);
            ctx.Warnings.Add(
                $"Budget exhausted — skipped steps: {string.Join(", ", budgetSkipped)}. " +
                $"Recommended budget for {Id}: {recommended.MaxSeconds}s / {recommended.MaxRequests} requests.");
        }

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

    private AutoScanPipeline.AutoScanOptions BuildAutoScanOptions(
        string host,
        AttackSurfaceResult? surface,
        PlaybookRequest request,
        PlaybookDepthProfile depth,
        PlaybookContext ctx,
        int maxStepSeconds,
        bool tightBudget)
    {
        var write = ctx.SafetyMode.AllowsWriteVerbs();
        var options = new AutoScanPipeline.AutoScanOptions
        {
            Host = host,
            PreDiscoveredSurface = surface,
            TargetUrl = request.Scope.TargetUrl,
            TargetMethod = request.Scope.TargetMethod,
            MaxEndpointsPerScanner = tightBudget || _profile == A05ScanProfile.Core || depth.Depth == PlaybookDepth.Llm
                ? Math.Min(3, EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth))
                : EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
            TimeoutMs = Math.Min(maxStepSeconds * 1000, tightBudget || depth.Depth == PlaybookDepth.Llm ? 12000 : 60000),
            ConfirmBackend = ctx.SafetyMode.ToConfirmBackend(),
            ScanDepth = tightBudget || depth.Depth == PlaybookDepth.Llm ? "quick" : depth.AutoScanDepthName,
            PayloadProfile = request.PayloadProfile,
            Budget = ctx.Budget,
            MaxStepSeconds = maxStepSeconds,

            IncludeIdor = false,
            IncludeCsrf = false,
            IncludeMassAssignment = false,
            IncludeSsrf = false,
            IncludeOpenRedirect = false,
            IncludeCacheDeception = false,
            IncludeBflaAdminProbe = false,
            IncludeIdorMutatingProbes = false,
            IncludeSqliLoginSweep = false,
            IncludeDeserializationScan = false,
            IncludeFileUploadScan = false,
            SummarizeFindings = true,
            IncludeChainAnalysis = false,
            FindingsMode = "append"
        };

        switch (_profile)
        {
            case A05ScanProfile.Core:
                options.IncludeSqli = true;
                options.IncludeXss = true;
                options.IncludeXssDom = true;
                options.IncludeXssStored = false;
                options.IncludeSsti = false;
                options.IncludeSstiPolyglot = false;
                options.IncludeSstiStored = false;
                options.IncludeNosql = false;
                options.IncludeLdap = false;
                options.IncludeCmdCanary = true;
                options.IncludePrototypePollution = false;
                options.IncludeParserProbe = false;
                options.IncludeCsti = false;
                options.IncludePathTraversal = false;
                break;

            case A05ScanProfile.Templates:
                options.IncludeSqli = false;
                options.IncludeXss = false;
                options.IncludeXssDom = false;
                options.IncludeXssStored = false;
                options.IncludeSsti = true;
                options.IncludeSstiPolyglot = true;
                options.IncludeSstiStored = write;
                options.IncludeNosql = true;
                options.IncludeLdap = true;
                options.IncludeCmdCanary = false;
                options.IncludePrototypePollution = false;
                options.IncludeParserProbe = false;
                options.IncludeCsti = write ? null : false;
                options.IncludePathTraversal = true;
                break;

            case A05ScanProfile.Advanced:
                options.IncludeSqli = false;
                options.IncludeXss = false;
                options.IncludeXssDom = false;
                options.IncludeXssStored = false;
                options.IncludeSsti = false;
                options.IncludeSstiPolyglot = false;
                options.IncludeSstiStored = false;
                options.IncludeNosql = false;
                options.IncludeLdap = false;
                options.IncludeCmdCanary = false;
                options.IncludePrototypePollution = write;
                options.IncludeParserProbe = write ? null : false;
                options.IncludeCsti = false;
                options.IncludePathTraversal = false;
                break;

            default:
                // Full — LLM-fast shrinks to core scanners when budget/depth is tight.
                options.IncludeSqli = true;
                options.IncludeXss = true;
                options.IncludeXssDom = true;
                options.IncludeXssStored = !tightBudget && write;
                options.IncludeSsti = !tightBudget;
                options.IncludeSstiPolyglot = !tightBudget;
                options.IncludeSstiStored = !tightBudget && write;
                options.IncludeNosql = !tightBudget;
                options.IncludeLdap = !tightBudget;
                options.IncludeCmdCanary = true;
                options.IncludePrototypePollution = !tightBudget && write;
                options.IncludeParserProbe = tightBudget ? false : (write ? null : false);
                options.IncludeCsti = tightBudget ? false : null;
                options.IncludePathTraversal = !tightBudget;
                break;
        }

        return options;
    }

    private List<NextAction> BuildNextActions(
        PlaybookContext ctx, AttackSurfaceResult? surface, PlaybookRequest request)
    {
        var actions = new List<NextAction>();

        bool hasSqli = ctx.Findings.All.Any(f =>
            f.Category is "sqli" or "sqli-login-bypass" or "nosql-injection" or "deferred-injection");
        bool hasXss = ctx.Findings.All.Any(f =>
            f.Category is "xss" or "csti" or "ssti");
        bool hasCmdInjection = ctx.Findings.All.Any(f =>
            f.Category is "cmd-injection" or "command-injection" or "rce-indicator");
        bool hasDeferred = ctx.Findings.All.Any(f => f.Category is "deferred-injection");

        // Pre-filled verify-workflow stubs for the highest-value confirmations.
        foreach (var f in ctx.Findings.All
                     .Where(x => x.Category is "sqli" or "deferred-injection" or "cmd-injection"
                         or "command-injection" or "rce-indicator" or "xss" or "ssti")
                     .Take(6))
        {
            var stub = f.Category switch
            {
                "deferred-injection" => SecurityNextActions.VerifyDeferredInjectionStub(
                    f.Endpoint ?? "", f.Method, "param", null),
                "cmd-injection" or "command-injection" or "rce-indicator" =>
                    SecurityNextActions.VerifyCmdCanaryStub(f.Endpoint ?? "", null, null),
                "xss" or "ssti" => SecurityNextActions.VerifyStoredXssStub(f.Endpoint ?? "", null),
                _ => SecurityNextActions.VerifyDeferredInjectionStub(
                    f.Endpoint ?? "", f.Method ?? "GET", "param", null)
            };
            actions.Add(new NextAction
            {
                Action = "verify-workflow",
                WorkflowId = $"a05-{f.Category}",
                Rationale = $"{f.Title}: {stub}"
            });
        }

        if (hasDeferred && !actions.Any(a => a.WorkflowId == "a05-deferred-injection"))
        {
            actions.Add(new NextAction
            {
                Action = "verify-workflow",
                WorkflowId = "deferred-injection",
                Rationale = "Set-then-read flow suspected — POST payload then GET sibling render page with body-contains oracle."
            });
        }

        // Explicit header/body re-probe templates when surface has non-query sinks.
        if (surface != null)
        {
            foreach (var ep in surface.Endpoints
                         .Where(e => e.Parameters.Headers.Count > 0)
                         .Take(3))
            {
                var header = ep.Parameters.Headers[0];
                actions.Add(new NextAction
                {
                    Action = "manual-check",
                    Rationale =
                        $"Header sink '{header}' on {AttackSurfaceMapper.FormatDisplayUrl(ep)} — " +
                        $"POST /api/security/sqli-scan with request.headers['{header}']='§sqli§' " +
                        "(header sinks are easy to miss when only query params were browsed)."
                });
            }

            foreach (var ep in surface.Endpoints
                         .Where(e => InjectionParamClassifier.LooksLikeTemplateEndpoint(
                             string.IsNullOrEmpty(e.UrlTemplate) ? e.Url : e.UrlTemplate))
                         .Take(2))
            {
                actions.Add(new NextAction
                {
                    Action = "manual-check",
                    Rationale =
                        $"Template-like path {AttackSurfaceMapper.FormatDisplayUrl(ep)} — " +
                        "POST /api/security/ssti-scan with Content-Type text/plain and body=§INJECT§ if auto-scan missed SSTI."
                });
            }
        }

        if (_profile == A05ScanProfile.Core)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05b-injection-templates",
                Rationale = "Core slice done — continue with SSTI/NoSQL/LDAP/path (a05b)."
            });
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05c-injection-advanced",
                Rationale = "After templates, run login-sweep / deser / upload (a05c)."
            });
        }
        else if (_profile == A05ScanProfile.Templates)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05c-injection-advanced",
                Rationale = "Template slice done — continue with login-sweep / deser / upload (a05c)."
            });
        }

        if (hasSqli)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "SQL injection can bypass authentication — test access controls."
            });
        }

        if (hasXss)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "XSS/template injection can steal session tokens — test authentication resilience."
            });
        }

        if (hasCmdInjection)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a11-ssrf",
                Rationale = "Command injection may chain with SSRF for internal network access."
            });
        }

        _ = request; // reserved for scoped nextActions
        return actions;
    }

    private static bool IsInjectableEndpoint(AttackSurfaceEndpoint ep) =>
        ep.Parameters.Query.Count > 0
        || ep.Parameters.Body.Count > 0
        || ep.Parameters.Headers.Count > 0
        || (!string.IsNullOrEmpty(ep.Parameters.RequestBodySample)
            && ep.Parameters.RequestContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
        || InjectionParamClassifier.LooksLikeTemplateEndpoint(
            string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate);

    private static string NormalizeInjectionCategory(string scanner) => scanner.ToLowerInvariant() switch
    {
        "sqli" or "sqli-scan" => "sqli",
        "sqli-login" or "sqli-login-sweep" => "sqli-login-bypass",
        "nosql" or "nosql-scan" => "nosql-injection",
        "ldap" or "ldap-scan" => "ldap-injection",
        "ssti" or "ssti-scan" or "ssti-polyglot" or "ssti-stored" => "ssti",
        "xss" or "xss-scan" or "xss-dom" or "xss-stored" => "xss",
        "csti" or "csti-scan" => "csti",
        "cmd-canary" or "cmd" or "command-injection" or "rce-indicator" => "cmd-injection",
        "deferred-injection" => "deferred-injection",
        "parser-probe" or "parser" => "parser-differential",
        "prototype-pollution" or "proto-pollution" => "prototype-pollution",
        "path-traversal" or "path-traversal-scan" => "path-traversal",
        "deserialization" or "deserialization-scan" => "insecure-deserialization",
        "file-upload" or "file-upload-scan" => "file-upload-bypass",
        _ => scanner.ToLowerInvariant()
    };

    private static string RemediationForCategory(string scanner) => scanner.ToLowerInvariant() switch
    {
        "sqli" or "sqli-scan" or "sqli-login" or "sqli-login-sweep" =>
            "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
        "nosql" or "nosql-scan" =>
            "Sanitize operator keys ($gt, $ne, etc.) in MongoDB queries. Use schema validation.",
        "ldap" or "ldap-scan" =>
            "Escape LDAP special characters in user input. Use parameterized LDAP queries.",
        "ssti" or "ssti-scan" or "ssti-polyglot" or "ssti-stored" =>
            "Use logic-less templates or sandbox template execution. Never pass user input as template source.",
        "csti" or "csti-scan" =>
            "Avoid client-side template interpolation of user input. Use textContent instead of innerHTML.",
        "xss" or "xss-scan" or "xss-dom" or "xss-stored" =>
            "Encode all user input on output (HTML, JS, URL contexts). Use CSP with nonces. Prefer textContent over innerHTML.",
        "cmd-canary" or "cmd" =>
            "Avoid passing user input to shell commands. Use parameterized APIs instead of exec/system calls.",
        "parser-probe" or "parser" =>
            "Enforce strict Content-Type validation. Reject unexpected content types server-side.",
        "prototype-pollution" or "proto-pollution" =>
            "Freeze Object.prototype. Use Map instead of plain objects for user-controlled keys.",
        "path-traversal" or "path-traversal-scan" =>
            "Validate file paths against an allowlist. Use path canonicalization and chroot.",
        "deserialization" or "deserialization-scan" =>
            "Avoid deserializing untrusted data. Use safe formats (JSON) with schema validation.",
        "file-upload" or "file-upload-scan" =>
            "Validate file content-type server-side (magic bytes). Store uploads outside webroot.",
        "cache-map" =>
            CacheMapPresentation.IndicationRemediation,
        _ => "Validate and sanitize all user input. Apply principle of least privilege."
    };

    private static string ReferenceForCategory(string scanner) => scanner.ToLowerInvariant() switch
    {
        "sqli" or "sqli-scan" or "sqli-login" or "sqli-login-sweep" =>
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "ssti" or "ssti-scan" or "ssti-polyglot" or "ssti-stored" =>
            "https://portswigger.net/web-security/server-side-template-injection",
        "cmd-canary" or "cmd" =>
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        "path-traversal" or "path-traversal-scan" =>
            "https://owasp.org/www-community/attacks/Path_Traversal",
        "cache-map" =>
            CacheMapPresentation.IndicationReference,
        _ => "https://owasp.org/Top10/A03_2021-Injection/"
    };
}
