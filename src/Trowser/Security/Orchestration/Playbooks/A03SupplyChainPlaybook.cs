using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A03 Supply Chain: retire.js → third-party → firewall-test SRI-only → source-maps →
/// discover manifests → OSV lookup → deserialization + file-upload (active).
/// </summary>
public sealed class A03SupplyChainPlaybook : IPlaybook
{
    public string Id => "a03-supplychain";
    public string Title => "A03 Supply Chain";
    public string Category => "supply-chain";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "source-maps",
                Description = "Detect exposed source maps and debug artifacts",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "supply-chain-scan",
                Description = "Retire.js CVEs + manifest fetch + OSV lookup + CI/CD exposure + bundle fingerprinting",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Manifest fetch requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "firewall-sri",
                Description = "SRI (Subresource Integrity) validation for third-party scripts",
                HttpVerbs = "none (passive DOM check)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "secrets-harvest",
                Description = "Scan JS bundles, cookies, storage, and network for leaked secrets",
                HttpVerbs = "GET (JS fetch)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "JS fetch requires safe mode" : null
            },
            new DryRunStep
            {
                Name = "deserialization-scan",
                Description = "Test JSON endpoints for insecure deserialization",
                HttpVerbs = "POST, PUT",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "file-upload-scan",
                Description = "Test file upload endpoints for validation bypass and XXE",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        // Step 0: Light crawl to populate network log
        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: Source maps (passive)
        await ctx.RunStepAsync("source-maps", async _ =>
        {
            var result = await ctx.Automation.CheckSourceMaps();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a03-sourcemap-{findingCount}",
                    Source = "orchestrate-a03",
                    Category = "source-maps",
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = f.Description,
                    Endpoint = f.Url ?? await ctx.GetCurrentUrlAsync(),
                    Detail = f.Detail
                });
                findingCount++;
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 2: Supply chain scan (retire.js + manifests + OSV + CI/CD + bundle deps)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("supply-chain-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new SupplyChain.SupplyChainScanOptions
                {
                    IncludeManifestFetch = true,
                    IncludePathFilterBypass = true,
                    IncludeCiCdProbe = true,
                    IncludeBundleDeps = true,
                    IncludeSourceMaps = false, // already scanned above
                    IncludeCveReachability = ctx.SafetyMode.AllowsWriteVerbs(),
                    IncludeRetireOsvCrossCheck = true,
                    MaxOsvPackages = depth.Depth == PlaybookDepth.Quick ? 50 : 200,
                    MaxBundleScripts = depth.Depth == PlaybookDepth.Quick ? 8 : 24,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 30000)
                };

                var result = await ctx.Automation.RunSupplyChainScan(options, innerCt);
                int findingCount = 0;

                // Use the pre-built ChainFindings if available
                if (result.ChainFindings is { Count: > 0 })
                {
                    foreach (var f in result.ChainFindings)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a03-sc-{findingCount}",
                            Source = "orchestrate-a03",
                            Category = f.Category,
                            Severity = f.Severity,
                            Title = f.Title,
                            Endpoint = f.Endpoint,
                            Method = f.Method,
                            Parameter = f.Parameter,
                            Detail = f.Detail,
                            Evidence = f.Evidence,
                            Tags = f.Tags
                        });
                        findingCount++;
                    }
                }
                else
                {
                    foreach (var f in result.Findings)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a03-sc-{findingCount}",
                            Source = "orchestrate-a03",
                            Category = f.Category,
                            Severity = f.Severity,
                            Title = f.Title,
                            Endpoint = f.Endpoint,
                            Method = f.Method,
                            Detail = f.Detail,
                            Evidence = f.Evidence,
                            Tags = f.Tags
                        });
                        findingCount++;
                    }
                }

                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["manifests"] = result.ManifestCount,
                    ["declaredDeps"] = result.DeclaredDependencyCount,
                    ["vulnerableDeclared"] = result.VulnerableDeclaredCount,
                    ["retireVulnerable"] = result.RetireVulnerableCount,
                    ["cicdExposed"] = result.CiCdExposureCount,
                    ["missingSri"] = result.MissingSriExternalCount
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("supply-chain-scan",
                $"Manifest/OSV fetch requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3: Firewall/SRI check (passive DOM check)
        await ctx.RunStepAsync("firewall-sri", async _ =>
        {
            var result = await ctx.Automation.RunFirewallTest(["sri"]);
            int findingCount = 0;
            if (result.Sri is { Verdict: "bypassed" or "absent" })
            {
                foreach (var test in result.Sri.Tests.Where(t => t.Result == "bypassed"))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a03-sri-{findingCount}",
                        Source = "orchestrate-a03",
                        Category = "missing-sri",
                        Severity = test.Severity?.ToString()?.ToLowerInvariant() ?? "medium",
                        Title = $"SRI bypass: {test.Technique}",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = test.Detail
                    });
                    findingCount++;
                }
                if (findingCount == 0)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = "a03-sri-absent",
                        Source = "orchestrate-a03",
                        Category = "missing-sri",
                        Severity = "medium",
                        Title = "SRI not configured for third-party scripts",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = $"SRI verdict: {result.Sri.Verdict}"
                    });
                    findingCount = 1;
                }
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 4: Secrets harvest (requires probes for JS fetch)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("secrets-harvest", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunSecretsHarvest(
                    includeJsBundles: true,
                    includeCookiesAndStorage: true,
                    includeNetworkResponses: true,
                    includePageText: true,
                    includeSourceMaps: false);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a03-secret-{findingCount}",
                        Source = "orchestrate-a03",
                        Category = f.Category is { Length: > 0 } ? f.Category : "credential-exposure",
                        Severity = f.Severity,
                        Title = f.Description,
                        Endpoint = f.Location,
                        Detail = f.Snippet
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("secrets-harvest",
                $"JS bundle fetch requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 5: Deserialization scan (active only — via AutoScanPipeline)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("deserialization-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new AutoScanPipeline.AutoScanOptions
                {
                    Host = host,
                    MaxEndpointsPerScanner = depth.MaxEndpointsPerScanner,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 20000),
                    ConfirmBackend = true,
                    ScanDepth = depth.AutoScanDepthName,
                    PayloadProfile = request.PayloadProfile,

                    IncludeDeserializationScan = true,
                    IncludeFileUploadScan = true,

                    IncludeSqli = false,
                    IncludeIdor = false,
                    IncludeCsrf = false,
                    IncludePathTraversal = false,
                    IncludeSsrf = false,
                    IncludeOpenRedirect = false,
                    IncludeCacheDeception = false,
                    IncludeSsti = false,
                    IncludeCmdCanary = false,
                    IncludeNosql = false,
                    IncludeLdap = false,
                    IncludeSstiPolyglot = false,
                    IncludeSstiStored = false,
                    IncludePrototypePollution = false,
                    IncludeSqliLoginSweep = false,
                    IncludeMassAssignment = false,

                    SummarizeFindings = false,
                    IncludeChainAnalysis = false,
                    FindingsMode = "append"
                };

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a03-deser-{findingCount}",
                        Source = "orchestrate-a03",
                        Category = f.Scanner.ToLowerInvariant(),
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("deserialization-scan",
                $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
            ctx.SkipStep("file-upload-scan",
                $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
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

        bool hasCredentials = ctx.Findings.All.Any(f => f.Category == "credential-exposure");
        bool hasDeser = ctx.Findings.All.Any(f =>
            f.Category is "deserialization-suspected" or "content-type-confusion");

        if (hasCredentials)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "Leaked credentials need crypto/token analysis."
            });
        }

        if (hasDeser)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05-injection",
                Rationale = "Deserialization findings may lead to RCE via injection chains."
            });
        }

        return actions;
    }
}
