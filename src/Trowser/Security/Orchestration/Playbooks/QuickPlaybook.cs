using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.GadgetChains;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// LLM-optimized quick sweep (~60–120s): recon, misconfiguration, access control, injection (safe),
/// and federation decode when SAML/OIDC traffic is present. Skips logout side-effects and heavy tiers.
/// </summary>
public sealed class QuickPlaybook : IPlaybook
{
    public string Id => "quick";
    public string Title => "Quick Site Security";
    public string Category => "quick-assessment";

    private static readonly string[] CoreChildPlaybooks = ["a02-misconfig", "a01-access", "a05-injection"];

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        var steps = new List<DryRunStep>
        {
            PlaybookDryRun.CrawlLight(request, Math.Min(depth.MaxCrawlPages, 5), shared: true),
            new DryRunStep
            {
                Name = "attack-surface",
                Description = "Passive network-log analysis — endpoint map for LLM triage",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "client-surface",
                Description = "Client-side attack surface (runtime sinks, listeners, DOM facts)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "dom-xss-audit",
                Description = "DOM XSS audit: passive patterns, dom-flow probe, trace-input on URL query/hash (reach-only unless aggressive)",
                HttpVerbs = "GET (navigation + injection probes)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "DOM XSS audit requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "firewall-test",
                Description = "CSP/SRI/sandbox/Permissions-Policy bypass probes (in-page)",
                HttpVerbs = "none (local)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "postmessage",
                Description = "postMessage listener audit and safe fuzz",
                HttpVerbs = "none (synthetic events)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "csti-scan",
                Description = "Client-side template injection — quick probe on discovered URL params",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "client-prototype-pollution",
                Description = "URL/hash/postMessage PP canaries + js-audit application gadgets",
                HttpVerbs = "GET",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode (mutates Object.prototype)" : null
            },
            new DryRunStep
            {
                Name = "gadget-chains",
                Description = "Runtime gadget radar + tailored clobber/client-PP/dom-flow probes",
                HttpVerbs = "GET",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "trace-input",
                Description = "Light url-query trace with monitorSinks on current page",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            }
        };

        foreach (var id in CoreChildPlaybooks)
        {
            steps.Add(new DryRunStep
            {
                Name = $"playbook-{id}",
                Description = $"Quick tier: {id}",
                HttpVerbs = "varies",
                WritesSideEffects = id != "a02-misconfig"
            });
        }

        steps.Add(new DryRunStep
        {
            Name = "federation-decode",
            Description = "SAML/OIDC decode when federation traffic exists in the network log",
            HttpVerbs = "none (passive)",
            WritesSideEffects = false
        });

        steps.Add(new DryRunStep
        {
            Name = "playbook-a07-authn",
            Description = "Authentication deep-dive (includes logout probe — mutates session)",
            HttpVerbs = "varies",
            WritesSideEffects = true,
            SkippedByCurrentSafetyMode = true,
            SkipReason = "Skipped in quick preset — run POST /api/orchestrate/a07-authn when auth testing is needed"
        });

        return steps;
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);

        ctx.Warnings.Add(
            "Quick preset: ~90–180s LLM bundle (attack-surface + client-surface/DOM/CSTI/PP + A02 + A01 + A05 safe + federation). " +
            "For logout/session-fixation testing run a07-authn separately — it terminates the session.");

        await ctx.RunCrawlStepAsync(host, ct);

        await ctx.RunStepAsync("attack-surface", async _ =>
        {
            var surface = ctx.Automation.CheckAttackSurface(includeParameters: true, hostFilter: host);
            return new Dictionary<string, object?>
            {
                ["endpoints"] = surface.Endpoints.Count,
                ["highPriority"] = surface.Summary.HighPriority,
                ["authenticated"] = surface.Summary.Authenticated
            };
        }, ct);

        await ctx.RunStepAsync("client-surface", async _ =>
        {
            var map = await ctx.Automation.MapClientSurfaceAsync(installSensor: true, waitMs: 350);
            return new Dictionary<string, object?>
            {
                ["sinks"] = map.Sinks.Count,
                ["listeners"] = map.Listeners.Count,
                ["cells"] = map.Cells.Count
            };
        }, ct);

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("dom-xss-audit", async innerCt =>
            {
                innerCt.ThrowIfCancellationRequested();
                var plan = DomXssAuditRunner.DomXssAuditDepthPlan.ForDepth(SecurityScanDepth.Standard);
                var audit = await ctx.Automation.RunDomXssAuditAsync(
                    DomXssAuditRunner.ResolveOptions(
                        plan with { RunDomFlowProbe = ctx.SafetyMode.AllowsWriteVerbs() },
                        confirmExecution: ctx.SafetyMode >= SafetyMode.Aggressive,
                        maxSecondsOverride: 0,
                        runClientSurface: null,
                        runPassiveXss: null,
                        runDomFlowProbe: null,
                        runTraceInput: null,
                        probeAllUrlParams: null,
                        probeUrlHash: null,
                        runScriptGatedTraces: null,
                        fireEvents: null,
                        timeoutMs: null),
                    innerCt);
                return new Dictionary<string, object?>
                {
                    ["findings"] = audit.Findings.Count,
                    ["executionConfirmed"] = audit.ExecutionConfirmed,
                    ["worstSeverity"] = audit.WorstSeverity.ToString().ToLowerInvariant(),
                    ["exploitableDomFlows"] = audit.DomFlows?.ExploitableChainCount ?? 0
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("dom-xss-audit", "DOM XSS audit requires at least safe mode");
        }

        await ctx.RunStepAsync("firewall-test", async _ =>
        {
            var fw = await ctx.Automation.RunFirewallTest();
            return new Dictionary<string, object?>
            {
                ["verdict"] = fw.OverallVerdict,
                ["ineffective"] = fw.DefensesIneffective
            };
        }, ct);

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("postmessage", async _ =>
            {
                var pm = await ctx.Automation.AuditPostMessageAsync(ctx.SafetyMode.ToLabel(), fuzz: true, maxPayloads: 6);
                return new Dictionary<string, object?>
                {
                    ["listeners"] = pm.Listeners.Count,
                    ["findings"] = pm.Findings.Count
                };
            }, ct);

            await ctx.RunStepAsync("csti-scan", async innerCt =>
            {
                innerCt.ThrowIfCancellationRequested();
                var batch = await ctx.Automation.RunCstiScan(new CstiScanRunner.CstiScanOptions
                {
                    Escalate = false,
                    MonitorSinks = true,
                    MaxCandidates = 4,
                    TimeoutMs = 6000
                }, innerCt);
                return new Dictionary<string, object?>
                {
                    ["candidates"] = batch.CandidatesProbed,
                    ["findings"] = batch.Findings.Count
                };
            }, ct);

            ctx.SkipStep("trace-input", "Covered by dom-xss-audit step (url-query + url-hash trace-input)");
        }
        else
        {
            ctx.SkipStep("postmessage", "Requires at least safe mode");
            ctx.SkipStep("csti-scan", "Requires at least safe mode");
            ctx.SkipStep("trace-input", "Requires at least safe mode");
        }

        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("client-prototype-pollution", async _ =>
            {
                var pp = await ctx.Automation.ScanClientPrototypePollutionAsync(tryGadgets: true);
                return new Dictionary<string, object?>
                {
                    ["findings"] = pp.Findings.Count,
                    ["gadgetHits"] = pp.GadgetHits.Count(h => h.SinkReached)
                };
            }, ct);

            await ctx.RunStepAsync("gadget-chains", async _ =>
            {
                var gc = await ctx.Automation.RunGadgetChainsAsync(
                    new GadgetChainScanner.GadgetChainOptions { IncludeRadar = true },
                    "active");
                return new Dictionary<string, object?>
                {
                    ["findings"] = gc.Findings.Count,
                    ["radarHits"] = gc.RadarHits.Count
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("client-prototype-pollution", "Requires active mode (mutates Object.prototype)");
            ctx.SkipStep("gadget-chains", "Requires active mode");
        }

        var registry = new PlaybookRegistry();
        var childRequest = request.WithCrawlDisabled();

        foreach (var id in CoreChildPlaybooks)
        {
            if (ctx.Budget.IsExhausted)
            {
                ctx.SkipStep($"playbook-{id}", "Budget exhausted");
                continue;
            }

            var playbook = registry.Get(id);
            if (playbook == null)
            {
                ctx.SkipStep($"playbook-{id}", $"Playbook '{id}' not found");
                continue;
            }

            await ctx.RunStepAsync($"playbook-{id}", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var child = await playbook.RunAsync(ctx, childRequest, innerCt);
                return new Dictionary<string, object?>
                {
                    ["playbookId"] = id,
                    ["steps"] = child.StepsExecuted?.Count ?? 0,
                    ["warnings"] = child.Warnings?.Count ?? 0
                };
            }, ct);
        }

        await ctx.RunStepAsync("federation-decode", async _ =>
        {
            var hasSaml = ctx.Automation.Network.Entries.Any(e =>
                (e.Url ?? "").Contains("SAML", StringComparison.OrdinalIgnoreCase)
                || (e.RequestBody ?? "").Contains("SAMLResponse", StringComparison.OrdinalIgnoreCase));
            var hasOidc = ctx.Automation.Network.Entries.Any(e =>
                (e.Url ?? "").Contains(".well-known/openid", StringComparison.OrdinalIgnoreCase)
                || (e.Url ?? "").Contains("/oauth/", StringComparison.OrdinalIgnoreCase));

            if (!hasSaml && !hasOidc)
                return new Dictionary<string, object?> { ["skipped"] = true, ["reason"] = "No federation traffic" };

            var messages = 0;
            if (hasSaml)
            {
                try
                {
                    var results = SamlDecoder.DecodeAllFromNetwork(ctx.Automation.Network);
                    messages = results.Count(r => r.Success);
                }
                catch
                {
                    // best-effort
                }
            }

            return new Dictionary<string, object?>
            {
                ["samlMessages"] = messages,
                ["oidcDetected"] = hasOidc
            };
        }, ct);

        ctx.SkipStep("playbook-a07-authn",
            "Skipped in quick preset — run a07-authn for logout/session-fixation (terminates session)");

        var nextActions = new List<NextAction>
        {
            new()
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Quick preset skipped authn logout/session-fixation — run when session testing is needed."
            }
        };

        if (ctx.Findings.All.Any(f => f.Severity is "high" or "critical"))
        {
            nextActions.Add(new NextAction
            {
                Action = "investigate",
                Rationale = "Validate HIGH findings manually before treating as confirmed vulnerabilities."
            });
        }

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
            NextActions = nextActions
        };
    }
}
