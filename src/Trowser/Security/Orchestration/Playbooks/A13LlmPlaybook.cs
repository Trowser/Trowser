using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A13 AI &amp; LLM: discover → corpus red-team (LLM01–03 + LLM05–07 + LLM09) →
/// RAG/memory poison (LLM04/08) → unbounded consumption (LLM10) → output→sink trace.
/// Application-layer OWASP LLM Top 10 coverage; training-time risks out of scope.
/// </summary>
public sealed class A13LlmPlaybook : IPlaybook
{
    public string Id => "a13-llm";
    public string Title => "A13 AI & LLM";
    public string Category => "ai-llm";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(
                request,
                depth.MaxCrawlPages,
                description: "BFS crawl within scope.host to populate network log and discover LLM/chat endpoints"),
            new DryRunStep
            {
                Name = "llm-discover",
                Description = "Discover chat endpoints from network log and chat UI widgets from DOM",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "llm-redteam",
                Description = "OWASP LLM application subset: prompt injection, disclosure, output handling, agency, misinformation (corpus + WebMCP)",
                HttpVerbs = "POST (to LLM endpoints)",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Red-team probes require active mode (sends prompts to LLM)" : null
            },
            new DryRunStep
            {
                Name = "rag-poison",
                Description = "LLM04/LLM08: RAG/memory poison persistence + optional peer embedding isolation",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "unbounded-consumption",
                Description = "LLM10: prompt flood, oversized prompt, max-output, tool-loop on LLM surfaces",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "output-sink-trace",
                Description = "Trace LLM output to dangerous DOM sinks (innerHTML, eval) to confirm prompt injection → XSS chain",
                HttpVerbs = "POST (to LLM endpoints)",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode (sends probes to LLM)" : null
            }
        ];
    }

    public async Task<PlaybookResponse> RunAsync(PlaybookContext ctx, PlaybookRequest request, CancellationToken ct)
    {
        var startedAt = DateTime.UtcNow;
        var host = await ctx.ResolveHostAsync(request.Scope);
        var depth = ctx.DepthProfile;

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: LLM endpoint discovery (passive)
        LlmSurfaceSummary? surface = null;
        await ctx.RunStepAsync("llm-discover", async _ =>
        {
            surface = await ctx.Automation.RunLlmEndpointDiscover(ct);
            return new Dictionary<string, object?>
            {
                ["chatEndpoints"] = surface.ChatEndpointCount,
                ["chatWidgets"] = surface.ChatWidgetCount,
                ["webMcpTools"] = surface.WebMcpToolCount,
                ["iframeCopilots"] = surface.IframeCopilotCount,
                ["hasAiIntegration"] = surface.HasAiIntegration
            };
        }, ct);

        if (surface is not { HasAiIntegration: true })
        {
            ctx.Warnings.Add("No AI/LLM integration detected on this page. Skipping red-team probes.");
            ctx.SkipStep("llm-redteam", "No LLM endpoints or chat widgets found");
            ctx.SkipStep("rag-poison", "No LLM endpoints or chat widgets found");
            ctx.SkipStep("unbounded-consumption", "No LLM endpoints or chat widgets found");
            ctx.SkipStep("output-sink-trace", "No LLM endpoints or chat widgets found");
        }
        else
        {
            // Step 2: LLM red-team scan (active — sends prompts)
            if (ctx.SafetyMode.AllowsWriteVerbs())
            {
                await ctx.RunStepAsync("llm-redteam", async innerCt =>
                {
                    ctx.Budget.ThrowIfExhausted(innerCt);
                    var maxProbes = depth.Depth switch
                    {
                        PlaybookDepth.Quick => 8,
                        PlaybookDepth.Deep => 40,
                        _ => 28
                    };

                    // Prefer HTTP assist path — chat-UI burns budget when Typing… sticks.
                    var result = await ctx.Automation.RunLlmRedTeamScan(
                        new LlmRedTeamScanOptions
                        {
                            Mode = depth.Depth == PlaybookDepth.Quick ? "http" : "auto",
                            Preset = depth.Depth == PlaybookDepth.Quick ? "smoke" : null,
                            MaxProbes = maxProbes,
                            Concurrency = 2,
                            TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 60000),
                            ProbeDelayMs = depth.Depth == PlaybookDepth.Quick ? 400 : 1000,
                            IncludeWebMcpAbuse = true,
                            IncludeIndirectInjection = false,
                            IncludeUnboundedConsumption = false,
                            IncludeRagPoison = false,
                            RegisterWhisperHints = true
                        }, innerCt);

                    int findingCount = 0;

                    foreach (var r in result.Results.Where(r => r.Fired))
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a13-llm-{findingCount}",
                            Source = "orchestrate-a13",
                            Category = NormalizeLlmCategory(r.Category),
                            Severity = r.Severity,
                            Title = $"LLM {r.Category}: {r.ProbeId}",
                            Endpoint = r.TargetUrl ?? await ctx.GetCurrentUrlAsync(),
                            Detail = $"Confidence: {r.Confidence}. Matched: {r.Matched}. {r.Rationale}",
                            Evidence = r.ResponseExcerpt.Length > 500
                                ? r.ResponseExcerpt[..500] + "..."
                                : r.ResponseExcerpt,
                            Remediation = RemediationForLlmCategory(r.Category),
                            Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                        });
                        findingCount++;
                    }

                    foreach (var f in result.WebMcpAbuseFindings)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a13-mcp-{findingCount}",
                            Source = "orchestrate-a13",
                            Category = "web-mcp-abuse",
                            Severity = f.Severity,
                            Title = $"Web MCP tool abuse: {f.ToolName} ({f.PayloadKind})",
                            Endpoint = await ctx.GetCurrentUrlAsync(),
                            Detail = f.Detail,
                            Evidence = f.ArgumentJson,
                            Remediation = "Validate and sandbox MCP tool inputs. Apply least-privilege to tool permissions.",
                            Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                        });
                        findingCount++;
                    }

                    ctx.Budget.AddRequests(result.TotalProbes);
                    var probesCompleted = result.Results.Count(r => string.IsNullOrEmpty(r.Error));
                    var schemaFailed = result.Warnings.Any(w =>
                        w.Contains("body", StringComparison.OrdinalIgnoreCase)
                        || w.Contains("schema", StringComparison.OrdinalIgnoreCase)
                        || w.Contains("customBody", StringComparison.OrdinalIgnoreCase));
                    var metrics = new Dictionary<string, object?>
                    {
                        ["findings"] = findingCount,
                        ["probesFired"] = result.FiredCount,
                        ["probesCompleted"] = probesCompleted,
                        ["totalProbes"] = result.TotalProbes,
                        ["transport"] = result.Transport,
                        ["coverage"] = result.Coverage,
                        ["warnings"] = result.Warnings
                    };

                    if (result.TotalProbes > 0 && probesCompleted == 0)
                    {
                        metrics["_stepStatus"] = "degraded";
                        metrics["_stepReason"] = schemaFailed
                            ? "Could not build or send HTTP probe bodies (check requestBodySample / schema)."
                            : "0 probes completed successfully — transport or schema likely wrong.";
                        ctx.Warnings.Add(
                            $"llm-redteam degraded: 0/{result.TotalProbes} probes completed. "
                            + (schemaFailed
                                ? "Could not build HTTP body from sample — prefer customBodyJson matching the observed request shape."
                                : "Check httpTarget schema / chat selectors."));
                    }
                    else if (result.Warnings.Count > 0 && result.FiredCount == 0 && probesCompleted < Math.Max(1, result.TotalProbes / 2))
                    {
                        metrics["_stepStatus"] = "degraded";
                        metrics["_stepReason"] = result.Warnings[0];
                        foreach (var w in result.Warnings.Take(3))
                            ctx.Warnings.Add($"llm-redteam: {w}");
                    }

                    return metrics;
                }, ct);
            }
            else
            {
                ctx.SkipStep("llm-redteam", $"Red-team probes require active mode (current: {ctx.SafetyMode.ToLabel()})");
            }

            // Step 3: RAG / memory poison (LLM04) + optional peer isolation (LLM08)
            if (ctx.SafetyMode.AllowsWriteVerbs())
            {
                await ctx.RunStepAsync("rag-poison", async innerCt =>
                {
                    ctx.Budget.ThrowIfExhausted(innerCt);
                    var result = await ctx.Automation.RunLlmRedTeamScan(
                        new LlmRedTeamScanOptions
                        {
                            Mode = "auto",
                            MaxProbes = 0,
                            TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 45000),
                            IncludeWebMcpAbuse = false,
                            IncludeIndirectInjection = false,
                            IncludeRagPoison = true,
                            RegisterWhisperHints = true
                        }, innerCt);

                    int findingCount = 0;
                    foreach (var r in result.Results.Where(r => r.Fired))
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a13-rag-{findingCount}",
                            Source = "orchestrate-a13",
                            Category = NormalizeLlmCategory(r.Category),
                            Severity = r.Severity,
                            Title = $"LLM {r.Category}: {r.ProbeId}",
                            Endpoint = await ctx.GetCurrentUrlAsync(),
                            Detail = r.Rationale,
                            Evidence = r.ResponseExcerpt,
                            Remediation = RemediationForLlmCategory(r.Category),
                            Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                        });
                        findingCount++;
                    }

                    if (result.IndirectInjection is { InjectionObserved: true } indirect && findingCount == 0)
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a13-indirect-{findingCount}",
                            Source = "orchestrate-a13",
                            Category = "indirect-prompt-injection",
                            Severity = "high",
                            Title = "Indirect prompt injection confirmed",
                            Endpoint = await ctx.GetCurrentUrlAsync(),
                            Detail = indirect.Detail,
                            Evidence = indirect.ResponseExcerpt,
                            Remediation = "Sanitize and isolate external content before feeding to LLM. Use content boundaries and instruction hierarchies.",
                            Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                        });
                        findingCount++;
                    }

                    return new Dictionary<string, object?>
                    {
                        ["findings"] = findingCount,
                        ["attempted"] = result.RagPoison?.Attempted ?? result.IndirectInjection?.Attempted ?? false,
                        ["persistenceObserved"] = result.RagPoison?.PersistenceObserved ?? false,
                        ["crossTenantLeak"] = result.RagPoison?.CrossTenantLeakObserved ?? false
                    };
                }, ct);
            }
            else
            {
                ctx.SkipStep("rag-poison", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
            }

            // Step 4: LLM10 unbounded consumption (skipped at quick depth)
            if (ctx.SafetyMode.AllowsWriteVerbs() && depth.Depth != PlaybookDepth.Quick)
            {
                await ctx.RunStepAsync("unbounded-consumption", async innerCt =>
                {
                    ctx.Budget.ThrowIfExhausted(innerCt);
                    var result = await ctx.Automation.RunLlmRedTeamScan(
                        new LlmRedTeamScanOptions
                        {
                            Mode = "auto",
                            MaxProbes = 0,
                            TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 45000),
                            IncludeWebMcpAbuse = false,
                            IncludeUnboundedConsumption = true,
                            RegisterWhisperHints = true
                        }, innerCt);

                    int findingCount = 0;
                    foreach (var u in result.UnboundedConsumptionFindings.Where(f => f.Fired))
                    {
                        ctx.Findings.Add(new ChainableFinding
                        {
                            Id = $"a13-llm10-{findingCount}",
                            Source = "orchestrate-a13",
                            Category = "llm-unbounded-consumption",
                            Severity = u.Severity,
                            Title = $"LLM10 Unbounded Consumption: {u.ProbeId}",
                            Endpoint = u.TargetUrl ?? await ctx.GetCurrentUrlAsync(),
                            Detail = u.Detail,
                            Evidence = u.Evidence?.ToString() ?? "",
                            Remediation = "Enforce rate limits, max input/output tokens, timeouts, and tool-call circuit breakers on LLM endpoints.",
                            Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                        });
                        findingCount++;
                    }

                    return new Dictionary<string, object?>
                    {
                        ["findings"] = findingCount,
                        ["probes"] = result.UnboundedConsumptionFindings.Count
                    };
                }, ct);
            }
            else if (depth.Depth == PlaybookDepth.Quick)
            {
                ctx.SkipStep("unbounded-consumption", "Skipped at depth=quick (enable standard/deep)");
            }
            else
            {
                ctx.SkipStep("unbounded-consumption", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
            }

            // Step 5: Output-to-sink tracing (proves prompt injection → XSS/code-exec)
            if (ctx.SafetyMode.AllowsWriteVerbs())
            {
                var hasLlmFindings = ctx.Findings.All.Any(f =>
                    f.Category is "prompt-injection" or "jailbreak" or "data-exfiltration"
                        or "sensitive-disclosure" or "web-mcp-abuse"
                        or "llm04_data_and_model_poisoning" or "llm08_vector_and_embedding_weaknesses"
                        or "indirect-prompt-injection");

                if (hasLlmFindings || surface is { HasAiIntegration: true })
                {
                    await ctx.RunStepAsync("output-sink-trace", async innerCt =>
                    {
                        ctx.Budget.ThrowIfExhausted(innerCt);
                        var tracer = new LlmRedTeam.LlmOutputSinkTracer(ctx.Automation, (msg, _) => ctx.Warnings.Add(msg));
                        var result = await tracer.RunAsync(new LlmRedTeam.LlmOutputSinkTracer.SinkTraceOptions
                        {
                            MaxProbes = depth.Depth switch
                            {
                                PlaybookDepth.Quick => 4,
                                PlaybookDepth.Deep => 8,
                                _ => 6
                            },
                            ProbeDelayMs = 1500,
                            TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                            Sinks = LlmRedTeam.LlmOutputSinkTracer.SinkSet.All,
                            IncludeDomRenderCheck = true
                        }, innerCt);

                        int findingCount = 0;
                        foreach (var f in result.Findings)
                        {
                            var isConfirmedSinkHit = f.SinkType != "dom-render";
                            ctx.Findings.Add(new ChainableFinding
                            {
                                Id = $"a13-sinktrace-{findingCount}",
                                Source = "orchestrate-a13",
                                Category = f.Category,
                                Severity = isConfirmedSinkHit ? "critical" : "medium",
                                Title = isConfirmedSinkHit
                                    ? $"LLM output→{f.SinkType}: confirmed injection-to-XSS chain"
                                    : $"LLM output rendered in DOM (potential XSS via {f.SinkType})",
                                Endpoint = await ctx.GetCurrentUrlAsync(),
                                Detail = f.Detail,
                                Evidence = f.Evidence,
                                Remediation = isConfirmedSinkHit
                                    ? "Sanitize all LLM output before rendering in DOM. Use textContent instead of innerHTML. Apply CSP with no unsafe-inline/unsafe-eval."
                                    : "LLM output appears in DOM but did not reach an instrumented dangerous sink. Verify manually whether output is rendered as executable HTML or escaped text. Use textContent instead of innerHTML.",
                                Reference = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                            });
                            findingCount++;
                        }
                        ctx.Budget.AddRequests(result.ProbesFired);
                        return new Dictionary<string, object?>
                        {
                            ["findings"] = findingCount,
                            ["probesFired"] = result.ProbesFired,
                            ["sinksInstrumented"] = result.SinksInstrumented,
                            ["canariesReachedSink"] = result.CanariesReachedSink,
                            ["canariesRenderedInDom"] = result.CanariesRenderedInDom
                        };
                    }, ct);
                }
                else
                {
                    ctx.SkipStep("output-sink-trace", "No LLM findings or AI integration to trace");
                }
            }
            else
            {
                ctx.SkipStep("output-sink-trace", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
            }
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

        foreach (var step in ctx.Steps.Where(s =>
                     s.Status is "skipped" or "budget-exhausted" or "degraded" or "error"))
        {
            var followUp = step.Name switch
            {
                "llm-redteam" =>
                    "POST /api/security/llm-redteam-scan {\"safetyMode\":\"active\",\"mode\":\"http\",\"preset\":\"smoke\"} — or pass suggestedHttpTarget from llm-endpoint-discover",
                "rag-poison" =>
                    "POST /api/security/llm-redteam-scan {\"safetyMode\":\"active\",\"mode\":\"http\",\"maxProbes\":0,\"includeRagPoison\":true}",
                "unbounded-consumption" =>
                    "POST /api/security/llm-redteam-scan {\"safetyMode\":\"active\",\"mode\":\"http\",\"maxProbes\":0,\"includeUnboundedConsumption\":true}",
                "output-sink-trace" =>
                    "POST /api/security/llm-output-sink-trace {\"safetyMode\":\"active\"} after a successful HTTP prompt, or use llm-sink-assist",
                _ => $"Re-run playbook step '{step.Name}' with a higher budget or via the dedicated security API."
            };
            actions.Add(new NextAction
            {
                Action = "manual-check",
                Rationale = $"Step '{step.Name}' ended as {step.Status}"
                            + (string.IsNullOrWhiteSpace(step.Reason) ? "" : $": {step.Reason}")
                            + $". Follow-up: {followUp}"
            });
        }

        if (ctx.Findings.All.Any(f =>
            f.Category is "prompt-injection" or "indirect-prompt-injection" or "jailbreak"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05-injection",
                Rationale = "Prompt injection may chain with server-side injection if LLM output is used in queries/commands."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category is "data-exfiltration" or "sensitive-disclosure"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "LLM data exfiltration may expose secrets — test for credential exposure."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category == "web-mcp-abuse"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "Web MCP tool abuse may enable unauthorized access to protected resources."
            });
        }

        if (actions.Count == 0)
        {
            actions.Add(new NextAction
            {
                Action = "manual-check",
                Rationale =
                    "Warm-up complete. DIY next: llm-endpoint-discover → copy suggestedHttpTarget → llm-http-send / llm-redteam-scan mode=http."
            });
        }

        return actions;
    }

    private static string NormalizeLlmCategory(string category)
    {
        var c = category.ToLowerInvariant();
        if (c.StartsWith("llm01") || c is "prompt-injection" or "prompt_injection") return "prompt-injection";
        if (c is "jailbreak") return "jailbreak";
        if (c.StartsWith("llm02") || c is "data-exfiltration" or "data_exfiltration" or "sensitive-disclosure")
            return "data-exfiltration";
        if (c.StartsWith("llm03")) return "llm-supply-chain";
        if (c.StartsWith("llm04") || c.Contains("poison")) return "llm-data-poisoning";
        if (c.StartsWith("llm05") || c is "insecure-output" or "insecure_output") return "insecure-llm-output";
        if (c.StartsWith("llm06") || c is "tool-abuse" or "tool_abuse" or "excessive-agency") return "excessive-agency";
        if (c.StartsWith("llm07")) return "system-prompt-leakage";
        if (c.StartsWith("llm08") || c.Contains("embedding")) return "llm-embedding-weakness";
        if (c.StartsWith("llm09") || c is "hallucination" or "overreliance" or "misinformation") return "llm-misinformation";
        if (c.StartsWith("llm10") || c is "denial-of-service" or "dos" or "llm-unbounded-consumption")
            return "llm-unbounded-consumption";
        if (c is "model-theft" or "model_theft") return "model-theft";
        return c;
    }

    private static string RemediationForLlmCategory(string category)
    {
        var n = NormalizeLlmCategory(category);
        return n switch
        {
            "prompt-injection" =>
                "Implement input filtering and prompt hardening. Use system prompts with clear boundaries.",
            "jailbreak" =>
                "Strengthen system prompts. Implement output filtering and content safety classifiers.",
            "data-exfiltration" =>
                "Restrict LLM access to sensitive data. Implement output filtering for PII/secrets.",
            "excessive-agency" =>
                "Apply least-privilege to LLM tool access. Require human approval for sensitive actions.",
            "llm-data-poisoning" =>
                "Isolate and sanitize documents before RAG ingest. Segment tenant vector stores; re-validate retrieved context.",
            "llm-embedding-weakness" =>
                "Enforce per-tenant vector ACLs. Prevent cross-tenant retrieval and embedding inversion exposure.",
            "llm-misinformation" =>
                "Require grounded citations; refuse unknown DOIs/URLs/CVEs; add retrieval grounding checks.",
            "llm-unbounded-consumption" =>
                "Enforce rate limits, max input/output tokens, timeouts, and tool-call circuit breakers.",
            "insecure-llm-output" =>
                "Sanitize LLM output before rendering or executing; never pass model text to sinks unsafely.",
            "system-prompt-leakage" =>
                "Minimize secrets in system prompts; detect and block extraction patterns.",
            _ => "Follow OWASP LLM Top 10 guidelines. Implement defense-in-depth for AI integrations."
        };
    }
}
