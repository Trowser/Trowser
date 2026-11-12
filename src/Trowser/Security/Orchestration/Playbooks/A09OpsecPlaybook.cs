using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A09 Operational Security: fail-open → missing-parameter → console error harvest →
/// network error harvest → source maps (debug mode). Detects information leakage
/// via error handling, stack traces, debug output, and verbose error responses.
/// </summary>
public sealed class A09OpsecPlaybook : IPlaybook
{
    public string Id => "a09-opsec";
    public string Title => "A09 Operational Security";
    public string Category => "operational-security";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(
                request,
                depth.MaxCrawlPages,
                description: $"BFS crawl within scope.host to populate network log and trigger errors (max {depth.MaxCrawlPages} pages)"),
            new DryRunStep
            {
                Name = "attack-surface",
                Description = "Analyze network log to discover API endpoints (feeds POST URLs to downstream steps)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "fail-open",
                Description = "Probe endpoints with missing/invalid auth to detect verbose error responses",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires at least safe mode" : null
            },
            new DryRunStep
            {
                Name = "missing-parameter",
                Description = "Omit required fields to trigger server-side exceptions and stack traces",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "console-error-harvest",
                Description = "Analyze browser console for JavaScript errors, stack traces, and debug output",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "network-error-harvest",
                Description = "Analyze network log for 4xx/5xx responses, error bodies, and leaked stack traces",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "source-maps-debug",
                Description = "Detect exposed source maps and framework debug mode indicators",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "security-headers-info",
                Description = "Check headers that leak server info (Server, X-Powered-By, X-AspNet-Version)",
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

        // Step 1: Attack surface analysis (passive — discovers POST endpoints for missing-parameter step)
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

        // Step 2: Fail-open probes — look for verbose error responses
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("fail-open", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunFailOpenScan(
                    new FailOpenScanProbe.ScanOptions
                    {
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope, postEndpointUrls),
                        MaxEndpoints = EndpointScopeHelper.CapEndpoints(request.Scope,
                            Math.Min(depth.MaxEndpointsPerScanner, 10)),
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
                        Id = $"a09-failopen-{findingCount}",
                        Source = "orchestrate-a09",
                        Category = ClassifyOpsecCategory(f),
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.BodySnippet,
                        Remediation = "Implement generic error pages. Log detailed errors server-side, never expose stack traces to clients.",
                        Reference = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
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

        // Step 2: Missing parameter — triggers NullReferenceException etc.
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("missing-parameter", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunMissingParameterScan(
                    new MissingParameterScanProbe.ScanOptions
                    {
                        MaxEndpoints = EndpointScopeHelper.CapEndpoints(request.Scope,
                            Math.Min(depth.MaxEndpointsPerScanner, 8)),
                        MaxFieldsPerEndpoint = 6,
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 12000),
                        RegisterChainFindings = false,
                        Urls = EndpointScopeHelper.ScopedUrlList(request.Scope, postEndpointUrls)
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    bool isStackTrace = f.NpeHints.Count > 0 ||
                        (f.BodySnippet ?? "").Contains("Exception", StringComparison.OrdinalIgnoreCase) ||
                        (f.BodySnippet ?? "").Contains("stack trace", StringComparison.OrdinalIgnoreCase);

                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a09-missingparam-{findingCount}",
                        Source = "orchestrate-a09",
                        Category = isStackTrace ? "stack-trace-leak" : "verbose-error",
                        Severity = isStackTrace ? "medium" : f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Method = f.Method,
                        Parameter = f.OmittedField,
                        Detail = f.Detail,
                        Evidence = f.BodySnippet,
                        Remediation = "Use generic error responses (HTTP 400/500 with safe message). Log stack traces server-side only.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
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

        // Step 3: Console error harvest (passive)
        await ctx.RunStepAsync("console-error-harvest", async _ =>
        {
            var errors = ctx.Automation.GetConsoleErrors();
            int findingCount = 0;

            var stackTraceErrors = errors.Where(e =>
                ContainsStackTrace(e.Message)).ToList();

            foreach (var e in stackTraceErrors.Take(20))
            {
                var text = e.Message ?? "";
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a09-console-{findingCount}",
                    Source = "orchestrate-a09",
                    Category = "console-stack-trace",
                    Severity = "low",
                    Title = $"Console stack trace: {TruncateTitle(text)}",
                    Endpoint = await ctx.GetCurrentUrlAsync(),
                    Detail = text.Length > 500 ? text[..500] + "..." : text,
                    Remediation = "Strip stack traces from production console output. Use source maps server-side for debugging.",
                    Reference = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
                });
                findingCount++;
            }

            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["totalConsoleErrors"] = errors.Count
            };
        }, ct);

        // Step 4: Network error harvest (passive)
        await ctx.RunStepAsync("network-error-harvest", async _ =>
        {
            var entries = EndpointScopeHelper.FilterNetworkEntries(ctx.Automation.Network.Entries, request.Scope)
                .ToList();
            int findingCount = 0;

            var serverErrors = entries
                .Where(e => e.StatusCode >= 500 && e.StatusCode < 600)
                .Take(20)
                .ToList();

            foreach (var e in serverErrors)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a09-network-{findingCount}",
                    Source = "orchestrate-a09",
                    Category = "server-error-response",
                    Severity = "info",
                    Title = $"HTTP {e.StatusCode} on {e.Method} {TruncateUrl(e.Url)}",
                    Endpoint = e.Url,
                    Method = e.Method,
                    Detail = $"Server returned {e.StatusCode} ({e.ReasonPhrase}). Response size: {e.ResponseBody?.Length ?? 0} bytes.",
                    Remediation = "Investigate root cause. Ensure 5xx responses don't leak internal details.",
                    Reference = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
                });
                findingCount++;
            }

            return new Dictionary<string, object?>
            {
                ["findings"] = findingCount,
                ["totalServerErrors"] = entries.Count(e => e.StatusCode >= 500)
            };
        }, ct);

        // Step 5: Source maps and debug mode (passive)
        await ctx.RunStepAsync("source-maps-debug", async _ =>
        {
            var result = await ctx.Automation.CheckSourceMaps();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a09-sourcemap-{findingCount}",
                    Source = "orchestrate-a09",
                    Category = "source-maps-debug",
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = f.Description,
                    Endpoint = f.Url ?? await ctx.GetCurrentUrlAsync(),
                    Detail = f.Detail,
                    Remediation = "Remove source maps and debug mode indicators from production. Use build-time stripping.",
                    Reference = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                });
                findingCount++;
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 6: Information-leaking headers (passive)
        await ctx.RunStepAsync("security-headers-info", async _ =>
        {
            var result = await ctx.Automation.CheckSecurityHeaders();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings.Where(f => IsInfoLeakHeader(f.Header)))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a09-header-{findingCount}",
                        Source = "orchestrate-a09",
                        Category = "info-leak-headers",
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Info-leak header: {f.Header}",
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

        if (ctx.Findings.All.Any(f => f.Category is "stack-trace-leak" or "verbose-error"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05-injection",
                Rationale = "Verbose errors may reveal injection vectors (SQL queries, file paths, internal APIs)."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category is "fail-open" or "fail-open-unauthenticated"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a06-design",
                Rationale = "Fail-open behavior is an insecure design issue — test business logic flaws."
            });
        }

        if (ctx.Findings.All.Any(f => f.Category == "source-maps-debug"))
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "Source maps may expose hardcoded secrets in original source code."
            });
        }

        return actions;
    }

    private static string ClassifyOpsecCategory(FailOpenScanProbe.ScanFinding f)
    {
        if ((f.BodySnippet ?? "").Contains("Exception", StringComparison.OrdinalIgnoreCase) ||
            (f.BodySnippet ?? "").Contains("stack trace", StringComparison.OrdinalIgnoreCase) ||
            (f.Detail ?? "").Contains("stack trace", StringComparison.OrdinalIgnoreCase))
            return "stack-trace-leak";

        return f.Category is { Length: > 0 } ? f.Category : "fail-open";
    }

    private static bool IsInfoLeakHeader(string? header)
    {
        var h = (header ?? "").ToLowerInvariant();
        return h is "server" or "x-powered-by" or "x-aspnet-version" or "x-aspnetmvc-version"
            or "x-generator" or "x-drupal-cache" or "x-varnish";
    }

    private static bool ContainsStackTrace(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return text.Contains("    at ", StringComparison.Ordinal) ||
               text.Contains("Traceback", StringComparison.Ordinal) ||
               text.Contains("NullReferenceException", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("TypeError:", StringComparison.Ordinal) ||
               text.Contains("ReferenceError:", StringComparison.Ordinal) ||
               text.Contains("Uncaught", StringComparison.Ordinal);
    }

    private static string TruncateTitle(string text)
    {
        var firstLine = text.Split('\n', 2)[0].Trim();
        return firstLine.Length > 80 ? firstLine[..77] + "..." : firstLine;
    }

    private static string TruncateUrl(string url) =>
        url.Length > 80 ? url[..77] + "..." : url;
}
