using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A02 Misconfiguration: headers + cookies + storage + source-maps + smuggling (passive)
/// → discover API → CORS sweep → methods → forced-error → clickjack → subdomain-takeover.
/// </summary>
public sealed class A02MisconfigPlaybook : IPlaybook
{
    public string Id => "a02-misconfig";
    public string Title => "A02 Misconfiguration";
    public string Category => "security-misconfiguration";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "security-headers",
                Description = "Analyze HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "api-csp-headers",
                Description = "Flag unsafe CSP directives on same-origin API responses",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "cookie-audit",
                Description = "OWASP cookie security audit",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "source-maps",
                Description = "Detect exposed source maps and debug artifacts",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "cors-sweep",
                Description = "CORS misconfiguration sweep across discovered endpoints",
                HttpVerbs = "OPTIONS, GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "endpoint-discover",
                Description = "Directory/endpoint discovery for hidden admin panels and config files",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "forced-error",
                Description = "Provoke malformed API requests to detect stack trace / verbose error disclosure",
                HttpVerbs = "POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active mode" : null
            },
            new DryRunStep
            {
                Name = "http-methods",
                Description = "Test accepted HTTP methods (TRACE, PUT, DELETE, etc.)",
                HttpVerbs = "OPTIONS, TRACE, PUT, DELETE",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "smuggling-passive",
                Description = "Ambiguous response framing check (TE+CL); proxy/CDN headers are context only",
                HttpVerbs = "none (passive header analysis)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "subdomain-takeover",
                Description = "Detect dangling CNAMEs vulnerable to subdomain takeover",
                HttpVerbs = "GET (DNS-over-HTTPS + HTTP probe)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
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

        // Step 1: Security headers (passive)
        await ctx.RunStepAsync("security-headers", async _ =>
        {
            var result = await ctx.Automation.CheckSecurityHeaders();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a02-header-{findingCount}",
                    Source = "orchestrate-a02",
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
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 1b: Unsafe CSP on same-origin API responses (JSON often carries CSP but is skipped by document-only checks)
        await ctx.RunStepAsync("api-csp-headers", async _ =>
        {
            var origin = await ctx.GetCurrentUrlAsync();
            if (!Uri.TryCreate(origin, UriKind.Absolute, out var pageUri))
                return new Dictionary<string, object?> { ["findings"] = 0 };

            var host = pageUri.GetLeftPart(UriPartial.Authority);
            var findingCount = 0;
            var seenPolicies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var entry in ctx.Automation.Network.Entries.TakeLast(100))
            {
                if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var u)) continue;
                if (!string.Equals(u.GetLeftPart(UriPartial.Authority), host, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (entry.ResponseHeaders.Count == 0) continue;
                if (!entry.ResponseHeaders.Keys.Any(k =>
                        k.Equals("content-security-policy", StringComparison.OrdinalIgnoreCase)))
                    continue;

                var policy = entry.ResponseHeaders
                    .FirstOrDefault(kv => kv.Key.Equals("content-security-policy", StringComparison.OrdinalIgnoreCase))
                    .Value ?? "";
                if (!seenPolicies.Add(policy)) continue;

                foreach (var f in HeadersChecker.AnalyzeCspFromHeaders(entry.ResponseHeaders))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-api-csp-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = "weak-headers",
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"API CSP: {f.Description}",
                        Endpoint = entry.Url,
                        Detail = f.Description + (string.IsNullOrEmpty(f.CurrentValue) ? "" : $" Policy: {f.CurrentValue}"),
                        Remediation = f.Recommendation,
                        Reference = f.Reference
                    });
                    findingCount++;
                }
            }

            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 2: Cookie audit (passive)
        await ctx.RunStepAsync("cookie-audit", async _ =>
        {
            var result = await ctx.Automation.CheckCookieSecurity();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a02-cookie-{findingCount}",
                    Source = "orchestrate-a02",
                    Category = NormalizeCookieCategory(f.Category),
                    Severity = f.Severity.ToString().ToLowerInvariant(),
                    Title = $"Cookie: {f.Category} ({f.CookieName})",
                    Endpoint = await ctx.GetCurrentUrlAsync(),
                    Detail = f.Description,
                    Remediation = f.Recommendation,
                    Parameter = f.CookieName
                });
                findingCount++;
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 3: Source maps (passive)
        await ctx.RunStepAsync("source-maps", async _ =>
        {
            var result = await ctx.Automation.CheckSourceMaps();
            int findingCount = 0;
            foreach (var f in result.Findings)
            {
                ctx.Findings.Add(new ChainableFinding
                {
                    Id = $"a02-sourcemap-{findingCount}",
                    Source = "orchestrate-a02",
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

        // Step 4: CORS sweep (requires probes). Cap hard in quick depth — this step often
        // dominates wall-clock and starves injection/access child playbooks.
        if (ctx.SafetyMode.AllowsProbes() && ctx.DepthProfile.Depth != PlaybookDepth.Quick)
        {
            await ctx.RunStepAsync("cors-sweep", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.CheckCorsSweep(new CorsSweep.SweepOptions
                {
                    MaxUrls = depth.MaxEndpointsPerScanner
                });
                int findingCount = 0;
                foreach (var group in result.GroupedIssues)
                {
                    var affectedSample = group.AffectedUrls.Count <= 5
                        ? string.Join(", ", group.AffectedUrls)
                        : string.Join(", ", group.AffectedUrls.Take(4)) +
                          $" (+{group.AffectedUrls.Count - 4} more)";
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-cors-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = "cors-misconfig",
                        Severity = group.Severity,
                        Title = $"CORS: {group.RootCause}",
                        Endpoint = group.AffectedUrls.FirstOrDefault() ?? await ctx.GetCurrentUrlAsync(),
                        Detail = $"Policy: Allow-Origin={group.AllowOrigin ?? "(none)"}, " +
                                 $"Credentials={group.AllowCredentials}. " +
                                 $"Affected ({group.AffectedCount}): {affectedSample}"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.UrlsSwept);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["urlsSwept"] = result.UrlsSwept
                };
            }, ct);
        }
        else if (ctx.DepthProfile.Depth == PlaybookDepth.Quick)
        {
            ctx.SkipStep("cors-sweep", "Skipped at quick depth (use standard/deep for CORS sweep)");
        }
        else
        {
            ctx.SkipStep("cors-sweep", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 5: Endpoint discovery (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("endpoint-discover", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.DiscoverEndpoints(
                    wordlist: depth.WordlistSize,
                    spaMode: true);
                int findingCount = 0;
                foreach (var ep in result.Discovered)
                {
                    var severity = EndpointDiscoveryClassifier.ClassifySeverity(
                        ep.Path, ep.StatusCode, ep.BodySnippet);
                    if (severity == "info") continue;

                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-discover-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = "info-leak",
                        Severity = severity,
                        Title = EndpointDiscoveryClassifier.BuildTitle(ep.Path, ep.StatusCode),
                        Endpoint = ep.Url,
                        Detail = $"HTTP {ep.StatusCode}" +
                                 (ep.ContentType != null ? $", Content-Type: {ep.ContentType}" : "") +
                                 (ep.BodySnippet != null ? $". Snippet: {TruncateSnippet(ep.BodySnippet)}" : "")
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ScannedCount);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["pathsScanned"] = result.ScannedCount,
                    ["pathsDiscovered"] = result.DiscoveredCount
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("endpoint-discover", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 6: Forced error / stack trace disclosure (requires active mode)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            await ctx.RunStepAsync("forced-error", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ForcedErrorScanner.RunAsync(ctx.Automation,
                    new ForcedErrorScanner.ScanOptions
                    {
                        MaxEndpoints = Math.Min(depth.MaxEndpointsPerScanner, 12),
                        TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 12_000),
                        IncludeNetworkDiscovery = true
                    }, innerCt);

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-forced-error-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = f.Category,
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.BodySnippet,
                        Remediation = "Return generic error responses (400/500). Log stack traces server-side only.",
                        Reference = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsProbed * 2);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["endpointsProbed"] = result.EndpointsProbed,
                    ["endpointsSkipped"] = result.EndpointsSkipped
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("forced-error", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 7: HTTP methods (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("http-methods", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.CheckHttpMethods();
                int findingCount = 0;
                foreach (var row in result.Results.Where(r => r.Security != null))
                {
                    var severity = row.Method == "TRACE" ? "medium"
                        : row.Security!.Contains("501", StringComparison.Ordinal) ? "info"
                        : "low";
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-methods-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = "dangerous-methods",
                        Severity = severity,
                        Title = row.Security!,
                        Endpoint = result.Url,
                        Method = row.Method,
                        Detail = row.Security!
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.Results.Count);
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("http-methods", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 8: Ambiguous response framing (passive) — Via/CDN is not a finding
        await ctx.RunStepAsync("smuggling-passive", async _ =>
        {
            var entries = ctx.Automation.Network.Entries;
            int framing = 0;
            foreach (var entry in entries.Take(50))
            {
                if (entry.ResponseHeaders != null &&
                    HttpRequestSmugglingScanner.ResponseHasAmbiguousFraming(entry.ResponseHeaders))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-ambiguous-framing-{framing}",
                        Source = "orchestrate-a02",
                        Category = "ambiguous-framing",
                        Severity = "low",
                        Title = $"Ambiguous response framing on {entry.Url}",
                        Endpoint = entry.Url,
                        Detail = "Response contains both Transfer-Encoding and Content-Length, or conflicting Content-Length values. " +
                                 "Not confirmed request smuggling."
                    });
                    framing++;
                    if (framing >= 3) break;
                }
            }
            return new Dictionary<string, object?> { ["ambiguousFraming"] = framing };
        }, ct);

        // Step 9: Subdomain takeover (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("subdomain-takeover", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await SubdomainTakeoverChecker.RunAsync(ctx.Automation,
                    new SubdomainTakeoverChecker.SubdomainTakeoverOptions
                    {
                        MaxHostnames = depth.MaxEndpointsPerScanner,
                        RegisterChainFindings = false
                    }, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a02-subtakeover-{findingCount}",
                        Source = "orchestrate-a02",
                        Category = "subdomain-takeover",
                        Severity = f.Severity,
                        Title = $"Subdomain takeover: {f.Host} → {f.Provider}",
                        Endpoint = $"https://{f.Host}/",
                        Detail = f.Detail
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["hostnamesChecked"] = result.HostnamesChecked
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("subdomain-takeover", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
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

        bool hasCors = ctx.Findings.All.Any(f => f.Category == "cors-misconfig");
        bool hasSourceMaps = ctx.Findings.All.Any(f => f.Category == "source-maps");

        if (hasCors)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "CORS misconfiguration can amplify access control weaknesses — test IDOR/BFLA."
            });
        }

        if (hasSourceMaps)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "Exposed source maps may reveal hardcoded secrets — run secrets harvest."
            });
        }

        if (ctx.Findings.Count > 0)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a14-other",
                Rationale = "Misconfiguration findings may enable cache poisoning or host header attacks."
            });
        }

        return actions;
    }

    private static string TruncateSnippet(string snippet) =>
        snippet.Length <= 120 ? snippet : snippet[..120] + "…";

    private static string NormalizeHeaderCategory(string? header) => (header ?? "").ToLowerInvariant() switch
    {
        "content-security-policy" or "csp" => "missing-csp",
        "strict-transport-security" or "hsts" => "missing-hsts",
        "x-frame-options" => "missing-xframe",
        "x-content-type-options" => "missing-content-type-options",
        "referrer-policy" => "missing-referrer-policy",
        "permissions-policy" => "missing-permissions-policy",
        _ => "weak-headers"
    };

    private static string NormalizeCookieCategory(string? category) => (category ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("httponly") => "missing-httponly",
        string s when s.Contains("secure") => "missing-secure-flag",
        "samesitenone" or "samesitenoneinsecure" => "missing-samesite",
        string s when s.Contains("samesite") && s.Contains("none") => "missing-samesite",
        _ => "weak-cookies"
    };
}
