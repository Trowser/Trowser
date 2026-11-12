using Trowser.Security.ChainEngine;
using Trowser.Security.XsLeaks;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A14 Other: cache-identify + cache-map + live-key pollution + cache-poison + cache-deception +
/// HTTP smuggling + host-header injection + open-redirect + WebSocket audit + XS-Leaks.
/// </summary>
public sealed class A14OtherPlaybook : IPlaybook
{
    public string Id => "a14-other";
    public string Title => "A14 Other";
    public string Category => "other";

    public IReadOnlyList<DryRunStep> DescribeSteps(PlaybookRequest request)
    {
        var mode = SecurityPreflight.EffectiveMode(request.SafetyMode, request.Scope.Host);
        var depth = PlaybookDepthProfile.Resolve(request.Depth);
        return
        [
            PlaybookDryRun.CrawlLight(request, depth.MaxCrawlPages),
            new DryRunStep
            {
                Name = "smuggling-passive",
                Description = "Passive check for ambiguous response framing (TE+CL); proxy/CDN headers are context only",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "smuggling-active",
                Description = "Active HTTP request smuggling: CL-TE/TE-CL differential 404 confirmation (raw TCP)",
                HttpVerbs = "Raw TCP",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Active smuggling requires active mode (raw TCP probes)" : null
            },
            new DryRunStep
            {
                Name = "host-header-injection",
                Description = "Host header injection scanning (Host override, X-Forwarded-Host, password-reset poisoning)",
                HttpVerbs = "Raw TCP",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Host header probing requires active mode" : null
            },
            new DryRunStep
            {
                Name = "cache-identify",
                Description = "Passive cache identification from document headers (vendors, HIT/MISS/DYNAMIC/no-store). A cache is not a finding.",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false
            },
            new DryRunStep
            {
                Name = "cache-map",
                Description = "Cache key-mapping with unique query busters (does not poison the live URL)",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Cache-map requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "cache-pollution",
                Description = "Live-key error pollution: miss-forcing header, store an error, confirm with a clean GET",
                HttpVerbs = "GET",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Cache pollution requires active mode (may store an error on the shared URL)" : null
            },
            new DryRunStep
            {
                Name = "cache-deception",
                Description = "Web cache deception: test path confusion to cache authenticated responses publicly",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Cache deception requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "cache-poison",
                Description = "Cache poisoning: test unkeyed headers that modify cached responses",
                HttpVerbs = "GET",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Cache poisoning requires active mode (may poison cache)" : null
            },
            new DryRunStep
            {
                Name = "open-redirect",
                Description = "Open redirect scanning across discovered redirect parameters",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "websocket-audit",
                Description = "WebSocket fuzzing for injection and message-type confusion",
                HttpVerbs = "WebSocket",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "sse-audit",
                Description = "Server-Sent Events audit: sensitive data, handler sinks, optional active subscribe checks",
                HttpVerbs = "GET (EventSource)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "xs-leaks",
                Description = "XS-Leaks: can a cross-origin attacker distinguish current page vs a miss URL (iframe/script/img)?",
                HttpVerbs = "GET (attacker page mock)",
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

        await ctx.RunCrawlStepAsync(host, ct);

        // Step 1: Smuggling — passive framing check only (Via/CDN is context, not a finding)
        await ctx.RunStepAsync("smuggling-passive", async _ =>
        {
            var entries = EndpointScopeHelper.FilterNetworkEntries(ctx.Automation.Network.Entries, request.Scope)
                .Take(depth.Depth == PlaybookDepth.Deep ? 100 : 50)
                .ToList();
            int framing = 0;
            int proxyContext = 0;
            foreach (var entry in entries)
            {
                if (entry.ResponseHeaders == null) continue;
                if (HttpRequestSmugglingScanner.ResponseHasAmbiguousFraming(entry.ResponseHeaders))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-ambiguous-framing-{framing}",
                        Source = "orchestrate-a14",
                        Category = "ambiguous-framing",
                        Severity = "low",
                        Title = $"Ambiguous response framing on {entry.Url}",
                        Endpoint = entry.Url,
                        Detail = "Response includes both Transfer-Encoding and Content-Length, or conflicting Content-Length values. Not confirmed request smuggling.",
                        Remediation = "Normalize response framing. Run active smuggling with safetyMode active; act only on confirmed differential 404.",
                        Reference = "https://portswigger.net/web-security/request-smuggling"
                    });
                    framing++;
                    if (framing >= 5) break;
                }
                else if (HasProxyContextHeaders(entry))
                {
                    proxyContext++;
                }
            }
            return new Dictionary<string, object?> { ["ambiguousFraming"] = framing, ["proxyContextResponses"] = proxyContext };
        }, ct);

        // Step 2: Active smuggling detection (active only)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            var skipSmuggling = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "smuggling-active");
            if (skipSmuggling != null)
                ctx.SkipStep("smuggling-active", skipSmuggling);
            else
            await ctx.RunStepAsync("smuggling-active", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunHttpSmugglingScan(
                    url: null,
                    techniques: null,
                    timeoutMs: Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                    delayThresholdMs: 3000,
                    teObfuscations: true);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    if (f.FindingCategory != "vulnerability" ||
                        !string.Equals(f.ConfirmationMethod, "differential-response", StringComparison.OrdinalIgnoreCase))
                        continue;
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-smuggling-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "http-smuggling",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"HTTP smuggling ({f.Technique}): {f.Description}",
                        Endpoint = result.Url,
                        Detail = f.Description,
                        Evidence = f.Evidence,
                        Remediation = f.Remediation.Length > 0 ? f.Remediation
                            : "Normalize Transfer-Encoding handling across all proxies. Reject ambiguous requests.",
                        Reference = "https://portswigger.net/web-security/request-smuggling"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesRun);
                return new Dictionary<string, object?>
                {
                    ["verdict"] = result.Verdict,
                    ["findings"] = findingCount,
                    ["probesRun"] = result.ProbesRun
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("smuggling-active",
                $"Active smuggling probes require active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 3: Host header injection (active only)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            var skipHost = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "host-header-injection");
            if (skipHost != null)
                ctx.SkipStep("host-header-injection", skipHost);
            else
            await ctx.RunStepAsync("host-header-injection", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var currentUrl = await ctx.GetCurrentUrlAsync();
                if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out _))
                {
                    return new Dictionary<string, object?> { ["findings"] = 0, ["skipped"] = "No valid URL" };
                }

                var options = new HostHeaderInjectionScanner.HostHeaderScanOptions
                {
                    Url = currentUrl,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await HostHeaderInjectionScanner.RunAsync(options, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-hostheader-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "host-header-injection",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Host header injection ({f.Probe}): {f.ReflectionType}",
                        Endpoint = result.Url,
                        Detail = f.Description,
                        Evidence = f.Evidence,
                        Remediation = f.Remediation.Length > 0 ? f.Remediation
                            : "Validate the Host header server-side. Use a hardcoded canonical hostname for password resets.",
                        Reference = "https://portswigger.net/web-security/host-header"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.RequestsRun);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["probesRun"] = result.ProbesRun
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("host-header-injection",
                $"Host header probing requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 4: Cache identify (passive) then map (indication) then live-key pollution then poison
        string? pollutionBypass = null;
        string? pollutionBypassValue = null;
        List<string>? poisonHeaders = null;
        var cacheInPlay = false;

        await ctx.RunStepAsync("cache-identify", async _ =>
        {
            var stack = await ctx.Automation.CheckTechStack();
            cacheInPlay = IsCacheInPlay(stack.Cache);
            return IdentifyMetrics(stack.Cache);
        }, ct);

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("cache-map", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new CacheMapOptions
                {
                    MaxTargets = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    Urls = EndpointScopeHelper.IsEndpointScoped(request.Scope) ? [request.Scope.TargetUrl!] : null,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000),
                    IncludeBrowserCookies = true,
                    IncludeHeaderProbes = ctx.SafetyMode.AllowsWriteVerbs(),
                    IncludeFatGet = ctx.SafetyMode.AllowsWriteVerbs()
                };
                var result = await ctx.Automation.RunCacheMapScan(options, innerCt);
                if (IsCacheInPlay(result.Identify))
                    cacheInPlay = true;
                poisonHeaders = result.KeyComponents.Headers.Count > 0 ? result.KeyComponents.Headers : null;
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    if (f.Indicator is "key-explosion-possible")
                        continue;
                    var category = f.Indicator == "cacheable-error" || f.Indicator.Contains("unkeyed", StringComparison.Ordinal)
                        ? "cache-poison"
                        : "cache-map";
                    ctx.Findings.Add(CacheMapPresentation.ToChainableFinding(
                        f, $"a14-cachemap-{findingCount}", "orchestrate-a14", category));
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesRun);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["detected"] = result.Identify.Detected,
                    ["documentStatus"] = result.Identify.DocumentStatus
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("cache-map",
                $"Cache-map requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        if (!ctx.SafetyMode.AllowsWriteVerbs())
        {
            ctx.SkipStep("cache-pollution",
                $"Cache pollution requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }
        else if (!cacheInPlay)
        {
            ctx.SkipStep("cache-pollution",
                "No cache identified — skipping live-key pollution");
        }
        else
        {
            await ctx.RunStepAsync("cache-pollution", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new CachePollutionOptions
                {
                    Urls = EndpointScopeHelper.IsEndpointScoped(request.Scope) ? [request.Scope.TargetUrl!] : null,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await ctx.Automation.RunCachePollutionScan(options, innerCt);
                if (result.BypassHeader != null)
                {
                    pollutionBypass = result.BypassHeader.Name;
                    pollutionBypassValue = result.BypassHeader.Value;
                }
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-cachepollution-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "cache-poison",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = f.Title,
                        Endpoint = f.Url,
                        Detail = f.Detail,
                        Evidence = f.CacheHeaders,
                        Remediation = "Do not cache error responses. Include miss-forcing and unkeyed headers in the cache key.",
                        Reference = "https://portswigger.net/web-security/web-cache-poisoning"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesRun);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["bypassHeader"] = pollutionBypass,
                    ["probesRun"] = result.ProbesRun
                };
            }, ct);
        }

        // Step 5: Cache deception (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            var skipCacheDeception = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "cache-deception");
            if (skipCacheDeception != null)
                ctx.SkipStep("cache-deception", skipCacheDeception);
            else
            await ctx.RunStepAsync("cache-deception", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new CacheDeceptionOptions
                {
                    MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await ctx.Automation.RunCacheDeceptionScan(options, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-cachedeception-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "cache-deception",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Cache deception: {f.Url} via {f.VariantPath}",
                        Endpoint = f.Url,
                        Detail = $"Authed status: {f.AuthedStatus}, Anon status: {f.AnonStatus}. Cache: {f.CacheHeaders}",
                        Evidence = f.BodySnippet,
                        Remediation = "Configure Cache-Control: no-store on authenticated pages. Avoid path-based cache rules.",
                        Reference = "https://portswigger.net/web-security/web-cache-deception"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.CandidatesProbed);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["candidatesProbed"] = result.CandidatesProbed
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("cache-deception",
                $"Cache deception requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 5: Cache poisoning (active only; skip when no cache is in play)
        if (!ctx.SafetyMode.AllowsWriteVerbs())
        {
            ctx.SkipStep("cache-poison",
                $"Cache poisoning probes require active mode (current: {ctx.SafetyMode.ToLabel()})");
        }
        else if (!cacheInPlay)
        {
            ctx.SkipStep("cache-poison",
                "No cache identified — skipping cache poisoning");
        }
        else
        {
            var skipCachePoison = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "cache-poison");
            if (skipCachePoison != null)
                ctx.SkipStep("cache-poison", skipCachePoison);
            else
            await ctx.RunStepAsync("cache-poison", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new CachePoisonOptions
                {
                    MaxTargets = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    Urls = EndpointScopeHelper.IsEndpointScoped(request.Scope)
                        ? [request.Scope.TargetUrl!]
                        : null,
                    Headers = poisonHeaders,
                    BypassHeader = pollutionBypass,
                    BypassHeaderValue = pollutionBypassValue,
                    IncludeHeaderInjectionFuzz = false,
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await ctx.Automation.RunCachePoisonScan(options, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-cachepoison-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "cache-poison",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Cache poisoning via {f.HeaderName}: {f.HeaderDescription}",
                        Endpoint = f.Url,
                        Detail = $"Poison status: {f.PoisonStatus}, Clean status: {f.CleanStatus}. Reflected: {string.Join(", ", f.ReflectedInPoison)}",
                        Evidence = f.CacheHeaders,
                        Remediation = "Include all response-affecting headers in the cache key. Add Vary headers.",
                        Reference = "https://portswigger.net/web-security/web-cache-poisoning"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.ProbesRun);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["probesRun"] = result.ProbesRun
                };
            }, ct);
        }

        // Step 6: Open redirect (requires probes)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("open-redirect", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new OpenRedirectOptions
                {
                    MaxCandidates = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    ExplicitUrls = EndpointScopeHelper.IsEndpointScoped(request.Scope)
                        ? [request.Scope.TargetUrl!]
                        : null,
                    IncludeDomDiscovery = !EndpointScopeHelper.IsEndpointScoped(request.Scope),
                    TimeoutMs = Math.Min(ctx.Budget.RemainingSeconds * 1000, 15000)
                };
                var result = await ctx.Automation.RunOpenRedirectScan(options, innerCt);
                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-redirect-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "open-redirect",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"Open redirect via {f.ParamName}: {f.Indicator}",
                        Endpoint = f.Url,
                        Method = f.Method,
                        Parameter = f.ParamName,
                        Detail = $"Payload: {f.Payload}. Location: {f.Location}. Bypass: {f.BypassTechnique ?? "none"}",
                        Evidence = f.Snippet,
                        Remediation = "Validate redirect targets against an allowlist. Use relative paths for internal redirects.",
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

        // Step 7: WebSocket fuzzing (requires probes + active WS connections)
        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("websocket-audit", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new Trowser.Security.WebSocket.WebSocketFuzzOptions
                {
                    MaxConnections = depth.Depth == PlaybookDepth.Deep ? 5 : 3,
                    MaxPayloadsPerSet = depth.Depth == PlaybookDepth.Quick ? 4 : 8
                };
                var result = await ctx.Automation.RunWebSocketFuzz(options, innerCt);
                if (result.SkippedReason != null)
                {
                    return new Dictionary<string, object?> { ["findings"] = 0, ["skipped"] = result.SkippedReason };
                }

                int findingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-ws-{findingCount}",
                        Source = "orchestrate-a14",
                        Category = "websocket-injection",
                        Severity = f.Severity.ToLowerInvariant(),
                        Title = $"WebSocket ({f.PayloadSet}): {f.Indicator}",
                        Endpoint = f.Url,
                        Detail = f.Detail,
                        Evidence = f.ReceivedSnippet,
                        Remediation = "Validate WebSocket Origin header. Sanitize incoming messages. Implement authentication.",
                        Reference = "https://portswigger.net/web-security/websockets"
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.PayloadsSent);
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["connectionsFuzzed"] = result.ConnectionsFuzzed,
                    ["payloadsSent"] = result.PayloadsSent
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("websocket-audit",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("sse-audit", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var audit = await ctx.Automation.RunSseAuditAsync(new Trowser.Security.Sse.SseAuditor.AuditOptions
                {
                    SafetyMode = ctx.SafetyMode,
                    Checks = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "all" }
                }, ctx.PeerRegistry, innerCt);
                var high = audit.Findings.Count(f =>
                    f.Severity is "high" or "critical");
                foreach (var f in audit.Findings.Where(x => x.Severity is "high" or "critical" or "medium"))
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-sse-{f.Check}-{ctx.Findings.Count}",
                        Source = "orchestrate-a14",
                        Category = "sse",
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Url,
                        Detail = f.Detail,
                        Evidence = f.Evidence,
                        Remediation = f.Remediation
                    });
                }

                return new Dictionary<string, object?>
                {
                    ["findings"] = audit.Findings.Count,
                    ["highOrCritical"] = high,
                    ["messagesCaptured"] = audit.Coverage.MessagesCaptured
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("sse-audit",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("xs-leaks", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var current = await ctx.GetCurrentUrlAsync();
                if (string.IsNullOrWhiteSpace(current) || !Uri.TryCreate(current, UriKind.Absolute, out var curUri))
                    return new Dictionary<string, object?> { ["skipped"] = "no current URL" };

                XsLeakScanner.XsLeakResult result;
                try
                {
                    var options = new XsLeakScanner.XsLeakOptions
                    {
                        AutoStates = true,
                        Techniques =
                        [
                            "iframe-load", "script-error", "img-error", "iframe-framecount",
                            "fetch-redirect-type", "resource-transfer-size", "broadcast-channel-probe"
                        ],
                        Trials = 2,
                        SkipWarmup = true
                    };
                    result = await ctx.Automation.RunXsLeaksAsync(options, ctx.SafetyMode.ToLabel());
                }
                catch (InvalidOperationException ex)
                {
                    return new Dictionary<string, object?>
                    {
                        ["skipped"] = ex.Message,
                        ["detail"] = "Browse authenticated APIs or capture identities on this host, then re-run."
                    };
                }
                var findingCount = 0;
                foreach (var cf in result.ChainFindings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a14-{cf.Id}",
                        Source = "orchestrate-a14",
                        Category = cf.Category,
                        Severity = cf.Severity,
                        Title = cf.Title,
                        Endpoint = cf.Endpoint ?? current,
                        Detail = cf.Detail,
                        Remediation = cf.Remediation + (result.Posture?.Recommendations.Count > 0
                            ? " Posture: " + string.Join(" ", result.Posture.Recommendations.Take(2))
                            : ""),
                        Reference = cf.Reference,
                        Tags = cf.Tags
                    });
                    findingCount++;
                }
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["summary"] = result.Summary,
                    ["cookieMode"] = result.CookieMode
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("xs-leaks",
                $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
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

        bool hasSmuggling = ctx.Findings.All.Any(f => f.Category == "http-smuggling");
        bool hasCacheIssues = ctx.Findings.All.Any(f =>
            f.Category is "cache-deception" or "cache-poison" or "cache-map");
        bool hasHostHeader = ctx.Findings.All.Any(f =>
            f.Category == "host-header-injection");
        bool hasOpenRedirect = ctx.Findings.All.Any(f =>
            f.Category == "open-redirect");

        if (hasSmuggling)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a01-access",
                Rationale = "HTTP smuggling can bypass front-end access controls - test authorization."
            });
        }

        if (hasCacheIssues)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a04-crypto",
                Rationale = "Cache deception/poisoning may expose sensitive cached data - check for secret leaks."
            });
        }

        if (hasHostHeader)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "Host header injection can poison password-reset emails - test authentication flows."
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

    private static bool IsCacheInPlay(CacheIdentifySummary? identify) =>
        identify is { Detected: true }
        && !string.Equals(identify.DocumentStatus, CacheHeaderAnalyzer.DocumentStatusNotCached,
            StringComparison.OrdinalIgnoreCase);

    private static Dictionary<string, object?> IdentifyMetrics(CacheIdentifySummary identify) => new()
    {
        ["detected"] = identify.Detected,
        ["documentStatus"] = identify.DocumentStatus,
        ["cacheable"] = identify.Cacheable,
        ["vendors"] = identify.Vendors,
        ["vary"] = identify.Vary,
        ["evidence"] = identify.Evidence
    };

    private static bool HasProxyContextHeaders(Automation.NetworkEntry entry)
    {
        if (entry.ResponseHeaders == null) return false;
        var headers = entry.ResponseHeaders;
        return headers.Keys.Any(k =>
            k.Equals("via", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("x-forwarded-for", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("cf-ray", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("x-cache", StringComparison.OrdinalIgnoreCase) ||
            k.Equals("x-served-by", StringComparison.OrdinalIgnoreCase));
    }
}
