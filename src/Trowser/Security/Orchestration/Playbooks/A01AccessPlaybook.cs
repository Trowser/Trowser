using Trowser.Api;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration.Playbooks;

/// <summary>
/// A01 Access Control: attack-surface → classify by auth tier → anon probe →
/// low-priv peer diff → idor/bfla/mass-assignment/csrf/role-matrix.
/// </summary>
public sealed class A01AccessPlaybook : IPlaybook
{
    public string Id => "a01-access";
    public string Title => "A01 Access Control";
    public string Category => "access-control";

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
                Description = "Analyze network log to discover API endpoints and classify by auth tier",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = false
            },
            new DryRunStep
            {
                Name = "security-headers",
                Description = "Check HTTP security headers on the current page",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = false
            },
            new DryRunStep
            {
                Name = "cookie-audit",
                Description = "OWASP cookie security audit (Secure, HttpOnly, SameSite)",
                HttpVerbs = "none (passive)",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = false
            },
            new DryRunStep
            {
                Name = "csrf-scan",
                Description = "Scan state-changing endpoints for CSRF vulnerabilities",
                HttpVerbs = "GET, POST",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active or aggressive mode" : null
            },
            new DryRunStep
            {
                Name = "idor-scan",
                Description = "Test authorization on discovered endpoints with different ID values",
                HttpVerbs = mode.ToReadOnlyProbes() ? "GET, HEAD, OPTIONS" : "GET, POST, PUT, PATCH, DELETE",
                WritesSideEffects = !mode.ToReadOnlyProbes(),
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "mass-assignment-scan",
                Description = "Test for mass assignment / parameter pollution vulnerabilities",
                HttpVerbs = "POST, PUT, PATCH",
                WritesSideEffects = true,
                SkippedByCurrentSafetyMode = !mode.AllowsWriteVerbs(),
                SkipReason = !mode.AllowsWriteVerbs() ? "Requires active or aggressive mode" : null
            },
            new DryRunStep
            {
                Name = "bfla-admin-probe",
                Description = "Probe admin/management endpoints as non-admin",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "authz-diff",
                Description = "Cross-identity response comparison to discover BOLA/data leakage (requires peer)",
                HttpVerbs = "GET",
                WritesSideEffects = false,
                SkippedByCurrentSafetyMode = !mode.AllowsProbes(),
                SkipReason = !mode.AllowsProbes() ? "Requires safe mode or above" : null
            },
            new DryRunStep
            {
                Name = "authz-boundary",
                Description = "Confirm unauthorized access using harvested IDs across authorization boundaries",
                HttpVerbs = "GET",
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

        // Step 1: Attack surface analysis (always passive)
        AttackSurfaceResult? surface = null;
        await ctx.RunStepAsync("attack-surface", async _ =>
        {
            surface = ctx.AnalyzeNetworkSurface(host, request.Scope);
            return new Dictionary<string, object?>
            {
                ["endpointsDiscovered"] = surface.Endpoints.Count
            };
        }, ct);

        // Step 2: Security headers (passive)
        var skipHeaders = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "security-headers");
        if (skipHeaders != null)
            ctx.SkipStep("security-headers", skipHeaders);
        else
        await ctx.RunStepAsync("security-headers", async _ =>
        {
            var result = await ctx.Automation.CheckSecurityHeaders();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a01-header-{findingCount}",
                        Source = "orchestrate-a01",
                        Category = NormalizeHeaderCategory(f.Header),
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Missing/weak header: {f.Header}",
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

        // Step 3: Cookie audit (passive)
        var skipCookies = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "cookie-audit");
        if (skipCookies != null)
            ctx.SkipStep("cookie-audit", skipCookies);
        else
        await ctx.RunStepAsync("cookie-audit", async _ =>
        {
            var result = await ctx.Automation.CheckCookieSecurity();
            int findingCount = 0;
            if (result.Findings != null)
            {
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a01-cookie-{findingCount}",
                        Source = "orchestrate-a01",
                        Category = NormalizeCookieCategory(f.Category),
                        Severity = f.Severity.ToString().ToLowerInvariant(),
                        Title = $"Cookie issue: {f.Category} ({f.CookieName})",
                        Endpoint = await ctx.GetCurrentUrlAsync(),
                        Detail = f.Description,
                        Remediation = f.Recommendation,
                        Parameter = f.CookieName
                    });
                    findingCount++;
                }
            }
            return new Dictionary<string, object?> { ["findings"] = findingCount };
        }, ct);

        // Step 4: CSRF scan (requires active mode for POST probes)
        if (ctx.SafetyMode.AllowsWriteVerbs())
        {
            var skipCsrf = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "csrf-scan");
            if (skipCsrf != null)
                ctx.SkipStep("csrf-scan", skipCsrf);
            else
            await ctx.RunStepAsync("csrf-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var result = await ctx.Automation.RunCsrfTest(
                    maxEndpoints: depth.MaxEndpointsPerScanner,
                    hostFilter: host);
                int findingCount = 0;
                foreach (var scenario in result.Scenarios.Where(s => s.Vulnerable))
                {
                    var severity = !string.IsNullOrEmpty(scenario.Severity)
                        ? scenario.Severity
                        : (string.Equals(scenario.Method, "GET", StringComparison.OrdinalIgnoreCase) ? "info" : "medium");
                    // GET CSRF is taxonomy noise vs dedicated CSRF scanner — keep as info only.
                    if (string.Equals(scenario.Method, "GET", StringComparison.OrdinalIgnoreCase)
                        && severity is "medium" or "high")
                        severity = "info";

                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a01-csrf-{findingCount}",
                        Source = "orchestrate-a01",
                        Category = "csrf",
                        Severity = severity,
                        Title = $"CSRF: {scenario.Method} {scenario.Path}",
                        Endpoint = scenario.Url,
                        Method = scenario.Method,
                        Detail = scenario.Description
                    });
                    findingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsTested);
                return new Dictionary<string, object?> { ["findings"] = findingCount };
            }, ct);
        }
        else
        {
            ctx.SkipStep("csrf-scan", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 5: IDOR + mass-assignment + BFLA via AutoScanPipeline
        // Prepare peer info early for budget reservation
        var peerRegistry = ctx.PeerRegistry;
        var hasPeer = peerRegistry != null && peerRegistry.Count > 0;
        // Reserve budget for authz-diff and authz-boundary steps (they need ~60s minimum)
        var reservedForAuthzSeconds = (hasPeer ? 60 : 0) + 30; // 60s for authz-diff, 30s for authz-boundary
        var idorMaxSeconds = Math.Max(30, ctx.Budget.RemainingSeconds - reservedForAuthzSeconds);

        if (ctx.SafetyMode.AllowsProbes())
        {
            await ctx.RunStepAsync("idor-scan", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);
                var options = new AutoScanPipeline.AutoScanOptions
                {
                    Host = host,
                    MaxEndpointsPerScanner = EndpointScopeHelper.CapProbeEndpoints(request.Scope, depth),
                    TimeoutMs = Math.Min(idorMaxSeconds * 1000, 30000),
                    ConfirmBackend = ctx.SafetyMode.ToConfirmBackend(),
                    ScanDepth = depth.AutoScanDepthName,
                    PayloadProfile = request.PayloadProfile,
                    SummarizeFindings = false,
                    IncludeChainAnalysis = false,
                    FindingsMode = "append",
                    MaxStepSeconds = idorMaxSeconds,
                    Budget = ctx.Budget
                };
                options.DisableAllScanners();
                options.IncludeIdor = true;
                options.IncludeMassAssignment = ctx.SafetyMode.AllowsWriteVerbs();
                options.IncludeBflaAdminProbe = true;
                options.IncludeIdorMutatingProbes = ctx.SafetyMode.AllowsWriteVerbs() && ctx.SafetyMode.ToDangerousOk();
                options.IdorReadOnlyProbes = ctx.SafetyMode.ToReadOnlyProbes();
                EndpointScopeHelper.ApplyToAutoScan(options, request.Scope, surface);

                var result = await AutoScanPipeline.RunAsync(ctx.Automation, options, innerCt, ctx.ChainCatalog);
                int findingCount = 0;
                var idorFindingCount = 0;
                var restScaffoldFindingCount = 0;
                foreach (var f in result.Findings)
                {
                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a01-autoscan-{findingCount}",
                        Source = "orchestrate-a01",
                        Category = f.Scanner.ToLowerInvariant(),
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Method = f.Method,
                        Detail = f.Detail,
                        Evidence = f.Evidence
                    });
                    findingCount++;
                    if (f.Scanner.Equals("idor", StringComparison.OrdinalIgnoreCase))
                        idorFindingCount++;
                    else if (f.Scanner.Equals("rest-scaffold", StringComparison.OrdinalIgnoreCase))
                        restScaffoldFindingCount++;
                }
                ctx.Budget.AddRequests(result.EndpointsScanned);
                return new Dictionary<string, object?>
                {
                    ["findings"] = idorFindingCount,
                    ["restScaffoldFindings"] = restScaffoldFindingCount,
                    ["totalAutoScanFindings"] = findingCount,
                    ["endpointsScanned"] = result.EndpointsScanned
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("idor-scan", $"Requires at least safe mode with probes (current: {ctx.SafetyMode.ToLabel()})");
            ctx.SkipStep("mass-assignment-scan", $"Requires active mode (current: {ctx.SafetyMode.ToLabel()})");
            ctx.SkipStep("bfla-admin-probe", $"Requires at least safe mode (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Step 6: Authz-diff — cross-identity response comparison (requires peer)
        List<AuthzDiffFinding> authzDiffFindings = [];

        if (ctx.SafetyMode.AllowsProbes() && hasPeer)
        {
            var skipAuthzDiff = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "authz-diff");
            if (skipAuthzDiff != null)
                ctx.SkipStep("authz-diff", skipAuthzDiff);
            else
            await ctx.RunStepAsync("authz-diff", async innerCt =>
            {
                ctx.Budget.ThrowIfExhausted(innerCt);

                // Collect API endpoints from attack surface for diff comparison
                var diffEndpoints = surface?.Endpoints
                    .Where(ep => ep.Methods.Any(m => m.Equals("GET", StringComparison.OrdinalIgnoreCase)))
                    .Select(ep => ep.Url)
                    .Take(depth.MaxEndpointsPerScanner)
                    .ToList() ?? [];

                if (EndpointScopeHelper.IsEndpointScoped(request.Scope))
                    diffEndpoints = diffEndpoints
                        .Where(u => PlaybookScopeFilter.UrlsMatch(u, request.Scope.TargetUrl!))
                        .Take(1)
                        .ToList();

                if (diffEndpoints.Count == 0)
                {
                    return new Dictionary<string, object?> { ["findings"] = 0, ["skipped"] = "no GET endpoints discovered" };
                }

                var peer = peerRegistry!.GetAll().First();
                int findingCount = 0;
                int endpointsCompared = 0;
                int bolaSuspected = 0;
                int filteredResponse = 0;
                int properlyDenied = 0;

                foreach (var url in diffEndpoints)
                {
                    if (ctx.Budget.IsExhausted) break;
                    innerCt.ThrowIfCancellationRequested();

                    // Local fetch
                    string localJson;
                    try { localJson = await ctx.Automation.Fetch(url, "GET", null, null); }
                    catch { continue; }

                    // Peer fetch via forwarding — ask peer to fetch same URL
                    var fetchBody = System.Text.Json.JsonSerializer.Serialize(new { url, method = "GET" });
                    var peerResult = await peerRegistry!.ForwardAsync(peer.Name, "POST", "/api/fetch-direct", fetchBody,
                        timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(30_000));
                    endpointsCompared++;

                    if (!peerResult.Success) continue;

                    // Parse local response
                    int localStatus = 0, peerStatus = 0;
                    string localBody = "", peerBody = "";
                    try
                    {
                        using var localDoc = System.Text.Json.JsonDocument.Parse(localJson);
                        localStatus = localDoc.RootElement.GetProperty("status").GetInt32();
                        localBody = localDoc.RootElement.TryGetProperty("body", out var lb) ? lb.GetString() ?? "" : "";
                    }
                    catch { continue; }

                    try
                    {
                        using var peerDoc = System.Text.Json.JsonDocument.Parse(peerResult.Body ?? "{}");
                        var data = peerDoc.RootElement.TryGetProperty("data", out var d) ? d : peerDoc.RootElement;
                        peerStatus = data.TryGetProperty("status", out var ps) ? ps.GetInt32() : peerResult.StatusCode;
                        peerBody = data.TryGetProperty("body", out var pb) ? pb.GetString() ?? "" : "";
                    }
                    catch { peerStatus = peerResult.StatusCode; }

                    // Determine verdict
                    string verdict;
                    if (localStatus is >= 200 and < 300 && peerStatus is >= 400)
                    {
                        verdict = "BOLA_SUSPECTED";
                        bolaSuspected++;
                    }
                    else if (localStatus is >= 200 and < 300 && peerStatus is >= 200 and < 300
                             && localBody.Length > 10 && peerBody.Length > 10 && localBody != peerBody)
                    {
                        // Check if this is likely just login-state UI difference on a public page
                        // (nav bar showing username vs login button, cart count, etc.)
                        if (IsLikelyPublicPageWithLoginStateDiff(url, localBody, peerBody))
                        {
                            properlyDenied++; // not a real authz issue
                            continue;
                        }
                        verdict = "FILTERED_RESPONSE";
                        filteredResponse++;
                    }
                    else
                    {
                        properlyDenied++;
                        continue;
                    }

                    var severity = verdict == "BOLA_SUSPECTED" ? "high" : "medium";
                    var category = verdict == "BOLA_SUSPECTED" ? "authz-diff-bola" : "authz-diff-filtered";
                    authzDiffFindings.Add(new AuthzDiffFinding
                    {
                        Url = url, Method = "GET", Verdict = verdict,
                        LocalStatus = localStatus, PeerStatus = peerStatus
                    });

                    ctx.Findings.Add(new ChainableFinding
                    {
                        Id = $"a01-authzdiff-{findingCount}",
                        Source = "orchestrate-a01",
                        Category = category,
                        Severity = severity,
                        Title = $"Authorization diff ({verdict}): {url}",
                        Endpoint = url,
                        Method = "GET",
                        Detail = $"Local: {localStatus}, Peer ({peer.Name}): {peerStatus}. " +
                                 $"Body match: {localBody == peerBody}.",
                        Evidence = localBody.Length > 200 ? localBody[..200] + "..." : localBody,
                        Remediation = "Implement object-level authorization checks. Verify that each request is authorized for the specific resource being accessed.",
                        Reference = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                    });
                    findingCount++;
                }

                ctx.Budget.AddRequests(endpointsCompared * 2); // local + peer
                return new Dictionary<string, object?>
                {
                    ["findings"] = findingCount,
                    ["endpointsCompared"] = endpointsCompared,
                    ["bolaSuspected"] = bolaSuspected,
                    ["filteredResponse"] = filteredResponse,
                    ["properlyDenied"] = properlyDenied
                };
            }, ct);
        }
        else
        {
            ctx.SkipStep("authz-diff", hasPeer
                ? $"Requires safe mode or above (current: {ctx.SafetyMode.ToLabel()})"
                : "No peer registered — register a peer via POST /api/peer/register for cross-identity testing");
        }

        // Step 7: Authz-boundary — confirm unauthorized access with harvested IDs
        if (ctx.SafetyMode.AllowsProbes())
        {
            var skipAuthzBoundary = EndpointScopeHelper.SiteWideSkipReason(request.Scope, "authz-boundary");
            if (skipAuthzBoundary != null)
            {
                ctx.SkipStep("authz-boundary", skipAuthzBoundary);
            }
            else
            {
            // Trigger boundary testing from either authz-diff findings OR harvested IDs from IDOR scan
            var hasAuthzCandidates = authzDiffFindings.Count > 0
                || ctx.Findings.All.Any(f => f.Category is "idor" or "bfla" or "authz-diff-bola");

            if (hasAuthzCandidates)
            {
                await ctx.RunStepAsync("authz-boundary", async innerCt =>
                {
                    ctx.Budget.ThrowIfExhausted(innerCt);

                    // Harvest IDs from network log for boundary testing
                    var harvestResult = await ObjectIdHarvester.RunAsync(
                        ctx.Automation,
                        new ObjectIdHarvester.HarvestOptions(),
                        innerCt);

                    var suggestions = harvestResult.SuggestedBoundaryTests
                        .Take(Math.Min(depth.MaxEndpointsPerScanner, 5))
                        .ToList();

                    if (suggestions.Count == 0)
                    {
                        return new Dictionary<string, object?> { ["findings"] = 0, ["skipped"] = "no boundary test candidates" };
                    }

                    int findingCount = 0;
                    int endpointsTested = 0;

                    foreach (var suggestion in suggestions)
                    {
                        if (ctx.Budget.IsExhausted) break;
                        innerCt.ThrowIfCancellationRequested();

                        // Decode URL-encoded placeholders
                        var urlTemplate = suggestion.UrlTemplate
                            .Replace("%7b", "{").Replace("%7B", "{")
                            .Replace("%7d", "}").Replace("%7D", "}");

                        var parameter = suggestion.Parameter ?? "id";

                        // Get baseline with authorized value
                        if (suggestion.AuthorizedValues.Count == 0 || suggestion.UnauthorizedValues.Count == 0)
                            continue;

                        var authorizedUrl = urlTemplate.Replace($"{{{parameter}}}", suggestion.AuthorizedValues[0]);
                        string baselineJson;
                        try { baselineJson = await ctx.Automation.Fetch(authorizedUrl, suggestion.Method ?? "GET", null, null); }
                        catch { continue; }

                        int baselineStatus;
                        string baselineBody;
                        try
                        {
                            using var doc = System.Text.Json.JsonDocument.Parse(baselineJson);
                            baselineStatus = doc.RootElement.GetProperty("status").GetInt32();
                            baselineBody = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
                        }
                        catch { continue; }

                        // Test with unauthorized values
                        foreach (var unauthorizedValue in suggestion.UnauthorizedValues)
                        {
                            if (ctx.Budget.IsExhausted) break;

                            var testUrl = urlTemplate.Replace($"{{{parameter}}}", unauthorizedValue);
                            string testJson;
                            try { testJson = await ctx.Automation.Fetch(testUrl, suggestion.Method ?? "GET", null, null); }
                            catch { continue; }

                            endpointsTested++;

                            int testStatus;
                            string testBody;
                            try
                            {
                                using var doc = System.Text.Json.JsonDocument.Parse(testJson);
                                testStatus = doc.RootElement.GetProperty("status").GetInt32();
                                testBody = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
                            }
                            catch { continue; }

                            // Determine if unauthorized access was granted
                            string? verdict = null;
                            if (testStatus is >= 200 and < 300 && testBody.Length > 10)
                            {
                                verdict = testBody == baselineBody ? "SAME_RESPONSE" : "ACCESS_GRANTED";
                            }

                            if (verdict != null)
                            {
                                // Check if this is a public resource (blog posts, catalog products)
                                // Enumeration of public content is not true IDOR
                                var isPublicResource = IsLikelyPublicResource(urlTemplate, testBody);
                                var severity = isPublicResource ? "info" : "high";
                                var category = isPublicResource ? "public-enumeration" : "idor";
                                var title = isPublicResource
                                    ? $"Public resource enumeration: {urlTemplate} (param: {parameter})"
                                    : $"Confirmed IDOR: {urlTemplate} (param: {parameter})";

                                ctx.Findings.Add(new ChainableFinding
                                {
                                    Id = $"a01-authzboundary-{findingCount}",
                                    Source = "orchestrate-a01",
                                    Category = category,
                                    Severity = severity,
                                    Title = title,
                                    Endpoint = urlTemplate,
                                    Method = suggestion.Method ?? "GET",
                                    Parameter = parameter,
                                    Detail = $"Unauthorized value '{unauthorizedValue}' returned {testStatus} " +
                                             $"(verdict: {verdict}). {suggestion.Reason}",
                                    Evidence = testBody.Length > 200 ? testBody[..200] + "..." : testBody,
                                    Remediation = "Implement object-level authorization. Verify resource ownership on every request.",
                                    Reference = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                });
                                findingCount++;
                            }
                        }
                        ctx.Budget.AddRequests(1 + suggestion.UnauthorizedValues.Count); // baseline + tests
                    }

                    return new Dictionary<string, object?>
                    {
                        ["findings"] = findingCount,
                        ["endpointsTested"] = endpointsTested,
                        ["suggestionsAvailable"] = harvestResult.SuggestedBoundaryTests.Count
                    };
                }, ct);
            }
            else
            {
                ctx.SkipStep("authz-boundary", "No IDOR/BOLA candidates from authz-diff or IDOR scan to confirm");
            }
            }
        }
        else
        {
            ctx.SkipStep("authz-boundary", $"Requires safe mode or above (current: {ctx.SafetyMode.ToLabel()})");
        }

        // Build next actions
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

    /// <summary>Intermediate finding from authz-diff for boundary test candidate selection.</summary>
    private sealed class AuthzDiffFinding
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Verdict { get; init; } = "";
        public int LocalStatus { get; init; }
        public int PeerStatus { get; init; }
    }

    /// <summary>
    /// Detects whether a response body difference is likely just login-state UI
    /// (nav bar showing username vs login button) on a public page.
    /// </summary>
    private static bool IsLikelyPublicPageWithLoginStateDiff(string url, string localBody, string peerBody)
    {
        // Public pages that commonly differ only in login state
        var path = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.AbsolutePath : url;
        var publicPaths = new[] { "/", "/about", "/blog", "/catalog", "/login", "/logout",
            "/register", "/signup", "/contact", "/help", "/faq", "/terms", "/privacy" };
        var isPublicPath = publicPaths.Any(p => path.Equals(p, StringComparison.OrdinalIgnoreCase)
                                               || path.StartsWith(p + "/", StringComparison.OrdinalIgnoreCase)
                                               || path.StartsWith(p + "?", StringComparison.OrdinalIgnoreCase));
        if (!isPublicPath) return false;

        // If the body difference is small relative to total size, it's likely just nav/header changes
        var shorter = Math.Min(localBody.Length, peerBody.Length);
        var longer = Math.Max(localBody.Length, peerBody.Length);
        if (shorter == 0) return false;
        var lengthRatio = (double)shorter / longer;
        // If bodies are >90% similar in length AND both are HTML pages, likely login-state diff
        return lengthRatio > 0.85;
    }

    /// <summary>
    /// Detects whether a URL template points to a publicly accessible resource
    /// (blog posts, products, articles) where enumeration is expected behavior, not IDOR.
    /// </summary>
    private static bool IsLikelyPublicResource(string urlTemplate, string responseBody)
    {
        var lower = urlTemplate.ToLowerInvariant();
        var publicNouns = new[] { "/blog", "/post", "/article", "/catalog", "/product",
            "/category", "/page", "/news", "/event", "/faq", "/doc", "/help" };
        var matchesPublicNoun = publicNouns.Any(n => lower.Contains(n));
        if (!matchesPublicNoun) return false;

        // If the response doesn't contain user-specific or sensitive data indicators, it's public
        var bodyLower = responseBody.ToLowerInvariant();
        var sensitiveIndicators = new[] { "email", "password", "ssn", "credit_card", "creditcard",
            "phone_number", "address", "salary", "balance", "secret" };
        return !sensitiveIndicators.Any(s => bodyLower.Contains(s));
    }

    private static List<NextAction> BuildNextActions(PlaybookContext ctx)
    {
        var actions = new List<NextAction>();

        bool hasCsrf = ctx.Findings.All.Any(f => f.Category == "csrf");
        bool hasIdor = ctx.Findings.All.Any(f => f.Category is "idor" or "bfla");

        if (hasIdor)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a07-authn",
                Rationale = "IDOR/BFLA findings suggest weak authorization — test authentication flows."
            });
        }

        if (hasCsrf)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a02-misconfig",
                Rationale = "CSRF findings may be worsened by CORS misconfiguration."
            });
        }

        if (ctx.Findings.Count > 0)
        {
            actions.Add(new NextAction
            {
                Action = "run-playbook",
                PlaybookId = "a05-injection",
                Rationale = "Access control issues combined with injection can lead to full compromise."
            });
        }

        return actions;
    }

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

    private static string NormalizeCookieCategory(string? issue) => (issue ?? "").ToLowerInvariant() switch
    {
        string s when s.Contains("httponly") => "missing-httponly",
        string s when s.Contains("secure") => "missing-secure-flag",
        "samesitenone" or "samesitenoneinsecure" => "missing-samesite",
        string s when s.Contains("samesite") && s.Contains("none") => "missing-samesite",
        _ => "weak-cookies"
    };
}
