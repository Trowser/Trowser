using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Robustness;

/// <summary>
/// TrowserInterrupter: auto-discovers API calls from the network log, injects faults
/// via mocks, reloads the page, and reports deterministic pass/fail per scenario.
/// No LLM in the test loop — evaluation uses hard technical signals only.
/// </summary>
public class InterrupterTester
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private static readonly FaultPreset[] AllFaultPresets =
    [
        new()
        {
            Name = "server-error",
            Description = "HTTP 500 Internal Server Error",
            StatusCode = 500,
            Body = "{\"error\":\"Internal Server Error\"}",
        },
        new()
        {
            Name = "not-found",
            Description = "HTTP 404 Not Found",
            StatusCode = 404,
            Body = "{\"error\":\"Not Found\"}",
        },
        new()
        {
            Name = "empty-body",
            Description = "HTTP 200 with empty response body",
            StatusCode = 200,
            Body = "",
        },
        new()
        {
            Name = "invalid-json",
            Description = "HTTP 200 with malformed JSON body",
            StatusCode = 200,
            Body = "not valid json{{{",
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" },
        },
        new()
        {
            Name = "slow-response",
            Description = "HTTP 200 with 5-second delay",
            StatusCode = 200,
            DelayMs = 5000,
        },
        new()
        {
            Name = "unauthorized",
            Description = "HTTP 401 Unauthorized — verifies auth failure removes sensitive data from the UI",
            StatusCode = 401,
            Body = "{\"error\":\"Unauthorized\"}",
        },
        new()
        {
            Name = "forbidden",
            Description = "HTTP 403 Forbidden — verifies permission denial is handled with a redirect or clear message",
            StatusCode = 403,
            Body = "{\"error\":\"Forbidden\"}",
        },
        new()
        {
            Name = "rate-limited",
            Description = "HTTP 429 Too Many Requests — verifies the app handles throttling gracefully",
            StatusCode = 429,
            Body = "{\"error\":\"Too Many Requests\",\"retryAfter\":60}",
            Headers = new Dictionary<string, string> { ["Retry-After"] = "60" },
        },
        new()
        {
            Name = "mutate-response",
            Description = "HTTP 200 with corrupted version of the original response body — verifies the app handles malformed data",
            StatusCode = 200,
            IsMutation = true,
        },
    ];

    private static readonly HashSet<string> StaticResourceTypes =
        new(StringComparer.OrdinalIgnoreCase) { "Image", "Media", "Font", "Stylesheet", "Script" };

    private static readonly HashSet<string> StaticExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        { ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map" };

    private static readonly string[] ErrorPagePatterns =
    [
        "internal server error", "500 internal", "404 not found", "403 forbidden",
        "502 bad gateway", "503 service unavailable", "error occurred",
        "something went wrong", "page not found", "access denied",
    ];

    private static readonly string[] ApiPathPatterns =
    [
        "/api/", "/api.", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/",
        "/json", "/rpc", "/ws/", "/webhook", "/callback", "/odata/",
    ];

    private static readonly Regex GuidIdRegex = new(
        @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        RegexOptions.Compiled);
    private static readonly Regex NumericIdRegex = new(
        @"^\d{1,10}$", RegexOptions.Compiled);
    private static readonly Regex MongoIdRegex = new(
        @"^[0-9a-fA-F]{24}$", RegexOptions.Compiled);
    private static readonly Regex AlphanumIdRegex = new(
        @"^[a-zA-Z0-9_-]{8,36}$", RegexOptions.Compiled);

    public InterrupterTester(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<InterrupterResult> RunAsync(InterrupterOptions? options = null)
    {
        options ??= new InterrupterOptions();
        var startTime = DateTime.UtcNow;
        var startUrl = await _ctx.GetCurrentUrl();
        var scenarios = new List<InterrupterScenario>();
        var parameterScenarios = new List<ParameterTamperScenario>();

        if (options.WaitForIdle)
        {
            _log("TrowserInterrupter: waiting for network idle before discovery...", "#888888");
            await _ctx.WaitForIdle(quietPeriodMs: 2000, timeoutMs: 15000);
        }

        var endpoints = DiscoverEndpoints(options, startUrl);
        var faults = GetFaultPresets(options);
        var totalScenarios = endpoints.Count * faults.Count;

        _log($"TrowserInterrupter: {endpoints.Count} endpoint(s), {faults.Count} fault(s) = {totalScenarios} scenario(s)", "#888888");
        if (options.Actions is { Count: > 0 })
            _log($"  Action replay: {options.Actions.Count} action(s) after each reload", "#888888");
        if (options.CooldownMs > 0)
            _log($"  Cooldown: {options.CooldownMs}ms between scenarios", "#888888");

        try
        {
            var scenarioIndex = 0;
            foreach (var endpoint in endpoints)
            {
                foreach (var fault in faults)
                {
                    scenarioIndex++;
                    _log($"  [{scenarioIndex}/{totalScenarios}] {endpoint.Method} {endpoint.UrlPattern} + {fault.Name}", "#888888");

                    var scenario = await RunScenario(startUrl, endpoint, fault, options.Actions);
                    scenarios.Add(scenario);

                    string statusColor, statusText;
                    if (!scenario.Passed)
                    {
                        statusColor = "#F44747";
                        var errorCount = scenario.Signals.Count(s => s.Severity == SignalSeverity.Error);
                        statusText = $"FAIL ({errorCount} error(s))";
                    }
                    else if (scenario.HasWarnings)
                    {
                        statusColor = "#CCCC00";
                        statusText = $"PASS ({scenario.Signals.Count} warning(s))";
                    }
                    else
                    {
                        statusColor = "#4EC9B0";
                        statusText = "PASS";
                    }
                    _log($"    {statusText}", statusColor);

                    if (options.CooldownMs > 0 && scenarioIndex < totalScenarios)
                        await Task.Delay(options.CooldownMs);
                }
            }
        }
        finally
        {
            _ctx.ClearMocks();
        }

        // Restore the original page and detect login redirects
        string? finalUrl = null;
        bool loginRedirectDetected = false;
        string? restoreError = null;

        if (options.RestoreUrl)
        {
            try
            {
                await ClearDomainCookies(startUrl);
                await _ctx.Navigate(startUrl);
                await _ctx.WaitForIdle(quietPeriodMs: 1000, timeoutMs: 5000);

                finalUrl = await _ctx.GetCurrentUrl();

                if (finalUrl != null && !finalUrl.Equals(startUrl, StringComparison.OrdinalIgnoreCase))
                {
                    var finalLower = finalUrl.ToLowerInvariant();
                    loginRedirectDetected = finalLower.Contains("login") || finalLower.Contains("signin") ||
                        finalLower.Contains("auth") || finalLower.Contains("sso") ||
                        finalLower.Contains("saml") || finalLower.Contains("oauth") ||
                        finalLower.Contains("adfs") || finalLower.Contains("idp");

                    if (loginRedirectDetected)
                    {
                        _log($"  WARNING: Page redirected to login ({finalUrl}). Session may have been disrupted by fault injection.", "#CCCC00");
                    }
                }
            }
            catch (Exception ex)
            {
                restoreError = ex.Message;
                _log($"  WARNING: Failed to restore original page: {ex.Message}", "#CCCC00");
            }
        }

        if (options.TestParameters && endpoints.Count > 0)
        {
            try
            {
                parameterScenarios = await RunParameterTampering(endpoints);
            }
            catch (Exception ex)
            {
                _log($"  Parameter tampering error: {ex.Message}", "#F44747");
            }
        }

        var elapsed = (DateTime.UtcNow - startTime).TotalSeconds;

        return new InterrupterResult
        {
            StartUrl = startUrl,
            Timestamp = startTime,
            DurationSeconds = elapsed,
            EndpointsTested = endpoints.Count,
            DiscoveredEndpoints = endpoints,
            Scenarios = scenarios,
            ParameterScenarios = parameterScenarios,
            Options = options,
            FinalUrl = finalUrl,
            LoginRedirectDetected = loginRedirectDetected,
            RestoreError = restoreError,
        };
    }

    private List<DiscoveredEndpoint> DiscoverEndpoints(InterrupterOptions options, string pageUrl)
    {
        if (!string.IsNullOrEmpty(options.Url))
        {
            return
            [
                new DiscoveredEndpoint
                {
                    UrlPattern = options.Url,
                    Method = options.Method ?? "*",
                    OriginalUrl = options.Url,
                    RelevanceScore = 100,
                }
            ];
        }

        var pageHost = GetHost(pageUrl);
        var allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(pageHost))
            allowedHosts.Add(pageHost);
        if (options.AllowedHosts is { Count: > 0 })
            foreach (var h in options.AllowedHosts)
                allowedHosts.Add(h);

        var entries = _ctx.Network.Entries;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<DiscoveredEndpoint>();

        foreach (var entry in entries)
        {
            if (StaticResourceTypes.Contains(entry.ResourceType))
                continue;

            if (entry.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) && IsStaticAsset(entry.Url))
                continue;

            if (!string.IsNullOrEmpty(options.Method) &&
                !entry.Method.Equals(options.Method, StringComparison.OrdinalIgnoreCase))
                continue;

            var entryHost = GetHost(entry.Url);
            if (!string.IsNullOrEmpty(entryHost) && !IsDiscoveryHostAllowed(entryHost, pageHost, allowedHosts))
                continue;

            var pathOnly = GetPathWithoutQuery(entry.Url);
            var key = $"{entry.Method}|{entryHost}|{pathOnly}";

            if (!seen.Add(key))
                continue;

            var score = ScoreEndpoint(entry, pageHost);

            candidates.Add(new DiscoveredEndpoint
            {
                UrlPattern = pathOnly,
                Method = entry.Method,
                OriginalUrl = entry.Url,
                ResponseBody = entry.ResponseBody,
                ContentType = entry.ContentType,
                ResourceType = entry.ResourceType,
                RelevanceScore = score,
            });
        }

        if (options.MergeAttackSurface)
            MergeAttackSurfaceEndpoints(candidates, seen, options, pageHost, allowedHosts);

        return candidates
            .Where(e => e.RelevanceScore >= options.MinRelevanceScore)
            .OrderByDescending(e => e.RelevanceScore)
            .ThenBy(e => e.UrlPattern, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.Method, StringComparer.OrdinalIgnoreCase)
            .Take(options.MaxEndpoints)
            .ToList();
    }

    private void MergeAttackSurfaceEndpoints(
        List<DiscoveredEndpoint> candidates,
        HashSet<string> seen,
        InterrupterOptions options,
        string? pageHost,
        HashSet<string> allowedHosts)
    {
        if (_ctx.Network.Entries.Count == 0)
            return;

        var mapper = new AttackSurfaceMapper();
        // Do not pass hostFilter: extra origins in allowedHosts must still surface here; filter per-endpoint below.
        var surface = mapper.Analyze(_ctx.Network.Entries.ToList(), hostFilter: null);

        foreach (var ep in surface.Endpoints)
        {
            foreach (var method in ep.Methods)
            {
                if (method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase) ||
                    method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!string.IsNullOrEmpty(options.Method) &&
                    !method.Equals(options.Method, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
                    continue;

                var entryHost = uri.Host;
                if (!string.IsNullOrEmpty(entryHost) && !IsDiscoveryHostAllowed(entryHost, pageHost, allowedHosts))
                    continue;

                var pathOnly = uri.AbsolutePath;
                var key = $"{method}|{entryHost}|{pathOnly}";
                if (!seen.Add(key))
                    continue;

                var score = ScoreAttackSurfaceEndpoint(ep, method, pageHost);
                candidates.Add(new DiscoveredEndpoint
                {
                    UrlPattern = pathOnly,
                    Method = method,
                    OriginalUrl = ep.Url,
                    ResponseBody = null,
                    ContentType = "",
                    ResourceType = "",
                    RelevanceScore = score,
                });
            }
        }
    }

    private static int ScoreAttackSurfaceEndpoint(AttackSurfaceEndpoint ep, string method, string? pageHost)
    {
        var score = 45 + ScoreFromAttackSurfacePriority(ep.TestPriority);
        var path = GetPathWithoutQuery(ep.Url).ToLowerInvariant();
        if (ApiPathPatterns.Any(p => path.Contains(p)))
            score += 12;
        if (method.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
            method.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
            method.Equals("PATCH", StringComparison.OrdinalIgnoreCase) ||
            method.Equals("DELETE", StringComparison.OrdinalIgnoreCase))
            score += 8;
        if (path.Contains("socket.io", StringComparison.OrdinalIgnoreCase))
            score -= 14;
        var entryHost = GetHost(ep.Url);
        if (!string.IsNullOrEmpty(pageHost) && !string.IsNullOrEmpty(entryHost) &&
            entryHost.Equals(pageHost, StringComparison.OrdinalIgnoreCase))
            score += 5;
        else if (!string.IsNullOrEmpty(pageHost) && !string.IsNullOrEmpty(entryHost) &&
                 string.Equals(BaseDomainHeuristic(entryHost), BaseDomainHeuristic(pageHost), StringComparison.OrdinalIgnoreCase))
            score += 3;
        return Math.Clamp(score, 0, 100);
    }

    private static int ScoreFromAttackSurfacePriority(string p) => p.ToLowerInvariant() switch
    {
        "critical" => 25,
        "high" => 18,
        "medium" => 10,
        "low" => 2,
        _ => 6
    };

    /// <summary>
    /// Score an endpoint 0-100 based on how likely it is to be an important API call.
    /// Higher = more interesting to test. Used to rank discovered endpoints before capping at maxEndpoints.
    /// </summary>
    private static int ScoreEndpoint(Automation.NetworkEntry entry, string? pageHost)
    {
        var path = GetPathWithoutQuery(entry.Url).ToLowerInvariant();
        var hasApiPath = ApiPathPatterns.Any(p => path.Contains(p));
        var score = 58;

        if (entry.ResourceType.Equals("Fetch", StringComparison.OrdinalIgnoreCase) ||
            entry.ResourceType.Equals("XHR", StringComparison.OrdinalIgnoreCase))
            score += 15;
        else if (entry.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase))
            score += hasApiPath ? 12 : 2;
        else if (entry.ResourceType.Equals("Other", StringComparison.OrdinalIgnoreCase))
            score += 10;

        var ct = entry.ContentType.ToLowerInvariant();
        if (ct.Contains("application/json") || ct.Contains("text/json"))
            score += 15;
        else if (ct.Contains("application/xml") || ct.Contains("text/xml"))
            score += 10;
        else if (string.IsNullOrEmpty(ct) && hasApiPath)
            score += 14;
        else if (ct.Contains("text/html"))
            score -= 4;

        var method = entry.Method.ToUpperInvariant();
        if (method is "POST" or "PUT" or "PATCH" or "DELETE")
            score += 10;

        if (hasApiPath)
            score += 10;

        if (entry.IsSuccess)
            score += 6;

        var entryHost = GetHost(entry.Url);
        if (!string.IsNullOrEmpty(pageHost) && !string.IsNullOrEmpty(entryHost) &&
            entryHost.Equals(pageHost, StringComparison.OrdinalIgnoreCase))
            score += 5;
        else if (!string.IsNullOrEmpty(pageHost) && !string.IsNullOrEmpty(entryHost) &&
                 string.Equals(BaseDomainHeuristic(entryHost), BaseDomainHeuristic(pageHost), StringComparison.OrdinalIgnoreCase))
            score += 3;

        if (!string.IsNullOrEmpty(entry.ResponseBody))
            score += 5;

        if (path.Contains("socket.io", StringComparison.OrdinalIgnoreCase))
            score -= 16;

        return Math.Clamp(score, 0, 100);
    }

    /// <summary>
    /// Same-origin or same registrable host (last two labels) as the page, or an explicitly allowed host.
    /// </summary>
    private static bool IsDiscoveryHostAllowed(string entryHost, string? pageHost, HashSet<string> allowedHosts)
    {
        if (allowedHosts.Count == 0)
            return true;
        if (IsHostAllowed(entryHost, allowedHosts))
            return true;
        if (string.IsNullOrEmpty(pageHost))
            return false;
        return string.Equals(BaseDomainHeuristic(entryHost), BaseDomainHeuristic(pageHost), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Naive eTLD+1-style grouping (last two DNS labels) — good enough to pair www. with api. on typical domains.</summary>
    private static string BaseDomainHeuristic(string host)
    {
        var parts = host.Split('.');
        if (parts.Length < 2)
            return host;
        return string.Join(".", parts[^2], parts[^1]);
    }

    private static string MockUrlMatchPattern(DiscoveredEndpoint endpoint) =>
        !string.IsNullOrEmpty(endpoint.OriginalUrl) ? endpoint.OriginalUrl : endpoint.UrlPattern;

    private static bool IsHostAllowed(string host, HashSet<string> allowedHosts)
    {
        if (allowedHosts.Contains(host)) return true;
        foreach (var allowed in allowedHosts)
            if (host.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static string? GetHost(string url)
    {
        try { return new Uri(url).Host; }
        catch { return null; }
    }

    private static List<FaultPreset> GetFaultPresets(InterrupterOptions options)
    {
        var result = new List<FaultPreset>();

        if (options.Faults == null || options.Faults.Count == 0)
        {
            // No filter — include original 5 presets for backward compat (not the new security ones by default)
            result.AddRange(AllFaultPresets.Take(5));
        }
        else
        {
            var requested = new HashSet<string>(options.Faults, StringComparer.OrdinalIgnoreCase);
            result.AddRange(AllFaultPresets.Where(f => requested.Contains(f.Name)));
        }

        // #1: Merge custom faults
        if (options.CustomFaults is { Count: > 0 })
        {
            foreach (var cf in options.CustomFaults)
            {
                if (string.IsNullOrWhiteSpace(cf.Name)) continue;
                result.Add(new FaultPreset
                {
                    Name = cf.Name,
                    Description = $"Custom: HTTP {cf.Status}{(cf.Body != null ? $" — {TruncateBody(cf.Body, 60)}" : "")}",
                    StatusCode = cf.Status,
                    Body = cf.Body,
                    Headers = cf.Headers,
                    DelayMs = cf.DelayMs,
                });
            }
        }

        return result;
    }

    private async Task<InterrupterScenario> RunScenario(
        string pageUrl, DiscoveredEndpoint endpoint, FaultPreset fault, List<InterrupterAction>? actions)
    {
        var signals = new List<InterrupterSignal>();

        _ctx.Console.Clear();

        var baselineErrors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in _ctx.Console.GetErrors())
            baselineErrors.Add(e.Message);

        // #6: Capture baseline page text for content-change detection
        string? baselineText = null;
        try
        {
            baselineText = await _ctx.GetPageText();
        }
        catch { /* baseline capture failure is non-fatal */ }

        var mockMethod = endpoint.Method == "*" ? null : endpoint.Method;
        var mockBody = fault.IsMutation
            ? MutateResponseBody(endpoint.ResponseBody)
            : fault.Body ?? endpoint.ResponseBody ?? "";
        var mockMatch = MockUrlMatchPattern(endpoint);
        _ctx.MockResponse(mockMatch, fault.StatusCode, mockBody, mockMethod, fault.Headers, fault.DelayMs);

        try
        {
            _ctx.Console.Clear();
            _ctx.Network.Clear();

            await _ctx.Navigate(pageUrl);
            await _ctx.WaitForIdle(quietPeriodMs: 1000, timeoutMs: 10000);

            // #7: Replay user actions after reload (for user-triggered endpoints)
            if (actions is { Count: > 0 })
            {
                await ReplayActions(actions);
                await _ctx.WaitForIdle(quietPeriodMs: 1000, timeoutMs: 10000);
            }

            signals.AddRange(CollectConsoleErrorSignals(baselineErrors));
            signals.AddRange(await CollectBlankPageSignals());
            signals.AddRange(CollectNetworkErrorSignals(mockMatch));
            signals.AddRange(await CollectContentChangeSignals(baselineText));
            signals.AddRange(await CollectErrorPageSignals());
        }
        catch (Exception ex)
        {
            signals.Add(new InterrupterSignal
            {
                Type = "test-error",
                Message = $"Exception during scenario: {ex.Message}",
            });
        }
        finally
        {
            _ctx.RemoveMock(mockMatch);
        }

        ClassifySignalSeverity(signals, fault);

        return new InterrupterScenario
        {
            Endpoint = endpoint.UrlPattern,
            OriginalUrl = endpoint.OriginalUrl,
            Method = endpoint.Method,
            FaultName = fault.Name,
            FaultDescription = fault.Description,
            Signals = signals,
        };
    }

    private async Task<List<ParameterTamperScenario>> RunParameterTampering(List<DiscoveredEndpoint> endpoints)
    {
        const int maxVariants = 20;
        var allVariants = new List<(DiscoveredEndpoint ep, string url, string tamperType, string desc)>();

        foreach (var endpoint in endpoints)
        {
            foreach (var (url, tamperType, desc) in GenerateTamperedUrls(endpoint.OriginalUrl))
                allVariants.Add((endpoint, url, tamperType, desc));
        }

        if (allVariants.Count == 0) return [];

        if (allVariants.Count > maxVariants)
        {
            _log($"  Capping to {maxVariants} variant(s) (from {allVariants.Count})", "#888888");
            allVariants = allVariants.Take(maxVariants).ToList();
        }

        var endpointCount = allVariants.Select(v => v.ep.OriginalUrl).Distinct().Count();
        _log($"TrowserInterrupter: parameter tampering — {allVariants.Count} variant(s) from {endpointCount} endpoint(s)", "#888888");

        var scenarios = new List<ParameterTamperScenario>();
        for (int i = 0; i < allVariants.Count; i++)
        {
            var (ep, url, tamperType, desc) = allVariants[i];
            _log($"  [{i + 1}/{allVariants.Count}] {tamperType}: {GetPathWithoutQuery(url)}", "#888888");

            var scenario = await RunParameterTamperScenario(ep, url, tamperType, desc);
            scenarios.Add(scenario);
        }

        return scenarios;
    }

    private async Task<ParameterTamperScenario> RunParameterTamperScenario(
        DiscoveredEndpoint endpoint, string tamperedUrl, string tamperType, string description)
    {
        var signals = new List<InterrupterSignal>();
        int status = 0;
        string? statusText = null;

        try
        {
            var method = endpoint.Method == "*" ? "GET" : endpoint.Method;
            var responseJson = await _ctx.Fetch(tamperedUrl, method, null, null, 8000);

            using var doc = System.Text.Json.JsonDocument.Parse(responseJson);
            status = doc.RootElement.GetProperty("status").GetInt32();
            statusText = doc.RootElement.GetProperty("statusText").GetString();

            if (status >= 500)
            {
                signals.Add(new InterrupterSignal
                {
                    Type = "server-error",
                    Message = $"Server returned {status} {statusText} for tampered request",
                    Severity = SignalSeverity.Error,
                });
            }
            else if (status >= 200 && status < 300 && tamperType.StartsWith("invalid"))
            {
                signals.Add(new InterrupterSignal
                {
                    Type = "unexpected-success",
                    Message = $"Server returned {status} for {tamperType} — may indicate missing input validation",
                    Severity = SignalSeverity.Warning,
                });
            }
        }
        catch (Exception ex)
        {
            signals.Add(new InterrupterSignal
            {
                Type = "test-error",
                Message = $"Fetch failed: {ex.Message}",
            });
        }

        string statusColor, statusLabel;
        if (signals.Any(s => s.Severity == SignalSeverity.Error))
        {
            statusColor = "#F44747";
            statusLabel = "FAIL";
        }
        else if (signals.Count > 0)
        {
            statusColor = "#CCCC00";
            statusLabel = "WARN";
        }
        else
        {
            statusColor = "#4EC9B0";
            statusLabel = "OK";
        }
        _log($"    {statusLabel}: -> {status} {statusText}", statusColor);

        return new ParameterTamperScenario
        {
            OriginalUrl = endpoint.OriginalUrl,
            TamperedUrl = tamperedUrl,
            Method = endpoint.Method == "*" ? "GET" : endpoint.Method,
            TamperType = tamperType,
            Description = description,
            ResponseStatus = status,
            ResponseStatusText = statusText,
            Signals = signals,
        };
    }

    // #7: Execute a list of InterrupterActions against the live page
    private async Task ReplayActions(List<InterrupterAction> actions)
    {
        foreach (var act in actions)
        {
            var selector = ResolveActionSelector(act);
            try
            {
                switch (act.Action.ToLowerInvariant())
                {
                    case "click":
                        if (selector == null) break;
                        await _ctx.Click(selector);
                        break;
                    case "type":
                        if (selector == null) break;
                        await _ctx.Type(selector, act.Text ?? "");
                        break;
                    case "select":
                        if (selector == null) break;
                        await _ctx.Select(selector, act.Value ?? "");
                        break;
                    case "hover":
                        if (selector == null) break;
                        await _ctx.Hover(selector);
                        break;
                    case "press_key" or "presskey" or "key":
                        await _ctx.PressKey(act.Key ?? act.Text ?? "Enter", selector);
                        break;
                    case "scroll":
                        await _ctx.Scroll(selector, act.Value ?? "down", scrollIntoView: selector != null);
                        break;
                    case "wait" or "sleep":
                        var delayMs = act.DelayMs > 0 ? act.DelayMs : 1000;
                        await Task.Delay(delayMs);
                        break;
                }
            }
            catch (Exception ex)
            {
                _log($"    Action replay error ({act.Action}): {ex.Message}", "#F44747");
            }
        }
    }

    /// <summary>
    /// Resolve a selector string from an InterrupterAction using semantic locators.
    /// Priority: ref > selector > byText > placeholder > role+name > label > testId.
    /// </summary>
    private string? ResolveActionSelector(InterrupterAction act)
    {
        if (act.Ref.HasValue)
        {
            var sel = _ctx.GetSelectorByRef(act.Ref.Value);
            if (sel != null) return sel;
        }
        if (!string.IsNullOrEmpty(act.Selector)) return act.Selector;
        if (!string.IsNullOrEmpty(act.ByText)) return $"@text:{act.ByText}";
        if (!string.IsNullOrEmpty(act.Placeholder)) return $"@placeholder:{act.Placeholder}";
        if (!string.IsNullOrEmpty(act.Role))
        {
            var name = act.Name ?? "";
            return $"@role:{act.Role}:{name}";
        }
        if (!string.IsNullOrEmpty(act.Label)) return $"@label:{act.Label}";
        if (!string.IsNullOrEmpty(act.TestId)) return $"@testid:{act.TestId}";
        return null;
    }

    private List<InterrupterSignal> CollectConsoleErrorSignals(HashSet<string> baselineErrors)
    {
        var signals = new List<InterrupterSignal>();
        var pageErrors = _ctx.Console.GetPageErrors();

        foreach (var error in pageErrors)
        {
            if (baselineErrors.Contains(error.Message))
                continue;

            var isUncaught = error.Message.Contains("Uncaught", StringComparison.OrdinalIgnoreCase)
                          || error.Message.Contains("unhandled", StringComparison.OrdinalIgnoreCase);

            signals.Add(new InterrupterSignal
            {
                Type = isUncaught ? "uncaught-exception" : "console-error",
                Message = error.Message,
                Source = error.Source,
            });
        }

        return signals;
    }

    private async Task<List<InterrupterSignal>> CollectBlankPageSignals()
    {
        var signals = new List<InterrupterSignal>();

        try
        {
            var pageText = await _ctx.GetPageText();
            if (string.IsNullOrWhiteSpace(pageText) || pageText.Trim().Length < 10)
            {
                signals.Add(new InterrupterSignal
                {
                    Type = "blank-page",
                    Message = pageText.Trim().Length == 0
                        ? "Page is completely blank after fault injection"
                        : $"Page has minimal content ({pageText.Trim().Length} chars) after fault injection",
                });
            }
        }
        catch
        {
            signals.Add(new InterrupterSignal
            {
                Type = "blank-page",
                Message = "Could not read page text (page may have crashed)",
            });
        }

        return signals;
    }

    private List<InterrupterSignal> CollectNetworkErrorSignals(string mockedUrlPattern)
    {
        var signals = new List<InterrupterSignal>();
        var pageErrors = _ctx.Network.FindPageErrors();

        foreach (var error in pageErrors)
        {
            if (error.Url.Contains(mockedUrlPattern, StringComparison.OrdinalIgnoreCase))
                continue;

            signals.Add(new InterrupterSignal
            {
                Type = "network-error",
                Message = $"{error.Method} {error.Url} -> {error.StatusCode} {error.ReasonPhrase}",
                Source = error.Url,
            });
        }

        return signals;
    }

    // #6: Detect significant content change by comparing page text against pre-fault baseline
    private async Task<List<InterrupterSignal>> CollectContentChangeSignals(string? baselineText)
    {
        var signals = new List<InterrupterSignal>();
        if (baselineText == null) return signals;

        try
        {
            var currentText = await _ctx.GetPageText();
            if (currentText == null) return signals;

            var baselineNorm = NormalizeForComparison(baselineText);
            var currentNorm = NormalizeForComparison(currentText);

            if (baselineNorm == currentNorm) return signals;

            // Jaccard-like similarity on word sets — detects wholesale content replacement
            var baselineWords = new HashSet<string>(baselineNorm.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
            var currentWords = new HashSet<string>(currentNorm.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);

            if (baselineWords.Count == 0 || currentWords.Count == 0) return signals;

            var intersection = new HashSet<string>(baselineWords, StringComparer.OrdinalIgnoreCase);
            intersection.IntersectWith(currentWords);
            var union = new HashSet<string>(baselineWords, StringComparer.OrdinalIgnoreCase);
            union.UnionWith(currentWords);

            var similarity = union.Count > 0 ? (double)intersection.Count / union.Count : 1.0;

            // Less than 50% overlap = significant content change (likely an error page replaced the real content)
            if (similarity < 0.50)
            {
                var preview = currentText.Trim();
                if (preview.Length > 150) preview = preview[..147] + "...";
                signals.Add(new InterrupterSignal
                {
                    Type = "content-changed",
                    Message = $"Page content significantly changed after fault injection (similarity {similarity:P0}). Current text: {preview}",
                });
            }
        }
        catch { /* non-fatal */ }

        return signals;
    }

    // #6: Detect error pages by checking URL/title/body for common error patterns
    private async Task<List<InterrupterSignal>> CollectErrorPageSignals()
    {
        var signals = new List<InterrupterSignal>();

        try
        {
            var url = await _ctx.GetCurrentUrl();
            var title = await _ctx.GetTitle();
            var combined = $"{url} {title}".ToLowerInvariant();

            foreach (var pattern in ErrorPagePatterns)
            {
                if (combined.Contains(pattern))
                {
                    signals.Add(new InterrupterSignal
                    {
                        Type = "error-page",
                        Message = $"URL or title matches error pattern \"{pattern}\": title=\"{title}\"",
                        Source = url,
                    });
                    break;
                }
            }
        }
        catch { /* non-fatal */ }

        return signals;
    }

    /// <summary>
    /// Downgrade signals to Warning severity when the detected behavior is expected
    /// given the fault that was injected. Uncaught exceptions are always real errors.
    /// </summary>
    private static void ClassifySignalSeverity(List<InterrupterSignal> signals, FaultPreset fault)
    {
        var isDataCorruptionFault = fault.Name is "empty-body" or "invalid-json" or "mutate-response";
        var isClientErrorFault = fault.StatusCode >= 400 && fault.StatusCode < 500;

        foreach (var signal in signals)
        {
            if (signal.Type is "uncaught-exception" or "test-error")
                continue;

            // Apps commonly log fetch failures to console — that's error handling, not a bug
            if (signal.Type == "console-error")
            {
                signal.Severity = SignalSeverity.Warning;
                continue;
            }

            // Cascading network errors: only 500+ is a real backend bug, 4xx is expected degradation
            if (signal.Type == "network-error")
            {
                var statusMatch = Regex.Match(signal.Message, @"-> (\d+)");
                if (statusMatch.Success && int.TryParse(statusMatch.Groups[1].Value, out var httpStatus) && httpStatus < 500)
                    signal.Severity = SignalSeverity.Warning;
                continue;
            }

            // For 4xx faults: showing an error page or changed content is expected behavior
            if (isClientErrorFault && signal.Type is "error-page" or "content-changed")
            {
                signal.Severity = SignalSeverity.Warning;
                continue;
            }

            if (isDataCorruptionFault)
            {
                // Content change is expected when the response data is corrupted
                if (signal.Type == "content-changed")
                {
                    signal.Severity = SignalSeverity.Warning;
                    continue;
                }

                // Minimal content (not completely blank) is tolerable when data is gone/corrupted
                if (signal.Type == "blank-page" &&
                    !signal.Message.Contains("completely blank", StringComparison.OrdinalIgnoreCase))
                {
                    signal.Severity = SignalSeverity.Warning;
                    continue;
                }
            }
        }
    }

    private static bool IsStaticAsset(string url)
    {
        try
        {
            var path = new Uri(url).AbsolutePath;
            var ext = System.IO.Path.GetExtension(path);
            return !string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext);
        }
        catch
        {
            return false;
        }
    }

    private static string GetPathWithoutQuery(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.AbsolutePath;
        }
        catch
        {
            var qIdx = url.IndexOf('?');
            return qIdx >= 0 ? url[..qIdx] : url;
        }
    }

    /// <summary>
    /// Classify a URL path segment or query parameter value as an ID type,
    /// or return null if it doesn't look like a dynamic identifier.
    /// </summary>
    private static string? ClassifyIdSegment(string segment)
    {
        if (string.IsNullOrEmpty(segment) || segment.Length > 40) return null;
        if (GuidIdRegex.IsMatch(segment)) return "guid";
        if (MongoIdRegex.IsMatch(segment)) return "mongoid";
        if (NumericIdRegex.IsMatch(segment)) return "numeric";
        if (AlphanumIdRegex.IsMatch(segment) && segment.Any(char.IsDigit) && segment.Any(char.IsLetter))
            return "hash";
        return null;
    }

    private static string GetInvalidReplacement(string idType) => idType switch
    {
        "guid" => "00000000-0000-0000-0000-000000000000",
        "numeric" => "-1",
        "mongoid" => "000000000000000000000000",
        _ => "INVALID_ID",
    };

    /// <summary>
    /// Generate tampered URL variants for parameter robustness testing.
    /// Detects ID-like path segments and query parameters, produces missing + invalid variants.
    /// </summary>
    private static List<(string url, string tamperType, string description)> GenerateTamperedUrls(string originalUrl)
    {
        var results = new List<(string, string, string)>();

        Uri uri;
        try { uri = new Uri(originalUrl); }
        catch { return results; }

        var baseUrl = $"{uri.Scheme}://{uri.Authority}";
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        for (int i = 0; i < segments.Length; i++)
        {
            var decoded = Uri.UnescapeDataString(segments[i]);
            var idType = ClassifyIdSegment(decoded);
            if (idType == null) continue;

            var withoutSegments = segments.Where((_, idx) => idx != i).ToArray();
            var removedPath = "/" + string.Join("/", withoutSegments);
            results.Add((baseUrl + removedPath + uri.Query, "missing-id",
                $"Removed {idType} '{TruncateBody(decoded, 24)}' from path"));

            var tampered = (string[])segments.Clone();
            tampered[i] = GetInvalidReplacement(idType);
            var invalidPath = "/" + string.Join("/", tampered);
            results.Add((baseUrl + invalidPath + uri.Query, "invalid-id",
                $"Replaced {idType} with '{GetInvalidReplacement(idType)}' in path"));
        }

        if (!string.IsNullOrEmpty(uri.Query))
        {
            var pairs = ParseQueryParams(uri.Query);
            for (int i = 0; i < pairs.Count; i++)
            {
                var (key, value) = pairs[i];
                var idType = ClassifyIdSegment(value);
                if (idType == null) continue;

                var withoutPairs = pairs.Where((_, idx) => idx != i).ToList();
                var removedQuery = withoutPairs.Count > 0
                    ? "?" + string.Join("&", withoutPairs.Select(p => $"{p.key}={Uri.EscapeDataString(p.value)}"))
                    : "";
                results.Add((baseUrl + uri.AbsolutePath + removedQuery, "missing-param",
                    $"Removed query param '{key}' ({idType})"));

                var invalidPairs = pairs.Select((p, idx) => idx == i
                    ? (p.key, value: GetInvalidReplacement(idType)) : p).ToList();
                var invalidQuery = "?" + string.Join("&",
                    invalidPairs.Select(p => $"{p.key}={Uri.EscapeDataString(p.value)}"));
                results.Add((baseUrl + uri.AbsolutePath + invalidQuery, "invalid-param",
                    $"Replaced query param '{key}' with '{GetInvalidReplacement(idType)}'"));
            }
        }

        return results;
    }

    private static List<(string key, string value)> ParseQueryParams(string query)
    {
        var results = new List<(string, string)>();
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eqIdx = pair.IndexOf('=');
            if (eqIdx < 0) continue;
            results.Add((pair[..eqIdx], Uri.UnescapeDataString(pair[(eqIdx + 1)..])));
        }
        return results;
    }

    /// <summary>
    /// Corrupt a cached response body to test how the app handles malformed data.
    /// For JSON: nullify random values, inject unexpected types, truncate arrays.
    /// For non-JSON or missing bodies: return a truncated/garbled version.
    /// </summary>
    private const int MaxMutationBodyLength = 50_000;

    private static string MutateResponseBody(string? originalBody)
    {
        if (string.IsNullOrEmpty(originalBody))
            return "{\"__mutated\":true,\"data\":null}";

        if (originalBody.Length > MaxMutationBodyLength)
            originalBody = originalBody[..MaxMutationBodyLength];

        try
        {
            var doc = System.Text.Json.JsonDocument.Parse(originalBody);
            var root = doc.RootElement;

            if (root.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                var props = root.EnumerateObject().ToList();
                if (props.Count == 0) return "{\"__mutated\":true}";

                var sb = new System.Text.StringBuilder("{");
                var first = true;
                foreach (var prop in props)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append($"\"{prop.Name}\":");
                    sb.Append(MutateJsonValue(prop.Value));
                }
                sb.Append('}');
                return sb.ToString();
            }

            if (root.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                // Truncate array to first element + inject a null
                var items = root.EnumerateArray().ToList();
                if (items.Count == 0) return "[null]";
                return $"[{MutateJsonValue(items[0])},null]";
            }

            return MutateJsonValue(root);
        }
        catch
        {
            // Not valid JSON — truncate and garble
            if (originalBody.Length > 20)
                return originalBody[..(originalBody.Length / 2)] + "<<<TRUNCATED>>>";
            return originalBody + "<<<CORRUPTED>>>";
        }
    }

    private static string MutateJsonValue(System.Text.Json.JsonElement value)
    {
        return value.ValueKind switch
        {
            System.Text.Json.JsonValueKind.String => "null",
            System.Text.Json.JsonValueKind.Number => "\"not_a_number\"",
            System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False => "\"not_a_boolean\"",
            System.Text.Json.JsonValueKind.Array => "[]",
            System.Text.Json.JsonValueKind.Object => "null",
            System.Text.Json.JsonValueKind.Null => "\"unexpected_string\"",
            _ => "null",
        };
    }

    private static string NormalizeForComparison(string text) =>
        System.Text.RegularExpressions.Regex.Replace(text.Trim(), @"\s+", " ");

    private static string TruncateBody(string body, int max) =>
        body.Length <= max ? body : body[..(max - 3)] + "...";

    /// <summary>
    /// Clear cookies for the test URL's domain to prevent session-state poisoning.
    /// Repeated reloads with injected faults can corrupt server-side session state
    /// (e.g. AWS ALB sticky-session cookies pointing to a broken backend).
    /// </summary>
    private async Task ClearDomainCookies(string pageUrl)
    {
        try
        {
            var cookies = await _ctx.GetCookies();
            var uri = new Uri(pageUrl);
            var domain = uri.Host;

            foreach (var cookie in cookies)
            {
                if (cookie.TryGetValue("domain", out var cookieDomain) &&
                    cookieDomain is string domainStr &&
                    (domainStr.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                     domainStr.TrimStart('.').Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                     domain.EndsWith("." + domainStr.TrimStart('.'), StringComparison.OrdinalIgnoreCase)))
                {
                    if (cookie.TryGetValue("name", out var nameObj) && nameObj is string name)
                    {
                        var path = cookie.TryGetValue("path", out var pathObj) && pathObj is string p ? p : "/";
                        await _ctx.DeleteCookie(name, domainStr, path);
                    }
                }
            }
        }
        catch
        {
            // Best-effort: cookie cleanup failure should not mask test results
        }
    }

    private class FaultPreset
    {
        public string Name { get; init; } = "";
        public string Description { get; init; } = "";
        public int StatusCode { get; init; }
        public string? Body { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public int DelayMs { get; init; }
        public bool IsMutation { get; init; }
    }
}
