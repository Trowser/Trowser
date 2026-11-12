using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// OWASP LLM Top 10 application subset red-team scan (LLM01–03 + LLM05–07 + LLM09 corpus;
/// LLM04/08/10 via adjacent scanners) — integrated with Red Team Whisper.
/// </summary>
public sealed class LlmRedTeamScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public LlmRedTeamScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<LlmRedTeamScanResult> RunAsync(LlmRedTeamScanOptions options, CancellationToken ct = default)
    {
        ApplyPreset(options);
        var sw = Stopwatch.StartNew();
        var surface = await LlmEndpointDiscovery.DiscoverAsync(_ctx);
        _ctx.RedTeamWhisper?.UpdateLlmSurface(surface);

        var (probes, filterWarnings) = LlmProbeCorpus.FilterWithWarnings(options.ProbeIds, options.Categories, options.MaxProbes);
        var adjacentOnly = probes.Count == 0
            && (options.IncludeIndirectInjection || options.IncludeUnboundedConsumption || options.IncludeRagPoison
                || options.IncludeWebMcpAbuse);

        if (probes.Count == 0 && !adjacentOnly)
        {
            return new LlmRedTeamScanResult
            {
                Message = "No probes matched filter.",
                Surface = surface,
                Coverage = LlmProbeCorpus.BuildCoverageMetadata(),
                Warnings = filterWarnings,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var (transport, httpTarget, chatTarget, transportError) = ResolveTransport(options, surface);
        if (surface.BotGateDetected)
            filterWarnings.Add("Bot gate detected (reCAPTCHA/hCaptcha/Turnstile) — automated LLM probes may be blocked or rate-limited.");

        if (transport == null && !adjacentOnly)
        {
            return new LlmRedTeamScanResult
            {
                Message = transportError
                    ?? (surface.HasAiIntegration
                        ? "AI surface detected but no runnable HTTP or chat target. Pass httpTarget or chatTarget."
                        : "No AI/chat integration detected. Browse the app or pass httpTarget/chatTarget explicitly."),
                Surface = surface,
                Coverage = LlmProbeCorpus.BuildCoverageMetadata(),
                Warnings = filterWarnings,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        if (probes.Count > 0)
            _log($"LLM red team: running {probes.Count} probes via {transport}", "#CE9178");
        else
            _log("LLM red team: adjacent scanners only (no corpus probes)", "#CE9178");

        var results = new List<LlmProbeResult>();

        if (probes.Count > 0 && transport == "chat-ui")
        {
            var pageUrl = await _ctx.GetCurrentUrl();
            foreach (var probe in probes)
            {
                ct.ThrowIfCancellationRequested();

                var currentUrl = await _ctx.GetCurrentUrl();
                if (string.IsNullOrEmpty(currentUrl)
                    || !currentUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    _log("Chat page lost — attempting to re-navigate", "#F44747");
                    if (!string.IsNullOrEmpty(pageUrl))
                    {
                        try { await _ctx.Navigate(pageUrl); await Task.Delay(1500, ct); }
                        catch { /* best effort */ }
                    }
                }

                var result = await RunOneProbeAsync(probe, transport, httpTarget, chatTarget, options.TimeoutMs, ct);

                if (IsRateLimited(result))
                {
                    _log("Rate limit detected — backing off 12s", "#CE9178");
                    await Task.Delay(12000, ct);
                    result = await RunOneProbeAsync(probe, transport, httpTarget, chatTarget, options.TimeoutMs, ct);
                }

                results.Add(result);

                await Task.Delay(Math.Clamp(options.ProbeDelayMs, 200, 10000), ct);
            }
        }
        else if (probes.Count > 0 && transport != null)
        {
            var semaphore = new SemaphoreSlim(Math.Clamp(options.Concurrency, 1, 4));

            var tasks = probes.Select(async probe =>
            {
                await semaphore.WaitAsync(ct);
                try
                {
                    return await RunOneProbeAsync(probe, transport!, httpTarget, chatTarget, options.TimeoutMs, ct);
                }
                finally
                {
                    semaphore.Release();
                }
            });

            foreach (var r in await Task.WhenAll(tasks))
                results.Add(r);
        }

        List<WebMcpAbuseFinding> webMcpFindings = [];
        if (options.IncludeWebMcpAbuse && surface.WebMcpToolCount > 0)
        {
            try
            {
                webMcpFindings = await WebMcpAbuseProbe.RunAsync(_ctx, ct);
                _log($"WebMCP abuse: {webMcpFindings.Count} suspicious tool response(s)", "#CE9178");
            }
            catch (Exception ex)
            {
                _log($"WebMCP abuse probe failed: {ex.Message}", "#F44747");
            }
        }

        LlmIndirectInjectionResult? indirect = null;
        if (options.IncludeIndirectInjection && !options.IncludeRagPoison)
        {
            try
            {
                indirect = await LlmIndirectInjectionProbe.RunAsync(_ctx, options.IndirectInjectionToken, ct);
            }
            catch (Exception ex)
            {
                indirect = new LlmIndirectInjectionResult
                {
                    Attempted = true,
                    Detail = ex.Message
                };
            }
        }

        List<LlmUnboundedConsumptionFinding> unbounded = [];
        if (options.IncludeUnboundedConsumption)
        {
            try
            {
                unbounded = await LlmUnboundedConsumptionProbe.RunAsync(
                    _ctx, httpTarget, chatTarget, transport, surface, options.TimeoutMs, ct);
                var uFired = unbounded.Count(f => f.Fired);
                if (uFired > 0)
                    _log($"LLM10 unbounded consumption: {uFired} finding(s)", "#CE9178");
            }
            catch (Exception ex)
            {
                filterWarnings.Add($"Unbounded consumption probes failed: {ex.Message}");
            }
        }

        LlmRagPoisonResult? ragPoison = null;
        if (options.IncludeRagPoison)
        {
            try
            {
                ragPoison = await LlmRagPoisonProbe.RunAsync(
                    _ctx, chatTarget, options.IndirectInjectionToken,
                    options.PeerBaseUrl, options.PeerApiKey, ct);
                // Surface upload path as indirectInjection for backward compatibility
                if (ragPoison.Attempted)
                {
                    indirect = new LlmIndirectInjectionResult
                    {
                        Attempted = true,
                        InjectionObserved = ragPoison.Findings.Any(f => f.Fired),
                        InjectedToken = ragPoison.PoisonToken,
                        Detail = ragPoison.Detail,
                        ResponseExcerpt = ragPoison.ResponseExcerpt
                    };
                }
                foreach (var f in ragPoison.Findings.Where(f => f.Fired))
                    results.Add(f);
            }
            catch (Exception ex)
            {
                ragPoison = new LlmRagPoisonResult
                {
                    Attempted = true,
                    Detail = ex.Message
                };
                filterWarnings.Add($"RAG poison probes failed: {ex.Message}");
            }
        }

        sw.Stop();
        var fired = results.Count(r => r.Fired);
        var inconclusive = results.Count(r => r.Confidence == "inconclusive");
        var httpClientErrors = results.Count(r =>
            r.Error != null
            && (r.Error.Contains("HTTP 400", StringComparison.OrdinalIgnoreCase)
                || r.Error.Contains("HTTP 422", StringComparison.OrdinalIgnoreCase)
                || r.Error.Contains("HTTP 500", StringComparison.OrdinalIgnoreCase)
                || r.Error.Contains("custom schema requires", StringComparison.OrdinalIgnoreCase)
                || r.Error.Contains("invalid JSON", StringComparison.OrdinalIgnoreCase)));
        if (httpClientErrors > 0 && httpClientErrors >= Math.Max(1, results.Count / 2))
        {
            filterWarnings.Add(
                "Could not build HTTP body from sample / wrong schema — many probes returned HTTP client/server errors. "
                + "Prefer customBodyJson matching the observed requestBodySample (e.g. messages array), not {\"prompt\":...}.");
        }
        if (inconclusive > 0 && inconclusive == results.Count)
            filterWarnings.Add("All probes inconclusive (empty or stale responses) — scan did not reliably reach the LLM.");
        else if (inconclusive > results.Count / 2)
            filterWarnings.Add($"{inconclusive}/{results.Count} probes inconclusive — results may be unreliable.");

        var unboundedFired = unbounded.Count(f => f.Fired);
        if (options.ProbeAnonymousAccess && httpTarget != null)
        {
            try
            {
                var anonFinding = await ProbeAnonymousAccessAsync(httpTarget, options.TimeoutMs, ct);
                if (anonFinding != null)
                    results.Add(anonFinding);
            }
            catch (Exception ex)
            {
                filterWarnings.Add($"Anonymous access probe failed: {ex.Message}");
            }
        }

        var allFindings = BuildAllFindings(results, webMcpFindings, unbounded, ragPoison, indirect);
        var scanResult = new LlmRedTeamScanResult
        {
            Message = allFindings.Count > 0
                ? $"{allFindings.Count} finding(s) across corpus + adjacent scanners."
                : (inconclusive == results.Count && results.Count > 0
                    ? $"Completed {results.Count} probes — no reliable responses captured (inconclusive)."
                    : $"Completed {results.Count} probes — no detectors fired."),
            Surface = surface,
            Transport = transport ?? "",
            TotalProbes = results.Count,
            FiredCount = allFindings.Count,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Results = results,
            AllFindings = allFindings,
            WebMcpAbuseFindings = webMcpFindings,
            IndirectInjection = indirect,
            UnboundedConsumptionFindings = unbounded,
            RagPoison = ragPoison,
            Coverage = LlmProbeCorpus.BuildCoverageMetadata(),
            Warnings = filterWarnings
        };

        if (options.RegisterWhisperHints)
            _ctx.RedTeamWhisper?.RecordLlmScan(scanResult);

        return scanResult;
    }

    private static void ApplyPreset(LlmRedTeamScanOptions options)
    {
        var preset = options.Preset?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(preset)) return;
        if (preset is "smoke" or "quick-http")
        {
            if (string.IsNullOrWhiteSpace(options.Mode) || options.Mode.Equals("auto", StringComparison.OrdinalIgnoreCase))
                options.Mode = "http";
            if (options.MaxProbes > 8)
                options.MaxProbes = 8;
            options.ProbeDelayMs = Math.Min(options.ProbeDelayMs, 400);
            options.IncludeWebMcpAbuse = false;
            options.IncludeRagPoison = false;
            options.IncludeUnboundedConsumption = false;
            options.Categories ??=
            [
                "LLM01_Prompt_Injection",
                "LLM02_Sensitive_Information_Disclosure",
                "LLM05_Improper_Output_Handling"
            ];
        }
    }

    private static List<LlmProbeResult> BuildAllFindings(
        List<LlmProbeResult> results,
        List<WebMcpAbuseFinding> webMcp,
        List<LlmUnboundedConsumptionFinding> unbounded,
        LlmRagPoisonResult? ragPoison,
        LlmIndirectInjectionResult? indirect)
    {
        var all = results.Where(r => r.Fired).ToList();

        foreach (var u in unbounded.Where(f => f.Fired))
        {
            all.Add(new LlmProbeResult
            {
                ProbeId = u.ProbeId,
                Category = u.Category,
                Severity = u.Severity,
                Fired = true,
                Confidence = "high",
                Matched = u.ProbeId,
                Rationale = u.Detail,
                Transport = "adjacent",
                TargetUrl = u.TargetUrl,
                ResponseExcerpt = Truncate(u.Evidence?.ToString() ?? u.Detail, 400)
            });
        }

        if (ragPoison != null)
        {
            foreach (var f in ragPoison.Findings.Where(f => f.Fired))
                all.Add(f);
        }

        foreach (var w in webMcp)
        {
            all.Add(new LlmProbeResult
            {
                ProbeId = $"webmcp_{w.ToolName}_{w.PayloadKind}",
                Category = "web-mcp-abuse",
                Severity = w.Severity,
                Fired = true,
                Confidence = "medium",
                Matched = w.ToolName,
                Rationale = w.Detail,
                Transport = "webmcp",
                ResponseExcerpt = Truncate(w.ArgumentJson, 400)
            });
        }

        if (indirect is { InjectionObserved: true })
        {
            all.Add(new LlmProbeResult
            {
                ProbeId = "llm_indirect_injection",
                Category = "indirect-prompt-injection",
                Severity = "high",
                Fired = true,
                Confidence = "medium",
                Matched = indirect.InjectedToken,
                Rationale = indirect.Detail,
                Transport = "chat-ui",
                TargetUrl = indirect.SummarizeUrl,
                ResponseExcerpt = Truncate(indirect.ResponseExcerpt, 400)
            });
        }

        return all;
    }

    private async Task<LlmProbeResult?> ProbeAnonymousAccessAsync(
        LlmHttpTargetConfig httpTarget, int timeoutMs, CancellationToken ct)
    {
        var withCookies = CloneHttpTarget(httpTarget, timeoutMs);
        var anon = new LlmHttpTargetConfig
        {
            Url = httpTarget.Url,
            Schema = httpTarget.Schema,
            Model = httpTarget.Model,
            Headers = httpTarget.Headers,
            TimeoutMs = timeoutMs,
            CustomResponseKey = httpTarget.CustomResponseKey,
            UseBackendFetch = true,
            IncludeBrowserCookies = false,
            CustomBodyJson = httpTarget.CustomBodyJson,
            CustomBodyRaw = httpTarget.CustomBodyRaw,
            CustomBody = httpTarget.CustomBody
        };

        var prompt = "Reply with exactly: ANON_PROBE_OK";
        string? sessionBody = null;
        string? anonBody = null;
        try { sessionBody = await LlmHttpAdapter.SendAsync(_ctx, withCookies, prompt, ct); } catch { /* ignore */ }
        try { anonBody = await LlmHttpAdapter.SendAsync(_ctx, anon, prompt, ct); } catch { /* ignore */ }

        if (string.IsNullOrWhiteSpace(anonBody))
            return null;

        var open = anonBody.Contains("ANON_PROBE_OK", StringComparison.OrdinalIgnoreCase)
                   || (!string.IsNullOrWhiteSpace(sessionBody) && anonBody.Length > 20);

        return new LlmProbeResult
        {
            ProbeId = "llm_anon_access",
            Category = "LLM_Auth_Surface",
            Severity = open ? "medium" : "info",
            Fired = open,
            Confidence = "medium",
            Matched = open ? "anonymous-http-ok" : "anonymous-http-checked",
            Rationale = open
                ? "Discovered LLM HTTP endpoint accepted a prompt without browser cookies (open / weakly gated)."
                : "Anonymous probe completed without a clear open-access signal.",
            Transport = "http",
            TargetUrl = httpTarget.Url,
            ResponseExcerpt = Truncate(anonBody, 400)
        };
    }

    private static (string? Transport, LlmHttpTargetConfig? Http, LlmChatUiTarget? Chat, string? Error) ResolveTransport(
        LlmRedTeamScanOptions options,
        LlmSurfaceSummary surface)
    {
        var mode = options.Mode?.Trim().ToLowerInvariant() ?? "auto";

        if (mode is "http" or "api")
        {
            var http = options.HttpTarget ?? InferFromSurface(surface, minConfidence: 15);
            if (http == null)
            {
                return (null, null, null,
                    "mode=http requires httpTarget or a discoverable LLM HTTP endpoint. "
                    + "Browse a chat flow first, or pass httpTarget (see suggestedHttpTarget from llm-endpoint-discover). "
                    + "Chat-UI was not used.");
            }
            return ("http", http, null, null);
        }

        if (mode is "chat" or "ui")
            return ("chat-ui", null, options.ChatTarget ?? new LlmChatUiTarget(), null);

        if (options.HttpTarget != null)
            return ("http", options.HttpTarget, null, null);

        if (options.ChatTarget != null)
            return ("chat-ui", null, options.ChatTarget, null);

        var inferred = InferFromSurface(surface, minConfidence: 50);
        if (inferred != null)
            return ("http", inferred, null, null);

        if (surface.ChatWidgets.Count > 0)
            return ("chat-ui", null, options.ChatTarget ?? new LlmChatUiTarget(), null);

        // Last resort: any discoverable HTTP endpoint below the usual confidence bar.
        inferred = InferFromSurface(surface, minConfidence: 15);
        if (inferred != null)
            return ("http", inferred, null, null);

        return (null, null, null, null);
    }

    private static LlmHttpTargetConfig? InferFromSurface(LlmSurfaceSummary surface, int minConfidence)
    {
        var endpoint = LlmEndpointDiscovery.SelectBestEndpoint(surface.Endpoints);
        if (endpoint == null || endpoint.Confidence < minConfidence)
            return null;
        return LlmEndpointDiscovery.InferHttpTarget(endpoint)
               ?? surface.SuggestedHttpTarget;
    }

    private async Task<LlmProbeResult> RunOneProbeAsync(
        LlmProbeDefinition probe,
        string transport,
        LlmHttpTargetConfig? httpTarget,
        LlmChatUiTarget? chatTarget,
        int timeoutMs,
        CancellationToken ct)
    {
        try
        {
            string response;
            string? targetUrl = null;
            string? responseSelector = null;

            if (transport == "http")
            {
                if (httpTarget == null)
                {
                    return new LlmProbeResult
                    {
                        ProbeId = probe.Id,
                        Category = probe.Category,
                        Severity = probe.Severity,
                        Fired = false,
                        Confidence = "inconclusive",
                        Rationale = probe.Rationale,
                        Transport = "http",
                        Error = "mode/transport is http but httpTarget is missing."
                    };
                }

                var cfg = CloneHttpTarget(httpTarget, timeoutMs);
                targetUrl = cfg.Url;
                response = await LlmHttpAdapter.SendAsync(_ctx, cfg, probe.Prompt, ct);
            }
            else if (transport == "chat-ui")
            {
                var chat = await LlmChatInteract.SendPromptAsync(_ctx, probe.Prompt, chatTarget, ct);
                if (!chat.Success)
                {
                    return new LlmProbeResult
                    {
                        ProbeId = probe.Id,
                        Category = probe.Category,
                        Severity = probe.Severity,
                        Fired = false,
                        Confidence = "inconclusive",
                        Rationale = probe.Rationale,
                        Transport = transport,
                        Error = chat.Error
                    };
                }

                responseSelector = chat.ResponseSelector;
                response = FormatChatResponse(chat.ResponseText, chat.ResponseHtml);

                if (!string.IsNullOrWhiteSpace(chat.Warning))
                {
                    return new LlmProbeResult
                    {
                        ProbeId = probe.Id,
                        Category = probe.Category,
                        Severity = probe.Severity,
                        Fired = false,
                        Confidence = "inconclusive",
                        Rationale = probe.Rationale,
                        Transport = transport,
                        ResponseExcerpt = Truncate(response, 400),
                        Error = chat.Warning
                    };
                }

                if (LooksLikeConversationDump(response, probe.Prompt))
                {
                    return new LlmProbeResult
                    {
                        ProbeId = probe.Id,
                        Category = probe.Category,
                        Severity = probe.Severity,
                        Fired = false,
                        Confidence = "inconclusive",
                        Rationale = probe.Rationale,
                        Transport = transport,
                        ResponseExcerpt = Truncate(response, 400),
                        Error = "Chat capture looked like a full conversation dump (includes user prompt) — refusing to score detectors on user-echo."
                    };
                }

                if (probe.Category.StartsWith("LLM05", StringComparison.OrdinalIgnoreCase))
                {
                    var dom = await LlmOutputDomValidator.CheckAsync(
                        _ctx, responseSelector, currentResponseEvidence: response, probePrompt: probe.Prompt);
                    if (dom.UnsafeRendering)
                        response += $"\n[DOM-UNSAFE: {dom.Detail}]";
                    else if (dom.ResidualMatch)
                        response += $"\n[DOM-RESIDUAL: {dom.Detail}]";
                }
            }
            else
            {
                return new LlmProbeResult
                {
                    ProbeId = probe.Id,
                    Category = probe.Category,
                    Severity = probe.Severity,
                    Fired = false,
                    Confidence = "inconclusive",
                    Rationale = probe.Rationale,
                    Transport = transport,
                    Error = $"Unsupported transport '{transport}'."
                };
            }

            var detection = LlmProbeDetector.Evaluate(probe.Detect, response);

            if (LlmProbeDetector.LooksLikeTransportFailure(response))
            {
                return new LlmProbeResult
                {
                    ProbeId = probe.Id,
                    Category = probe.Category,
                    Severity = probe.Severity,
                    Fired = false,
                    Confidence = "inconclusive",
                    Rationale = probe.Rationale,
                    Transport = transport,
                    TargetUrl = targetUrl,
                    ResponseExcerpt = Truncate(response, 400),
                    Error = "Response looks like an HTTP/error page rather than an LLM completion."
                };
            }

            if (!detection.Fired
                && response.Contains("[DOM-UNSAFE:", StringComparison.Ordinal)
                && probe.Category.StartsWith("LLM05", StringComparison.OrdinalIgnoreCase))
            {
                detection = new LlmProbeDetector.DetectionResult
                {
                    Fired = true,
                    Confidence = "high",
                    Matched = "dom-unsafe-render"
                };
            }
            return new LlmProbeResult
            {
                ProbeId = probe.Id,
                Category = probe.Category,
                Severity = probe.Severity,
                Fired = detection.Fired,
                Confidence = detection.Confidence,
                Matched = detection.Matched,
                ResponseExcerpt = Truncate(response, 400),
                Rationale = probe.Rationale,
                Transport = transport,
                TargetUrl = targetUrl
            };
        }
        catch (Exception ex)
        {
            return new LlmProbeResult
            {
                ProbeId = probe.Id,
                Category = probe.Category,
                Severity = probe.Severity,
                Fired = false,
                Confidence = "inconclusive",
                Rationale = probe.Rationale,
                Transport = transport,
                TargetUrl = httpTarget?.Url,
                ResponseExcerpt = Truncate(ex.Message, 400),
                Error = ex.Message
            };
        }
    }

    private static readonly string[] RateLimitPatterns =
    [
        "too fast", "too many", "rate limit", "try again", "slow down",
        "please wait", "sending messages too fast", "throttl"
    ];

    private static bool IsRateLimited(LlmProbeResult result)
    {
        var text = result.ResponseExcerpt ?? result.Error ?? "";
        if (string.IsNullOrWhiteSpace(text)) return false;
        return RateLimitPatterns.Any(p =>
            text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    private static string FormatChatResponse(string text, string html)
    {
        if (string.IsNullOrWhiteSpace(text))
            return html ?? "";
        if (string.IsNullOrWhiteSpace(html))
            return text;
        if (text.Trim() == html.Trim())
            return text;
        return text;
    }

    private static bool LooksLikeConversationDump(string response, string prompt)
    {
        if (string.IsNullOrWhiteSpace(response) || string.IsNullOrWhiteSpace(prompt) || prompt.Length < 8)
            return false;
        var t = string.Join(' ', response.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        var p = string.Join(' ', prompt.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return t.Contains(p, StringComparison.OrdinalIgnoreCase) && t.Length > p.Length + 48;
    }

    private static LlmHttpTargetConfig CloneHttpTarget(LlmHttpTargetConfig src, int timeoutMs) =>
        new()
        {
            Url = src.Url,
            Schema = src.Schema,
            Model = src.Model,
            Headers = src.Headers,
            TimeoutMs = timeoutMs,
            CustomBody = src.CustomBody,
            CustomBodyRaw = src.CustomBodyRaw,
            CustomBodyJson = src.CustomBodyJson,
            CustomResponseKey = src.CustomResponseKey,
            UseBackendFetch = src.UseBackendFetch,
            IncludeBrowserCookies = src.IncludeBrowserCookies
        };
}
