using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Discovers LLM/chat endpoints from network log and chat UI widgets from DOM.
/// </summary>
public static class LlmEndpointDiscovery
{
    private static readonly string[] UrlPathPatterns =
    [
        "/v1/chat/completions", "/v1/messages", "/v1/responses", "/v1/assistants",
        "/api/chat", "/api/assistant", "/api/copilot", "/api/llm", "/api/generate",
        "/api/completion", "/api/prompt", "/chat/completions", "/graphql"
    ];

    // Avoid bare /embed — matches HubSpot hsforms counters.gif and similar tracking pixels.
    private static readonly Regex ChatPathRegex = new(
        @"(?i)(/chat(?:/|$)|/assistant(?:/|$)|/copilot(?:/|$)|/llm(?:/|$)|/completion(?:/|$)|/prompt(?:/|$)|/generate(?:/|$)|/inference(?:/|$)|/rag(?:/|$)|/summarize(?:/|$)|/send-message(?:/|$))",
        RegexOptions.Compiled);

    private static readonly string[] StaticPathExtensions =
        [".gif", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2", ".map"];

    private static readonly string[] ExcludedPathFragments =
    [
        "/web-interactives", "/hs-scripts", "/counters", "/tracking", "/analytics",
        "/pixel", "/beacon", "/collect"
    ];

    private static readonly string[] ThirdPartyBlocklist =
    [
        "hubspot.com", "hsforms.com", "hs-scripts.com", "hs-analytics.net",
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "facebook.com", "facebook.net", "hotjar.com", "segment.io", "segment.com",
        "sentry.io", "datadoghq.com", "newrelic.com", "mixpanel.com",
        "intercom.io", "intercomcdn.com", "crisp.chat", "fullstory.com",
        "clarity.ms", "mouseflow.com", "heap.io", "amplitude.com",
        "cdn.jsdelivr.net", "unpkg.com", "cloudflareinsights.com"
    ];

    public static async Task<LlmSurfaceSummary> DiscoverAsync(AutomationContext ctx)
    {
        var pageUrl = "";
        try { pageUrl = await ctx.GetCurrentUrl(); } catch { /* ignore */ }
        var host = Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri) ? pageUri.Host : null;

        var endpoints = DiscoverNetworkEndpoints(ctx);
        var wsEndpoints = DiscoverWebSocketEndpoints(ctx);
        endpoints.AddRange(wsEndpoints);

        // Merge session memory (survives navigation that clears page network log).
        foreach (var remembered in LlmEndpointSessionMemory.GetRemembered(host))
        {
            if (endpoints.Any(e => UrlsMatch(e.Url, remembered.Url)))
                continue;
            endpoints.Add(new LlmEndpointHint
            {
                Url = remembered.Url,
                Method = remembered.Method,
                Source = "session-memory",
                MatchReason = remembered.MatchReason + "+remembered",
                ContentType = remembered.ContentType,
                IsSse = remembered.IsSse,
                Confidence = Math.Max(40, remembered.Confidence - 5),
                SampleRequestBody = remembered.SampleRequestBody
            });
        }

        // Merge attack-surface LLM-shaped endpoints (OpenAPI / prior traffic).
        foreach (var fromSurface in DiscoverFromAttackSurface(ctx))
        {
            if (endpoints.Any(e => UrlsMatch(e.Url, fromSurface.Url)))
                continue;
            endpoints.Add(fromSurface);
        }

        endpoints = endpoints
            .OrderByDescending(e => e.Confidence)
            .ThenBy(e => e.Url, StringComparer.OrdinalIgnoreCase)
            .Take(30)
            .ToList();

        LlmEndpointSessionMemory.Remember(host, endpoints);

        var httpMcp = DiscoverHttpMcpEndpoints(ctx);
        foreach (var remembered in LlmEndpointSessionMemory.GetRememberedMcp(host))
        {
            if (httpMcp.Any(e => UrlsMatch(e.Url, remembered.Url))) continue;
            httpMcp.Add(remembered);
        }
        LlmEndpointSessionMemory.RememberMcp(host, httpMcp);

        var dom = await DiscoverDomHintsAsync(ctx);
        var webMcpCount = 0;
        try
        {
            var tools = await ctx.GetWebMcpTools();
            webMcpCount = tools.Count;
        }
        catch
        {
            // ignore
        }

        var best = SelectBestEndpoint(endpoints);
        LlmHttpTargetConfig? suggested = best != null ? InferHttpTarget(best) : null;

        return new LlmSurfaceSummary
        {
            ChatEndpointCount = endpoints.Count,
            ChatWidgetCount = dom.Widgets.Count,
            WebMcpToolCount = webMcpCount,
            HttpMcpEndpointCount = httpMcp.Count,
            IframeCopilotCount = dom.IframeCopilotCount,
            Endpoints = endpoints,
            ChatWidgets = dom.Widgets,
            HttpMcpEndpoints = httpMcp.OrderByDescending(e => e.Confidence).Take(10).ToList(),
            SuggestedHttpTarget = suggested,
            BotGateDetected = await DetectBotGateAsync(ctx)
        };
    }

    private static bool UrlsMatch(string a, string b)
    {
        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua)) return false;
        if (!Uri.TryCreate(b, UriKind.Absolute, out var ub)) return false;
        return string.Equals(NormalizeUrlKey(ua), NormalizeUrlKey(ub), StringComparison.OrdinalIgnoreCase);
    }

    private static List<LlmEndpointHint> DiscoverFromAttackSurface(AutomationContext ctx)
    {
        var results = new List<LlmEndpointHint>();
        try
        {
            var surface = ctx.CheckAttackSurface(includeParameters: true, includeAuth: false, includeResponsePatterns: false);
            foreach (var ep in surface.Endpoints)
            {
                var sample = ep.Parameters.RequestBodySample;
                var path = "";
                if (Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
                    path = uri.AbsolutePath.ToLowerInvariant();
                else
                    path = (ep.UrlTemplate ?? ep.Url).ToLowerInvariant();

                var looksLlm = (!string.IsNullOrWhiteSpace(sample) && LooksLikeLlmRequestBody(sample))
                               || UrlPathPatterns.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase))
                               || ChatPathRegex.IsMatch(path);
                if (!looksLlm) continue;
                if (!ep.Methods.Any(m => m.Equals("POST", StringComparison.OrdinalIgnoreCase)
                                         || m.Equals("PUT", StringComparison.OrdinalIgnoreCase)))
                    continue;

                results.Add(new LlmEndpointHint
                {
                    Url = ep.Url,
                    Method = ep.Methods.Contains("POST") ? "POST" : ep.Methods.FirstOrDefault() ?? "POST",
                    Source = "attack-surface",
                    MatchReason = "attack-surface:llm-shaped",
                    ContentType = ep.Parameters.RequestContentType,
                    Confidence = !string.IsNullOrWhiteSpace(sample) && LooksLikeLlmRequestBody(sample) ? 75 : 55,
                    SampleRequestBody = sample
                });
            }
        }
        catch
        {
            // Attack surface may be empty / unavailable — discovery still works from network log.
        }

        return results;
    }

    private static List<LlmHttpMcpHint> DiscoverHttpMcpEndpoints(AutomationContext ctx)
    {
        var results = new List<LlmHttpMcpHint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.GetPageNetworkLog())
        {
            if (string.IsNullOrWhiteSpace(entry.Url)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (IsBlockedThirdParty(uri.Host)) continue;

            var path = uri.AbsolutePath.ToLowerInvariant();
            var body = entry.RequestBody ?? "";
            var isMcpPath = path.Contains("/mcp", StringComparison.OrdinalIgnoreCase)
                            || path.EndsWith("/sse", StringComparison.OrdinalIgnoreCase);
            var isJsonRpc = body.Contains("\"jsonrpc\"", StringComparison.OrdinalIgnoreCase)
                            && (body.Contains("\"initialize\"", StringComparison.OrdinalIgnoreCase)
                                || body.Contains("\"tools/list\"", StringComparison.OrdinalIgnoreCase)
                                || body.Contains("\"tools/call\"", StringComparison.OrdinalIgnoreCase)
                                || body.Contains("\"notifications/", StringComparison.OrdinalIgnoreCase));

            if (!isMcpPath && !isJsonRpc) continue;

            var key = NormalizeUrlKey(uri);
            if (!seen.Add(key)) continue;

            var tools = new List<string>();
            var resp = entry.ResponseBody ?? "";
            foreach (Match m in Regex.Matches(resp, "\"name\"\\s*:\\s*\"([a-zA-Z0-9_.-]{2,64})\"",
                         RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
            {
                var name = m.Groups[1].Value;
                if (name is "jsonrpc" or "result" or "error" or "id" or "method") continue;
                if (!tools.Contains(name, StringComparer.OrdinalIgnoreCase))
                    tools.Add(name);
            }

            results.Add(new LlmHttpMcpHint
            {
                Url = $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}",
                Source = "network",
                Confidence = isJsonRpc ? 90 : (isMcpPath ? 70 : 50),
                MatchReason = isJsonRpc ? "jsonrpc-mcp" : "path:/mcp",
                SampleInitializeBody = body.Length > 500 ? body[..500] : body,
                ToolNames = tools.Take(40).ToList()
            });
        }

        return results;
    }

    /// <summary>
    /// Detect common invisible bot gates that can silently block automated LLM probes.
    /// </summary>
    public static async Task<bool> DetectBotGateAsync(AutomationContext ctx)
    {
        try
        {
            var raw = await ctx.ExecuteJs(
                "(function(){" +
                "if(window.grecaptcha||window.___grecaptcha_cfg) return true;" +
                "if(document.querySelector('.g-recaptcha,[data-sitekey],iframe[src*=\"recaptcha\"],iframe[src*=\"hcaptcha\"],iframe[src*=\"challenges.cloudflare\"]')) return true;" +
                "if(document.querySelector('script[src*=\"recaptcha\"],script[src*=\"hcaptcha\"],script[src*=\"turnstile\"]')) return true;" +
                "return false;" +
                "})()");
            if (string.IsNullOrWhiteSpace(raw)) return false;
            var unwrapped = raw.Trim();
            if (unwrapped.StartsWith('"'))
                unwrapped = JsonSerializer.Deserialize<string>(unwrapped) ?? unwrapped;
            return unwrapped.Equals("true", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static List<LlmEndpointHint> DiscoverNetworkEndpoints(AutomationContext ctx) =>
        DiscoverNetworkEndpoints(ctx.GetPageNetworkLog());

    public static List<LlmEndpointHint> DiscoverNetworkEndpoints(IEnumerable<NetworkEntry> entries)
    {
        var results = new List<LlmEndpointHint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (entry.IsTrowserGenerated) continue;
            if (string.IsNullOrWhiteSpace(entry.Url)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (IsBlockedThirdParty(uri.Host)) continue;
            if (IsStaticAssetPath(uri.AbsolutePath)) continue;
            if (IsExcludedPath(uri.AbsolutePath)) continue;

            var pathLower = uri.AbsolutePath.ToLowerInvariant();
            var reason = MatchUrlReason(pathLower, entry);
            if (reason == null) continue;

            var confidence = ScoreEndpoint(reason, entry);
            if (confidence < 15) continue;

            if (IsWeakMatch(reason) && !IsAcceptableWeakMatch(entry))
                continue;

            var dedupeKey = NormalizeUrlKey(uri);
            if (!seen.Add(dedupeKey)) continue;

            var isSse = IsEventStream(entry);

            results.Add(new LlmEndpointHint
            {
                Url = entry.Url,
                Method = entry.Method,
                Source = "network",
                MatchReason = reason,
                ContentType = string.IsNullOrWhiteSpace(entry.ContentType) ? null : entry.ContentType,
                IsSse = isSse,
                Confidence = confidence,
                SampleRequestBody = entry.RequestBody
            });
        }

        return results
            .OrderByDescending(e => e.Confidence)
            .ThenByDescending(e => e.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            .ThenBy(e => e.Url, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .ToList();
    }

    /// <summary>
    /// Cheap Whisper gate: true when the page log has a non-weak LLM/chat API
    /// (same matching as endpoint discover). GraphQL-only hits are too common to corroborate a chat UI.
    /// </summary>
    public static bool HasCorroboratingLlmTraffic(IEnumerable<NetworkEntry>? entries)
    {
        if (entries == null) return false;
        foreach (var hint in DiscoverNetworkEndpoints(entries))
        {
            if (hint.Confidence < 50) continue;
            if (hint.MatchReason.Contains("graphql", StringComparison.OrdinalIgnoreCase))
                continue;
            return true;
        }

        return false;
    }

    private static readonly string[] WsLlmJsonKeys =
        ["content", "message", "response", "answer", "text", "reply", "output"];

    private static readonly string[] WsLlmUserKeys =
        ["user", "role", "sender", "author", "from", "name"];

    public static List<LlmEndpointHint> DiscoverWebSocketEndpoints(AutomationContext ctx)
    {
        var results = new List<LlmEndpointHint>();
        try
        {
            var wsManager = ctx.ActiveTab.WebSocket;
            foreach (var conn in wsManager.GetConnections())
            {
                var url = conn.Url ?? "";
                if (string.IsNullOrWhiteSpace(url)) continue;

                var confidence = 0;
                var reasons = new List<string>();

                var urlLower = url.ToLowerInvariant();
                if (ChatPathRegex.IsMatch(urlLower))
                {
                    confidence += 40;
                    reasons.Add("ws-url:chat-like");
                }

                var frames = wsManager.GetFrames(conn.ConnectionId);
                var jsonMessageCount = 0;
                var hasContentKey = false;
                var hasUserKey = false;
                var hasMultiTurn = false;

                foreach (var frame in frames.TakeLast(50))
                {
                    if (!frame.IsJson || string.IsNullOrWhiteSpace(frame.Data)) continue;
                    jsonMessageCount++;

                    var dataLower = frame.Data.ToLowerInvariant();
                    foreach (var key in WsLlmJsonKeys)
                    {
                        if (dataLower.Contains($"\"{key}\""))
                        {
                            hasContentKey = true;
                            break;
                        }
                    }

                    foreach (var key in WsLlmUserKeys)
                    {
                        if (dataLower.Contains($"\"{key}\""))
                        {
                            hasUserKey = true;
                            break;
                        }
                    }
                }

                if (jsonMessageCount >= 2)
                {
                    var sentCount = frames.Count(f => f.Direction == "sent" && f.IsJson);
                    var recvCount = frames.Count(f => f.Direction == "received" && f.IsJson);
                    hasMultiTurn = sentCount >= 1 && recvCount >= 1;
                }

                if (hasContentKey)
                {
                    confidence += 30;
                    reasons.Add("ws-body:content-key");
                }
                if (hasUserKey)
                {
                    confidence += 15;
                    reasons.Add("ws-body:user-key");
                }
                if (hasMultiTurn)
                {
                    confidence += 20;
                    reasons.Add("ws-pattern:multi-turn");
                }
                if (jsonMessageCount >= 2)
                {
                    confidence += 10;
                    reasons.Add($"ws-traffic:{jsonMessageCount}-json-frames");
                }

                if (confidence < 25) continue;

                results.Add(new LlmEndpointHint
                {
                    Url = url,
                    Method = "WS",
                    Source = "websocket",
                    MatchReason = string.Join("+", reasons),
                    Confidence = Math.Clamp(confidence, 0, 100),
                    IsSse = false
                });
            }
        }
        catch
        {
            // WebSocket manager may not be available
        }

        return results;
    }

    /// <summary>Pick the best endpoint for auto HTTP mode (strong body-shape signals over path heuristics).</summary>
    public static LlmEndpointHint? SelectBestEndpoint(IEnumerable<LlmEndpointHint> endpoints) =>
        endpoints
            .Where(e => e.Confidence >= 40)
            .OrderByDescending(e => e.Confidence)
            .ThenByDescending(e => e.MatchReason.StartsWith("body:", StringComparison.OrdinalIgnoreCase)
                                   || e.MatchReason.StartsWith("sse:", StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(e => e.IsSse)
            .ThenByDescending(e => e.Method.Equals("POST", StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault();

    private static string NormalizeUrlKey(Uri uri) =>
        $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}".TrimEnd('/');

    private static bool IsBlockedThirdParty(string host)
    {
        foreach (var blocked in ThirdPartyBlocklist)
        {
            if (host.Equals(blocked, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + blocked, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsStaticAssetPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return StaticPathExtensions.Any(ext => lower.EndsWith(ext, StringComparison.Ordinal));
    }

    private static bool IsExcludedPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return ExcludedPathFragments.Any(fragment => lower.Contains(fragment, StringComparison.Ordinal));
    }

    private static bool IsWeakMatch(string reason) =>
        reason.StartsWith("path:chat-like", StringComparison.OrdinalIgnoreCase);

    private static bool IsAcceptableWeakMatch(NetworkEntry entry)
    {
        var ct = entry.ContentType ?? "";
        if (ct.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("text/html", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase))
            return false;

        if (entry.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            return false;

        return ct.Contains("json", StringComparison.OrdinalIgnoreCase)
               || ct.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(entry.RequestBody);
    }

    private static int ScoreEndpoint(string reason, NetworkEntry entry)
    {
        var score = reason switch
        {
            var r when r.StartsWith("path:/v1/chat", StringComparison.OrdinalIgnoreCase) => 95,
            var r when r.StartsWith("path:/v1/messages", StringComparison.OrdinalIgnoreCase) => 95,
            var r when r.StartsWith("path:/api/", StringComparison.OrdinalIgnoreCase) => 85,
            var r when r.StartsWith("body:", StringComparison.OrdinalIgnoreCase) => 80,
            var r when r.StartsWith("sse:", StringComparison.OrdinalIgnoreCase) => 70,
            var r when r.StartsWith("path:chat-like", StringComparison.OrdinalIgnoreCase) => 25,
            _ => 50
        };

        var ct = entry.ContentType ?? "";
        if (ct.Contains("application/json", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (ct.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase)) score += 15;
        if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)) score += 5;
        if (ct.StartsWith("image/", StringComparison.OrdinalIgnoreCase)) score -= 50;
        if (ct.StartsWith("text/html", StringComparison.OrdinalIgnoreCase)) score -= 30;

        return Math.Clamp(score, 0, 100);
    }

    private static string? MatchUrlReason(string pathLower, NetworkEntry entry)
    {
        foreach (var p in UrlPathPatterns)
        {
            if (pathLower.Contains(p, StringComparison.OrdinalIgnoreCase))
                return $"path:{p}";
        }

        if (ChatPathRegex.IsMatch(pathLower))
            return "path:chat-like";

        if (entry.RequestBody != null && LooksLikeLlmFormBody(entry.RequestBody))
            return "body:llm-form-shape";

        if (entry.RequestBody != null && LooksLikeLlmRequestBody(entry.RequestBody))
            return "body:llm-json-shape";

        // Streaming LLM endpoints often use opaque paths (e.g. /submit.php) with SSE responses.
        if (IsEventStream(entry))
            return "sse:event-stream";

        return null;
    }

    private static bool IsEventStream(NetworkEntry entry) => entry.IsEventStream;

    private static bool LooksLikeLlmRequestBody(string body)
    {
        if (body.Contains("\"messages\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase))
            return true;

        // Bare OpenAI-style turn array: [{"role":"user","content":"..."}]
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('[')
            && body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"content\"", StringComparison.OrdinalIgnoreCase))
            return true;

        if (body.Contains("\"prompt\"", StringComparison.OrdinalIgnoreCase)
            && (body.Contains("\"model\"", StringComparison.OrdinalIgnoreCase)
                || body.Contains("\"defender\"", StringComparison.OrdinalIgnoreCase)
                || body.Contains("\"temperature\"", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (body.Contains("\"input\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"model\"", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    private static readonly Regex FormPromptField = new(
        @"(?:^|&)(prompt|message|input|query|content|attacker_input|user_input|user_message|chat_input|question)=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static bool LooksLikeLlmFormBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('[')) return false;
        if (!body.Contains('=')) return false;
        return FormPromptField.IsMatch(body);
    }

    public static async Task<LlmDomDiscovery> DiscoverDomHintsAsync(AutomationContext ctx)
    {
        var raw = await ctx.ExecuteJs(DomDiscoveryScript);
        if (string.IsNullOrWhiteSpace(raw) || raw == "null") return new LlmDomDiscovery();

        try
        {
            if (raw.StartsWith('"'))
                raw = JsonSerializer.Deserialize<string>(raw) ?? "";
            return JsonSerializer.Deserialize<LlmDomDiscovery>(raw, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new LlmDomDiscovery();
        }
        catch
        {
            return new LlmDomDiscovery();
        }
    }

    public static LlmHttpTargetConfig? InferHttpTarget(LlmEndpointHint hint)
    {
        if (string.IsNullOrWhiteSpace(hint.Url)) return null;

        if (!string.IsNullOrWhiteSpace(hint.SampleRequestBody)
            && TryInferCustomTarget(hint, out var custom))
            return custom;

        var schema = hint.Url.Contains("/v1/chat/completions", StringComparison.OrdinalIgnoreCase)
                     || hint.Url.Contains("/v1/messages", StringComparison.OrdinalIgnoreCase)
            ? "openai"
            : "simple";

        // Last-resort: messages-array shaped samples must never become {"prompt":...}.
        if (!string.IsNullOrWhiteSpace(hint.SampleRequestBody)
            && LooksLikeMessagesArraySample(hint.SampleRequestBody!))
        {
            return BuildMessagesArrayHttpTarget(hint.Url, new JsonArray
            {
                new JsonObject { ["role"] = "user", ["content"] = "{{PROMPT}}" }
            });
        }

        return new LlmHttpTargetConfig
        {
            Url = hint.Url,
            Schema = schema,
            IncludeBrowserCookies = true
        };
    }

    private static bool TryInferCustomTarget(LlmEndpointHint hint, out LlmHttpTargetConfig config)
    {
        config = null!;
        var sample = hint.SampleRequestBody;
        if (string.IsNullOrWhiteSpace(sample)) return false;

        // Form-urlencoded bodies (common for CSRF-protected LLM playgrounds). Skip JSON object/array samples.
        var trimmed = sample.TrimStart();
        if (!trimmed.StartsWith('{') && !trimmed.StartsWith('[') && LooksLikeLlmFormBody(sample))
        {
            var rebuilt = ReplaceFormPromptWithPlaceholder(sample);
            if (rebuilt == null) return false;

            config = new LlmHttpTargetConfig
            {
                Url = hint.Url,
                Schema = "custom",
                CustomBodyRaw = rebuilt,
                IncludeBrowserCookies = true,
                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                }
            };
            return true;
        }

        try
        {
            var parsed = JsonNode.Parse(sample);
            // Prefer sample shape over param-name heuristics. A root messages array must stay an array —
            // wrapping as {"prompt":…} or {"messages":…} breaks APIs that POST [{role,content},…].
            if (parsed is JsonArray rootArr && rootArr.Count > 0 && LooksLikeMessagesArray(rootArr))
            {
                config = BuildMessagesArrayHttpTarget(hint.Url, rootArr);
                return true;
            }

            var node = parsed as JsonObject;
            if (node == null) return false;

            var replaced = false;

            // OpenAI-style chat: messages[{role,content},…] — single-turn default for corpus probes.
            if (node["messages"] is JsonArray messages && messages.Count > 0)
            {
                node["messages"] = BuildSingleTurnMessages(messages);
                replaced = true;
            }

            if (!replaced)
            {
                foreach (var key in new[] { "prompt", "input", "message", "query", "content", "attacker_input", "user_input" })
                {
                    if (node[key] is JsonValue val && val.TryGetValue<string>(out var s)
                        && !string.IsNullOrWhiteSpace(s) && s.Length > 2)
                    {
                        node[key] = "{{PROMPT}}";
                        replaced = true;
                        break;
                    }
                }
            }

            if (!replaced) return false;

            config = new LlmHttpTargetConfig
            {
                Url = hint.Url,
                Schema = "custom",
                CustomBodyJson = node.ToJsonString(),
                IncludeBrowserCookies = true,
                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = "application/json"
                }
            };
            return true;
        }
        catch
        {
            // Truncated attack-surface samples often end with "..." and fail JsonNode.Parse.
            // Still prefer messages-array shape over inventing {"prompt":...}.
            if (LooksLikeMessagesArraySample(sample))
            {
                config = BuildMessagesArrayHttpTarget(hint.Url, new JsonArray
                {
                    new JsonObject { ["role"] = "user", ["content"] = "{{PROMPT}}" }
                });
                return true;
            }
            return false;
        }
    }

    private static bool LooksLikeMessagesArraySample(string sample)
    {
        var t = sample.TrimStart();
        return t.StartsWith('[')
               && sample.Contains("\"role\"", StringComparison.OrdinalIgnoreCase)
               && sample.Contains("\"content\"", StringComparison.OrdinalIgnoreCase);
    }

    private static LlmHttpTargetConfig BuildMessagesArrayHttpTarget(string url, JsonArray messages) =>
        new()
        {
            Url = url,
            Schema = "custom",
            CustomBodyJson = BuildSingleTurnMessages(messages).ToJsonString(),
            IncludeBrowserCookies = true,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json"
            }
        };

    private static bool LooksLikeMessagesArray(JsonArray arr)
    {
        foreach (var item in arr)
        {
            if (item is not JsonObject msg) continue;
            var role = msg["role"]?.ToString()?.Trim('"') ?? "";
            if (!string.IsNullOrEmpty(role) && msg["content"] != null)
                return true;
        }
        return false;
    }

    private static JsonArray BuildSingleTurnMessages(JsonArray messages)
    {
        JsonObject? lastUser = null;
        var systems = new List<JsonObject>();
        foreach (var item in messages)
        {
            if (item is not JsonObject msg) continue;
            var role = msg["role"]?.ToString()?.Trim('"') ?? "";
            if (role.Equals("system", StringComparison.OrdinalIgnoreCase))
                systems.Add(msg);
            else if (role.Equals("user", StringComparison.OrdinalIgnoreCase))
                lastUser = msg;
        }

        var singleTurn = new JsonArray();
        foreach (var sys in systems)
            singleTurn.Add(JsonNode.Parse(sys.ToJsonString())!);

        if (lastUser != null)
        {
            var userClone = JsonNode.Parse(lastUser.ToJsonString())!.AsObject();
            userClone["content"] = "{{PROMPT}}";
            singleTurn.Add(userClone);
        }
        else if (messages.Count > 0 && messages[^1] is JsonObject fallback)
        {
            var clone = JsonNode.Parse(fallback.ToJsonString())!.AsObject();
            clone["role"] = clone["role"] ?? "user";
            clone["content"] = "{{PROMPT}}";
            singleTurn.Add(clone);
        }

        return singleTurn;
    }

    private static string? ReplaceFormPromptWithPlaceholder(string formBody)
    {
        var match = FormPromptField.Match(formBody);
        if (!match.Success) return null;
        var field = match.Groups[1].Value;
        return Regex.Replace(
            formBody,
            $@"(?:^|&)({Regex.Escape(field)})=[^&]*",
            m =>
            {
                var prefix = m.Value.StartsWith('&') ? "&" : "";
                return $"{prefix}{m.Groups[1].Value}={{{{PROMPT}}}}";
            },
            RegexOptions.IgnoreCase);
    }

    private static readonly string DomDiscoveryScript =
        "(function(){\n" +
        LlmDomScripts.DeepSearchJs +
        LlmDomScripts.VisibilityJs +
        """
  function cssPath(el){
    if(!el||el.nodeType!==1)return '';
    if(el.id)return '#'+CSS.escape(el.id);
    var parts=[];
    while(el&&el.nodeType===1&&parts.length<8){
      var tag=el.tagName.toLowerCase();
      if(el.id){parts.unshift('#'+CSS.escape(el.id));break;}
      var parent=el.parentElement;
      if(!parent){parts.unshift(tag);break;}
      var siblings=[].filter.call(parent.children,function(c){return c.tagName===el.tagName;});
      if(siblings.length>1){
        var idx=siblings.indexOf(el)+1;
        tag+=':nth-of-type('+idx+')';
      }
      parts.unshift(tag);
      el=parent;
    }
    return parts.join(' > ');
  }
  function aiText(el){
    return ((el.placeholder||'')+' '+(el.getAttribute('aria-label')||'')+' '+(el.getAttribute('data-testid')||'')+' '+(el.getAttribute('name')||'')).toLowerCase();
  }
  function findNearbyButton(el){
    var scopes=[el.closest('form'),el.parentElement,el.parentElement&&el.parentElement.parentElement,el.parentElement&&el.parentElement.parentElement&&el.parentElement.parentElement.parentElement];
    for(var s=0;s<scopes.length;s++){
      var scope=scopes[s];
      if(!scope) continue;
      var btn=scope.querySelector('button,[role="button"],input[type="submit"],a[role="button"]');
      if(btn&&btn!==el) return btn;
    }
    return null;
  }
  function countVisibleInputs(){
    var all=deepQueryAll('textarea,input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]),[contenteditable="true"],[role="textbox"]');
    var n=0;
    for(var i=0;i<all.length;i++) if(isVisibleEnough(all[i])) n++;
    return n;
  }
  var formFieldNames=/^(email|e-mail|name|first.?name|last.?name|full.?name|username|user.?name|website|url|phone|tel|address|city|state|zip|country|company|organization|subject|title|comment|feedback|review|rating|captcha|password|confirm)$/i;
  var formFieldLabels=/\b(email|e-?mail|name|phone|website|url|address|company|subject|password|captcha)\b/i;
  function countFormSiblingInputs(el){
    var form=el.closest('form');
    if(!form) return 0;
    var inputs=form.querySelectorAll('textarea,input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"]),[contenteditable="true"]');
    return inputs.length;
  }
  function hasFormFieldSemantics(el){
    var form=el.closest('form');
    if(!form) return false;
    var inputs=form.querySelectorAll('textarea,input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([type="submit"]):not([type="button"])');
    var formFieldCount=0;
    for(var fi=0;fi<inputs.length;fi++){
      var n=(inputs[fi].getAttribute('name')||'').trim();
      if(n&&formFieldNames.test(n)) formFieldCount++;
      var labels=form.querySelectorAll('label[for="'+inputs[fi].id+'"],label');
      for(var li=0;li<labels.length;li++){
        if(formFieldLabels.test(labels[li].textContent||'')) formFieldCount++;
      }
    }
    return formFieldCount>=2;
  }
  function isTraditionalForm(el){
    var form=el.closest('form');
    if(!form) return false;
    var action=(form.getAttribute('action')||'').trim();
    if(action&&action!=='#'&&!action.startsWith('javascript:')&&!/^https?:\/\/[^/]+\/(api|graphql|chat|assistant|copilot|llm)/i.test(action)){
      if(form.method&&form.method.toUpperCase()==='POST') return true;
    }
    return false;
  }
  function scoreChatInput(el){
    var offscreen=!isVisibleEnough(el)&&isDomPresent(el);
    if(!isVisibleEnough(el)&&!offscreen) return 0;
    var score=offscreen?10:0;
    var tag=(el.tagName||'').toLowerCase();
    var rect=el.getBoundingClientRect();
    var vh=window.innerHeight||document.documentElement.clientHeight||800;
    var t=aiText(el);
    if(/ask|chat|message|ai|assist|prompt|copilot|question|type your|how can i help|send/.test(t)) score+=35;
    if(el.closest('[class*="chat"],[id*="chat"],[data-testid*="chat"],[class*="copilot"],[class*="assistant"],[class*="message"]')) score+=25;
    if(el.closest('[class*="device"],[class*="phone"],[class*="mockup"],[class*="mobile"],[class*="frame"],[class*="bezel"]')) score+=20;
    if(tag==='textarea') score+=30;
    if(el.isContentEditable||el.getAttribute('contenteditable')==='true') score+=28;
    if(tag==='input') score+=15;
    if(rect.top>vh*0.42) score+=25;
    if(findNearbyButton(el)) score+=35;
    if(countVisibleInputs()===1) score+=45;
    if(el.closest('form')) score+=10;
    score+=Math.min(visibleArea(el)/200,50);

    // Negative signals: traditional HTML forms, not chat widgets
    var siblingInputs=countFormSiblingInputs(el);
    if(siblingInputs>=3) score-=60;
    else if(siblingInputs>=2) score-=30;
    if(hasFormFieldSemantics(el)) score-=50;
    if(isTraditionalForm(el)) score-=40;
    var elName=(el.getAttribute('name')||'').trim();
    if(elName&&formFieldNames.test(elName)) score-=25;

    return Math.max(score,0);
  }
  function looksLikeChatInput(el){
    return scoreChatInput(el)>=40;
  }
  var defaultRespSel='.answer:not(label):not(h1):not(h2):not(h3),p.answer,[class*="answer"]:not(label):not(h1):not(h2):not(h3),.response:not(label):not(h1):not(h2):not(h3),[class*="response"]:not(label):not(h1):not(h2):not(h3),.bot-message,.assistant-message,[data-role="assistant"]';
  function detectResponseArea(inputEl){
    if(!inputEl) return defaultRespSel;
    var root=inputEl.closest('[class*="chat"],[id*="chat"],[class*="message"],[class*="conversation"],[role="log"],[role="main"],form');
    if(!root) root=inputEl.parentElement&&inputEl.parentElement.parentElement;
    if(!root) return defaultRespSel;
    var table=root.querySelector('table');
    if(table){
      var tid=table.id?'#'+CSS.escape(table.id):cssPath(table);
      if(tid) return tid+' tr:last-child td:last-child';
    }
    var list=root.querySelector('ul,ol,[role="log"]');
    if(list){
      var lid=list.id?'#'+CSS.escape(list.id):cssPath(list);
      if(lid) return lid+'>*:last-child';
    }
    for(var ci=0;ci<root.children.length;ci++){
      var ch=root.children[ci];
      if(ch===inputEl||ch.contains(inputEl)) continue;
      var chText=(ch.innerText||ch.textContent||'').trim();
      if(chText.length>10){
        var cid=ch.id?'#'+CSS.escape(ch.id):cssPath(ch);
        if(cid) return cid;
      }
    }
    return defaultRespSel;
  }
  var widgets=[];
  var seen={};
  var candidates=deepQueryAll('textarea,input[type="text"],input:not([type]),[contenteditable="true"],[role="textbox"]');
  var scored=[];
  for(var i=0;i<candidates.length;i++){
    var el=candidates[i];
    var sc=scoreChatInput(el);
    if(sc<40) continue;
    scored.push({el:el,score:sc});
  }
  scored.sort(function(a,b){return b.score-a.score;});
  for(var j=0;j<scored.length;j++){
    var el=scored[j].el;
    var sel=cssPath(el);
    if(!sel||seen[sel]) continue;
    seen[sel]=1;
    var submit=null;
    var btn=findNearbyButton(el);
    if(btn) submit=cssPath(btn);
    var form=el.closest('form');
    if(!submit&&form){
      var fbtn=form.querySelector('button[type="submit"],button:not([type]),input[type="submit"]');
      if(fbtn) submit=cssPath(fbtn);
    }
    var respSel=detectResponseArea(el);
    widgets.push({
      inputSelector: sel,
      submitSelector: submit,
      responseSelector: respSel,
      placeholder: el.placeholder||'',
      matchReason: 'dom:chat-input-scored:'+scored[j].score
    });
  }
  var iframes=deepQueryAll('iframe[src*="chat"],iframe[src*="copilot"],iframe[src*="assistant"]');
  var iframeCopilotCount=iframes.length;
  for(var k=0;k<iframes.length;k++){
    try{
      var idoc=iframes[k].contentDocument;
      if(!idoc) continue;
      var inner=idoc.querySelectorAll('textarea,input:not([type="hidden"]),[contenteditable="true"],[role="textbox"]');
      for(var m=0;m<inner.length;m++){
        var iel=inner[m];
        if(scoreChatInput(iel)<40) continue;
        var isel=cssPath(iel);
        if(!isel||seen[isel]) continue;
        seen[isel]=1;
        var ibtn=findNearbyButton(iel);
        widgets.push({
          inputSelector: isel,
          submitSelector: ibtn?cssPath(ibtn):null,
          responseSelector: '.answer:not(label):not(h1):not(h2):not(h3),p.answer,[class*="answer"]:not(label),.response:not(label):not(h1):not(h2):not(h3),[class*="response"]:not(label)',
          placeholder: iel.placeholder||'',
          matchReason: 'dom:iframe-chat-input'
        });
      }
    }catch(e){}
  }
  return JSON.stringify({ widgets: widgets.slice(0,8), iframeCopilotCount: iframeCopilotCount });
})();
""";
}
