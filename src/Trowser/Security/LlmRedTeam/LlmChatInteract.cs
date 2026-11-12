using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;
using Trowser.Security.WebSocket;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Sends a prompt through an in-page chat widget and captures the assistant response.
/// </summary>
public static class LlmChatInteract
{
    public static async Task<LlmChatInteractResult> SendPromptAsync(
        AutomationContext ctx,
        string prompt,
        LlmChatUiTarget? target = null,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        if (string.IsNullOrWhiteSpace(prompt))
            return Fail(prompt, "Prompt is required.", sw);

        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl)
            || !currentUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            return Fail(prompt, "Navigate to an http(s) page with a chat widget first.", sw);

        target ??= new LlmChatUiTarget();

        if (target.ResetUi)
        {
            try
            {
                await ctx.Navigate(currentUrl);
                await Task.Delay(900, ct);
                currentUrl = await ctx.GetCurrentUrl();
            }
            catch
            {
                // best effort
            }
        }

        var resolved = await ResolveSelectorsAsync(ctx, target);
        if (resolved.InputSelector == null)
            return Fail(prompt, target.AutoDetect
                ? "No chat input detected on page. Pass chatTarget.inputSelector or browse to a chat UI."
                : "autoDetect is false but no inputSelector provided in chatTarget.", sw);

        try
        {
            var baseline = await SnapshotCandidatesAsync(ctx, resolved.ResponseSelector, resolved.InputSelector);

            var wsBaseline = SnapshotWebSocketState(ctx);
            var networkBaselineCount = ctx.GetPageNetworkLog().Count;

            await LlmDomInteract.FillInputAsync(ctx, resolved.InputSelector, prompt);
            if (!string.IsNullOrWhiteSpace(resolved.SubmitSelector))
            {
                await LlmDomInteract.ClickSubmitAsync(ctx, resolved.SubmitSelector);
            }
            else
            {
                await LlmDomInteract.SubmitViaEnterAsync(ctx, resolved.InputSelector);
            }

            var capture = await WaitForResponseAsync(
                ctx, resolved, target, baseline, prompt, networkBaselineCount, ct);

            // Prefer real assistant text. Do not trust unchanged DOM nodes (stale prior turn).
            var responseText = capture.ChangedFromBaseline ? capture.Text : "";
            var responseHtml = capture.ChangedFromBaseline ? capture.Html : "";
            var responseSelector = capture.SelectorUsed;
            var responseChanged = capture.ChangedFromBaseline;

            if (LooksLikeStaleOrEmptyCapture(responseText, prompt, baseline))
            {
                responseText = "";
                responseHtml = "";
                responseChanged = false;
            }

            // Prefer dual-channel network when DOM is empty, typing, a conversation dump, or low-confidence structural chrome.
            var preferNetwork = string.IsNullOrWhiteSpace(responseText)
                || IsTypingIndicator(responseText)
                || LooksLikeConversationDump(responseText, prompt)
                || IsLowConfidenceSelector(responseSelector)
                || string.Equals(capture.Confidence, "low", StringComparison.OrdinalIgnoreCase);

            if (preferNetwork)
            {
                if (wsBaseline != null)
                {
                    var wsResponse = CaptureWebSocketResponse(ctx, wsBaseline);
                    if (!string.IsNullOrWhiteSpace(wsResponse) && !IsUserEcho(wsResponse, prompt)
                        && !LooksLikeConversationDump(wsResponse, prompt))
                    {
                        responseText = wsResponse;
                        responseHtml = "";
                        responseSelector = "websocket";
                        responseChanged = true;
                        preferNetwork = false;
                    }
                }

                if (preferNetwork)
                {
                    var netResponse = CaptureNetworkHttpResponse(ctx, networkBaselineCount, prompt);
                    if (!string.IsNullOrWhiteSpace(netResponse))
                    {
                        responseText = netResponse;
                        responseHtml = "";
                        responseSelector = "network";
                        responseChanged = true;
                    }
                }
            }

            var noNetworkActivity = !HasNewOutboundPost(ctx, networkBaselineCount);
            var stuckTyping = await IsTypingStillVisibleAsync(ctx, resolved.ResponseSelector);

            // HTTP failover when UI is stuck / empty (B1) — prefer known endpoints over thrashing the SPA.
            if ((string.IsNullOrWhiteSpace(responseText) || IsTypingIndicator(responseText))
                && target.FailoverToHttp)
            {
                var failover = await TryHttpFailoverAsync(ctx, prompt, ct);
                if (failover != null)
                {
                    sw.Stop();
                    RecordChatVerboseTrace(
                        ctx, currentUrl, prompt, resolved, failover.Value.Text, true,
                        "chat-ui capture failed; used HTTP failover",
                        (int)sw.ElapsedMilliseconds, networkBaselineCount);
                    return new LlmChatInteractResult
                    {
                        Success = true,
                        Prompt = prompt,
                        ResponseText = failover.Value.Text,
                        ResponseHtml = "",
                        InputSelector = resolved.InputSelector,
                        ResponseSelector = "http-failover",
                        ResponseChanged = true,
                        Warning = "Chat UI did not yield a response; used HTTP adapter failover on a discovered endpoint.",
                        RecoveryHint = "Prefer mode=http / llm-http-send for subsequent probes. Optional: chatTarget.resetUi=true before retrying chat-ui.",
                        ElapsedMs = (int)sw.ElapsedMilliseconds
                    };
                }
            }

            sw.Stop();

            var warning = (string?)null;
            string? recovery = null;
            if (string.IsNullOrWhiteSpace(responseText) || IsStaticUiLabel(responseText))
            {
                if (IsStaticUiLabel(responseText))
                {
                    responseText = "";
                    responseHtml = "";
                    responseChanged = false;
                }

                if (stuckTyping || noNetworkActivity)
                {
                    warning = stuckTyping
                        ? "No LLM response captured — chat UI appears stuck on a Typing… / loading indicator."
                        : "No LLM response captured — no outbound chat POST observed after submit (SPA may be ignoring Send).";
                    recovery =
                        "Recovery: force-navigate back to the chat URL (or set chatTarget.resetUi=true), "
                        + "then retry; or switch to HTTP with suggestedHttpTarget from llm-endpoint-discover / llm-http-send.";
                }
                else
                {
                    warning = "No LLM response captured — the prompt may not have reached the model.";
                    recovery = "If the page chat is wedged, set chatTarget.resetUi=true or use llm-http-send / mode=http.";
                }
            }
            else if (!responseChanged)
                warning = "Response text unchanged from pre-submit baseline — probe may not have executed (stale content).";

            RecordChatVerboseTrace(
                ctx, currentUrl, prompt, resolved, responseText, responseChanged, warning,
                (int)sw.ElapsedMilliseconds, networkBaselineCount);

            return new LlmChatInteractResult
            {
                Success = true,
                Prompt = prompt,
                ResponseText = responseText,
                ResponseHtml = responseHtml,
                InputSelector = resolved.InputSelector,
                ResponseSelector = responseSelector,
                ResponseChanged = responseChanged,
                Warning = warning,
                RecoveryHint = recovery,
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return Fail(prompt, ex.Message, sw, resolved.InputSelector, resolved.ResponseSelector);
        }
    }

    private static bool HasNewOutboundPost(AutomationContext ctx, int networkBaselineCount)
    {
        try
        {
            var entries = ctx.GetPageNetworkLog();
            if (entries.Count <= networkBaselineCount) return false;
            return entries.Skip(networkBaselineCount).Any(e =>
                e.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                || e.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> IsTypingStillVisibleAsync(AutomationContext ctx, string? responseSelector)
    {
        try
        {
            var raw = await ctx.ExecuteJs(
                "(function(){var t=(document.body&&(document.body.innerText||''))||'';" +
                "t=t.toLowerCase();" +
                "return /typing[.…]*$|thinking[.…]*$|generating[.…]*$|●\\s*●\\s*●/.test(t.slice(-80));})()");
            if (string.IsNullOrWhiteSpace(raw)) return false;
            var u = UnwrapJsString(raw).Trim();
            return u.Equals("true", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<(string Text, string Url)?> TryHttpFailoverAsync(
        AutomationContext ctx, string prompt, CancellationToken ct)
    {
        try
        {
            var surface = await LlmEndpointDiscovery.DiscoverAsync(ctx);
            var endpoint = LlmEndpointDiscovery.SelectBestEndpoint(surface.Endpoints);
            if (endpoint == null || endpoint.Confidence < 50) return null;
            var http = LlmEndpointDiscovery.InferHttpTarget(endpoint);
            if (http == null) return null;
            var text = await LlmHttpAdapter.SendAsync(ctx, http, prompt, ct);
            if (string.IsNullOrWhiteSpace(text)) return null;
            return (text, http.Url);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<ResolvedSelectors> ResolveSelectorsAsync(AutomationContext ctx, LlmChatUiTarget target)
    {
        if (!string.IsNullOrWhiteSpace(target.InputSelector))
        {
            return new ResolvedSelectors
            {
                InputSelector = target.InputSelector,
                SubmitSelector = target.SubmitSelector,
                ResponseSelector = target.ResponseSelector
            };
        }

        if (!target.AutoDetect)
            return new ResolvedSelectors();

        var dom = await LlmEndpointDiscovery.DiscoverDomHintsAsync(ctx);
        var first = dom.Widgets.FirstOrDefault();
        if (first == null) return new ResolvedSelectors();

        return new ResolvedSelectors
        {
            InputSelector = first.InputSelector,
            SubmitSelector = first.SubmitSelector ?? target.SubmitSelector,
            ResponseSelector = target.ResponseSelector ?? first.ResponseSelector
        };
    }

    private static async Task<Dictionary<string, string>> SnapshotCandidatesAsync(
        AutomationContext ctx,
        string? responseSelector,
        string? inputSelector)
    {
        var raw = await ExecuteCaptureScript(ctx, responseSelector, inputSelector, baselineJson: "null", promptJson: "null");
        if (string.IsNullOrWhiteSpace(raw)) return new Dictionary<string, string>(StringComparer.Ordinal);

        try
        {
            using var doc = JsonDocument.Parse(UnwrapJsString(raw));
            if (!doc.RootElement.TryGetProperty("snapshot", out var snap) || snap.ValueKind != JsonValueKind.Object)
                return new Dictionary<string, string>(StringComparer.Ordinal);

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var prop in snap.EnumerateObject())
                result[prop.Name] = prop.Value.GetString() ?? "";
            return result;
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }
    }

    private static readonly string[] TypingIndicatorPatterns =
    [
        "[typing", "typing...", "thinking...", "generating...", "loading...",
        "writing...", "processing...", "responding...", "…",
        "● ● ●", "• • •", "...", ". . ."
    ];

    private static bool IsUserEcho(string text, string prompt)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prompt)) return false;
        var t = CollapseWs(text);
        var p = CollapseWs(prompt);
        if (t.Equals(p, StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith(p, StringComparison.OrdinalIgnoreCase) && t.Length < p.Length + 40) return true;
        if (t.Length < 120 && p.Contains(t, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string CollapseWs(string s) =>
        string.Join(' ', s.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    /// <summary>
    /// Reject captures that are empty, typing-only, exact user echoes, or unchanged prior-turn
    /// assistant bubbles (classic off-by-one when the new reply has not arrived yet).
    /// </summary>
    private static bool LooksLikeStaleOrEmptyCapture(
        string responseText,
        string prompt,
        Dictionary<string, string> baseline)
    {
        if (string.IsNullOrWhiteSpace(responseText) || IsTypingIndicator(responseText))
            return true;
        if (IsUserEcho(responseText, prompt))
            return true;
        if (LooksLikeConversationDump(responseText, prompt))
            return true;
        if (IsStaticUiLabel(responseText))
            return true;

        // If the exact captured text was already present in the pre-submit snapshot, it is stale.
        var collapsed = CollapseWs(responseText);
        foreach (var kv in baseline)
        {
            if (kv.Key is "__fullPageText__" or "__assistantCount__") continue;
            if (CollapseWs(kv.Value).Equals(collapsed, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>True when capture still contains the submitted user prompt plus substantial other text.</summary>
    private static bool LooksLikeConversationDump(string text, string prompt)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(prompt) || prompt.Length < 8)
            return false;
        var t = CollapseWs(text);
        var p = CollapseWs(prompt);
        return t.Contains(p, StringComparison.OrdinalIgnoreCase) && t.Length > p.Length + 48;
    }

    private static readonly string[] ChatUrlHints =
    [
        "/chat", "/completion", "/completions", "/messages", "/assistant", "/generate",
        "/llm", "/copilot", "/ask", "/prompt", "/openai", "/anthropic", "/api/ai"
    ];

    private static string? CaptureNetworkHttpResponse(
        AutomationContext ctx,
        int networkBaselineCount,
        string prompt)
    {
        try
        {
            var entries = ctx.GetPageNetworkLog();
            if (entries.Count <= networkBaselineCount) return null;

            string? best = null;
            foreach (var entry in entries.Skip(networkBaselineCount).Reverse())
            {
                if (entry.IsTrowserGenerated) continue;
                var isWrite = entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                              || entry.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase);
                var isGetStream = entry.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) && entry.IsEventStream;
                if (!isWrite && !isGetStream)
                    continue;
                if (entry.StatusCode is < 200 or >= 300) continue;

                var bodyForExtract = entry.ResponseBody;
                if (isGetStream && string.IsNullOrWhiteSpace(bodyForExtract))
                {
                    var conn = ctx.ActiveTab.Sse.GetConnections(urlFilter: entry.Url).FirstOrDefault();
                    if (conn != null)
                    {
                        var msgs = ctx.ActiveTab.Sse.GetMessages(conn.ConnectionId, last: 30);
                        bodyForExtract = string.Join("\n", msgs.Select(m => "data: " + m.Data));
                    }
                }

                if (string.IsNullOrWhiteSpace(bodyForExtract)) continue;

                var url = entry.Url ?? "";
                var looksChat = ChatUrlHints.Any(h => url.Contains(h, StringComparison.OrdinalIgnoreCase))
                                || LooksLikeLlmRequestBody(entry.RequestBody)
                                || LooksLikeLlmResponseBody(bodyForExtract);
                if (!looksChat) continue;

                var extracted = ExtractAssistantFromNetworkBody(bodyForExtract, entry.ContentType);
                if (string.IsNullOrWhiteSpace(extracted) || extracted.Length < 2) continue;
                if (IsTypingIndicator(extracted) || IsUserEcho(extracted, prompt)) continue;
                if (IsStaticUiLabel(extracted)) continue;

                // Prefer longer, more recent assistant payloads.
                if (best == null || extracted.Length > best.Length)
                    best = extracted;
            }

            return best;
        }
        catch
        {
            return null;
        }
    }

    private static bool LooksLikeLlmRequestBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var b = body.ToLowerInvariant();
        return (b.Contains("\"messages\"") && b.Contains("\"role\""))
               || b.Contains("\"prompt\"")
               || b.Contains("\"input\"")
               || b.Contains("attacker_input")
               || b.Contains("user_input");
    }

    private static bool LooksLikeLlmResponseBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var b = body;
        if (b.Contains("data:", StringComparison.Ordinal) && b.Contains("\n"))
            return true;
        var lower = b.ToLowerInvariant();
        return lower.Contains("\"choices\"")
               || lower.Contains("\"message\"")
               || lower.Contains("\"content\"")
               || lower.Contains("\"response\"")
               || lower.Contains("\"answer\"");
    }

    private static string ExtractAssistantFromNetworkBody(string body, string? contentType)
    {
        if (!string.IsNullOrWhiteSpace(contentType)
            && contentType.Contains("event-stream", StringComparison.OrdinalIgnoreCase))
            return LlmHttpAdapter.ExtractSseText(body);

        if (LlmHttpAdapter.LooksLikeSse(body) || body.Contains("data:", StringComparison.Ordinal))
        {
            var sse = LlmHttpAdapter.ExtractSseText(body);
            if (!string.IsNullOrWhiteSpace(sse)) return sse;
        }

        return LlmHttpAdapter.ExtractResponse(
            new LlmHttpTargetConfig { Schema = "custom", CustomResponseKey = "response" },
            body);
    }

    private static bool IsTypingIndicator(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim();
        if (trimmed.Length > 80) return false;
        foreach (var pattern in TypingIndicatorPatterns)
        {
            if (trimmed.Equals(pattern, StringComparison.OrdinalIgnoreCase)
                || trimmed.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Detect CSS spinner / animated dots with no real text content
        if (trimmed.Length <= 3 && trimmed.All(c => c == '.' || c == '●' || c == '•' || c == '·'))
            return true;

        return false;
    }

    private static async Task<(string Text, string Html, string? SelectorUsed, bool ChangedFromBaseline, string Confidence)> WaitForResponseAsync(
        AutomationContext ctx,
        ResolvedSelectors resolved,
        LlmChatUiTarget target,
        Dictionary<string, string> baseline,
        string prompt,
        int networkBaselineCount,
        CancellationToken ct)
    {
        var waitMs = Math.Clamp(target.WaitAfterSubmitMs, 500, 30000);
        var started = DateTime.UtcNow;
        // Honor waitAfterSubmitMs as a minimum floor for low-confidence DOM; allow extra for slow APIs.
        var minWaitUntil = started.AddMilliseconds(waitMs);
        var deadline = started.AddMilliseconds(Math.Max(waitMs, 8000));
        var pollMs = 400;
        string? lastText = null;
        var stablePolls = 0;
        var seenTypingIndicator = false;
        var baselineJson = JsonSerializer.Serialize(baseline);
        var promptJson = JsonSerializer.Serialize(prompt);
        var hasCustomSelector = !string.IsNullOrWhiteSpace(resolved.ResponseSelector);

        while (DateTime.UtcNow < deadline)
        {
            // Network often settles before DOM bubbles; prefer it over structural chrome.
            var netEarly = CaptureNetworkHttpResponse(ctx, networkBaselineCount, prompt);
            if (!string.IsNullOrWhiteSpace(netEarly))
                return (netEarly, "", "network", true, "high");

            var capture = await CaptureChangedResponseAsync(ctx, resolved, baselineJson, promptJson);
            if (!string.IsNullOrWhiteSpace(capture.Text) && capture.ChangedFromBaseline
                && !LooksLikeStaleOrEmptyCapture(capture.Text, prompt, baseline))
            {
                if (IsTypingIndicator(capture.Text))
                {
                    seenTypingIndicator = true;
                    stablePolls = 0;
                    lastText = null;
                    await Task.Delay(pollMs, ct);
                    continue;
                }

                var highConfidence = string.Equals(capture.Confidence, "high", StringComparison.OrdinalIgnoreCase)
                    || (hasCustomSelector && !IsLowConfidenceSelector(capture.SelectorUsed));
                var pastMinWait = DateTime.UtcNow >= minWaitUntil;

                // Never early-accept low-confidence structural/nav matches before the requested wait.
                if (!highConfidence && !pastMinWait)
                {
                    await Task.Delay(pollMs, ct);
                    continue;
                }

                if (capture.Text == lastText)
                {
                    stablePolls++;
                    if (stablePolls >= 2 && (highConfidence || pastMinWait))
                        return capture;
                }
                else
                {
                    stablePolls = 0;
                    lastText = capture.Text;
                }
            }
            else if (seenTypingIndicator)
            {
                stablePolls = 0;
                lastText = null;
            }

            await Task.Delay(pollMs, ct);
        }

        var net = CaptureNetworkHttpResponse(ctx, networkBaselineCount, prompt);
        if (!string.IsNullOrWhiteSpace(net))
            return (net, "", "network", true, "high");

        var final = await CaptureChangedResponseAsync(ctx, resolved, baselineJson, promptJson);
        if (IsTypingIndicator(final.Text) || LooksLikeStaleOrEmptyCapture(final.Text, prompt, baseline)
            || IsLowConfidenceSelector(final.SelectorUsed))
            return ("", "", final.SelectorUsed, false, final.Confidence);
        return final;
    }

    private static bool IsLowConfidenceSelector(string? selector) =>
        !string.IsNullOrWhiteSpace(selector)
        && (selector.StartsWith("structural:", StringComparison.OrdinalIgnoreCase)
            || selector.StartsWith("fullpage", StringComparison.OrdinalIgnoreCase));

    private static async Task<(string Text, string Html, string? SelectorUsed, bool ChangedFromBaseline, string Confidence)> CaptureChangedResponseAsync(
        AutomationContext ctx,
        ResolvedSelectors resolved,
        string baselineJson,
        string promptJson)
    {
        var raw = await ExecuteCaptureScript(ctx, resolved.ResponseSelector, resolved.InputSelector, baselineJson, promptJson);
        if (string.IsNullOrWhiteSpace(raw))
            return ("", "", null, false, "none");

        try
        {
            using var doc = JsonDocument.Parse(UnwrapJsString(raw));
            var root = doc.RootElement;
            var text = root.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";
            var html = root.TryGetProperty("html", out var h) ? h.GetString() ?? "" : "";
            var selector = root.TryGetProperty("selector", out var s) ? s.GetString() : null;
            var changed = root.TryGetProperty("changed", out var c) && c.GetBoolean();
            var confidence = root.TryGetProperty("confidence", out var conf) ? conf.GetString() ?? "medium" : "medium";
            if (IsLowConfidenceSelector(selector))
                confidence = "low";
            return (text, html, string.IsNullOrWhiteSpace(selector) ? null : selector, changed, confidence);
        }
        catch
        {
            return ("", "", null, false, "none");
        }
    }

    private static async Task<string> ExecuteCaptureScript(
        AutomationContext ctx,
        string? responseSelector,
        string? inputSelector,
        string baselineJson,
        string promptJson)
    {
        var selectorJs = JsonSerializer.Serialize(responseSelector ?? "");
        var inputJs = JsonSerializer.Serialize(inputSelector ?? "");
        return await ctx.ExecuteJs(
            "(function(){" +
            LlmDomScripts.DeepSearchJs +
            LlmDomScripts.VisibilityJs +
            "var custom=" + selectorJs + ";" +
            "var inputSel=" + inputJs + ";" +
            "var baseline=" + baselineJson + "||{};" +
            "var userPrompt=" + promptJson + "||'';" +

            // Class-based selectors — assistant roles first (Broken Crystals uses .message-role-assistant;
            // prefer role/class assistant markers over generic .response / list heuristics).
            "var common=[" +
            "  '.message-role-assistant','.message.message-role-assistant','[class*=\"message-role-assistant\"]'," +
            "  '[data-message-author-role=\"assistant\"]','[data-role=\"assistant\"]'," +
            "  '.bot-message','.assistant-message','[data-testid*=\"assistant\"]'," +
            "  '[class*=\"assistant-message\"]','[class*=\"AssistantMessage\"]'," +
            "  '.answer:not(label):not(legend):not(h1):not(h2):not(h3):not(h4):not(h5):not(h6)'," +
            "  'p.answer','[class*=\"answer\"]:not(label):not(legend):not(h1):not(h2):not(h3):not(h4):not(h5):not(h6)'," +
            "  '.response:not(label):not(legend):not(h1):not(h2):not(h3):not(h4):not(h5):not(h6)'," +
            "  '[class*=\"response\"]:not(label):not(legend):not(h1):not(h2):not(h3):not(h4):not(h5):not(h6)'," +
            "  '[data-testid*=\"response\"]','[class*=\"assistant\"]:not(input):not(textarea):not([contenteditable=\"true\"]):not(label):not(h1):not(h2):not(h3)'," +
            "  '[class*=\"bot\"]:not(input):not(textarea):not([contenteditable=\"true\"]):not(label):not(h1):not(h2):not(h3)'" +
            "];" +

            "function norm(s){return (s||'').replace(/\\s+/g,' ').trim();}" +
            "function isUserEcho(text){" +
            "  var t=norm(text); if(!t||!userPrompt) return false;" +
            "  var p=norm(userPrompt);" +
            "  if(t===p||t.indexOf(p)===0) return true;" +
            "  return t.length<120&&p.indexOf(t)>-1;" +
            "}" +
            // Full chat containers that still contain the just-submitted user prompt.
            "function isConversationDump(text){" +
            "  var t=norm(text); if(!t||!userPrompt) return false;" +
            "  var p=norm(userPrompt);" +
            "  if(!p||p.length<8) return false;" +
            "  return t.indexOf(p)>=0 && t.length>p.length+48;" +
            "}" +
            "function isNavChrome(el){" +
            "  if(!el||!el.closest) return false;" +
            "  return !!el.closest('nav,header,footer,aside,[role=\"navigation\"],[role=\"banner\"],[role=\"contentinfo\"],.navbar,.nav-menu,.sidebar');" +
            "}" +
            "function isAssistantEl(el){" +
            "  if(!el) return false;" +
            "  var role=(el.getAttribute&&(el.getAttribute('data-role')||el.getAttribute('data-message-author-role')||''))||'';" +
            "  var cls=(el.className&&String(el.className))||'';" +
            "  if(/assistant/i.test(role)) return true;" +
            "  if(/message-role-assistant|assistant-message|bot-message/i.test(cls)) return true;" +
            "  return false;" +
            "}" +
            "function isUserRoleEl(el){" +
            "  if(!el) return false;" +
            "  var role=(el.getAttribute&&(el.getAttribute('data-role')||el.getAttribute('data-message-author-role')||''))||'';" +
            "  var cls=(el.className&&String(el.className))||'';" +
            "  if(/\\b(user|human|me)\\b/i.test(role)) return true;" +
            "  if(/message-role-user|user-message|human-message/i.test(cls)) return true;" +
            "  return false;" +
            "}" +

            // Static UI labels mistaken for model output (e.g. a heading whose class is .response)
            "var staticLabels=/^(response|answer|output|assistant|bot|reply|result|message|messages|chat|prompt|vulnerabilities|about|docs|documentation|home|login|logout)$/i;" +
            "function isStaticLabel(text){" +
            "  var t=norm(text); if(!t) return true;" +
            "  if(t.length<=28&&staticLabels.test(t)) return true;" +
            "  return false;" +
            "}" +
            "function isLabelOrHeading(el){" +
            "  if(!el||!el.tagName) return false;" +
            "  var tag=el.tagName.toLowerCase();" +
            "  if(tag==='label'||tag==='legend'||tag==='th'||tag==='caption'||tag==='summary'||tag==='a') return true;" +
            "  if(/^h[1-6]$/.test(tag)) return true;" +
            "  if(el.getAttribute&&el.getAttribute('role')==='heading') return true;" +
            "  return false;" +
            "}" +

            // Typing indicator detection — skip elements that are just loading spinners
            "var typingPats=[/^\\[typing/i,/^typing\\.{3}/i,/^thinking\\.{3}/i,/^generating/i," +
            "  /^loading\\.{3}/i,/^writing\\.{3}/i,/^processing/i,/^responding/i," +
            "  /^\\.{2,4}$/,/^[●•·\\s]{1,10}$/,/^\\u2026$/];" +
            "function isTypingText(text){" +
            "  var t=norm(text); if(!t||t.length>80) return false;" +
            "  for(var i=0;i<typingPats.length;i++) if(typingPats[i].test(t)) return true;" +
            "  return false;" +
            "}" +
            "function isTypingElement(el){" +
            "  if(!el) return false;" +
            "  var cls=(el.className||'')+(el.parentElement?(' '+(el.parentElement.className||'')):'');" +
            "  if(/\\b(typing|loading|spinner|thinking|generating|pending)\\b/i.test(cls)) return true;" +
            "  if(el.getAttribute&&el.getAttribute('aria-busy')==='true') return true;" +
            "  return isTypingText(norm(el.innerText||el.textContent||''));" +
            "}" +
            "function isUsableResponseEl(el,text){" +
            "  if(!el||isLabelOrHeading(el)||isTypingElement(el)||isNavChrome(el)||isUserRoleEl(el)) return false;" +
            "  if(!text||isUserEcho(text)||isTypingText(text)||isStaticLabel(text)||isConversationDump(text)) return false;" +
            "  return true;" +
            "}" +

            // Strategy 1: User-provided custom selector (exclusive when set — do not fall through to nav lists)
            "function tryCustomSelector(){" +
            "  if(!custom) return null;" +
            "  var nodes=deepQueryAll(custom);" +
            // Agents often pass :last-of-type expecting 'last match'; CSS :last-of-type is tag-based and often matches nothing.
            "  if(!nodes.length && /:(last-of-type|last-child)\\b/.test(custom))" +
            "    nodes=deepQueryAll(custom.replace(/:(last-of-type|last-child)\\b/g,'').trim());" +
            "  if(!nodes.length) return null;" +
            "  for(var ni=nodes.length-1;ni>=0;ni--){" +
            "    var el=nodes[ni];" +
            "    if(isLabelOrHeading(el)||isTypingElement(el)||isNavChrome(el)||isUserRoleEl(el)) continue;" +
            "    var t=norm(el.innerText||el.textContent||'');" +
            "    var key='custom::'+ni;" +
            "    var base=baseline[key]||baseline['custom::0']||baseline[custom+'::0']||'';" +
            "    var isolated=isolateLastResponse(el);" +
            "    if(isolated&&isUsableResponseEl(el,isolated.text)&&isolated.text!==base)" +
            "      return {text:isolated.text,html:isolated.html,sel:custom+'#isolated',changed:true,confidence:'high'};" +
            "    if(isUsableResponseEl(el,t)&&t!==base)" +
            "      return {text:t,html:el.innerHTML||'',sel:custom,changed:true,confidence:'high'};" +
            "  }" +
            "  return null;" +
            "}" +

            // Strategy 2: Standard class-based selectors
            "function tryClassSelectors(selectors){" +
            "  var best=null;" +
            "  for(var i=0;i<selectors.length;i++){" +
            "    var sel=selectors[i];" +
            "    var nodes=deepQueryAll(sel);" +
            "    for(var j=0;j<nodes.length;j++){" +
            "      var el=nodes[j];" +
            "      if(inputSel&&el.matches&&el.matches(inputSel)) continue;" +
            "      if(isLabelOrHeading(el)||isTypingElement(el)||isNavChrome(el)||isUserRoleEl(el)) continue;" +
            "      var text=norm(el.innerText||el.textContent||'');" +
            "      if(!isUsableResponseEl(el,text)) continue;" +
            "      var key=sel+'::'+j;" +
            "      var base=baseline[key]||'';" +
            "      var changed=text!==base;" +
            "      if(!changed&&base) continue;" +
            "      var seen=false; for(var bk in baseline){ if(bk!=='__fullPageText__'&&baseline[bk]===text){seen=true;break;} }" +
            "      if(seen) continue;" +
            "      var score=text.length+(changed?1000:0)+(isAssistantEl(el)?800:0);" +
            "      if(/assistant|bot-message|message-role-assistant/i.test(sel)) score+=500;" +
            "      if(text.length<8) score-=500;" +
            "      if(!best||score>best.score) best={score:score,text:text,html:el.innerHTML||'',sel:sel,changed:changed,confidence:isAssistantEl(el)?'high':'medium'};" +
            "    }" +
            "  }" +
            "  return best;" +
            "}" +

            // Strategy 3: Structural heuristics — ONLY inside chat roots near the input (never document-wide nav lists)
            "function tryStructuralHeuristics(){" +
            "  var input=inputSel?deepQueryBest(inputSel):null;" +
            "  if(!input) return null;" +
            "  var searchRoots=[" +
            "    input.closest('[class*=\"chat\"],[id*=\"chat\"],[class*=\"message\"],[class*=\"conversation\"],[class*=\"thread\"],[role=\"log\"]')," +
            "    input.parentElement&&input.parentElement.parentElement" +
            "  ].filter(Boolean);" +
            "  if(!searchRoots.length) return null;" +

            "  var tableSelectors=[" +
            "    'table[class*=\"chat\"] tr:last-child td'," +
            "    'table[id*=\"chat\"] tr:last-child td'," +
            "    'table[class*=\"message\"] tr:last-child td'" +
            "  ];" +
            "  var containerSelectors=[" +
            "    '[role=\"log\"]>*:last-child'," +
            "    '[class*=\"conversation\"]>*:last-child'," +
            "    '[class*=\"messages\"]>*:last-child'," +
            "    '[class*=\"chat-area\"]>*:last-child'," +
            "    '[class*=\"message-list\"]>*:last-child'" +
            "  ];" +
            // Intentionally omit bare 'ul>li:last-child' — matches site nav (e.g. \"Vulnerabilities\").
            "  var allStructural=tableSelectors.concat(containerSelectors);" +
            "  for(var i=0;i<allStructural.length;i++){" +
            "    var sel=allStructural[i];" +
            "    for(var r=0;r<searchRoots.length;r++){" +
            "      try{" +
            "        if(isNavChrome(searchRoots[r])) continue;" +
            "        var nodes=searchRoots[r].querySelectorAll(sel);" +
            "        if(!nodes.length) continue;" +
            "        var el=null;" +
            "        for(var ni=nodes.length-1;ni>=0;ni--){" +
            "          if(!isTypingElement(nodes[ni])&&!isNavChrome(nodes[ni])&&!isUserRoleEl(nodes[ni])){el=nodes[ni];break;}" +
            "        }" +
            "        if(!el) continue;" +
            "        var t=norm(el.innerText||el.textContent||'');" +
            "        if(!isUsableResponseEl(el,t)) continue;" +
            "        if(t.length<12) continue;" +
            "        var key='struct::'+sel+'::'+r;" +
            "        var base=baseline[key]||'';" +
            "        if(t===base) continue;" +
            "        var seen=false; for(var bk in baseline){ if(bk!=='__fullPageText__'&&baseline[bk]===t){seen=true;break;} }" +
            "        if(seen) continue;" +
            "        return {text:t,html:el.innerHTML||'',sel:'structural:'+sel,changed:true,confidence:'low'};" +
            "      }catch(e){}" +
            "    }" +
            "  }" +

            // Walk from input upward, find sibling containers
            "  if(input){" +
            "    var root=input.closest('[class*=\"chat\"],[id*=\"chat\"],[class*=\"message\"],[class*=\"conversation\"],[role=\"log\"],[role=\"main\"]');" +
            "    if(root){" +
            "      var kids=root.querySelectorAll('tr td,li,p,div,[class*=\"message\"],.markdown,.prose');" +
            "      for(var k=kids.length-1;k>=0;k--){" +
            "        var m=kids[k]; if(m===input||(input&&m.contains(input))) continue;" +
            "        if(isTypingElement(m)) continue;" +
            "        var mt=norm(m.innerText||m.textContent||'');" +
            "        if(!isUsableResponseEl(m,mt)) continue;" +
            "        var mk='conversation::'+k; var mb=baseline[mk]||'';" +
            "        if(mt===mb) continue;" +
            "        var seen2=false; for(var bk2 in baseline){ if(baseline[bk2]===mt){seen2=true;break;} }" +
            "        if(seen2) continue;" +
            "        if(mt!==mb) return {text:mt,html:m.innerHTML||'',sel:'conversation:last',changed:true};" +
            "      }" +
            "    }" +
            "  }" +
            "  return null;" +
            "}" +

            // Strategy 4: Full-page text diff (ultimate fallback — Enhancement)
            "function tryFullPageDiff(){" +
            "  var baseText=baseline['__fullPageText__']||'';" +
            "  if(!baseText) return null;" +
            "  var currentText=norm(document.body.innerText||document.body.textContent||'');" +
            "  if(currentText===baseText) return null;" +

            // Find the new text by simple suffix/diff
            "  var baseLines=baseText.split(/\\n+/).filter(Boolean);" +
            "  var curLines=currentText.split(/\\n+/).filter(Boolean);" +
            "  var newLines=[];" +
            "  var bSet={};" +
            "  for(var i=0;i<baseLines.length;i++) bSet[baseLines[i]]=1;" +
            "  for(var j=0;j<curLines.length;j++){" +
            "    if(!bSet[curLines[j]]) newLines.push(curLines[j]);" +
            "  }" +
            "  var newText=newLines.join(' ').trim();" +
            "  if(newText&&!isUserEcho(newText)&&!isTypingText(newText)&&!isStaticLabel(newText))" +
            "    return {text:newText,html:'',sel:'fullPageDiff',changed:true};" +
            "  return null;" +
            "}" +

            // Isolate latest *new* assistant response from a conversation container.
            // Prefer children that were not present (by text) in the pre-submit baseline.
            "function isolateLastResponse(container){" +
            "  if(!container) return null;" +
            "  var children=container.querySelectorAll('tr,li,p,div,[class*=\"message\"],.markdown,.prose,dd,[data-role=\"assistant\"]');" +
            "  if(children.length<1) return null;" +
            "  var baseTexts={};" +
            "  for(var bk in baseline){ if(bk.indexOf('conversation::')===0||bk.indexOf('::')>0) baseTexts[baseline[bk]]=1; }" +
            "  for(var i=children.length-1;i>=0;i--){" +
            "    var ch=children[i];" +
            "    if(inputSel&&ch.matches&&ch.matches(inputSel)) continue;" +
            "    if(ch.querySelector&&inputSel&&ch.querySelector(inputSel)) continue;" +
            "    if(isTypingElement(ch)) continue;" +
            "    var role=(ch.getAttribute&& (ch.getAttribute('data-role')||ch.getAttribute('data-message-author-role')||''))||'';" +
            "    var cls=(ch.className||'')+'';" +
            "    if(/\\b(user|human|me)\\b/i.test(role)||/\\b(user|human)-message\\b/i.test(cls)) continue;" +
            "    var t=norm(ch.innerText||ch.textContent||'');" +
            "    if(!isUsableResponseEl(ch,t)) continue;" +
            "    if(baseTexts[t]) continue;" + // must be new vs baseline content
            "    return {text:t,html:ch.innerHTML||''};" +
            "  }" +
            "  return null;" +
            "}" +

            // Run strategies in priority order. When a custom responseSelector is provided,
            // never fall through to structural/nav heuristics (those caused "Vulnerabilities" FPs).
            "function pickBest(){" +
            "  var r=tryCustomSelector(); if(r&&r.changed) return r;" +
            "  if(custom) return {text:'',html:'',sel:'',changed:false,confidence:'none'};" +
            "  r=tryClassSelectors(common); if(r&&r.changed) return r;" +
            "  r=tryStructuralHeuristics(); if(r&&r.changed&&r.confidence!=='low') return r;" +
            "  r=tryFullPageDiff(); if(r&&r.changed&&!isConversationDump(r.text)) return r;" +
            "  return {text:'',html:'',sel:'',changed:false,confidence:'none'};" +
            "}" +

            // Build snapshot for baseline comparison
            "function buildSnapshot(){" +
            "  var snap={};" +
            "  var allSels=custom?[custom].concat(common):common;" +
            "  for(var i=0;i<allSels.length;i++){" +
            "    var sel=allSels[i];" +
            "    try{" +
            "      var nodes=deepQueryAll(sel);" +
            "      for(var j=0;j<nodes.length;j++){" +
            "        var t=norm(nodes[j].innerText||nodes[j].textContent||'');" +
            "        if(t) snap[sel+'::'+j]=t;" +
            "      }" +
            "    }catch(e){}" +
            "  }" +
            "  if(custom){" +
            "    var cn=deepQueryAll(custom);" +
            "    if(cn.length){var ct=norm(cn[cn.length-1].innerText||cn[cn.length-1].textContent||''); if(ct) snap['custom::0']=ct;}" +
            "  }" +
            // Capture full page text for diff fallback
            "  snap['__fullPageText__']=norm(document.body.innerText||document.body.textContent||'');" +
            // Capture structural baselines
            "  var input=inputSel?deepQueryBest(inputSel):null;" +
            "  if(input){" +
            "    var root=input.closest('[class*=\"chat\"],[id*=\"chat\"],[class*=\"message\"],[class*=\"conversation\"],[role=\"log\"],[role=\"main\"]');" +
            "    if(root){" +
            "      var kids=root.querySelectorAll('tr td,li,p,div,[class*=\"message\"],.markdown,.prose');" +
            "      for(var k=0;k<kids.length;k++){" +
            "        var mt=norm(kids[k].innerText||kids[k].textContent||'');" +
            "        if(mt) snap['conversation::'+k]=mt;" +
            "      }" +
            "    }" +
            "  }" +
            "  return snap;" +
            "}" +

            "var snap=buildSnapshot();" +
            "var picked=pickBest();" +
            "return JSON.stringify({text:picked.text||'',html:picked.html||'',selector:picked.sel||'',changed:!!picked.changed,confidence:picked.confidence||'medium',snapshot:snap});" +
            "})()");
    }

    // ── Dual-channel WebSocket response capture ──

    private static readonly string[] WsContentKeys =
        ["content", "message", "response", "answer", "text", "reply", "output", "data"];

    private sealed class WsBaseline
    {
        public required Dictionary<int, int> LastFrameIdByConnection { get; init; }
    }

    private static WsBaseline? SnapshotWebSocketState(AutomationContext ctx)
    {
        try
        {
            var wsManager = ctx.ActiveTab.WebSocket;
            var connections = wsManager.GetConnections(stateFilter: "open");
            if (connections.Count == 0) return null;

            var snapshot = new Dictionary<int, int>();
            foreach (var conn in connections)
            {
                var frames = wsManager.GetFrames(conn.ConnectionId, last: 1);
                var lastId = frames.Count > 0 ? frames[^1].FrameId : 0;
                snapshot[conn.ConnectionId] = lastId;
            }

            return new WsBaseline { LastFrameIdByConnection = snapshot };
        }
        catch
        {
            return null;
        }
    }

    private static string? CaptureWebSocketResponse(AutomationContext ctx, WsBaseline baseline)
    {
        try
        {
            var wsManager = ctx.ActiveTab.WebSocket;
            foreach (var (connId, lastFrameId) in baseline.LastFrameIdByConnection)
            {
                var newFrames = wsManager.GetFrames(
                    connId,
                    directionFilter: "received",
                    sinceFrameId: lastFrameId);

                foreach (var frame in newFrames)
                {
                    if (!frame.IsJson || string.IsNullOrWhiteSpace(frame.Data)) continue;
                    var content = ExtractWsContentField(frame.Data);
                    if (!string.IsNullOrWhiteSpace(content)
                        && content.Length > 5
                        && !IsTypingIndicator(content))
                        return content;
                }
            }
        }
        catch
        {
            // WebSocket access failure is non-fatal
        }

        return null;
    }

    private static string? ExtractWsContentField(string json)
    {
        try
        {
            var node = JsonNode.Parse(json);
            if (node is not JsonObject obj) return null;

            foreach (var key in WsContentKeys)
            {
                if (obj[key] is JsonValue val && val.TryGetValue<string>(out var s)
                    && !string.IsNullOrWhiteSpace(s))
                    return s;
            }

            // Check nested: { "message": { "content": "..." } } or { "choices": [{ "message": { "content": "..." } }] }
            if (obj["message"] is JsonObject msgObj)
            {
                foreach (var key in WsContentKeys)
                {
                    if (msgObj[key] is JsonValue v && v.TryGetValue<string>(out var s2)
                        && !string.IsNullOrWhiteSpace(s2))
                        return s2;
                }
            }

            if (obj["choices"] is JsonArray choices && choices.Count > 0
                && choices[0] is JsonObject choice
                && choice["message"] is JsonObject choiceMsg
                && choiceMsg["content"] is JsonValue cv
                && cv.TryGetValue<string>(out var s3))
                return s3;
        }
        catch
        {
            // Malformed JSON is non-fatal
        }

        return null;
    }

    private static string UnwrapJsString(string raw)
    {
        if (raw.StartsWith('"'))
            return JsonSerializer.Deserialize<string>(raw) ?? raw;
        return raw;
    }

    private static readonly string[] StaticUiLabels =
    [
        "response", "answer", "output", "assistant", "bot", "reply", "result",
        "message", "messages", "chat", "prompt", "vulnerabilities", "vulnerability",
        "home", "login", "logout", "register", "about", "docs", "documentation"
    ];

    private static bool IsStaticUiLabel(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = text.Trim();
        if (t.Length > 24) return false;
        return StaticUiLabels.Any(l => t.Equals(l, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Populate <c>verboseTrace</c> for chat-ui probes: record the DOM submit plus any new POSTs
    /// observed in the page network log after submit.
    /// </summary>
    private static void RecordChatVerboseTrace(
        AutomationContext ctx,
        string pageUrl,
        string prompt,
        ResolvedSelectors resolved,
        string responseText,
        bool responseChanged,
        string? warning,
        int elapsedMs,
        int networkBaselineCount)
    {
        try
        {
            var excerpt = string.IsNullOrWhiteSpace(responseText)
                ? null
                : (responseText.Length <= 400 ? responseText : responseText[..400] + "...");
            var payload =
                $"input={resolved.InputSelector}; submit={resolved.SubmitSelector}; prompt={TruncateForTrace(prompt, 200)}"
                + (excerpt != null ? $"; response={excerpt}" : "");

            ctx.RecordOutboundRequest(
                "CHAT",
                string.IsNullOrWhiteSpace(pageUrl) ? "chat-ui" : pageUrl,
                payload,
                responseChanged && string.IsNullOrWhiteSpace(warning) ? 200 : 0,
                elapsedMs,
                warning,
                "chat-ui");

            var entries = ctx.GetPageNetworkLog();
            if (entries.Count <= networkBaselineCount) return;

            foreach (var entry in entries.Skip(networkBaselineCount))
            {
                if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                    && !entry.Method.Equals("PUT", StringComparison.OrdinalIgnoreCase))
                    continue;

                var body = entry.RequestBody;
                if (string.IsNullOrWhiteSpace(body) && !string.IsNullOrWhiteSpace(entry.ResponseBody))
                {
                    var responseBody = entry.ResponseBody!;
                    var ct = entry.ContentType ?? "";
                    body = ct.Contains("event-stream", StringComparison.OrdinalIgnoreCase)
                        ? LlmHttpAdapter.ExtractSseText(responseBody)
                        : responseBody;
                    if (!string.IsNullOrEmpty(body))
                        body = "response:" + TruncateForTrace(body, 400);
                }

                ctx.RecordOutboundRequest(
                    entry.Method,
                    entry.Url,
                    body,
                    entry.StatusCode,
                    (long)(entry.DurationMs ?? 0),
                    entry.StatusCode >= 400 ? $"HTTP {entry.StatusCode}" : null,
                    "chat-ui-network");
            }
        }
        catch
        {
            // Tracing must never break chat interact.
        }
    }

    private static string TruncateForTrace(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    private static LlmChatInteractResult Fail(
        string prompt, string error, Stopwatch sw, string? input = null, string? response = null) =>
        new()
        {
            Success = false,
            Prompt = prompt,
            Error = error,
            InputSelector = input,
            ResponseSelector = response,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };

    private sealed class ResolvedSelectors
    {
        public string? InputSelector { get; init; }
        public string? SubmitSelector { get; init; }
        public string? ResponseSelector { get; init; }
    }
}
