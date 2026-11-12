using System.IO;
using System.Diagnostics;
using System.Text.Json;
using Trowser.Api;
using Trowser.Security.LlmRedTeam;

namespace Trowser.Security.Workflow;

public sealed class WorkflowStepExecutor
{
    private static readonly JsonSerializerOptions CompactJson = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public async Task<Dictionary<string, object?>> ExecuteAsync(
        JsonElement step,
        int index,
        string phase,
        WorkflowExecutionContext ctx,
        WorkflowDependencies deps)
    {
        var stepId = step.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
            ? idEl.GetString() : null;

        if (step.TryGetProperty("delay", out var delayEl) && delayEl.ValueKind == JsonValueKind.Number)
        {
            var delayMs = Math.Clamp(delayEl.GetInt32(), 0, 30_000);
            if (delayMs > 0)
                await Task.Delay(delayMs, deps.Cancellation);
        }

        var type = step.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String
            ? typeEl.GetString()?.ToLowerInvariant()
            : null;

        try
        {
            return type switch
            {
                "identity" => await ExecuteIdentityAsync(step, index, stepId, phase, ctx, deps),
                "navigate" => await ExecuteNavigateAsync(step, index, stepId, phase, ctx, deps),
                "fetch" => await ExecuteFetchAsync(step, index, stepId, phase, ctx, deps, isTrigger: phase == "trigger"),
                "wait" => await ExecuteWaitAsync(step, index, stepId, phase),
                "waitforidle" or "wait-for-idle" => await ExecuteWaitForIdleAsync(step, index, stepId, phase, deps),
                "screenshot" => await ExecuteScreenshotAsync(step, index, stepId, phase, ctx, deps),
                "capture" => ExecuteCapture(step, index, stepId, phase, ctx),
                "inject" => await ExecuteInjectAsync(step, index, stepId, phase, ctx, deps),
                "mock" => ExecuteMock(step, index, stepId, phase, ctx, deps),
                "intercept" => await ExecuteIntercept(step, index, stepId, phase, ctx, deps),
                "load-script" => await ExecuteLoadScriptAsync(step, index, stepId, phase, ctx, deps),
                "llm-chat" => await ExecuteLlmChatAsync(step, index, stepId, phase, ctx, deps),
                null when step.TryGetProperty("path", out _) => await ExecuteRestStepAsync(step, index, stepId, phase, ctx, deps),
                _ => Fail(index, stepId, phase, type, $"Unknown workflow step type: {type ?? "(missing)"}")
            };
        }
        catch (Exception ex)
        {
            return Fail(index, stepId, phase, type, ex.Message);
        }
    }

    private static Dictionary<string, object?> Fail(int index, string? id, string phase, string? type, string error) =>
        new()
        {
            ["index"] = index, ["id"] = id, ["phase"] = phase, ["type"] = type,
            ["success"] = false, ["error"] = error
        };

    private static async Task<Dictionary<string, object?>> ExecuteIdentityAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var action = step.TryGetProperty("action", out var actEl) ? actEl.GetString()?.ToLowerInvariant() : null;
        var name = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null, ctx.Vars);

        if (!IdentityStore.IsValidName(name))
            return Fail(index, stepId, phase, "identity", "Identity step requires valid 'name'.");

        if (action == "capture")
        {
            var includeAuthHeaders = !step.TryGetProperty("includeAuthHeaders", out var iah) || iah.ValueKind != JsonValueKind.False;
            var snapshot = await deps.IdentityStore.CaptureAsync(deps.Context, name!, deps.SessionName, includeAuthHeaders);
            return Ok(index, stepId, phase, "identity", new { action, name, cookieCount = snapshot.Cookies.Count });
        }

        if (action == "apply")
        {
            var navigateTo = step.TryGetProperty("navigateTo", out var navEl) && navEl.ValueKind == JsonValueKind.String
                ? WorkflowVarSubstitution.Substitute(navEl.GetString(), ctx.Vars) : null;
            IdentityVerifyOptions? verify = null;
            if (step.TryGetProperty("verify", out var verifyEl) && verifyEl.ValueKind == JsonValueKind.Object)
                verify = ParseIdentityVerify(WorkflowVarSubstitution.SubstituteElement(verifyEl, ctx.Vars));

            var target = step.TryGetProperty("target", out var targetEl) && targetEl.ValueKind == JsonValueKind.String
                ? targetEl.GetString()?.Trim().ToLowerInvariant() : "self";

            if (target == "peer")
            {
                var peer = step.TryGetProperty("peer", out var peerEl) ? peerEl.GetString()?.Trim() : null;
                if (string.IsNullOrWhiteSpace(peer) || deps.Peers == null)
                    return Fail(index, stepId, phase, "identity", "target=peer requires registered 'peer'.");

                var forwardBody = new Dictionary<string, object?> { ["name"] = name, ["target"] = "self", ["navigateTo"] = navigateTo };
                if (verify != null)
                    forwardBody["verify"] = new { verify.Url, verify.ExpectStatus, verify.Method, verify.Headers, verify.Body, verify.TimeoutMs };
                var peerResp = await deps.Peers.ForwardAsync(peer, "POST", "/api/identity/apply",
                    JsonSerializer.Serialize(forwardBody, CompactJson),
                    timeoutMs: PeerRegistry.OperationTimeoutMs);
                var ok = peerResp.Success || peerResp.StatusCode == 200;
                return new Dictionary<string, object?>
                {
                    ["index"] = index, ["id"] = stepId, ["phase"] = phase, ["type"] = "identity", ["action"] = action,
                    ["success"] = ok, ["peer"] = peer, ["peerStatus"] = peerResp.StatusCode
                };
            }

            var result = await deps.IdentityStore.ApplyAsync(deps.Context, name!, navigateTo, verify);
            var success = verify == null || result.Verified;
            return Ok(index, stepId, phase, "identity", new
            {
                action, name, applied = result.Applied, verified = result.Verified,
                verifyStatus = result.VerifyStatus, verifyError = result.VerifyError,
                success
            });
        }

        return Fail(index, stepId, phase, "identity", "Unknown identity action. Use capture or apply.");
    }

    private static async Task<Dictionary<string, object?>> ExecuteNavigateAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var url = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(url))
            return Fail(index, stepId, phase, "navigate", "Missing 'url'.");
        var unresolved = WorkflowVarSubstitution.FindUnresolvedPlaceholders(url, ctx.Vars);
        if (unresolved.Count > 0)
            return Fail(index, stepId, phase, "navigate", $"Unresolved template variable in URL: {url}");

        await deps.Context.Navigate(url);
        if (step.TryGetProperty("waitForIdle", out var idleEl) && idleEl.ValueKind == JsonValueKind.True)
            await deps.Context.WaitForIdle(timeoutMs: step.TryGetProperty("waitForIdleTimeoutMs", out var tEl) ? tEl.GetInt32() : 10_000);

        return Ok(index, stepId, phase, "navigate", new { url });
    }

    private static async Task<Dictionary<string, object?>> ExecuteFetchAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps, bool isTrigger)
    {
        var url = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(url))
            return Fail(index, stepId, phase, "fetch", "Missing 'url'.");
        var unresolved = WorkflowVarSubstitution.FindUnresolvedPlaceholders(url, ctx.Vars);
        if (unresolved.Count > 0)
            return Fail(index, stepId, phase, "fetch", $"Unresolved template variable in URL: {url}");

        var method = step.TryGetProperty("method", out var mEl) ? mEl.GetString() ?? "GET" : "GET";
        Dictionary<string, string>? headers = null;
        if (step.TryGetProperty("headers", out var hEl) && hEl.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in hEl.EnumerateObject())
                headers[p.Name] = WorkflowVarSubstitution.Substitute(p.Value.GetString(), ctx.Vars);
        }

        string? body = null;
        if (step.TryGetProperty("body", out var bEl) && bEl.ValueKind == JsonValueKind.String)
            body = WorkflowVarSubstitution.Substitute(bEl.GetString(), ctx.Vars);
        else if (step.TryGetProperty("json", out var jEl))
        {
            body = WorkflowVarSubstitution.SubstituteElement(jEl, ctx.Vars).GetRawText();
            headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            headers.TryAdd("Content-Type", "application/json");
        }

        var timeout = step.TryGetProperty("timeoutMs", out var tEl) && tEl.ValueKind == JsonValueKind.Number
            ? tEl.GetInt32() : 30_000;
        var redirect = step.TryGetProperty("redirect", out var rEl) ? rEl.GetString() : null;

        var raw = await deps.Context.Fetch(url, method, headers, body, timeout, redirect);
        using var doc = JsonDocument.Parse(raw);
        var fetchEl = doc.RootElement.Clone();
        ctx.LastFetch = fetchEl;
        if (isTrigger)
            ctx.LastTriggerFetch = fetchEl;

        ApplyCaptureFromFetch(step, fetchEl, ctx);

        var status = fetchEl.TryGetProperty("status", out var stEl) ? stEl.GetInt32() : 0;
        var respBody = fetchEl.TryGetProperty("body", out var rbEl) ? rbEl.GetString() : null;
        return Ok(index, stepId, phase, "fetch", new
        {
            url, method, status, bodyLength = respBody?.Length ?? 0,
            bodyHash = WorkflowVarSubstitution.BodyHash(respBody),
            capturedVars = ctx.Vars.Keys.ToList()
        });
    }

    private static async Task<Dictionary<string, object?>> ExecuteWaitAsync(JsonElement step, int index, string? stepId, string phase)
    {
        var ms = step.TryGetProperty("ms", out var msEl) ? msEl.GetInt32()
            : step.TryGetProperty("timeoutMs", out var tEl) ? tEl.GetInt32() : 1000;
        await Task.Delay(Math.Clamp(ms, 0, 60_000));
        return Ok(index, stepId, phase, "wait", new { ms });
    }

    private static async Task<Dictionary<string, object?>> ExecuteWaitForIdleAsync(
        JsonElement step, int index, string? stepId, string phase, WorkflowDependencies deps)
    {
        var timeout = step.TryGetProperty("timeoutMs", out var tEl) ? tEl.GetInt32() : 10_000;
        var ok = await deps.Context.WaitForIdle(timeoutMs: timeout);
        return Ok(index, stepId, phase, "waitForIdle", new { idle = ok });
    }

    private static async Task<Dictionary<string, object?>> ExecuteScreenshotAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        Directory.CreateDirectory(deps.ScreenshotDir);
        var path = Path.Combine(deps.ScreenshotDir, $"workflow-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.jpeg");
        var bytes = await deps.Context.ScreenshotToBytes(format: "jpeg", quality: 70);
        await File.WriteAllBytesAsync(path, bytes, deps.Cancellation);

        if (step.TryGetProperty("as", out var asEl) && asEl.ValueKind == JsonValueKind.String)
            ctx.Vars[asEl.GetString()!] = path;

        if (step.TryGetProperty("markBeforeTrigger", out var markEl) && markEl.ValueKind == JsonValueKind.True)
            ctx.ScreenshotBeforeTrigger = path;

        return Ok(index, stepId, phase, "screenshot", new { path });
    }

    private static Dictionary<string, object?> ExecuteCapture(
        JsonElement step, int index, string? stepId, string phase, WorkflowExecutionContext ctx)
    {
        if (ctx.LastFetch == null)
            return Fail(index, stepId, phase, "capture", "No fetch result to capture. Run a fetch step first.");

        var fetch = ctx.LastFetch.Value;
        if (step.TryGetProperty("capture", out var capEl))
            WorkflowCaptureHelper.ApplyCapture(capEl, fetch, ctx.Vars);
        else
        {
            foreach (var prop in step.EnumerateObject())
            {
                if (prop.NameEquals("type") || prop.NameEquals("id") || prop.NameEquals("delay")) continue;
                var (varName, field) = WorkflowCaptureHelper.ResolveMapping(prop.Name, prop.Value);
                var val = WorkflowCaptureHelper.ExtractFetchField(fetch, field);
                if (val != null)
                    ctx.Vars[varName] = val;
            }
        }

        return Ok(index, stepId, phase, "capture", new { vars = ctx.Vars.ToDictionary(kv => kv.Key, kv => kv.Value) });
    }

    private static void ApplyCaptureFromFetch(JsonElement step, JsonElement fetch, WorkflowExecutionContext ctx)
    {
        if (!step.TryGetProperty("capture", out var capEl)) return;
        WorkflowCaptureHelper.ApplyCapture(capEl, fetch, ctx.Vars);
    }

    private static async Task<Dictionary<string, object?>> ExecuteInjectAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var substituted = WorkflowVarSubstitution.SubstituteElement(step, ctx.Vars);
        if (!WorkflowInjectParser.TryParse(substituted, out var opt, out var parseError))
            return Fail(index, stepId, phase, "inject", parseError ?? "Invalid inject step.");

        if (substituted.TryGetProperty("markers", out var markersEl) && markersEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in markersEl.EnumerateObject())
                ctx.Markers[p.Name] = WorkflowVarSubstitution.Substitute(p.Value.GetString(), ctx.Vars);
        }
        if (substituted.TryGetProperty("payload", out var payloadEl) && payloadEl.ValueKind == JsonValueKind.String)
            ctx.Markers["PAYLOAD"] = WorkflowVarSubstitution.Substitute(payloadEl.GetString(), ctx.Vars);
        foreach (var kv in ctx.Vars)
            ctx.Markers.TryAdd(kv.Key, kv.Value);

        var sw = Stopwatch.StartNew();
        var result = await ExploitVerifier.VerifyAsync(deps.Context, ctx.Markers, opt);
        sw.Stop();

        ctx.Vars["effectObserved"] = result.EffectObserved.ToString();
        if (result.EffectValue != null)
            ctx.Vars["effectValue"] = result.EffectValue.ToString() ?? "";

        return new Dictionary<string, object?>
        {
            ["index"] = index, ["id"] = stepId, ["phase"] = phase, ["type"] = "inject",
            ["success"] = string.IsNullOrEmpty(result.Error),
            ["verified"] = result.Verified,
            ["effectObserved"] = result.EffectObserved, ["effectValue"] = result.EffectValue,
            ["renderUrl"] = opt.RenderUrl, ["resolvedRenderUrl"] = ExploitVerifier.ResolveRenderUrl(opt, ctx.Markers),
            ["elapsedMs"] = sw.ElapsedMilliseconds,
            ["error"] = result.Error
        };
    }

    private static async Task<Dictionary<string, object?>> ExecuteLlmChatAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var prompt = step.TryGetProperty("prompt", out var pEl)
            ? WorkflowVarSubstitution.Substitute(pEl.GetString(), ctx.Vars)
            : null;
        if (string.IsNullOrWhiteSpace(prompt))
            return Fail(index, stepId, phase, "llm-chat", "llm-chat step requires prompt.");

        int? waitMs = null;
        if (step.TryGetProperty("waitAfterSubmitMs", out var waitEl) && waitEl.ValueKind == JsonValueKind.Number)
            waitMs = waitEl.GetInt32();
        string? responseSelector = null;
        if (step.TryGetProperty("responseSelector", out var rsEl) && rsEl.ValueKind == JsonValueKind.String)
            responseSelector = rsEl.GetString();

        LlmChatUiTarget? target = null;
        if (waitMs.HasValue || !string.IsNullOrWhiteSpace(responseSelector))
        {
            target = new LlmChatUiTarget
            {
                WaitAfterSubmitMs = waitMs ?? 4000,
                ResponseSelector = responseSelector
            };
        }

        var sw = Stopwatch.StartNew();
        var result = await LlmChatInteract.SendPromptAsync(deps.Context, prompt!, target, deps.Cancellation);
        sw.Stop();

        // Assistant-only evidence: never feed conversation dumps (which include the just-submitted user prompt)
        // into chain-prove oracles — that false-proves LLM05 via user-echo.
        var responseText = result.ResponseText ?? "";
        var responseHtml = result.ResponseHtml ?? "";
        if (!string.IsNullOrWhiteSpace(prompt)
            && responseText.Contains(prompt, StringComparison.OrdinalIgnoreCase)
            && responseText.Length > prompt.Length + 48)
        {
            responseText = "";
            responseHtml = "";
        }

        ctx.Vars["responseText"] = responseText;
        ctx.Vars["responseHtml"] = responseHtml;

        if (step.TryGetProperty("capture", out var capEl) && capEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in capEl.EnumerateObject())
            {
                var key = prop.Value.GetString() ?? prop.Name;
                ctx.Vars[key] = prop.Name switch
                {
                    "responseText" => responseText,
                    "responseHtml" => responseHtml,
                    _ => responseText
                };
            }
        }

        return new Dictionary<string, object?>
        {
            ["index"] = index,
            ["id"] = stepId,
            ["phase"] = phase,
            ["type"] = "llm-chat",
            ["success"] = result.Success,
            ["prompt"] = prompt,
            ["responseText"] = responseText,
            ["responseHtml"] = responseHtml,
            ["elapsedMs"] = sw.ElapsedMilliseconds,
            ["error"] = result.Error,
            ["warning"] = result.Warning
        };
    }

    private static async Task<Dictionary<string, object?>> ExecuteRestStepAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        // Minimal REST delegation for navigate/fetch via path+method in .trw compatibility
        var path = step.GetProperty("path").GetString()!.Trim().ToLowerInvariant();
        var method = step.GetProperty("method").GetString()!.Trim().ToUpperInvariant();

        if (path is "/api/navigate" && method == "POST" && step.TryGetProperty("body", out var navBody))
        {
            var url = navBody.TryGetProperty("url", out var u) ? WorkflowVarSubstitution.Substitute(u.GetString(), ctx.Vars) : null;
            if (!string.IsNullOrWhiteSpace(url))
            {
                await deps.Context.Navigate(url);
                return Ok(index, stepId, phase, "rest", new { path, url });
            }
        }

        return Fail(index, stepId, phase, "rest", $"Unsupported REST workflow step: {method} {path}");
    }

    private static Dictionary<string, object?> ExecuteMock(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var action = step.TryGetProperty("action", out var actEl) ? actEl.GetString()?.ToLowerInvariant() : "add";
        if (action == "clear")
        {
            deps.Context.ClearMocks();
            return Ok(index, stepId, phase, "mock", new { action = "clear" });
        }

        var urlPattern = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("urlPattern", out var urlEl) ? urlEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(urlPattern))
            return Fail(index, stepId, phase, "mock", "mock step requires urlPattern unless action=clear.");

        var statusCode = step.TryGetProperty("statusCode", out var scEl) && scEl.ValueKind == JsonValueKind.Number
            ? scEl.GetInt32() : 200;
        var body = step.TryGetProperty("body", out var bodyEl) && bodyEl.ValueKind == JsonValueKind.String
            ? WorkflowVarSubstitution.Substitute(bodyEl.GetString(), ctx.Vars) : null;
        var method = step.TryGetProperty("method", out var mEl) ? mEl.GetString() : null;

        Dictionary<string, string>? headers = null;
        if (step.TryGetProperty("headers", out var hEl) && hEl.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in hEl.EnumerateObject())
                headers[p.Name] = WorkflowVarSubstitution.Substitute(p.Value.GetString(), ctx.Vars);
        }

        deps.Context.MockResponse(urlPattern, statusCode, body, method, headers);
        return Ok(index, stepId, phase, "mock", new { action = "add", urlPattern, statusCode });
    }

    private static async Task<Dictionary<string, object?>> ExecuteIntercept(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var action = step.TryGetProperty("action", out var actEl) ? actEl.GetString()?.ToLowerInvariant() : "auto-fulfill";
        if (action is "clear" or "remove-all")
        {
            deps.Context.ClearInterceptRules();
            await deps.Context.SetNetworkCacheDisabledAsync(false);
            return Ok(index, stepId, phase, "intercept", new { action = "clear" });
        }

        var urlPattern = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("urlPattern", out var urlEl) ? urlEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(urlPattern))
            return Fail(index, stepId, phase, "intercept", "intercept step requires urlPattern unless action=clear.");

        if (step.TryGetProperty("disableCache", out var dcEl) && dcEl.ValueKind == JsonValueKind.True)
            await deps.Context.SetNetworkCacheDisabledAsync(true);

        var statusCode = step.TryGetProperty("statusCode", out var scEl) && scEl.ValueKind == JsonValueKind.Number
            ? scEl.GetInt32() : 200;
        var body = step.TryGetProperty("body", out var bodyEl) && bodyEl.ValueKind == JsonValueKind.String
            ? WorkflowVarSubstitution.Substitute(bodyEl.GetString(), ctx.Vars) : null;
        var method = step.TryGetProperty("method", out var mEl) ? mEl.GetString() : null;

        Dictionary<string, string>? headers = null;
        if (step.TryGetProperty("headers", out var hEl) && hEl.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in hEl.EnumerateObject())
                headers[p.Name] = WorkflowVarSubstitution.Substitute(p.Value.GetString(), ctx.Vars);
        }

        deps.Context.AddAutoFulfillInterceptRule(urlPattern, statusCode, body, method, headers);
        return Ok(index, stepId, phase, "intercept", new { action = "auto-fulfill", urlPattern, statusCode });
    }

    private static async Task<Dictionary<string, object?>> ExecuteLoadScriptAsync(
        JsonElement step, int index, string? stepId, string phase,
        WorkflowExecutionContext ctx, WorkflowDependencies deps)
    {
        var url = WorkflowVarSubstitution.Substitute(
            step.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null, ctx.Vars);
        if (string.IsNullOrWhiteSpace(url))
            return Fail(index, stepId, phase, "load-script", "load-script step requires url.");

        var timeout = step.TryGetProperty("timeoutMs", out var tEl) && tEl.ValueKind == JsonValueKind.Number
            ? tEl.GetInt32() : 15_000;
        var asModule = step.TryGetProperty("module", out var modEl) && modEl.ValueKind == JsonValueKind.True
            || step.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String
               && typeEl.GetString()?.Equals("module", StringComparison.OrdinalIgnoreCase) == true;

        var escaped = System.Text.Json.JsonSerializer.Serialize(url);
        var timeoutJs = Math.Clamp(timeout, 1000, 60_000);
        var moduleType = asModule ? "module" : "text/javascript";
        var js = $@"
(function() {{
  return new Promise(function(resolve, reject) {{
    var base = {escaped};
    var sep = base.indexOf('?') >= 0 ? '&' : '?';
    var s = document.createElement('script');
    s.type = '{moduleType}';
    var timer = setTimeout(function() {{ reject('script load timeout'); }}, {timeoutJs});
    s.src = base + sep + '_trowser_bust=' + Date.now();
    s.onload = function() {{ clearTimeout(timer); resolve('loaded'); }};
    s.onerror = function() {{ clearTimeout(timer); reject('script load error'); }};
    (document.head || document.documentElement).appendChild(s);
  }});
}})()";

        try
        {
            var result = await deps.Context.ExecuteJsAsync(js, timeout);
            return Ok(index, stepId, phase, "load-script", new { url, result });
        }
        catch (Exception ex)
        {
            return Fail(index, stepId, phase, "load-script", ex.Message);
        }
    }

    private static Dictionary<string, object?> Ok(int index, string? id, string phase, string type, object data)
    {
        var dict = new Dictionary<string, object?>
        {
            ["index"] = index, ["id"] = id, ["phase"] = phase, ["type"] = type, ["success"] = true
        };
        foreach (var prop in data.GetType().GetProperties())
            dict[prop.Name] = prop.GetValue(data);
        return dict;
    }

    private static IdentityVerifyOptions? ParseIdentityVerify(JsonElement verifyEl)
    {
        var url = verifyEl.TryGetProperty("url", out var u) ? u.GetString() : null;
        if (string.IsNullOrWhiteSpace(url)) return null;

        Dictionary<string, string>? headers = null;
        if (verifyEl.TryGetProperty("headers", out var hEl) && hEl.ValueKind == JsonValueKind.Object)
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in hEl.EnumerateObject())
                headers[p.Name] = p.Value.GetString() ?? "";
        }

        return new IdentityVerifyOptions
        {
            Url = url,
            ExpectStatus = verifyEl.TryGetProperty("expectStatus", out var es) && es.ValueKind == JsonValueKind.Number ? es.GetInt32() : 200,
            Method = verifyEl.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
            Headers = headers,
            Body = verifyEl.TryGetProperty("body", out var b) ? b.GetString() : null,
            TimeoutMs = verifyEl.TryGetProperty("timeoutMs", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetInt32() : 30_000
        };
    }
}
