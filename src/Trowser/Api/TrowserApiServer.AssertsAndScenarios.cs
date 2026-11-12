using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

/// <summary>
/// Wait, assert, test-scenario and batch handlers.
/// </summary>
public partial class TrowserApiServer
{
    private async Task HandlePostWaitForNavigation(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var timeout = body.GetInt("timeout", 10000);

        var navigated = await _context.WaitForNavigation(timeout);
        var url = await _context.GetCurrentUrl();
        var title = await _context.GetTitle();
        await WriteSuccess(response, new { navigated, url, title });
    }

    private async Task HandlePostWaitForIdle(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var quietPeriod = body.GetInt("quietPeriod", 500);
        var timeout = body.GetInt("timeout", 10000);

        var idle = await _context.WaitForIdle(quietPeriod, timeout);
        await WriteSuccess(response, new { idle, quietPeriodMs = quietPeriod, timeoutMs = timeout });
    }

    private async Task HandlePostWaitForFinalNavigation(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var quietPeriod = body.GetInt("quietPeriod", 500);
        var timeout = body.GetInt("timeout", 15000);

        var navCount = await _context.WaitForFinalNavigation(quietPeriod, timeout);
        var url = await _context.GetCurrentUrl();
        var title = await _context.GetTitle();
        await WriteSuccess(response, new { navigations = navCount, url, title, quietPeriodMs = quietPeriod, timeoutMs = timeout });
    }

    private async Task HandlePostAssertPageContains(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var text = body.GetString("text");
        if (string.IsNullOrEmpty(text))
        {
            await WriteError(response, 400, "Missing required field: text");
            return;
        }

        var message = body.GetString("message");
        await _context.AssertPageContains(text, message);

        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertPageNotContains(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var text = body.GetString("text");
        if (string.IsNullOrEmpty(text))
        {
            await WriteError(response, 400, "Missing required field: text");
            return;
        }

        var message = body.GetString("message");
        await _context.AssertPageNotContains(text, message);

        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementVisible(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var message = body.GetString("message");
        await _context.AssertElementVisible(selector, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementNotVisible(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var message = body.GetString("message");
        await _context.AssertElementNotVisible(selector, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementText(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var expected = body.GetString("expected");
        if (string.IsNullOrEmpty(expected)) { await WriteError(response, 400, "Missing required field: expected"); return; }

        var message = body.GetString("message");
        await _context.AssertElementText(selector, expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementTextBatch(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var items = body.GetArray("assertions");
        if (items == null || items.Count == 0)
        {
            await WriteError(response, 400, "Missing required field: assertions (non-empty array of { ref|selector|..., \"expected\": \"...\", \"contains?\": bool })");
            return;
        }

        var defaultTimeout = body.GetInt("timeout", 0);
        var startIdx = _context.Assert.TotalCount;

        try
        {
            foreach (var doc in items)
            {
                using (doc)
                {
                    var item = new JsonBody(doc);
                    var (selector, error, _) = ResolveSelector(item);
                    if (selector == null)
                    {
                        await WriteError(response, 400, error!);
                        return;
                    }

                    var expected = item.GetString("expected");
                    if (string.IsNullOrEmpty(expected))
                    {
                        await WriteError(response, 400, "Each assertion requires \"expected\" (string).");
                        return;
                    }

                    var contains = item.GetBool("contains");
                    var message = item.GetString("message");
                    var stepTimeout = item.HasProperty("timeout") ? item.GetInt("timeout", 0) : defaultTimeout;
                    int? t = stepTimeout > 0 ? stepTimeout : null;

                    try
                    {
                        var actual = await _context.GetText(selector, t);
                        if (contains)
                        {
                            var desc = message ?? $"Element contains: \"{expected}\"";
                            if (actual.Contains(expected, StringComparison.Ordinal))
                                _context.Assert.Pass(desc);
                            else
                                _context.Assert.Fail(desc, $"Expected to contain: \"{expected}\"\n     In: \"{actual}\"");
                        }
                        else
                        {
                            var desc = message ?? $"Element text equals: \"{expected}\"";
                            if (string.Equals(actual.Trim(), expected.Trim(), StringComparison.Ordinal))
                                _context.Assert.Pass(desc);
                            else
                                _context.Assert.Fail(desc, $"Expected: \"{expected}\"\n     Got: \"{actual}\"");
                        }
                    }
                    catch (Exception ex)
                    {
                        _context.Assert.Fail(message ?? $"Text read {selector}", ex.Message);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            await WriteError(response, 500, ex.Message);
            return;
        }

        var batchResults = _context.Assert.Results.Skip(startIdx).ToList();
        foreach (var r in batchResults)
            SessionLogger?.LogApiAssert(r.Description, r.Passed, r.Details);

        await WriteSuccess(response, new
        {
            allPassed = batchResults.All(r => r.Passed),
            count = batchResults.Count,
            results = batchResults.Select(r => new { r.Passed, r.Description, r.Details }).ToList(),
            assertions = new
            {
                passed = _context.Assert.PassCount,
                failed = _context.Assert.FailCount,
                total = _context.Assert.TotalCount
            }
        });
    }

    private async Task HandlePostAssertElementContainsText(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var expected = body.GetString("expected");
        if (string.IsNullOrEmpty(expected)) { await WriteError(response, 400, "Missing required field: expected"); return; }

        var message = body.GetString("message");
        await _context.AssertElementContainsText(selector, expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementAttribute(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var attribute = body.GetString("attribute");
        if (string.IsNullOrEmpty(attribute)) { await WriteError(response, 400, "Missing required field: attribute"); return; }

        var expected = body.GetString("expected");
        if (string.IsNullOrEmpty(expected)) { await WriteError(response, 400, "Missing required field: expected"); return; }

        var message = body.GetString("message");
        await _context.AssertElementAttribute(selector, attribute, expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertUrl(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var expected = body.GetString("expected");
        if (string.IsNullOrEmpty(expected)) { await WriteError(response, 400, "Missing required field: expected"); return; }

        var message = body.GetString("message");
        await _context.AssertUrl(expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertTitle(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var expected = body.GetString("expected");
        if (string.IsNullOrEmpty(expected)) { await WriteError(response, 400, "Missing required field: expected"); return; }

        var message = body.GetString("message");
        await _context.AssertTitle(expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private async Task HandlePostAssertElementCount(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) { await WriteError(response, 400, error!); return; }

        var expected = body.GetInt("expected", -1);
        if (expected < 0) { await WriteError(response, 400, "Missing required field: expected (integer)"); return; }

        var message = body.GetString("message");
        await _context.AssertElementCount(selector, expected, message);
        await WriteSuccess(response, AssertResultPayload());
    }

    private object AssertResultPayload()
    {
        var lastResult = _context.Assert.Results.Last();
        SessionLogger?.LogApiAssert(lastResult.Description, lastResult.Passed, lastResult.Details);
        return new
        {
            passed = lastResult.Passed,
            description = lastResult.Description,
            details = lastResult.Details,
            assertions = new
            {
                passed = _context.Assert.PassCount,
                failed = _context.Assert.FailCount,
                total = _context.Assert.TotalCount
            }
        };
    }

    /// <summary>
    /// Runs a sequence of REST API calls in-process (single client round-trip). Same JSON schema can be stored in a <c>.trw</c> file and referenced via <c>file</c>.
    /// Supports flat <c>steps[]</c> or v2 <c>phases</c> (setup/trigger/oracle/cleanup).
    /// </summary>
    private async Task HandlePostTestScenario(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        const int defaultMaxSteps = 250;

        var stepElements = new List<JsonElement>();
            JsonDocument? fileDoc = null;

            try
            {
            var filePath = body.GetString("file");
            if (!string.IsNullOrWhiteSpace(filePath))
            {
                if (!ExportPathGuard.TryResolveRead(filePath, out var scenarioPath, out var pathError))
                {
                    await WriteError(response, 400, pathError ?? "Scenario path rejected.");
                    return;
                }
                filePath = scenarioPath;
                if (!File.Exists(filePath))
                {
                    await WriteError(response, 400, $"Scenario file not found: {filePath}");
                    return;
                }

                var ext = Path.GetExtension(filePath);
                if (!ext.Equals(".trw", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".json", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteError(response, 400, "Scenario file must use a .trw or .json extension.");
                    return;
                }

                var raw = await File.ReadAllTextAsync(filePath);
                fileDoc = JsonDocument.Parse(raw);

                // .trw v2 — phased workflow (setup/trigger/oracle/cleanup)
                if (fileDoc.RootElement.TryGetProperty("phases", out var phasesEl) && phasesEl.ValueKind == JsonValueKind.Object)
                {
                    await RunPhasedScenarioAsync(response, fileDoc.RootElement, body);
                    return;
                }

                if (fileDoc.RootElement.TryGetProperty("steps", out var fileSteps) && fileSteps.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in fileSteps.EnumerateArray())
                        stepElements.Add(el.Clone());
                }
            }

            if (body.TryGetRoot(out var inlineRoot) && inlineRoot.TryGetProperty("phases", out var inlinePhases) && inlinePhases.ValueKind == JsonValueKind.Object)
            {
                await RunPhasedScenarioAsync(response, inlineRoot, body);
                return;
            }

            var inlineSteps = body.GetArray("steps");
            if (inlineSteps != null)
            {
                foreach (var doc in inlineSteps)
                {
                    stepElements.Add(doc.RootElement.Clone());
                    doc.Dispose();
                }
            }

            if (stepElements.Count == 0)
            {
                await WriteError(response, 400, "Provide a non-empty \"steps\" array in the body and/or load steps from a \"file\" (.trw / .json).");
                return;
            }

            var maxSteps = defaultMaxSteps;
            if (body.HasProperty("maxSteps"))
                maxSteps = body.GetInt("maxSteps", defaultMaxSteps);
            else if (fileDoc != null && fileDoc.RootElement.TryGetProperty("maxSteps", out var msCap) && msCap.ValueKind == JsonValueKind.Number)
                maxSteps = msCap.GetInt32();
            maxSteps = Math.Clamp(maxSteps, 1, 500);

            if (stepElements.Count > maxSteps)
            {
                await WriteError(response, 400, $"Too many steps ({stepElements.Count}). Raise \"maxSteps\" (max 500) or split the scenario.");
                return;
            }

            bool stopOnError = true;
            if (body.HasProperty("stopOnError"))
                stopOnError = body.GetBool("stopOnError");
            else if (fileDoc != null && fileDoc.RootElement.TryGetProperty("stopOnError", out var se) && se.ValueKind is JsonValueKind.True or JsonValueKind.False)
                stopOnError = se.GetBoolean();

            string? scenarioName = body.GetString("name");
            if (scenarioName == null && fileDoc != null && fileDoc.RootElement.TryGetProperty("name", out var ne) && ne.ValueKind == JsonValueKind.String)
                scenarioName = ne.GetString();

            var pacingMs = 0;
            if (fileDoc != null)
            {
                if (fileDoc.RootElement.TryGetProperty("pacingMs", out var pm) && pm.ValueKind == JsonValueKind.Number)
                    pacingMs = Math.Clamp(pm.GetInt32(), 0, 300_000);
                else if (fileDoc.RootElement.TryGetProperty("globalDelay", out var gd) && gd.ValueKind == JsonValueKind.Number)
                    pacingMs = Math.Clamp(gd.GetInt32(), 0, 300_000);
            }

            if (body.HasProperty("pacingMs"))
                pacingMs = Math.Clamp(body.GetInt("pacingMs", 0), 0, 300_000);
            else if (body.HasProperty("globalDelay"))
                pacingMs = Math.Clamp(body.GetInt("globalDelay", 0), 0, 300_000);

            var results = new List<object>();
            var stoppedEarly = false;
            var vars = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);

            for (var i = 0; i < stepElements.Count; i++)
            {
                await _context.CheckScriptExecutionAsync();

                if (i > 0 && pacingMs > 0)
                    await Task.Delay(pacingMs, _context.OperationCancellation);

                var step = stepElements[i];
                string? stepId = null;
                if (step.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String)
                    stepId = idEl.GetString();

                // Delay: wait before executing the step
                if (step.TryGetProperty("delay", out var delayEl) && delayEl.ValueKind == JsonValueKind.Number)
                {
                    var delayMs = Math.Clamp(delayEl.GetInt32(), 0, 30000);
                    if (delayMs > 0)
                        await Task.Delay(delayMs, _context.OperationCancellation);
                }

                if (step.TryGetProperty("type", out var typeEl) &&
                    typeEl.ValueKind == JsonValueKind.String &&
                    typeEl.GetString()?.Equals("identity", StringComparison.OrdinalIgnoreCase) == true)
                {
                    var identityResult = await ExecuteIdentityScenarioStepAsync(step, stepId, i);
                    results.Add(identityResult);
                    var identitySuccess = identityResult is Dictionary<string, object?> idDict &&
                                          idDict.TryGetValue("success", out var okObj) && okObj is true;
                    if (!identitySuccess && stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                if (!step.TryGetProperty("path", out var pathEl) || pathEl.ValueKind != JsonValueKind.String)
                {
                    results.Add(new { index = i, id = stepId, success = false, error = "Each step requires a string \"path\" (e.g. /api/navigate)." });
                    if (stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                var path = pathEl.GetString()!.Trim();
                if (!path.StartsWith('/'))
                    path = "/" + path;
                path = path.TrimEnd('/').ToLowerInvariant();

                if (!step.TryGetProperty("method", out var methEl) || methEl.ValueKind != JsonValueKind.String)
                {
                    results.Add(new { index = i, id = stepId, path, success = false, error = "Each step requires a string \"method\" (GET, POST, or DELETE)." });
                    if (stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                var method = methEl.GetString()!.Trim().ToUpperInvariant();
                if (method is not ("GET" or "POST" or "DELETE"))
                {
                    results.Add(new { index = i, id = stepId, path, success = false, error = $"Unsupported HTTP method for scenario steps: {method}" });
                    if (stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                if (path is "/api/test-scenario" or "/mcp")
                {
                    results.Add(new { index = i, id = stepId, path, method, success = false, error = "Nested /api/test-scenario and /mcp are not allowed inside a scenario." });
                    if (stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                _scenarioQueryOverride = null;
                _scenarioBodyOverride = null;
                if (step.TryGetProperty("query", out var qEl))
                {
                    if (qEl.ValueKind == JsonValueKind.String)
                    {
                        var qstr = qEl.GetString()!.Trim();
                        if (qstr.StartsWith('?')) qstr = qstr[1..];
                        _scenarioQueryOverride = System.Web.HttpUtility.ParseQueryString("?" + qstr);
                    }
                    else if (qEl.ValueKind == JsonValueKind.Object)
                    {
                        var nvc = new NameValueCollection();
                        foreach (var p in qEl.EnumerateObject())
                        {
                            var v = p.Value;
                            nvc[p.Name] = v.ValueKind switch
                            {
                                JsonValueKind.String => v.GetString() ?? "",
                                JsonValueKind.True => "true",
                                JsonValueKind.False => "false",
                                JsonValueKind.Number => v.GetRawText(),
                                _ => v.GetRawText()
                            };
                        }

                        _scenarioQueryOverride = nvc;
                    }
                }

                if (path == "/api/journal/export" && method == "GET")
                {
                    var jp = _scenarioQueryOverride?["json"];
                    if (!string.Equals(jp, "true", StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(new
                        {
                            index = i,
                            id = stepId,
                            path,
                            method,
                            success = false,
                            error = "GET /api/journal/export in a scenario requires query json=true (non-JSON responses are not captured)."
                        });
                        if (stopOnError) { stoppedEarly = true; break; }
                        continue;
                    }
                }

                if (method == "GET")
                    _scenarioBodyOverride = null;
                else if (step.TryGetProperty("body", out var bodyEl))
                {
                    _scenarioBodyOverride = bodyEl.ValueKind == JsonValueKind.String
                        ? bodyEl.GetString()
                        : bodyEl.GetRawText();
                }

                // Variable interpolation: replace {{varName}} in body and query strings
                if (vars.Count > 0)
                {
                    if (_scenarioBodyOverride != null)
                    {
                        var (interpolated, interpErr) = ScenarioInterpolateJson(_scenarioBodyOverride, vars);
                        if (interpErr != null)
                        {
                            results.Add(new { index = i, id = stepId, path, method, success = false, error = interpErr });
                            if (stopOnError) { stoppedEarly = true; break; }
                            continue;
                        }
                        _scenarioBodyOverride = interpolated;
                    }

                    if (_scenarioQueryOverride != null)
                    {
                        foreach (var key in _scenarioQueryOverride.AllKeys)
                        {
                            var val = _scenarioQueryOverride[key];
                            if (val != null && val.Contains("{{"))
                                _scenarioQueryOverride[key] = ScenarioInterpolateString(val, vars);
                        }
                    }
                }

                if (SafeMode && SafeModePolicy.IsRouteBlocked(path, method, _scenarioBodyOverride))
                {
                    results.Add(new { index = i, id = stepId, path, method, success = false, error = $"Blocked by safe mode: {path}" });
                    if (stopOnError) { stoppedEarly = true; break; }
                    continue;
                }

                // Capture the request body for inclusion in step results (enables richer GUI output)
                JsonElement? requestBody = null;
                if (_scenarioBodyOverride != null)
                {
                    try
                    {
                        using var rbDoc = JsonDocument.Parse(_scenarioBodyOverride);
                        requestBody = rbDoc.RootElement.Clone();
                    }
                    catch { /* non-JSON body — skip */ }
                }

                _scenarioResponseCapture = new ScenarioResponseCapture();
                object stepOut;
                var stepFailed = false;
                try
                {
                    await RouteRequestAsync(path, method, request, response);
                    var cap = _scenarioResponseCapture;
                    var bytes = cap.Stream.ToArray();
                    JsonElement? payload = null;
                    if (bytes.Length > 0)
                    {
                        using var parsed = JsonDocument.Parse(bytes);
                        payload = parsed.RootElement.Clone();
                    }

                    var status = cap.StatusCode;
                    var httpOk = status is >= 200 and < 300;
                    var logicalOk = httpOk;
                    if (payload.HasValue && payload.Value.ValueKind == JsonValueKind.Object &&
                        payload.Value.TryGetProperty("success", out var sp))
                    {
                        logicalOk = sp.ValueKind == JsonValueKind.True;
                    }

                    if (!logicalOk)
                        stepFailed = true;

                    // Capture variables from successful step responses
                    Dictionary<string, object>? captured = null;
                    if (logicalOk && payload.HasValue
                        && step.TryGetProperty("capture", out var captureEl) && captureEl.ValueKind == JsonValueKind.Object)
                    {
                        captured = new Dictionary<string, object>();
                        foreach (var cap2 in captureEl.EnumerateObject())
                        {
                            var varName = cap2.Name;
                            var dotPath = cap2.Value.ValueKind == JsonValueKind.String ? cap2.Value.GetString() : null;
                            if (string.IsNullOrWhiteSpace(dotPath))
                                continue;

                            var resolved = ScenarioResolveDotPath(payload.Value, dotPath!);
                            if (resolved.HasValue)
                            {
                                vars[varName] = resolved.Value.Clone();
                                captured[varName] = resolved.Value.Clone();
                            }
                        }
                    }

                    object? assertResult = null;
                    if (step.TryGetProperty("assert", out var stepAssertEl))
                    {
                        if (!payload.HasValue)
                        {
                            stepFailed = true;
                            logicalOk = false;
                            assertResult = new { passed = false, error = "No JSON response body to assert on" };
                        }
                        else
                        {
                            var (assertPassed, assertFailures) = ScenarioEvaluateAssertions(payload.Value, stepAssertEl);
                            if (!assertPassed)
                            {
                                stepFailed = true;
                                logicalOk = false;
                            }

                            assertResult = new
                            {
                                passed = assertPassed,
                                failures = assertFailures.Count > 0 ? assertFailures : null
                            };
                        }
                    }

                    stepOut = new
                    {
                        index = i,
                        id = stepId,
                        path,
                        method,
                        statusCode = status,
                        success = logicalOk,
                        body = payload.HasValue ? (object)payload.Value : null,
                        requestBody = requestBody.HasValue ? (object)requestBody.Value : null,
                        captured = captured?.Count > 0 ? (object)captured : null,
                        assert = assertResult
                    };
                }
                catch (Exception ex)
                {
                    stepFailed = true;
                    stepOut = new { index = i, id = stepId, path, method, success = false, error = ex.Message, requestBody = requestBody.HasValue ? (object)requestBody.Value : null };
                }
                finally
                {
                    _scenarioBodyOverride = null;
                    _scenarioQueryOverride = null;
                    _scenarioResponseCapture?.Stream.Dispose();
                    _scenarioResponseCapture = null;
                }

                results.Add(stepOut);
                if (stepFailed && stopOnError)
                {
                    stoppedEarly = true;
                    break;
                }
            }

            await WriteSuccess(response, new
            {
                name = scenarioName,
                pacingMs,
                stepCount = results.Count,
                stoppedEarly,
                results
            });
        }
        finally
        {
            fileDoc?.Dispose();
        }
    }

    /// <summary>
    /// Resolves a dot-path (e.g. "data.path", "data.results[0].id") against a JSON element.
    /// Returns null if any segment is missing.
    /// </summary>
    private static JsonElement? ScenarioResolveDotPath(JsonElement root, string dotPath)
    {
        var current = root;
        foreach (var rawSegment in dotPath.Split('.'))
        {
            if (string.IsNullOrEmpty(rawSegment)) continue;

            // Handle array indexing: "results[0]" → property "results", then index 0
            var bracketIdx = rawSegment.IndexOf('[');
            var propName = bracketIdx >= 0 ? rawSegment[..bracketIdx] : rawSegment;
            int arrayIndex = -1;
            if (bracketIdx >= 0)
            {
                var closeBracket = rawSegment.IndexOf(']', bracketIdx);
                if (closeBracket > bracketIdx + 1
                    && int.TryParse(rawSegment.AsSpan(bracketIdx + 1, closeBracket - bracketIdx - 1), out var idx))
                {
                    arrayIndex = idx;
                }
            }

            if (!string.IsNullOrEmpty(propName))
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(propName, out var next))
                    return null;
                current = next;
            }

            if (arrayIndex >= 0)
            {
                if (current.ValueKind != JsonValueKind.Array || arrayIndex >= current.GetArrayLength())
                    return null;
                current = current[arrayIndex];
            }
        }

        return current;
    }

    /// <summary>String form for scenario response assertions (trimmed string literals; other kinds use raw JSON text).</summary>
    private static string ScenarioJsonCompareString(JsonElement el) =>
        el.ValueKind switch
        {
            JsonValueKind.String => el.GetString()?.Trim() ?? "",
            JsonValueKind.Number => el.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "",
            _ => el.GetRawText()
        };

    /// <summary>
    /// Evaluate <c>assert</c> on a scenario sub-step JSON body. Object form: dot-path keys → expected values.
    /// Array form: <c>{ "path", "equals" | "expected", "contains"?: bool }</c>.
    /// </summary>
    private static (bool passed, List<object> failures) ScenarioEvaluateAssertions(JsonElement payload, JsonElement assertSpec)
    {
        var failures = new List<object>();
        switch (assertSpec.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in assertSpec.EnumerateObject())
                {
                    var path = p.Name;
                    ScenarioAssertOnePath(payload, path, p.Value, contains: false, failures);
                }
                break;

            case JsonValueKind.Array:
                foreach (var item in assertSpec.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object)
                    {
                        failures.Add(new { error = "assert array entries must be objects with path + equals/expected" });
                        continue;
                    }

                    if (!item.TryGetProperty("path", out var pathEl) || pathEl.ValueKind != JsonValueKind.String ||
                        string.IsNullOrEmpty(pathEl.GetString()))
                    {
                        failures.Add(new { error = "assert entry missing string \"path\"" });
                        continue;
                    }

                    var path = pathEl.GetString()!;
                    var contains = item.TryGetProperty("contains", out var cEl) &&
                        cEl.ValueKind is JsonValueKind.True;

                    if (item.TryGetProperty("equals", out var eq))
                        ScenarioAssertOnePath(payload, path, eq, contains, failures);
                    else if (item.TryGetProperty("expected", out var ex))
                        ScenarioAssertOnePath(payload, path, ex, contains, failures);
                    else
                        failures.Add(new { path, error = "assert entry needs \"equals\" or \"expected\"" });
                }
                break;

            default:
                failures.Add(new { error = "assert must be an object (path → expected) or an array of { path, equals|expected, contains? }" });
                break;
        }

        return (failures.Count == 0, failures);
    }

    private static void ScenarioAssertOnePath(JsonElement payload, string dotPath, JsonElement expectedEl, bool contains, List<object> failures)
    {
        var resolved = ScenarioResolveDotPath(payload, dotPath);
        if (!resolved.HasValue)
        {
            failures.Add(new { path = dotPath, error = "path not found in response" });
            return;
        }

        var exp = ScenarioJsonCompareString(expectedEl);
        var act = ScenarioJsonCompareString(resolved.Value);
        var ok = contains
            ? act.Contains(exp, StringComparison.Ordinal)
            : string.Equals(act, exp, StringComparison.Ordinal);
        if (!ok)
            failures.Add(new { path = dotPath, expected = exp, actual = act, contains });
    }

    /// <summary>
    /// Interpolates <c>{{varName}}</c> placeholders in a JSON string, preserving types.
    /// If a JSON string value is exactly <c>"{{varName}}"</c>, it is replaced with the
    /// captured <see cref="JsonElement"/> (preserving number/bool/object types).
    /// For partial matches like <c>"prefix-{{var}}-suffix"</c>, only string-valued
    /// captures are substituted; non-string captures are left as-is.
    /// Returns the interpolated JSON string and an optional error.
    /// </summary>
    private static (string? json, string? error) ScenarioInterpolateJson(string json, Dictionary<string, JsonElement> vars)
    {
        // Quick check: no placeholders at all
        if (!json.Contains("{{"))
            return (json, null);

        // Parse the JSON, walk string values, rebuild
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(json);
            root = doc.RootElement.Clone();
        }
        catch
        {
            // Not valid JSON — fall back to simple string interpolation
            return (ScenarioInterpolateString(json, vars), null);
        }

        var result = ScenarioInterpolateElement(root, vars, out var error);
        if (error != null) return (null, error);
        return (JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = false }), null);
    }

    private static JsonElement ScenarioInterpolateElement(JsonElement el, Dictionary<string, JsonElement> vars, out string? error)
    {
        error = null;

        switch (el.ValueKind)
        {
            case JsonValueKind.String:
            {
                var str = el.GetString() ?? "";
                // Exact match: "{{varName}}" — replace with the captured element (any type)
                if (str.StartsWith("{{") && str.EndsWith("}}") && str.IndexOf("}}", 2) == str.Length - 2)
                {
                    var varName = str[2..^2].Trim();
                    if (!vars.TryGetValue(varName, out var val))
                    {
                        error = $"Undefined variable '{{{{{{varName}}}}}}' — no step has captured it yet.";
                        return el;
                    }
                    return val;
                }
                // Partial match: "prefix-{{var}}-suffix" — string substitution only
                if (str.Contains("{{"))
                {
                    var interpolated = ScenarioInterpolateString(str, vars);
                    return JsonDocument.Parse($"\"{EscapeJsonString(interpolated)}\"").RootElement.Clone();
                }
                return el;
            }

            case JsonValueKind.Object:
            {
                using var ms = new MemoryStream();
                using (var w = new Utf8JsonWriter(ms))
                {
                    w.WriteStartObject();
                    foreach (var prop in el.EnumerateObject())
                    {
                        w.WritePropertyName(prop.Name);
                        var child = ScenarioInterpolateElement(prop.Value, vars, out error);
                        if (error != null) return el;
                        child.WriteTo(w);
                    }
                    w.WriteEndObject();
                }

                using var doc = JsonDocument.Parse(ms.ToArray());
                return doc.RootElement.Clone();
            }

            case JsonValueKind.Array:
            {
                using var ms = new MemoryStream();
                using (var w = new Utf8JsonWriter(ms))
                {
                    w.WriteStartArray();
                    foreach (var item in el.EnumerateArray())
                    {
                        var child = ScenarioInterpolateElement(item, vars, out error);
                        if (error != null) return el;
                        child.WriteTo(w);
                    }
                    w.WriteEndArray();
                }

                using var doc = JsonDocument.Parse(ms.ToArray());
                return doc.RootElement.Clone();
            }

            default:
                return el;
        }
    }

    /// <summary>Simple string-level interpolation: replaces all <c>{{varName}}</c> with string representations.</summary>
    private static string ScenarioInterpolateString(string text, Dictionary<string, JsonElement> vars)
    {
        return System.Text.RegularExpressions.Regex.Replace(text, @"\{\{(\s*\w+\s*)\}\}", match =>
        {
            var varName = match.Groups[1].Value.Trim();
            if (!vars.TryGetValue(varName, out var val))
                return match.Value; // leave unresolved
            return val.ValueKind == JsonValueKind.String
                ? val.GetString() ?? ""
                : val.GetRawText();
        });
    }

    private static string EscapeJsonString(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");

    private async Task HandlePostBatch(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var actions = body.GetArray("actions");
        if (actions == null || actions.Count == 0)
        {
            await WriteError(response, 400, "Missing required field: actions (array of {action, ...params})");
            return;
        }

        var results = new List<object>();
        foreach (var actionEl in actions)
        {
            var actionBody = new JsonBody(actionEl);
            var actionType = actionBody.GetString("action");
            if (string.IsNullOrWhiteSpace(actionType))
            {
                results.Add(new { success = false, error = "Missing 'action' field in batch step" });
                continue;
            }

            try
            {
                object result = actionType.ToLower() switch
                {
                    "click" => await ExecuteBatchClick(actionBody),
                    "type" => await ExecuteBatchType(actionBody),
                    "select" => await ExecuteBatchSelect(actionBody),
                    "text" => await ExecuteBatchText(actionBody),
                    "attribute" => await ExecuteBatchAttribute(actionBody),
                    "hover" => await ExecuteBatchHover(actionBody),
                    "scroll" => await ExecuteBatchScroll(actionBody),
                    "wait" => await ExecuteBatchWait(actionBody),
                    "sleep" => await ExecuteBatchSleep(actionBody),
                    _ => new { success = false, error = $"Unknown batch action: {actionType}" }
                };
                results.Add(result);
            }
            catch (Exception ex)
            {
                results.Add(new { success = false, action = actionType, error = ex.Message });
            }
        }

        await WriteSuccess(response, new { count = results.Count, results });
    }

    private async Task<object> ExecuteBatchClick(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        await _context.Click(selector);
        return new { success = true, action = "click", selector };
    }

    private async Task<object> ExecuteBatchType(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        var html = body.GetString("html");
        var text = ResolveTypeContent(body);
        if (text == null && string.IsNullOrEmpty(html))
            return new { success = false, error = "Provide 'text' or 'value' (content to type), or 'html'." };
        await _context.Type(selector, text ?? "", html: html);
        return new { success = true, action = "type", selector, text, html };
    }

    private async Task<object> ExecuteBatchSelect(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        var value = body.GetString("value") ?? "";
        await _context.Select(selector, value);
        return new { success = true, action = "select", selector, value };
    }

    private async Task<object> ExecuteBatchText(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        var text = await _context.GetText(selector);
        return new { success = true, action = "text", selector, text };
    }

    private async Task<object> ExecuteBatchAttribute(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        var attribute = body.GetString("attribute") ?? "";
        var value = await _context.GetAttribute(selector, attribute);
        return new { success = true, action = "attribute", selector, attribute, value };
    }

    private async Task<object> ExecuteBatchHover(JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(body);
        if (selector == null) return new { success = false, error };
        await _context.Hover(selector);
        return new { success = true, action = "hover", selector };
    }

    private async Task<object> ExecuteBatchScroll(JsonBody body)
    {
        var direction = body.GetString("direction") ?? "down";
        var scrollIntoView = body.GetBool("scrollIntoView");
        var timeout = body.GetInt("timeout", 0);
        string? selector = null;
        if (body.HasProperty("ref") || body.HasProperty("selector"))
        {
            var (resolved, error, _) = ResolveSelector(body);
            if (resolved == null) return new { success = false, error };
            selector = resolved;
        }
        await _context.Scroll(selector, direction, scrollIntoView, timeout > 0 ? timeout : null);
        return new { success = true, action = "scroll", direction };
    }

    private async Task<object> ExecuteBatchWait(JsonBody body)
    {
        var selector = body.GetString("selector") ?? "";
        var timeout = body.GetInt("timeout", 10000);
        try
        {
            await _context.WaitForElement(selector, timeout);
            return new { success = true, action = "wait", found = true, selector };
        }
        catch (TimeoutException)
        {
            return new { success = true, action = "wait", found = false, selector };
        }
    }

    private async Task<object> ExecuteBatchSleep(JsonBody body)
    {
        var ms = body.GetInt("ms", 100);
        await Task.Delay(ms);
        return new { success = true, action = "sleep", ms };
    }

}
