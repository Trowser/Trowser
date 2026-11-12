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

public partial class TrowserApiServer
{
private Task HandlePostSecurityLlmRedteamScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmRedteamScanAsync);

internal async Task<object> BuildSecurityLlmRedteamScanAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "LLM red-team scan sends jailbreak and extraction prompts to chat/API endpoints");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = LlmRedTeamRequestParser.ParseScanOptions(body);
        try
        {
            var result = await _context.RunLlmRedTeamScan(options);
            return LlmRedTeamRequestParser.FormatScanResult(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private async Task HandleGetSecurityLlmRedteamProbes(HttpListenerResponse response)
    {
        await WriteSuccess(response, LlmRedTeamRequestParser.FormatProbeCatalog());
    }

private Task HandleSecurityLlmEndpointDiscover(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmEndpointDiscoverAsync);

internal async Task<object> BuildSecurityLlmEndpointDiscoverAsync(JsonBody body)
    {
        try
        {
            var surface = await _context.RunLlmEndpointDiscover();
            return LlmRedTeamRequestParser.FormatSurface(surface);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityLlmEndpointDiscover(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmEndpointDiscoverAsync);

private Task HandlePostSecurityLlmChatInteract(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmChatInteractAsync);

internal async Task<object> BuildSecurityLlmChatInteractAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "llm-chat-interact sends a prompt through the page chat UI");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var prompt = body.GetString("prompt");
        if (string.IsNullOrWhiteSpace(prompt))
            throw new ApiCommandException(400, "Missing required field: prompt");

        LlmChatUiTarget? target = null;
        var chatDoc = body.GetObject("chatTarget");
        if (chatDoc != null)
        {
            using (chatDoc)
                target = LlmRedTeamRequestParser.ParseChatTarget(new JsonBody(chatDoc));
        }
        else if (body.GetString("inputSelector") != null || body.HasProperty("autoDetect") || body.HasProperty("resetUi"))
        {
            target = new LlmChatUiTarget
            {
                InputSelector = body.GetString("inputSelector"),
                SubmitSelector = body.GetString("submitSelector"),
                ResponseSelector = body.GetString("responseSelector"),
                WaitAfterSubmitMs = body.GetInt("waitAfterSubmitMs", 4000),
                AutoDetect = body.GetBool("autoDetect", true),
                ResetUi = body.GetBool("resetUi", false),
                FailoverToHttp = body.HasProperty("failoverToHttp") ? body.GetBool("failoverToHttp", true) : true
            };
        }

        try
        {
            var result = await _context.RunLlmChatInteract(prompt, target);
            return LlmRedTeamRequestParser.FormatChatInteract(result);
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityLlmHttpSend(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmHttpSendAsync);

internal async Task<object> BuildSecurityLlmHttpSendAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "llm-http-send posts a prompt to a discovered LLM HTTP endpoint");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var prompt = body.GetString("prompt");
        if (string.IsNullOrWhiteSpace(prompt))
            throw new ApiCommandException(400, "Missing required field: prompt");

        LlmHttpTargetConfig? target = null;
        var httpDoc = body.GetObject("httpTarget");
        if (httpDoc != null)
        {
            using (httpDoc)
                target = LlmRedTeamRequestParser.ParseHttpTarget(new JsonBody(httpDoc));
        }

        if (target == null || string.IsNullOrWhiteSpace(target.Url))
        {
            var surface = await _context.RunLlmEndpointDiscover();
            target = surface.SuggestedHttpTarget
                     ?? (LlmEndpointDiscovery.SelectBestEndpoint(surface.Endpoints) is { } ep
                         ? LlmEndpointDiscovery.InferHttpTarget(ep)
                         : null);
            if (target == null)
                throw new ApiCommandException(400,
                    "No httpTarget provided and no discoverable LLM HTTP endpoint. Browse a chat flow first.");
        }

        try
        {
            var text = await LlmHttpAdapter.SendAsync(_context, target, prompt!);
            return new
            {
                success = true,
                prompt,
                responseText = text,
                httpTarget = new
                {
                    target.Url,
                    target.Schema,
                    customBody = target.CustomBodyJson,
                    target.IncludeBrowserCookies
                }
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityLlmHttpMcpList(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmHttpMcpListAsync);

internal async Task<object> BuildSecurityLlmHttpMcpListAsync(JsonBody body)
    {
        // initialize + tools/list is read-only against the MCP server; still require active so it is intentional.
        var gateError = SafetyGate.RequireActive(body, "llm-http-mcp-list calls initialize/tools/list on an HTTP MCP endpoint");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
        {
            var surface = await _context.RunLlmEndpointDiscover();
            url = surface.HttpMcpEndpoints.OrderByDescending(e => e.Confidence).FirstOrDefault()?.Url;
            if (string.IsNullOrWhiteSpace(url))
                throw new ApiCommandException(400,
                    "Missing url and no HTTP MCP endpoint discovered. Browse an app that calls /mcp first.");
        }

        var result = await LlmHttpMcpClient.ListToolsAsync(
            _context, url!, body.GetBool("includeBrowserCookies", true));
        return new
        {
            result.Ok,
            result.Url,
            result.SessionId,
            toolNames = result.ToolNames,
            tools = result.RawTools,
            result.Error
        };
    }

private Task HandlePostSecurityLlmSinkAssist(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityLlmSinkAssistAsync);

internal async Task<object> BuildSecurityLlmSinkAssistAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "llm-sink-assist instruments DOM sinks and optionally injects a canary");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var canary = body.GetString("canary") ?? $"TROWSER_SINK_{Guid.NewGuid():N}";
        var mockChatApi = body.GetBool("mockChatApi", false);
        var chatApiUrl = body.GetString("chatApiUrl");

        var tracer = new LlmOutputSinkTracer(_context, (_, _) => { });
        var trace = await tracer.RunAsync(new LlmOutputSinkTracer.SinkTraceOptions
        {
            MaxProbes = body.GetInt("maxProbes", 1),
            ProbeDelayMs = body.GetInt("probeDelayMs", 1200),
            IncludeDomRenderCheck = true
        });

        bool? mockExecuted = null;
        if (mockChatApi)
        {
            if (string.IsNullOrWhiteSpace(chatApiUrl))
            {
                var surface = await _context.RunLlmEndpointDiscover();
                chatApiUrl = surface.SuggestedHttpTarget?.Url
                             ?? LlmEndpointDiscovery.SelectBestEndpoint(surface.Endpoints)?.Url;
            }

            if (!string.IsNullOrWhiteSpace(chatApiUrl))
            {
                var payload =
                    $"<img src=x onerror=\"window.__TROWSER_SINK_LOG && window.__TROWSER_SINK_LOG.push('{canary}')\">{canary}";
                _context.MockResponse(
                    chatApiUrl!,
                    statusCode: 200,
                    body: payload,
                    method: "POST",
                    headers: new Dictionary<string, string> { ["Content-Type"] = "text/html" });
                mockExecuted = false;
                try
                {
                    await _context.RunLlmChatInteract(
                        "ping",
                        new LlmChatUiTarget { WaitAfterSubmitMs = 3000, FailoverToHttp = false, ResetUi = true });
                    await Task.Delay(800);
                    var hit = await _context.ExecuteJs(
                        $"(window.__TROWSER_SINK_LOG||[]).some(function(v){{return String(v).indexOf('{canary}')>=0;}})");
                    mockExecuted = hit?.Contains("true", StringComparison.OrdinalIgnoreCase) == true;
                }
                catch
                {
                    mockExecuted = false;
                }
                finally
                {
                    try { _context.RemoveMock(chatApiUrl!); } catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
                }
            }
        }

        return new
        {
            message = "Sink assist complete — use canaryExecuted / findings to finish the write-up.",
            canary,
            canaryExecuted = mockExecuted,
            sinksInstrumented = trace.SinksInstrumented,
            canariesReachedSink = trace.CanariesReachedSink,
            canariesRenderedInDom = trace.CanariesRenderedInDom,
            findings = trace.Findings.Select(f => new
            {
                f.Severity,
                f.SinkType,
                f.Detail,
                f.Evidence
            }),
            note = "Assistive evidence, not auto-confirmed XSS. Prefer HTTP mock + render over chat Typing locks."
        };
    }
}
