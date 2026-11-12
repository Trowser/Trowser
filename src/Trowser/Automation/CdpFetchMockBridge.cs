using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

/// <summary>
/// CDP Fetch.requestPaused bridge for mock/intercept auto-fulfill on resource types
/// (e.g. ES module scripts) that may not reliably hit WebResourceRequested.
/// </summary>
internal static class CdpFetchMockBridge
{
    private static readonly HashSet<string> InterceptResourceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Script", "Stylesheet", "Fetch", "XHR", "Other", "Document"
    };

    public static async Task EnableAsync(CoreWebView2 core)
    {
        try
        {
            await core.CallDevToolsProtocolMethodAsync("Fetch.enable", """
                {"patterns":[
                  {"urlPattern":"*","resourceType":"Script","requestStage":"Request"},
                  {"urlPattern":"*","resourceType":"Stylesheet","requestStage":"Request"}
                ]}
                """);
        }
        catch
        {
            // best-effort
        }
    }

    public static async Task DisableAsync(CoreWebView2 core)
    {
        try
        {
            await core.CallDevToolsProtocolMethodAsync("Fetch.disable", "{}");
        }
        catch
        {
            // best-effort
        }
    }

    public static async Task HandleRequestPausedAsync(BrowserTab tab, CoreWebView2 core, string parameterJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(parameterJson);
            var root = doc.RootElement;
            var requestId = root.GetProperty("requestId").GetString();
            if (string.IsNullOrEmpty(requestId)) return;

            var request = root.GetProperty("request");
            var url = request.GetProperty("url").GetString() ?? "";
            var method = request.TryGetProperty("method", out var mEl) ? mEl.GetString() ?? "GET" : "GET";
            var resourceType = root.TryGetProperty("resourceType", out var rtEl) ? rtEl.GetString() ?? "" : "";

            if (!InterceptResourceTypes.Contains(resourceType))
            {
                await ContinueAsync(core, requestId);
                return;
            }

            if (tab.HasInterceptRules)
            {
                var interceptRule = tab.FindMatchingIntercept(url, method);
                if (interceptRule?.AutoFulfill != null)
                {
                    var auto = interceptRule.AutoFulfill;
                    tab.CacheResponseBody(method, url, auto.Body);
                    tab.CacheFulfilledResponse(method, url,
                        new BrowserTab.FulfilledResponseMarker("intercept-fulfill", interceptRule.UrlPattern));
                    await FulfillAsync(core, requestId, auto.StatusCode, auto.Body, auto.ResponseHeaders);
                    return;
                }
            }

            if (tab.HasMockRules)
            {
                var mock = tab.FindMatchingMock(url, method);
                if (mock != null)
                {
                    tab.CacheResponseBody(method, url, mock.Body);
                    tab.CacheFulfilledResponse(method, url,
                        new BrowserTab.FulfilledResponseMarker("mock", mock.UrlPattern));
                    await FulfillAsync(core, requestId, mock.StatusCode, mock.Body, mock.Headers);
                    return;
                }
            }

            await ContinueAsync(core, requestId);
        }
        catch
        {
            // If parsing/handling fails, try to unblock the request.
            try
            {
                using var doc = JsonDocument.Parse(parameterJson);
                var requestId = doc.RootElement.GetProperty("requestId").GetString();
                if (!string.IsNullOrEmpty(requestId))
                    await ContinueAsync(core, requestId);
            }
            catch { /* ignore */ }
        }
    }

    private static Task ContinueAsync(CoreWebView2 core, string requestId) =>
        core.CallDevToolsProtocolMethodAsync("Fetch.continueRequest",
            JsonSerializer.Serialize(new { requestId }));

    private static async Task FulfillAsync(
        CoreWebView2 core,
        string requestId,
        int statusCode,
        string? body,
        IReadOnlyDictionary<string, string>? headers)
    {
        var responseHeaders = new List<object>();
        if (headers != null)
        {
            foreach (var kv in headers)
                responseHeaders.Add(new { name = kv.Key, value = kv.Value });
        }
        else if (!string.IsNullOrEmpty(body))
        {
            responseHeaders.Add(new { name = "Content-Type", value = "application/javascript" });
        }

        var payload = new Dictionary<string, object?>
        {
            ["requestId"] = requestId,
            ["responseCode"] = statusCode,
            ["responseHeaders"] = responseHeaders,
            ["body"] = body != null ? Convert.ToBase64String(Encoding.UTF8.GetBytes(body)) : ""
        };

        await core.CallDevToolsProtocolMethodAsync("Fetch.fulfillRequest",
            JsonSerializer.Serialize(payload));
    }
}
