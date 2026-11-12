using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.ResourceUsage;

/// <summary>CDP bridge for memory and DOM resource metrics.</summary>
internal sealed class CdpResourceBridge
{
    private const int CallTimeoutMs = 30_000;

    private readonly WebView2 _webView;
    private readonly AutomationContext _ctx;
    private bool _performanceEnabled;
    private bool _runtimeEnabled;

    public CdpResourceBridge(WebView2 webView, AutomationContext ctx)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
        _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
    }

    public async Task<Dictionary<string, long>> GetMetricsAsync()
    {
        // Prefer page Performance APIs (same stability as POST /api/performance). CDP Performance.*
        // can hang on some WebView2 builds and wedge the UI dispatcher queue.
        var jsMetrics = await TryGetMetricsFromPageScriptAsync();
        if (HasCoreResourceMetrics(jsMetrics))
            return jsMetrics;

        var cdpJson = await CallCdpAsync("Performance.getMetrics", "{}");
        var result = ParseMetricsJson(cdpJson);
        if (HasCoreResourceMetrics(result))
            return result;

        if (!_performanceEnabled)
        {
            try
            {
                await CallCdpAsync("Performance.enable", "{}");
                _performanceEnabled = true;
                result = ParseMetricsJson(await CallCdpAsync("Performance.getMetrics", "{}"));
            }
            catch
            {
                // CDP path is optional when JS metrics succeeded partially
            }
        }

        return HasCoreResourceMetrics(result) ? result : jsMetrics;
    }

    private async Task<Dictionary<string, long>> TryGetMetricsFromPageScriptAsync()
    {
        const string script = """
            (function(){
              var metrics = [];
              function push(name, value) {
                if (typeof value === 'number' && isFinite(value)) metrics.push({ name: name, value: value });
              }
              push('Nodes', document.getElementsByTagName('*').length);
              push('Documents', window.frames ? window.frames.length + 1 : 1);
              push('Frames', window.frames ? window.frames.length : 0);
              if (performance && performance.memory) {
                push('JSHeapUsedSize', performance.memory.usedJSHeapSize);
                push('JSHeapTotalSize', performance.memory.totalJSHeapSize);
              }
              return JSON.stringify({ metrics: metrics });
            })()
            """;

        try
        {
            var json = await CallPageScriptAsync(script);
            return ParseMetricsJson(json);
        }
        catch
        {
            return new Dictionary<string, long>(StringComparer.Ordinal);
        }
    }

    private static bool HasCoreResourceMetrics(IReadOnlyDictionary<string, long> metrics) =>
        metrics.ContainsKey("Nodes") || metrics.ContainsKey("JSHeapUsedSize");

    private static Dictionary<string, long> ParseMetricsJson(string? json)
    {
        var result = new Dictionary<string, long>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(json)) return result;

        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("metrics", out var metrics) ||
            metrics.ValueKind != JsonValueKind.Array)
            return result;

        foreach (var m in metrics.EnumerateArray())
        {
            if (!m.TryGetProperty("name", out var nameEl) ||
                !m.TryGetProperty("value", out var valueEl))
                continue;
            var name = nameEl.GetString();
            if (string.IsNullOrEmpty(name)) continue;
            result[name] = (long)Math.Round(valueEl.GetDouble());
        }

        return result;
    }

    public async Task CollectGarbageAsync()
    {
        try
        {
            await CallCdpAsync("HeapProfiler.collectGarbage", "{}");
        }
        catch
        {
            // best-effort
        }

        await Task.Delay(300, LinkedCancellation());
    }

    public async Task PrepareForLeakDetectionAsync()
    {
        try
        {
            await CallCdpAsync("Memory.prepareForLeakDetection", "{}");
        }
        catch
        {
            // Memory domain may be unavailable on some WebView2 builds
        }
    }

    public async Task<int?> CountLiveHtmlElementsAsync()
    {
        try
        {
            await EnsureRuntimeEnabledAsync();

            var evalJson = await CallCdpAsync("Runtime.evaluate", JsonSerializer.Serialize(new
            {
                expression = "HTMLElement.prototype",
                returnByValue = false
            }));
            if (string.IsNullOrEmpty(evalJson)) return null;

            using var evalDoc = JsonDocument.Parse(evalJson);
            if (!evalDoc.RootElement.TryGetProperty("result", out var evalResult) ||
                !evalResult.TryGetProperty("objectId", out var protoIdEl))
                return null;

            var protoId = protoIdEl.GetString();
            if (string.IsNullOrEmpty(protoId)) return null;

            var queryJson = await CallCdpAsync("Runtime.queryObjects", JsonSerializer.Serialize(new
            {
                prototypeObjectId = protoId,
                objectGroup = "__trowser_resource_probe"
            }));
            if (string.IsNullOrEmpty(queryJson)) return null;

            using var queryDoc = JsonDocument.Parse(queryJson);
            if (!queryDoc.RootElement.TryGetProperty("objects", out var objectsEl) ||
                !objectsEl.TryGetProperty("objectId", out var objectsIdEl))
                return null;

            var objectsId = objectsIdEl.GetString();
            if (string.IsNullOrEmpty(objectsId)) return null;

            var countJson = await CallCdpAsync("Runtime.callFunctionOn", JsonSerializer.Serialize(new
            {
                objectId = objectsId,
                functionDeclaration = "function() { return this.length; }",
                returnByValue = true,
                objectGroup = "__trowser_resource_probe"
            }));
            if (string.IsNullOrEmpty(countJson)) return null;

            using var countDoc = JsonDocument.Parse(countJson);
            if (countDoc.RootElement.TryGetProperty("result", out var countResult) &&
                countResult.TryGetProperty("value", out var valueEl) &&
                valueEl.TryGetInt64(out var count))
                return (int)Math.Min(count, int.MaxValue);
        }
        catch
        {
            // queryObjects not supported or failed
        }
        finally
        {
            try
            {
                await CallCdpAsync("Runtime.releaseObjectGroup",
                    JsonSerializer.Serialize(new { objectGroup = "__trowser_resource_probe" }));
            }
            catch { /* ignore */ }
        }

        return null;
    }

    private async Task EnsureRuntimeEnabledAsync()
    {
        if (_runtimeEnabled) return;
        await CallCdpAsync("Runtime.enable", "{}");
        _runtimeEnabled = true;
    }

    private CancellationToken LinkedCancellation()
    {
        return CancellationTokenSource.CreateLinkedTokenSource(
            _ctx.ScriptCancellation,
            _ctx.OperationCancellation).Token;
    }

    private Task<string?> CallPageScriptAsync(string script) =>
        CallPageScriptAsync(script, CallTimeoutMs);

    private async Task<string?> CallPageScriptAsync(string script, int timeoutMs)
    {
        try
        {
            var raw = await WebViewUiScript.RunAsync(_webView, script, LinkedCancellation(), timeoutMs,
                operationLabel: "Resource snapshot");
            return string.IsNullOrEmpty(raw) ? null : raw;
        }
        catch (OperationCanceledException)
        {
            if (_ctx.OperationCancellation.IsCancellationRequested || _ctx.ScriptCancellation.IsCancellationRequested)
                throw;
            throw;
        }
    }

    private Task<string?> CallCdpAsync(string method, string parametersJson) =>
        CallCdpAsync(method, parametersJson, CancellationToken.None);

    private async Task<string?> CallCdpAsync(string method, string parametersJson, CancellationToken outerCancellation)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(
            _ctx.ScriptCancellation,
            _ctx.OperationCancellation,
            outerCancellation);
        timeoutCts.CancelAfter(CallTimeoutMs);

        var task = await _webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = _webView.CoreWebView2;
            if (core == null) return null;
            return await core.CallDevToolsProtocolMethodAsync(method, parametersJson);
        });

        try
        {
            return await task.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            if (_ctx.OperationCancellation.IsCancellationRequested || _ctx.ScriptCancellation.IsCancellationRequested)
                throw;

            WebViewCdpRecovery.TryTerminateExecutionAsync(_webView);

            throw new TimeoutException(
                $"CDP {method} timed out after {CallTimeoutMs / 1000} seconds. " +
                "The WebView UI thread may be blocked; try POST /api/force-navigate or POST /api/abort.");
        }
    }
}
