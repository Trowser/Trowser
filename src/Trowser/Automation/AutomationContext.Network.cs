using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Request Tracing (verbose transparency for scans and probes)

    /// <summary>
    /// Fallback when UI-thread marshaling (WebView2) drops <see cref="AsyncLocal{T}"/> after
    /// <c>ExecuteJs</c> — without this, <c>verbose: true</c> scans record zero requests.
    /// </summary>
    private RequestTrace? _requestTraceFallback;

    /// <summary>The request trace active on the current async flow, or null when not tracing.</summary>
    public RequestTrace? CurrentRequestTrace => _requestTrace.Value ?? _requestTraceFallback;

    /// <summary>
    /// Begin capturing every outbound HTTP request issued on this context (via <see cref="Fetch"/>
    /// and the security probe HTTP helpers) until the returned scope is disposed. Nests safely.
    /// </summary>
    public RequestTraceScope BeginRequestTrace(int maxEntries = 2000, int maxBodyChars = 4000)
    {
        var previous = _requestTrace.Value ?? _requestTraceFallback;
        var trace = new RequestTrace(maxEntries, maxBodyChars);
        _requestTrace.Value = trace;
        _requestTraceFallback = trace;
        return new RequestTraceScope(this, trace, previous);
    }

    /// <summary>Restore the previous trace when a <see cref="RequestTraceScope"/> is disposed.</summary>
    internal void EndRequestTrace(RequestTrace? previous)
    {
        _requestTrace.Value = previous;
        _requestTraceFallback = previous;
    }

    /// <summary>
    /// Record one completed outbound request against the active trace (no-op when not tracing).
    /// Called by <see cref="Fetch"/> and by <c>SecurityProbeHttp</c> for its server-side paths.
    /// </summary>
    internal void RecordOutboundRequest(string method, string url, string? body, int status, long elapsedMs, string? error, string transport)
        => CurrentRequestTrace?.Record(method, url, body, status, elapsedMs, error, transport);

    #endregion

    #region Network Helpers

    public List<NetworkEntry> GetNetworkLog() => Network.Entries;
    public List<NetworkEntry> GetPageNetworkLog() => Network.PageEntries;
    public List<NetworkEntry> FindRequests(string urlSubstring) => Network.FindByUrl(urlSubstring);
    public void ClearNetworkLog() => Network.Clear();

    public void PrintNetworkLog(int? maxEntries = null)
    {
        _logColored(Network.Format(maxEntries), "#569CD6");
    }

    public async Task<NetworkEntry> WaitForRequest(string urlSubstring, int timeoutMs = 10000)
    {
        return await WaitForRequest(urlSubstring, null, null, timeoutMs);
    }

    public async Task<NetworkEntry> WaitForRequest(string urlSubstring, string? method, int? status, int timeoutMs = 10000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);

        while (DateTime.UtcNow < deadline)
        {
            var matches = Network.FindByUrl(urlSubstring);
            foreach (var entry in matches.AsEnumerable().Reverse())
            {
                if (method != null && !entry.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;
                if (status != null && entry.StatusCode != status.Value) continue;
                return entry;
            }
            await Task.Delay(100, ScriptCancellation);
        }

        var desc = $"'{urlSubstring}'";
        if (method != null) desc += $" method={method}";
        if (status != null) desc += $" status={status}";
        throw new TimeoutException($"No network request matching {desc} within {timeoutMs}ms");
    }

    public async Task<bool> WaitForIdle(int quietPeriodMs = 500, int timeoutMs = 10000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        var lastNetworkCount = Network.Count;
        var lastChangeTime = DateTime.UtcNow;

        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(100, ScriptCancellation);

            var currentCount = Network.Count;
            if (currentCount != lastNetworkCount)
            {
                lastNetworkCount = currentCount;
                lastChangeTime = DateTime.UtcNow;
            }

            var networkQuiet = (DateTime.UtcNow - lastChangeTime).TotalMilliseconds >= quietPeriodMs;

            if (networkQuiet)
            {
                var animating = await RunJs(@"
                    (function() {
                        var anims = document.getAnimations ? document.getAnimations() : [];
                        var running = anims.filter(function(a) { return a.playState === 'running'; });
                        return running.length > 0 ? 'true' : 'false';
                    })()");

                if (animating != "true")
                    return true;
            }
        }

        return false;
    }

    #endregion

    #region Console Helpers

    public List<ConsoleEntry> GetConsoleLog() => Console.Entries;
    public List<ConsoleEntry> GetPageConsoleLog() => Console.PageEntries;
    public List<ConsoleEntry> GetConsoleErrors() => Console.GetErrors();
    public List<ConsoleEntry> GetPageConsoleErrors() => Console.GetPageErrors();
    public void ClearConsoleLog() => Console.Clear();

    public void PrintConsoleLog(int? maxEntries = null)
    {
        _logColored(Console.Format(maxEntries), "#DCDCAA");
    }

    #endregion

    #region Network Mocking (delegates to active tab)

    public void MockResponse(string urlPattern, int statusCode = 200,
        string? body = null, string? method = null,
        Dictionary<string, string>? headers = null, int delayMs = 0)
    {
        ActiveTab.MockResponse(urlPattern, statusCode, body, method, headers, delayMs);
    }

    public bool RemoveMock(string urlPattern) => ActiveTab.RemoveMock(urlPattern);
    public void ClearMocks() => ActiveTab.ClearMocks();
    public List<MockRule> GetMockRules() => ActiveTab.GetMockRules();
    public void SetMockRuleEnabled(string urlPattern, string? method, bool enabled)
        => ActiveTab.SetMockRuleEnabled(urlPattern, method, enabled);

    public MockRule? FindMatchingMock(string url, string method)
    {
        foreach (var tab in Tabs)
        {
            var match = tab.FindMatchingMock(url, method);
            if (match != null)
                return match;
        }

        return null;
    }

    #endregion

    #region Network Interception / Breakpoints (delegates to active tab)

    public void AddInterceptRule(string urlPattern, string? method = null, bool silent = true)
        => ActiveTab.AddInterceptRule(urlPattern, method, silent);

    public void AddAutoFulfillInterceptRule(
        string urlPattern,
        int statusCode = 200,
        string? body = null,
        string? method = null,
        Dictionary<string, string>? responseHeaders = null)
        => ActiveTab.AddAutoFulfillInterceptRule(urlPattern, statusCode, body, method, responseHeaders);

    public async Task SetNetworkCacheDisabledAsync(bool disabled)
    {
        var webView = ActiveTab.WebView;
        await webView.Dispatcher.InvokeAsync(async () =>
        {
            if (webView.CoreWebView2 == null) return;
            try
            {
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                    "Network.enable", "{}");
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                    "Network.setCacheDisabled",
                    System.Text.Json.JsonSerializer.Serialize(new { cacheDisabled = disabled }));
            }
            catch { /* best-effort */ }
        });
    }

    public void RemoveInterceptRule(string urlPattern, string? method = null)
        => ActiveTab.RemoveInterceptRule(urlPattern, method);
    public void ClearInterceptRules() => ActiveTab.ClearInterceptRules();
    public List<InterceptRule> GetInterceptRules() => ActiveTab.GetInterceptRules();
    public void SetInterceptRuleEnabled(string urlPattern, string? method, bool enabled)
        => ActiveTab.SetInterceptRuleEnabled(urlPattern, method, enabled);

    public InterceptRule? FindMatchingIntercept(string url, string method)
        => ActiveTab.FindMatchingIntercept(url, method);

    public List<PendingRequest> GetPendingRequests() => ActiveTab.GetPendingRequests();
    public PendingRequest? GetPendingRequest(int id) => ActiveTab.GetPendingRequest(id);

    public bool ResolvePendingRequest(int requestId, InterceptDecision decision)
        => ActiveTab.ResolvePendingRequest(requestId, decision);

    public bool HasInterceptRules => ActiveTab.HasInterceptRules;
    public bool HasPendingRequests => ActiveTab.HasPendingRequests;
    public int InterceptRuleCount => ActiveTab.InterceptRuleCount;
    public int PendingRequestCount => ActiveTab.PendingRequestCount;

    #endregion

    #region SAML Capture (delegates to active tab)

    public SamlCaptureManager SamlCapture => ActiveTab.SamlCapture;

    #endregion

    #region Network Throttling (CDP Network.emulateNetworkConditions)

    public record NetworkThrottleState(
        double DownloadKbps, double UploadKbps, int LatencyMs, bool Offline);

    private static readonly Dictionary<string, NetworkThrottleState> ThrottlePresets = new(StringComparer.OrdinalIgnoreCase)
    {
        ["offline"] = new(0, 0, 0, true),
        ["2g"]      = new(32, 6.4, 1800, false),
        ["slow3g"]  = new(50, 20, 2000, false),
        ["3g"]      = new(188, 38, 562, false),
        ["4g"]      = new(1500, 750, 170, false),
    };

    private NetworkThrottleState? _throttleState;
    private bool _cdpNetworkEnabled;

    public NetworkThrottleState? ThrottleState => _throttleState;

    public static IReadOnlyDictionary<string, NetworkThrottleState> GetThrottlePresets() => ThrottlePresets;

    public async Task SetNetworkThrottle(double downloadKbps, double uploadKbps, int latencyMs, bool offline = false)
    {
        var webView = ActiveTab.WebView;

        if (!_cdpNetworkEnabled)
        {
            await await webView.Dispatcher.InvokeAsync(async () =>
                await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Network.enable", "{}"));
            _cdpNetworkEnabled = true;
        }

        var downloadBps = (long)(downloadKbps * 1024 / 8);
        var uploadBps = (long)(uploadKbps * 1024 / 8);

        var json = JsonSerializer.Serialize(new
        {
            offline,
            latency = latencyMs,
            downloadThroughput = downloadBps,
            uploadThroughput = uploadBps,
        });

        await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Network.emulateNetworkConditions", json));

        _throttleState = new NetworkThrottleState(downloadKbps, uploadKbps, latencyMs, offline);
    }

    public async Task SetNetworkThrottle(string preset)
    {
        var normalized = preset.ToLowerInvariant().Replace(" ", "").Replace("-", "").Replace("_", "");
        if (!ThrottlePresets.TryGetValue(normalized, out var state))
        {
            var valid = string.Join(", ", ThrottlePresets.Keys);
            throw new ArgumentException($"Unknown throttle preset: '{preset}'. Valid presets: {valid}");
        }

        await SetNetworkThrottle(state.DownloadKbps, state.UploadKbps, state.LatencyMs, state.Offline);
    }

    public async Task ClearNetworkThrottle()
    {
        if (_throttleState == null) return;

        var webView = ActiveTab.WebView;

        var json = JsonSerializer.Serialize(new
        {
            offline = false,
            latency = 0,
            downloadThroughput = -1,
            uploadThroughput = -1,
        });

        await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(
                "Network.emulateNetworkConditions", json));

        _throttleState = null;
    }

    #endregion
}
