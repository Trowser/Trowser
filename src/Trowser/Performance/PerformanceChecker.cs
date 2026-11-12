using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Performance;

/// <summary>
/// Measures Web Vitals and page performance using browser Performance APIs.
/// Follows the same inject-and-poll pattern as AccessibilityChecker.
/// </summary>
public class PerformanceChecker
{
    private readonly WebView2 _webView;
    private string? _webVitalsScript;

    public PerformanceChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Measure performance metrics for the current page.
    /// Collects Core Web Vitals (LCP, CLS, INP), additional metrics (TTFB, FCP),
    /// navigation timing breakdown, and resource loading summary.
    /// </summary>
    public async Task<PerformanceResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var webVitalsScript = await GetWebVitalsScriptAsync();

        var injectResult = await WebViewUiScript.RunAsync(_webView,
            webVitalsScript + "\n; typeof webVitals !== 'undefined' ? 'OK' : 'FAIL'", cancellationToken,
            operationLabel: "Performance measurement");

        if (injectResult != "OK")
        {
            throw new InvalidOperationException(
                $"Failed to inject web-vitals into the page. Result: {injectResult}");
        }

        var callbackId = $"__trowser_perf_{Guid.NewGuid():N}";

        var measureScript = BuildMeasurementScript(callbackId);
        var startResult = await WebViewUiScript.RunAsync(_webView, measureScript, cancellationToken,
            operationLabel: "Performance measurement");

        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start performance measurement. Result: {startResult}");
        }

        // Poll for result -- metrics collection uses PerformanceObserver callbacks
        // which fire as microtasks; 5s timeout is very generous (typically <200ms)
        var deadline = DateTime.UtcNow.AddSeconds(5);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Performance measurement");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Performance measurement");

                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Performance measurement");
                break;
            }
            await Task.Delay(50, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("Performance measurement did not complete within 5 seconds.");
        }

        return ParseResults(json);
    }

    #region JavaScript Measurement Script

    private static string BuildMeasurementScript(string callbackId)
    {
        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    var metrics = {{}};
    var navigation = {{}};
    var resources = {{ totalCount: 0, totalTransferSize: 0, byType: {{}}, slowest: [] }};
    var finalized = false;
    var settleTimer = null;
    var SETTLE_MS = 300;
    var FALLBACK_MS = 400;

    // --- Synchronous collection ---

    // Navigation Timing
    var navEntries = performance.getEntriesByType('navigation');
    if (navEntries.length > 0) {{
        var nav = navEntries[0];
        navigation.redirectTime = Math.round(nav.redirectEnd - nav.redirectStart);
        navigation.dnsTime = Math.round(nav.domainLookupEnd - nav.domainLookupStart);
        navigation.tcpTime = Math.round(nav.connectEnd - nav.connectStart);
        navigation.tlsTime = nav.secureConnectionStart > 0
            ? Math.round(nav.connectEnd - nav.secureConnectionStart) : 0;
        navigation.requestTime = Math.round(nav.responseStart - nav.requestStart);
        navigation.responseTime = Math.round(nav.responseEnd - nav.responseStart);
        navigation.domParsingTime = Math.round(nav.domInteractive - nav.responseEnd);
        navigation.domContentLoadedTime = Math.round(nav.domContentLoadedEventEnd - nav.startTime);
        navigation.pageLoadTime = nav.loadEventEnd > 0
            ? Math.round(nav.loadEventEnd - nav.startTime) : 0;
        navigation.transferSize = nav.transferSize || 0;
        navigation.decodedBodySize = nav.decodedBodySize || 0;

        metrics.ttfb = Math.round(nav.responseStart - nav.startTime);
    }}

    // Paint Timing (FP; FCP fallback until web-vitals onFCP fires)
    var paints = performance.getEntriesByType('paint');
    for (var i = 0; i < paints.length; i++) {{
        if (paints[i].name === 'first-paint')
            metrics.fp = Math.round(paints[i].startTime);
        if (paints[i].name === 'first-contentful-paint')
            metrics.fcp = Math.round(paints[i].startTime);
    }}

    // Resource Timing
    var res = performance.getEntriesByType('resource');
    resources.totalCount = res.length;
    var totalSize = 0;
    var byType = {{}};
    var sorted = res.slice().sort(function(a, b) {{ return b.duration - a.duration; }});

    for (var i = 0; i < res.length; i++) {{
        var r = res[i];
        totalSize += (r.transferSize || 0);
        var type = r.initiatorType || 'other';
        if (!byType[type]) byType[type] = {{ count: 0, totalSize: 0 }};
        byType[type].count++;
        byType[type].totalSize += (r.transferSize || 0);
    }}
    resources.totalTransferSize = totalSize;
    resources.byType = byType;

    for (var i = 0; i < Math.min(5, sorted.length); i++) {{
        var r = sorted[i];
        resources.slowest.push({{
            url: r.name.length > 120 ? r.name.substring(0, 120) + '...' : r.name,
            duration: Math.round(r.duration),
            size: r.transferSize || 0,
            type: r.initiatorType || 'other'
        }});
    }}

    // --- Core Web Vitals via web-vitals library ---

    function finalize() {{
        if (finalized) return;
        finalized = true;
        if (settleTimer) clearTimeout(settleTimer);
        window['{callbackId}'] = JSON.stringify({{
            url: location.href,
            timestamp: new Date().toISOString(),
            metrics: metrics,
            navigation: navigation,
            resources: resources
        }});
        window['{callbackId}_done'] = true;
    }}

    function scheduleFinalize() {{
        if (finalized) return;
        if (settleTimer) clearTimeout(settleTimer);
        settleTimer = setTimeout(finalize, SETTLE_MS);
    }}

    webVitals.onLCP(function(metric) {{
        metrics.lcp = Math.round(metric.value);
        if (metric.attribution && metric.attribution.target)
            metrics.lcpElement = metric.attribution.target;
        scheduleFinalize();
    }}, {{ reportAllChanges: true }});

    webVitals.onCLS(function(metric) {{
        metrics.cls = Math.round(metric.value * 10000) / 10000;
        scheduleFinalize();
    }}, {{ reportAllChanges: true }});

    webVitals.onINP(function(metric) {{
        metrics.inp = Math.round(metric.value);
        scheduleFinalize();
    }}, {{ reportAllChanges: true }});

    webVitals.onTTFB(function(metric) {{
        metrics.ttfb = Math.round(metric.value);
        scheduleFinalize();
    }});

    webVitals.onFCP(function(metric) {{
        metrics.fcp = Math.round(metric.value);
        scheduleFinalize();
    }}, {{ reportAllChanges: true }});

    // Absolute fallback if observers never settle
    setTimeout(function() {{
        if (!finalized) finalize();
    }}, FALLBACK_MS);

    scheduleFinalize();

    return 'STARTED';
}})()";
    }

    #endregion

    #region web-vitals Script Loading

    private async Task<string> GetWebVitalsScriptAsync()
    {
        if (_webVitalsScript != null) return _webVitalsScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.web-vitals.iife.js");

        if (stream == null)
        {
            throw new InvalidOperationException(
                "web-vitals script not found as embedded resource. " +
                "Ensure web-vitals.iife.js is in Resources/ and marked as EmbeddedResource in the .csproj.");
        }

        using var reader = new StreamReader(stream);
        _webVitalsScript = await reader.ReadToEndAsync();
        return _webVitalsScript;
    }

    #endregion

    #region Result Parsing

    private static PerformanceResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";
        var metricsEl = root.TryGetProperty("metrics", out var m) ? m : default;
        var navEl = root.TryGetProperty("navigation", out var n) ? n : default;
        var resEl = root.TryGetProperty("resources", out var r) ? r : default;

        var metrics = ParseMetrics(metricsEl);
        var navigation = ParseNavigation(navEl);
        var resources = ParseResources(resEl);

        return new PerformanceResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Metrics = metrics,
            Navigation = navigation,
            Resources = resources
        };
    }

    private static List<WebVitalMetric> ParseMetrics(JsonElement el)
    {
        var metrics = new List<WebVitalMetric>();
        if (el.ValueKind != JsonValueKind.Object) return metrics;

        // LCP -- Largest Contentful Paint
        if (el.TryGetProperty("lcp", out var lcp))
        {
            var val = lcp.GetDouble();
            string? lcpElement = null;
            if (el.TryGetProperty("lcpElement", out var lcpEl) && lcpEl.ValueKind == JsonValueKind.String)
                lcpElement = lcpEl.GetString();

            metrics.Add(new WebVitalMetric
            {
                Name = "LCP",
                FullName = "Largest Contentful Paint",
                Value = val,
                Unit = "ms",
                Rating = RateLcp(val),
                Element = lcpElement
            });
        }

        // CLS -- Cumulative Layout Shift
        if (el.TryGetProperty("cls", out var cls))
        {
            var val = cls.GetDouble();
            metrics.Add(new WebVitalMetric
            {
                Name = "CLS",
                FullName = "Cumulative Layout Shift",
                Value = val,
                Unit = "score",
                Rating = RateCls(val)
            });
        }

        // INP -- Interaction to Next Paint
        if (el.TryGetProperty("inp", out var inp))
        {
            var val = inp.GetDouble();
            metrics.Add(new WebVitalMetric
            {
                Name = "INP",
                FullName = "Interaction to Next Paint",
                Value = val,
                Unit = "ms",
                Rating = RateInp(val)
            });
        }

        // TTFB -- Time to First Byte
        if (el.TryGetProperty("ttfb", out var ttfb))
        {
            var val = ttfb.GetDouble();
            metrics.Add(new WebVitalMetric
            {
                Name = "TTFB",
                FullName = "Time to First Byte",
                Value = val,
                Unit = "ms",
                Rating = RateTtfb(val)
            });
        }

        // FCP -- First Contentful Paint
        if (el.TryGetProperty("fcp", out var fcp))
        {
            var val = fcp.GetDouble();
            metrics.Add(new WebVitalMetric
            {
                Name = "FCP",
                FullName = "First Contentful Paint",
                Value = val,
                Unit = "ms",
                Rating = RateFcp(val)
            });
        }

        // FP -- First Paint (no official thresholds, use FCP thresholds)
        if (el.TryGetProperty("fp", out var fp))
        {
            var val = fp.GetDouble();
            metrics.Add(new WebVitalMetric
            {
                Name = "FP",
                FullName = "First Paint",
                Value = val,
                Unit = "ms",
                Rating = RateFcp(val)
            });
        }

        // INP requires a real user interaction. During an automated measurement window there is
        // usually none, so web-vitals never fires onINP. Surface it explicitly as unavailable
        // instead of silently omitting the metric, so callers can tell it wasn't measured.
        if (!metrics.Any(m => m.Name == "INP"))
        {
            metrics.Add(new WebVitalMetric
            {
                Name = "INP",
                FullName = "Interaction to Next Paint",
                Unit = "ms",
                Available = false,
                Note = "no interaction occurred during the measurement window; interact with the page (e.g. browser_click) before measuring to capture INP"
            });
        }

        return metrics;
    }

    private static NavigationTiming ParseNavigation(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) return new NavigationTiming();

        return new NavigationTiming
        {
            RedirectTime = GetDouble(el, "redirectTime"),
            DnsTime = GetDouble(el, "dnsTime"),
            TcpTime = GetDouble(el, "tcpTime"),
            TlsTime = GetDouble(el, "tlsTime"),
            RequestTime = GetDouble(el, "requestTime"),
            ResponseTime = GetDouble(el, "responseTime"),
            DomParsingTime = GetDouble(el, "domParsingTime"),
            DomContentLoadedTime = GetDouble(el, "domContentLoadedTime"),
            PageLoadTime = GetDouble(el, "pageLoadTime"),
            TransferSize = GetLong(el, "transferSize"),
            DecodedBodySize = GetLong(el, "decodedBodySize")
        };
    }

    private static ResourceSummary ParseResources(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) return new ResourceSummary();

        var byType = new Dictionary<string, ResourceTypeInfo>();
        if (el.TryGetProperty("byType", out var byTypeEl) && byTypeEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in byTypeEl.EnumerateObject())
            {
                byType[prop.Name] = new ResourceTypeInfo
                {
                    Count = (int)GetDouble(prop.Value, "count"),
                    TotalSize = GetLong(prop.Value, "totalSize")
                };
            }
        }

        var slowest = new List<SlowResource>();
        if (el.TryGetProperty("slowest", out var slowestEl) && slowestEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in slowestEl.EnumerateArray())
            {
                slowest.Add(new SlowResource
                {
                    Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                    Duration = GetDouble(item, "duration"),
                    Size = GetLong(item, "size"),
                    Type = item.TryGetProperty("type", out var t) ? t.GetString() ?? "" : ""
                });
            }
        }

        return new ResourceSummary
        {
            TotalCount = (int)GetDouble(el, "totalCount"),
            TotalTransferSize = GetLong(el, "totalTransferSize"),
            ByType = byType,
            Slowest = slowest
        };
    }

    #endregion

    #region Rating Thresholds (Google Core Web Vitals)

    private static PerformanceRating RateLcp(double ms) =>
        ms <= 2500 ? PerformanceRating.Good :
        ms <= 4000 ? PerformanceRating.NeedsImprovement :
        PerformanceRating.Poor;

    private static PerformanceRating RateCls(double score) =>
        score <= 0.1 ? PerformanceRating.Good :
        score <= 0.25 ? PerformanceRating.NeedsImprovement :
        PerformanceRating.Poor;

    private static PerformanceRating RateInp(double ms) =>
        ms <= 200 ? PerformanceRating.Good :
        ms <= 500 ? PerformanceRating.NeedsImprovement :
        PerformanceRating.Poor;

    private static PerformanceRating RateTtfb(double ms) =>
        ms <= 800 ? PerformanceRating.Good :
        ms <= 1800 ? PerformanceRating.NeedsImprovement :
        PerformanceRating.Poor;

    private static PerformanceRating RateFcp(double ms) =>
        ms <= 1800 ? PerformanceRating.Good :
        ms <= 3000 ? PerformanceRating.NeedsImprovement :
        PerformanceRating.Poor;

    #endregion

    #region Helpers
    private static string UnwrapJsonString(string jsonResult)
        => Trowser.Automation.WebViewScriptResult.UnwrapJsonString(jsonResult);

    private static double GetDouble(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val))
        {
            if (val.ValueKind == JsonValueKind.Number) return val.GetDouble();
        }
        return 0;
    }

    private static long GetLong(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val))
        {
            if (val.ValueKind == JsonValueKind.Number) return (long)val.GetDouble();
        }
        return 0;
    }


    #endregion
}
