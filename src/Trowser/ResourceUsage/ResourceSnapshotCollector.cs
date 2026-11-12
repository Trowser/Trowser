using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.ResourceUsage;

/// <summary>Collects resource snapshots via CDP and tab-local connection state.</summary>
public sealed class ResourceSnapshotCollector
{
    private readonly WebView2 _webView;
    private readonly BrowserTab _tab;
    private readonly CdpResourceBridge _cdp;

    public ResourceSnapshotCollector(WebView2 webView, BrowserTab tab, AutomationContext ctx)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
        _tab = tab ?? throw new ArgumentNullException(nameof(tab));
        _cdp = new CdpResourceBridge(webView, ctx);
    }

    public async Task<ResourceSnapshot> CollectAsync(bool prepareForLeakDetection = false)
    {
        // Default snapshot uses page script metrics only. CDP heap/queryObjects runs only for leak probes.
        var metrics = await _cdp.GetMetricsAsync();
        int? liveHtml = null;
        if (prepareForLeakDetection)
        {
            await _cdp.PrepareForLeakDetectionAsync();
            await _cdp.CollectGarbageAsync();
            liveHtml = await _cdp.CountLiveHtmlElementsAsync();
        }
        var url = await GetCurrentUrlAsync();

        var snapshot = new ResourceSnapshot
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            JsHeapUsedBytes = GetMetric(metrics, "JSHeapUsedSize"),
            JsHeapTotalBytes = GetMetric(metrics, "JSHeapTotalSize"),
            DomNodes = (int)GetMetric(metrics, "Nodes"),
            Documents = (int)GetMetric(metrics, "Documents"),
            Frames = (int)GetMetric(metrics, "Frames"),
            JsEventListeners = (int)GetMetric(metrics, "JSEventListeners"),
            LiveHtmlElements = liveHtml,
            WebSocketsOpen = CountOpenWebSockets(),
            Flags = BuildFlags(metrics)
        };

        return snapshot;
    }

    public Task CollectGarbageAsync() => _cdp.CollectGarbageAsync();

    public Task PrepareForLeakDetectionAsync() => _cdp.PrepareForLeakDetectionAsync();

    private int CountOpenWebSockets() =>
        _tab.WebSocket.GetConnections(stateFilter: "open").Count;

    private static long GetMetric(IReadOnlyDictionary<string, long> metrics, string name) =>
        metrics.TryGetValue(name, out var v) ? v : 0;

    private static List<string> BuildFlags(IReadOnlyDictionary<string, long> metrics)
    {
        var flags = new List<string>();
        var listeners = GetMetric(metrics, "JSEventListeners");
        var documents = GetMetric(metrics, "Documents");
        var nodes = GetMetric(metrics, "Nodes");
        var heapUsed = GetMetric(metrics, "JSHeapUsedSize");

        if (listeners > 3000)
            flags.Add($"High event listener count ({listeners}) — check for missing removeEventListener on route/modal teardown");
        if (documents > 3)
            flags.Add($"Multiple documents ({documents}) — possible iframe or popup leak");
        if (nodes > 15000)
            flags.Add($"Large DOM ({nodes} nodes) — may impact memory and layout performance");
        if (heapUsed > 100 * 1024 * 1024)
            flags.Add($"JS heap over 100 MB ({ResourceProbeResult.FormatBytes(heapUsed)}) — investigate retained objects if page is simple");

        return flags;
    }

    private async Task<string> GetCurrentUrlAsync()
    {
        try
        {
            var task = await _webView.Dispatcher.InvokeAsync(() =>
            {
                var core = _webView.CoreWebView2;
                return Task.FromResult(core?.Source ?? "");
            });
            return await task;
        }
        catch
        {
            return _tab.Url;
        }
    }
}

/// <summary>Analyzes probe samples and produces actionable findings.</summary>
public static class ResourceProbeAnalyzer
{
    public static List<ResourceFinding> Analyze(
        IReadOnlyList<ResourceSnapshot> samples,
        ResourceProbeOptions options)
    {
        if (samples.Count < 2) return [];

        var baseline = samples[0];
        var final = samples[^1];
        var findings = new List<ResourceFinding>();

        AddGrowthFinding(findings, "heap-leak", "JS heap grew after repeated actions",
            baseline.JsHeapUsedBytes, final.JsHeapUsedBytes, options.GrowthThresholdPercent,
            samples.Select(s => s.JsHeapUsedBytes).ToList(),
            "Heap did not return to baseline after garbage collection. Check closures, caches, and arrays that grow unbounded.",
            "Audit component teardown: nullify references, clear caches with bounds, and remove global registrations.");

        AddGrowthFinding(findings, "dom-node-leak", "DOM nodes grew after repeated actions",
            baseline.DomNodes, final.DomNodes, options.GrowthThresholdPercent,
            samples.Select(s => (long)s.DomNodes).ToList(),
            "DOM node count increased across iterations. Elements may be removed from the document but still retained in JS.",
            "Check for detached DOM nodes: remove event listeners before removing elements, avoid storing element refs in closures.",
            absoluteThreshold: options.NodeGrowthThreshold);

        AddGrowthFinding(findings, "listener-leak", "Event listeners grew after repeated actions",
            baseline.JsEventListeners, final.JsEventListeners, options.GrowthThresholdPercent,
            samples.Select(s => (long)s.JsEventListeners).ToList(),
            "Event listener count increased without matching DOM growth — classic sign of missing cleanup on route/modal close.",
            "Ensure removeEventListener (or framework equivalent) runs on unmount. Avoid attaching listeners to document/window without teardown.",
            absoluteThreshold: options.ListenerGrowthThreshold);

        if (final.Documents > baseline.Documents)
        {
            var delta = final.Documents - baseline.Documents;
            findings.Add(new ResourceFinding
            {
                Severity = delta >= 2 ? Severity.High : Severity.Medium,
                Category = "document-leak",
                Title = "Document count increased",
                Description = $"Documents rose from {baseline.Documents} to {final.Documents} (+{delta}) across iterations.",
                Recommendation = "Check for iframes, popups, or window.open calls that are not closed on navigation.",
                Confidence = IsMonotonicIncrease(samples.Select(s => (long)s.Documents).ToList())
                    ? ResourceConfidence.High
                    : ResourceConfidence.Medium,
                Evidence = new Dictionary<string, object?>
                {
                    ["baseline"] = baseline.Documents,
                    ["final"] = final.Documents,
                    ["delta"] = delta
                }
            });
        }

        if (final.WebSocketsOpen > baseline.WebSocketsOpen + 1)
        {
            var delta = final.WebSocketsOpen - baseline.WebSocketsOpen;
            findings.Add(new ResourceFinding
            {
                Severity = Severity.Medium,
                Category = "websocket-leak",
                Title = "Open WebSocket connections increased",
                Description = $"Open WebSockets rose from {baseline.WebSocketsOpen} to {final.WebSocketsOpen} (+{delta}).",
                Recommendation = "Close WebSocket connections when components unmount or routes change.",
                Confidence = ResourceConfidence.Medium,
                Evidence = new Dictionary<string, object?>
                {
                    ["baseline"] = baseline.WebSocketsOpen,
                    ["final"] = final.WebSocketsOpen,
                    ["delta"] = delta
                }
            });
        }

        if (baseline.LiveHtmlElements.HasValue && final.LiveHtmlElements.HasValue &&
            final.LiveHtmlElements.Value > baseline.LiveHtmlElements.Value + options.NodeGrowthThreshold / 2)
        {
            var delta = final.LiveHtmlElements.Value - baseline.LiveHtmlElements.Value;
            findings.Add(new ResourceFinding
            {
                Severity = Severity.Medium,
                Category = "dom-node-leak",
                Title = "Live HTMLElement instances in heap increased",
                Description = $"Runtime.queryObjects(HTMLElement) count rose from {baseline.LiveHtmlElements} to {final.LiveHtmlElements} (+{delta}) after GC.",
                Recommendation = "Detached DOM nodes are likely retained by JS references. Inspect modal/route cleanup and event handler closures.",
                Confidence = IsMonotonicIncrease(samples.Where(s => s.LiveHtmlElements.HasValue)
                    .Select(s => (long)s.LiveHtmlElements!.Value).ToList())
                    ? ResourceConfidence.High
                    : ResourceConfidence.Medium,
                Evidence = new Dictionary<string, object?>
                {
                    ["baseline"] = baseline.LiveHtmlElements,
                    ["final"] = final.LiveHtmlElements,
                    ["delta"] = delta
                }
            });
        }

        return findings;
    }

    private static void AddGrowthFinding(
        List<ResourceFinding> findings,
        string category,
        string title,
        long baselineValue,
        long finalValue,
        double percentThreshold,
        List<long> series,
        string description,
        string recommendation,
        int absoluteThreshold = 0)
    {
        var delta = finalValue - baselineValue;
        if (delta <= 0) return;

        var percentGrowth = baselineValue > 0 ? delta * 100.0 / baselineValue : 100;
        var absThreshold = absoluteThreshold > 0 ? absoluteThreshold : Math.Max(1, (long)(baselineValue * percentThreshold / 100));
        if (delta < absThreshold && percentGrowth < percentThreshold) return;

        var monotonic = IsMonotonicIncrease(series);
        var confidence = monotonic && percentGrowth >= percentThreshold
            ? ResourceConfidence.High
            : percentGrowth >= percentThreshold * 2 || delta >= absThreshold * 2
                ? ResourceConfidence.Medium
                : ResourceConfidence.Low;

        var severity = confidence switch
        {
            ResourceConfidence.High when percentGrowth >= percentThreshold * 2 => Severity.High,
            ResourceConfidence.High => Severity.Medium,
            ResourceConfidence.Medium => Severity.Medium,
            _ => Severity.Low
        };

        findings.Add(new ResourceFinding
        {
            Severity = severity,
            Category = category,
            Title = title,
            Description = $"{description} Baseline: {baselineValue:N0}, final: {finalValue:N0} (+{delta:N0}, +{percentGrowth:F1}%).",
            Recommendation = recommendation,
            Confidence = confidence,
            Evidence = new Dictionary<string, object?>
            {
                ["baseline"] = baselineValue,
                ["final"] = finalValue,
                ["delta"] = delta,
                ["percentGrowth"] = Math.Round(percentGrowth, 1),
                ["monotonic"] = monotonic
            }
        });
    }

    private static bool IsMonotonicIncrease(IReadOnlyList<long> series)
    {
        if (series.Count < 3) return false;
        var increases = 0;
        for (var i = 1; i < series.Count; i++)
        {
            if (series[i] > series[i - 1]) increases++;
        }
        return increases >= series.Count - 2;
    }
}
