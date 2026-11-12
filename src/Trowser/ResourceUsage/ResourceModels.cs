using Trowser.Security;

namespace Trowser.ResourceUsage;

/// <summary>Point-in-time resource usage metrics for the current page.</summary>
public class ResourceSnapshot
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public long JsHeapUsedBytes { get; init; }
    public long JsHeapTotalBytes { get; init; }
    public int DomNodes { get; init; }
    public int Documents { get; init; }
    public int Frames { get; init; }
    public int JsEventListeners { get; init; }
    public int? LiveHtmlElements { get; init; }
    public int WebSocketsOpen { get; init; }
    public List<string> Flags { get; init; } = [];
}

/// <summary>Configuration for a resource leak probe run.</summary>
public class ResourceProbeOptions
{
    /// <summary>Actions to replay each iteration (batch API format). Optional when <see cref="ReloadBetweenIterations"/> is true.</summary>
    public List<Robustness.InterrupterAction>? Actions { get; init; }

    /// <summary>Number of measurement iterations after baseline (default 5).</summary>
    public int Iterations { get; init; } = 5;

    /// <summary>Force garbage collection before each probe iteration sample (default true).</summary>
    public bool GcBetweenIterations { get; init; } = true;

    /// <summary>Force garbage collection before the final sample in a baseline comparison (default true).</summary>
    public bool GcBeforeFinal { get; init; } = true;

    /// <summary>Milliseconds to wait after actions before measuring (default 500).</summary>
    public int SettleMs { get; init; } = 500;

    /// <summary>Reload the current URL at the start of each iteration (good for refresh-leak detection).</summary>
    public bool ReloadBetweenIterations { get; init; }

    /// <summary>Percent growth threshold for heap/listeners (default 10).</summary>
    public double GrowthThresholdPercent { get; init; } = 10;

    /// <summary>Absolute listener growth that triggers a finding (default 50).</summary>
    public int ListenerGrowthThreshold { get; init; } = 50;

    /// <summary>Absolute DOM node growth that triggers a finding (default 100).</summary>
    public int NodeGrowthThreshold { get; init; } = 100;
}

/// <summary>Confidence that a finding indicates a real leak vs noise.</summary>
public enum ResourceConfidence
{
    Low,
    Medium,
    High
}

/// <summary>A clue about possible resource retention or leak behavior.</summary>
public class ResourceFinding
{
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Recommendation { get; init; }
    public ResourceConfidence Confidence { get; init; }
    public Dictionary<string, object?> Evidence { get; init; } = new();
}

/// <summary>Result of a resource leak probe.</summary>
public class ResourceProbeResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public ResourceSnapshot Baseline { get; init; } = new();
    public ResourceSnapshot Final { get; init; } = new();
    public List<ResourceSnapshot> Samples { get; init; } = [];
    public List<ResourceFinding> Findings { get; init; } = [];
    /// <summary>True when comparing a saved baseline to current state (not an iteration probe).</summary>
    public bool IsComparison { get; init; }
    public bool IsLikelyLeak => Findings.Any(f => f.Confidence >= ResourceConfidence.Medium);
    public bool IsClean => Findings.Count == 0;

    public string Format()
    {
        var lines = new List<string>
        {
            IsComparison ? "=== Resource Comparison ===" : "=== Resource Leak Probe ===",
            $"URL: {Url}",
        };
        if (!IsComparison)
            lines.Add($"Iterations: {Math.Max(0, Samples.Count - 1)}");
        lines.Add("");
        lines.AddRange(new[]
        {
            "",
            IsComparison ? "BASELINE (captured before your actions)" : "BASELINE (after GC)",
            FormatSnapshotLine(Baseline),
            "",
            "FINAL (after GC)",
            FormatSnapshotLine(Final),
            "",
            "DELTA",
            FormatDeltaLine(Baseline, Final),
            ""
        });

        if (Findings.Count == 0)
        {
            lines.Add("FINDINGS: None — no significant resource growth detected.");
            lines.Add("");
            lines.Add("ASSESSMENT: CLEAN");
        }
        else
        {
            lines.Add($"FINDINGS: {Findings.Count}");
            foreach (var f in Findings.OrderByDescending(x => x.Severity))
            {
                lines.Add($"  [{f.Severity.ToString().ToUpper()}] [{f.Category}] {f.Title} (confidence: {f.Confidence.ToString().ToLower()})");
                lines.Add($"    {f.Description}");
                if (!string.IsNullOrEmpty(f.Recommendation))
                    lines.Add($"    → {f.Recommendation}");
            }
            lines.Add("");
            lines.Add(IsLikelyLeak ? "ASSESSMENT: POSSIBLE LEAK — review findings above" : "ASSESSMENT: MINOR GROWTH — may be noise or intentional caching");
        }

        return string.Join(Environment.NewLine, lines);
    }

    public static string FormatSnapshotLine(ResourceSnapshot s) =>
        $"  Heap: {FormatBytes(s.JsHeapUsedBytes)} used / {FormatBytes(s.JsHeapTotalBytes)} total | " +
        $"DOM: {s.DomNodes} nodes, {s.Documents} doc(s), {s.Frames} frame(s) | " +
        $"Listeners: {s.JsEventListeners} | WS open: {s.WebSocketsOpen}" +
        (s.LiveHtmlElements.HasValue ? $" | Live HTMLElements: {s.LiveHtmlElements}" : "");

    public static string FormatDeltaLine(ResourceSnapshot baseline, ResourceSnapshot final)
    {
        var heapDelta = final.JsHeapUsedBytes - baseline.JsHeapUsedBytes;
        var heapPct = baseline.JsHeapUsedBytes > 0
            ? heapDelta * 100.0 / baseline.JsHeapUsedBytes
            : 0;
        return $"  Heap: {FormatSignedBytes(heapDelta)} ({heapPct:+0.0;-0.0;0}%) | " +
               $"Nodes: {final.DomNodes - baseline.DomNodes:+0;-0;0} | " +
               $"Listeners: {final.JsEventListeners - baseline.JsEventListeners:+0;-0;0} | " +
               $"Documents: {final.Documents - baseline.Documents:+0;-0;0} | " +
               $"WS: {final.WebSocketsOpen - baseline.WebSocketsOpen:+0;-0;0}";
    }

    internal static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    private static string FormatSignedBytes(long bytes)
    {
        var prefix = bytes >= 0 ? "+" : "-";
        return prefix + FormatBytes(Math.Abs(bytes));
    }
}

public static class ResourceSnapshotFormatter
{
    public static string Format(ResourceSnapshot s)
    {
        var lines = new List<string>
        {
            "=== Resource Snapshot ===",
            $"URL: {s.Url}",
            $"Time: {s.Timestamp:O}",
            ResourceProbeResult.FormatSnapshotLine(s)
        };
        if (s.Flags.Count > 0)
        {
            lines.Add("");
            lines.Add("FLAGS:");
            foreach (var flag in s.Flags)
                lines.Add($"  • {flag}");
        }
        return string.Join(Environment.NewLine, lines);
    }
}
