using System.Globalization;

namespace Trowser.Performance;

/// <summary>
/// Rating for a Web Vitals metric based on Google's Core Web Vitals thresholds.
/// </summary>
public enum PerformanceRating
{
    Good,
    NeedsImprovement,
    Poor
}

/// <summary>
/// A single Web Vitals metric measurement.
/// </summary>
public class WebVitalMetric
{
    /// <summary>Short name (e.g., "LCP", "CLS", "TTFB").</summary>
    public string Name { get; init; } = "";

    /// <summary>Full name (e.g., "Largest Contentful Paint").</summary>
    public string FullName { get; init; } = "";

    /// <summary>Measured value.</summary>
    public double Value { get; init; }

    /// <summary>Unit of measurement: "ms" for timing metrics, "score" for CLS.</summary>
    public string Unit { get; init; } = "ms";

    /// <summary>Rating based on Google's thresholds.</summary>
    public PerformanceRating Rating { get; init; }

    /// <summary>For LCP: description of the element that triggered it.</summary>
    public string? Element { get; init; }

    /// <summary>
    /// False when the metric could not be measured in this window (e.g. INP with no interaction).
    /// Unavailable metrics are excluded from <see cref="PerformanceResult.IsGood"/> /
    /// <see cref="PerformanceResult.HasPoorMetrics"/> and carry no meaningful <see cref="Rating"/>.
    /// </summary>
    public bool Available { get; init; } = true;

    /// <summary>Optional note explaining an unavailable or caveated metric.</summary>
    public string? Note { get; init; }

    /// <summary>Culture-invariant value string ("1900ms", "0.116"). Avoids locale decimal commas in reports.</summary>
    public string FormatValue()
    {
        if (!Available) return "n/a";
        return Unit == "ms"
            ? Value.ToString("F0", CultureInfo.InvariantCulture) + "ms"
            : Value.ToString("F3", CultureInfo.InvariantCulture);
    }

    public override string ToString()
    {
        var formatted = Available ? FormatValue() : "n/a";
        var rating = Available ? Rating.ToString() : "Unavailable";
        return $"{Name} ({FullName}): {formatted} [{rating}]";
    }
}

/// <summary>
/// Detailed breakdown of navigation timing phases.
/// </summary>
public class NavigationTiming
{
    public double RedirectTime { get; init; }
    public double DnsTime { get; init; }
    public double TcpTime { get; init; }
    public double TlsTime { get; init; }
    public double RequestTime { get; init; }
    public double ResponseTime { get; init; }
    public double DomParsingTime { get; init; }
    public double DomContentLoadedTime { get; init; }
    public double PageLoadTime { get; init; }
    public long TransferSize { get; init; }
    public long DecodedBodySize { get; init; }
}

/// <summary>
/// Summary of a resource type (scripts, styles, images, etc.).
/// </summary>
public class ResourceTypeInfo
{
    public int Count { get; init; }
    public long TotalSize { get; init; }
}

/// <summary>
/// A slow resource identified during page load.
/// </summary>
public class SlowResource
{
    public string Url { get; init; } = "";
    public double Duration { get; init; }
    public long Size { get; init; }
    public string Type { get; init; } = "";

    public override string ToString()
    {
        var shortUrl = Url.Length > 60 ? "..." + Url[^57..] : Url;
        var dur = Duration.ToString("F0", CultureInfo.InvariantCulture);
        return $"{shortUrl} ({dur}ms, {FormatBytes(Size)}, {Type})";
    }

    internal static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{(bytes / 1024.0).ToString("F1", CultureInfo.InvariantCulture)} KB";
        return $"{(bytes / (1024.0 * 1024.0)).ToString("F1", CultureInfo.InvariantCulture)} MB";
    }
}

/// <summary>
/// Resource loading summary.
/// </summary>
public class ResourceSummary
{
    public int TotalCount { get; init; }
    public long TotalTransferSize { get; init; }
    public Dictionary<string, ResourceTypeInfo> ByType { get; init; } = new();
    public List<SlowResource> Slowest { get; init; } = new();
}

/// <summary>
/// Complete results from a performance measurement run.
/// </summary>
public class PerformanceResult
{
    /// <summary>URL of the page that was measured.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the measurement.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All collected Web Vitals metrics.</summary>
    public List<WebVitalMetric> Metrics { get; init; } = new();

    /// <summary>Navigation timing breakdown.</summary>
    public NavigationTiming Navigation { get; init; } = new();

    /// <summary>Resource loading summary.</summary>
    public ResourceSummary Resources { get; init; } = new();

    /// <summary>True if all measured Core Web Vitals are rated "Good" (unavailable metrics are ignored).</summary>
    public bool IsGood => GetCoreWebVitals().Where(m => m.Available).All(m => m.Rating == PerformanceRating.Good);

    /// <summary>True if any measured metric is rated "Poor".</summary>
    public bool HasPoorMetrics => Metrics.Any(m => m.Available && m.Rating == PerformanceRating.Poor);

    /// <summary>True if any measured metric is rated "Needs Improvement" (but none Poor).</summary>
    public bool HasMetricsNeedingImprovement =>
        !HasPoorMetrics && Metrics.Any(m => m.Available && m.Rating == PerformanceRating.NeedsImprovement);

    /// <summary>Get a specific metric by short name (e.g., "LCP", "CLS").</summary>
    public WebVitalMetric? GetMetric(string name) =>
        Metrics.FirstOrDefault(m => m.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Get only Core Web Vitals (LCP, CLS, INP).</summary>
    public List<WebVitalMetric> GetCoreWebVitals() =>
        Metrics.Where(m => m.Name is "LCP" or "CLS" or "INP").ToList();

    /// <summary>Get metrics with a specific rating.</summary>
    public List<WebVitalMetric> GetByRating(PerformanceRating rating) =>
        Metrics.Where(m => m.Rating == rating).ToList();

    /// <summary>
    /// Format a human-readable performance report.
    /// </summary>
    public string Format(bool includeNavigation = true, bool includeResources = true)
    {
        var lines = new List<string>();

        lines.Add("=== Web Vitals Performance Report (powered by web-vitals) ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        // Core Web Vitals
        var coreVitals = GetCoreWebVitals();
        if (coreVitals.Count > 0)
        {
            lines.Add("CORE WEB VITALS:");
            foreach (var m in coreVitals)
            {
                if (!m.Available)
                {
                    var note = string.IsNullOrEmpty(m.Note) ? "unavailable" : m.Note;
                    lines.Add($"  {m.Name} ({m.FullName}): n/a [UNAVAILABLE] -- {note}");
                    continue;
                }
                var formatted = m.FormatValue();
                var ratingLabel = m.Rating switch
                {
                    PerformanceRating.Good => "GOOD",
                    PerformanceRating.NeedsImprovement => "NEEDS IMPROVEMENT",
                    PerformanceRating.Poor => "POOR",
                    _ => "?"
                };
                var line = $"  {m.Name} ({m.FullName}): {formatted} [{ratingLabel}]";
                if (m.Element != null) line += $" -- {m.Element}";
                lines.Add(line);
            }
            lines.Add("");
        }

        // Other metrics
        var otherMetrics = Metrics.Where(m => m.Name is not ("LCP" or "CLS" or "INP")).ToList();
        if (otherMetrics.Count > 0)
        {
            lines.Add("OTHER METRICS:");
            foreach (var m in otherMetrics)
            {
                var formatted = m.FormatValue();
                var ratingLabel = m.Rating switch
                {
                    PerformanceRating.Good => "GOOD",
                    PerformanceRating.NeedsImprovement => "NEEDS IMPROVEMENT",
                    PerformanceRating.Poor => "POOR",
                    _ => "?"
                };
                lines.Add($"  {m.Name} ({m.FullName}): {formatted} [{ratingLabel}]");
            }
            lines.Add("");
        }

        // Navigation timing breakdown
        if (includeNavigation && Navigation.PageLoadTime > 0)
        {
            lines.Add("NAVIGATION TIMING:");
            if (Navigation.RedirectTime > 0) lines.Add($"  Redirect:            {Navigation.RedirectTime:F0}ms");
            if (Navigation.DnsTime > 0) lines.Add($"  DNS Lookup:          {Navigation.DnsTime:F0}ms");
            if (Navigation.TcpTime > 0) lines.Add($"  TCP Connection:      {Navigation.TcpTime:F0}ms");
            if (Navigation.TlsTime > 0) lines.Add($"  TLS Negotiation:     {Navigation.TlsTime:F0}ms");
            lines.Add($"  Server Request:      {Navigation.RequestTime:F0}ms");
            lines.Add($"  Server Response:     {Navigation.ResponseTime:F0}ms");
            lines.Add($"  DOM Parsing:         {Navigation.DomParsingTime:F0}ms");
            lines.Add($"  DOM Content Loaded:  {Navigation.DomContentLoadedTime:F0}ms");
            lines.Add($"  Full Page Load:      {Navigation.PageLoadTime:F0}ms");
            if (Navigation.TransferSize > 0)
                lines.Add($"  Document Size:       {SlowResource.FormatBytes(Navigation.TransferSize)} (transfer) / {SlowResource.FormatBytes(Navigation.DecodedBodySize)} (decoded)");
            lines.Add("");
        }

        // Resource summary
        if (includeResources && Resources.TotalCount > 0)
        {
            lines.Add($"RESOURCES: {Resources.TotalCount} total, {SlowResource.FormatBytes(Resources.TotalTransferSize)} transferred");
            foreach (var (type, info) in Resources.ByType.OrderByDescending(kv => kv.Value.TotalSize))
            {
                lines.Add($"  {type}: {info.Count} file(s), {SlowResource.FormatBytes(info.TotalSize)}");
            }
            lines.Add("");

            if (Resources.Slowest.Count > 0)
            {
                lines.Add("SLOWEST RESOURCES:");
                foreach (var r in Resources.Slowest)
                {
                    var shortUrl = r.Url.Length > 80 ? "..." + r.Url[^77..] : r.Url;
                    lines.Add($"  {r.Duration:F0}ms  {SlowResource.FormatBytes(r.Size)}  {shortUrl}");
                }
                lines.Add("");
            }
        }

        // Overall assessment (only measured metrics count toward the verdict)
        if (coreVitals.Count > 0)
        {
            var measured = coreVitals.Where(m => m.Available).ToList();
            var unavailable = coreVitals.Where(m => !m.Available).Select(m => m.Name).ToList();
            var poorCount = measured.Count(m => m.Rating == PerformanceRating.Poor);
            var needsWorkCount = measured.Count(m => m.Rating == PerformanceRating.NeedsImprovement);
            var suffix = unavailable.Count > 0 ? $" ({string.Join("/", unavailable)} not measured)" : "";

            if (poorCount > 0)
                lines.Add($"ASSESSMENT: {poorCount} Core Web Vital(s) rated POOR -- significant performance issues detected.{suffix}");
            else if (needsWorkCount > 0)
                lines.Add($"ASSESSMENT: {needsWorkCount} Core Web Vital(s) NEED IMPROVEMENT.{suffix}");
            else if (measured.Count > 0)
                lines.Add($"ASSESSMENT: All measured Core Web Vitals are GOOD.{suffix}");
            else
                lines.Add("ASSESSMENT: No Core Web Vitals could be measured in this window.");
        }

        lines.Add("=====================================");
        return string.Join(Environment.NewLine, lines);
    }
}
