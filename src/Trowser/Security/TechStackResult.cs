using System.Text;

namespace Trowser.Security;

public record TechStackDetection
{
    public string Name { get; init; } = "";
    public string? Version { get; init; }
    public string Category { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Source { get; init; } = "";
    public double Confidence { get; init; }
}

public class TechStackResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public long ElapsedMs { get; init; }
    public List<TechStackDetection> Detections { get; init; } = [];

    public int DetectionCount => Detections.Count;
    public List<string> Categories => Detections.Select(d => d.Category).Distinct().OrderBy(c => c).ToList();

    public List<TechStackDetection> Frameworks => Detections.Where(d => d.Category is "framework" or "language" or "js-framework").ToList();
    public List<TechStackDetection> Servers => Detections.Where(d => d.Category is "server" or "cdn").ToList();
    public List<TechStackDetection> JsLibraries => Detections.Where(d => d.Category == "js-library").ToList();
    public List<TechStackDetection> Waf => Detections.Where(d => d.Category == "waf").ToList();
    public List<TechStackDetection> Cdn => Detections.Where(d => d.Category == "cdn").ToList();
    public List<TechStackDetection> CacheDetections => Detections.Where(d => d.Category == "cache").ToList();

    /// <summary>Whether this document was served through a cache (HIT/MISS/DYNAMIC/no-store), independent of CDN vendor labels.</summary>
    public CacheIdentifySummary Cache { get; init; } = new();

    public List<TechStackDetection> GetByCategory(string category) =>
        Detections.Where(d => d.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

    public string Format(bool includeDetails = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Tech Stack Detection ===");
        sb.AppendLine($"URL: {Url}");
        sb.AppendLine($"Scan time: {ElapsedMs}ms");
        sb.AppendLine();

        if (Detections.Count == 0)
        {
            sb.AppendLine("No technologies detected.");
            sb.AppendLine();
            AppendCacheSection(sb, includeDetails);
            sb.AppendLine("=============================");
            return sb.ToString();
        }

        sb.AppendLine($"DETECTED: {Detections.Count} technolog{(Detections.Count == 1 ? "y" : "ies")} across {Categories.Count} categor{(Categories.Count == 1 ? "y" : "ies")}");
        sb.AppendLine();

        var grouped = Detections
            .GroupBy(d => d.Category)
            .OrderBy(g => CategoryOrder(g.Key));

        foreach (var group in grouped)
        {
            sb.AppendLine($"{CategoryLabel(group.Key).ToUpperInvariant()}:");
            foreach (var d in group.OrderByDescending(d => d.Confidence))
            {
                var ver = d.Version != null ? $" {d.Version}" : "";
                var conf = d.Confidence >= 0.9 ? "high" : d.Confidence >= 0.6 ? "medium" : "low";
                sb.AppendLine($"  {d.Name}{ver} (confidence: {conf})");
                if (includeDetails)
                    sb.AppendLine($"    Evidence: {d.Evidence} [source: {d.Source}]");
            }
            sb.AppendLine();
        }

        var wafList = Waf;
        if (wafList.Count > 0)
        {
            sb.AppendLine("SECURITY NOTE: WAF/CDN detected — fuzz payloads may be filtered by " +
                          string.Join(", ", wafList.Select(w => w.Name)) + ".");
            sb.AppendLine();
        }

        AppendCacheSection(sb, includeDetails);
        sb.AppendLine("=============================");
        return sb.ToString();
    }

    private void AppendCacheSection(StringBuilder sb, bool includeDetails)
    {
        sb.AppendLine("CACHE:");
        if (Cache.Detected)
        {
            sb.AppendLine($"  Detected: yes (status={Cache.DocumentStatus}, cacheable={Cache.Cacheable})");
            if (Cache.Vendors.Count > 0)
                sb.AppendLine($"  Vendors: {string.Join(", ", Cache.Vendors)}");
            if (Cache.Vary.Count > 0)
                sb.AppendLine($"  Vary: {string.Join(", ", Cache.Vary)}");
            if (includeDetails && Cache.Evidence.Count > 0)
                sb.AppendLine($"  Evidence: {CacheHeaderAnalyzer.FormatEvidence(Cache)}");
            sb.AppendLine("  Next: POST /api/security/cache-map then POST /api/security/cache-pollution-scan (live-key; safetyMode active).");
        }
        else
        {
            sb.AppendLine("  Detected: no");
        }

        sb.AppendLine();
    }

    private static int CategoryOrder(string cat) => cat switch
    {
        "waf" => 0,
        "cdn" => 1,
        "cache" => 2,
        "server" => 3,
        "language" => 4,
        "framework" => 5,
        "js-library" => 6,
        "js-framework" => 7,
        "cms" => 8,
        "analytics" => 9,
        "ci-cd" => 10,
        _ => 99
    };

    private static string CategoryLabel(string cat) => cat switch
    {
        "waf" => "WAF / Security",
        "cdn" => "CDN / Hosting",
        "cache" => "Cache",
        "server" => "Web Server",
        "language" => "Language / Runtime",
        "framework" => "Framework",
        "js-library" => "JavaScript Libraries",
        "js-framework" => "JavaScript Framework",
        "cms" => "CMS / Platform",
        "analytics" => "Analytics / Tracking",
        "ci-cd" => "CI/CD / DevOps",
        _ => cat
    };
}
