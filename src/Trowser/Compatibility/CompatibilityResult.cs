using Trowser.Security;

namespace Trowser.Compatibility;

/// <summary>
/// A modern JavaScript feature detected in the page's scripts.
/// </summary>
public class DetectedFeature
{
    /// <summary>Human-readable name (e.g., "Optional chaining (?.)"). </summary>
    public string Name { get; init; } = "";

    /// <summary>Whether this is a syntax feature (causes parse error) or an API (runtime error).</summary>
    public FeatureCategory Category { get; init; }

    /// <summary>Minimum Safari version required.</summary>
    public string SafariMin { get; init; } = "";

    /// <summary>Minimum Chrome version required.</summary>
    public string ChromeMin { get; init; } = "";

    /// <summary>Minimum Firefox version required.</summary>
    public string FirefoxMin { get; init; } = "";

    /// <summary>Number of times this feature was found across all scripts.</summary>
    public int Occurrences { get; init; }

    /// <summary>Script URLs or labels where this feature was detected (up to 3).</summary>
    public List<string> FoundIn { get; init; } = new();

    /// <summary>MDN reference URL.</summary>
    public string? MdnUrl { get; init; }

    /// <summary>Which target browsers cannot run this feature.</summary>
    public List<string> IncompatibleWith { get; init; } = new();

    public override string ToString() =>
        $"{Name} (Chrome {ChromeMin}+, Safari {SafariMin}+) — {Occurrences} occurrence(s)";
}

/// <summary>
/// Whether a feature is syntax-level (causes parse errors) or API-level (runtime errors).
/// </summary>
public enum FeatureCategory
{
    /// <summary>Syntax features cause the entire script to fail to parse.</summary>
    Syntax,

    /// <summary>API features cause runtime errors only when the code path executes.</summary>
    Api
}

/// <summary>
/// A target browser that may have compatibility issues.
/// </summary>
public class TargetBrowser
{
    /// <summary>Display name (e.g., "iOS 15 (Safari 15.0)").</summary>
    public string Name { get; init; } = "";

    /// <summary>Browser engine name for matching (e.g., "safari", "chrome").</summary>
    public string Engine { get; init; } = "";

    /// <summary>Engine version number.</summary>
    public string Version { get; init; } = "";

    /// <summary>Features that this browser does NOT support.</summary>
    public List<DetectedFeature> UnsupportedFeatures { get; init; } = new();

    /// <summary>Risk level based on the number and category of unsupported features.</summary>
    public Severity RiskLevel { get; init; }

    public override string ToString() =>
        $"{Name}: {UnsupportedFeatures.Count} unsupported feature(s) [{RiskLevel}]";
}

/// <summary>
/// Complete results from a backward compatibility scan.
/// </summary>
public class CompatibilityResult
{
    /// <summary>URL of the page that was scanned.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the scan.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Number of scripts analyzed (inline + external).</summary>
    public int ScriptsAnalyzed { get; init; }

    /// <summary>Total bytes of JavaScript analyzed.</summary>
    public long TotalBytesAnalyzed { get; init; }

    /// <summary>Scripts that could not be fetched (CORS, etc.).</summary>
    public List<string> SkippedScripts { get; init; } = new();

    /// <summary>All modern features detected in the scripts.</summary>
    public List<DetectedFeature> Features { get; init; } = new();

    /// <summary>Target browsers with compatibility assessment.</summary>
    public List<TargetBrowser> Targets { get; init; } = new();

    /// <summary>Overall minimum Chrome version required by detected features.</summary>
    public string MinChromeRequired { get; init; } = "";

    /// <summary>Overall minimum Safari version required by detected features.</summary>
    public string MinSafariRequired { get; init; } = "";

    /// <summary>True if no compatibility risks were found for any target browser.</summary>
    public bool IsCompatible => Targets.All(t => t.UnsupportedFeatures.Count == 0);

    /// <summary>Number of features that cause issues for at least one target browser.</summary>
    public int IncompatibleFeatureCount =>
        Features.Count(f => f.IncompatibleWith.Count > 0);

    /// <summary>Highest risk level across all target browsers.</summary>
    public Severity HighestRisk =>
        Targets.Count > 0 ? Targets.Max(t => t.RiskLevel) : Severity.Low;

    /// <summary>Get features filtered by category.</summary>
    public List<DetectedFeature> GetSyntaxFeatures() =>
        Features.Where(f => f.Category == FeatureCategory.Syntax).ToList();

    /// <summary>Get features filtered by category.</summary>
    public List<DetectedFeature> GetApiFeatures() =>
        Features.Where(f => f.Category == FeatureCategory.Api).ToList();

    /// <summary>
    /// Format a human-readable compatibility report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Backward Compatibility Analysis ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add($"Scripts analyzed: {ScriptsAnalyzed} ({FormatBytes(TotalBytesAnalyzed)})");
        if (SkippedScripts.Count > 0)
            lines.Add($"Scripts skipped (CORS): {SkippedScripts.Count}");
        lines.Add("");

        if (Features.Count == 0)
        {
            lines.Add("No modern JavaScript features detected that would cause compatibility issues.");
            lines.Add("============================================");
            return string.Join(Environment.NewLine, lines);
        }

        var syntaxFeatures = Features.Where(f => f.Category == FeatureCategory.Syntax).ToList();
        var apiFeatures = Features.Where(f => f.Category == FeatureCategory.Api).ToList();

        lines.Add($"MODERN FEATURES DETECTED: {Features.Count}");
        if (syntaxFeatures.Count > 0)
            lines.Add($"  Syntax features: {syntaxFeatures.Count} (cause parse errors in old browsers)");
        if (apiFeatures.Count > 0)
            lines.Add($"  API features:    {apiFeatures.Count} (cause runtime errors when called)");
        lines.Add($"  Minimum Chrome: {MinChromeRequired}+");
        lines.Add($"  Minimum Safari: {MinSafariRequired}+");
        lines.Add("");

        // Target browser assessment
        lines.Add("TARGET BROWSER COMPATIBILITY:");
        foreach (var target in Targets)
        {
            if (target.UnsupportedFeatures.Count == 0)
            {
                lines.Add($"  {target.Name} — COMPATIBLE");
            }
            else
            {
                var syntaxCount = target.UnsupportedFeatures.Count(f => f.Category == FeatureCategory.Syntax);
                var apiCount = target.UnsupportedFeatures.Count(f => f.Category == FeatureCategory.Api);
                var riskLabel = target.RiskLevel.ToString().ToUpper();
                lines.Add($"  {target.Name} — [{riskLabel} RISK] {target.UnsupportedFeatures.Count} unsupported feature(s)" +
                    (syntaxCount > 0 ? $" ({syntaxCount} syntax)" : ""));
            }
        }
        lines.Add("");

        if (includeDetails)
        {
            var riskyTargets = Targets.Where(t => t.UnsupportedFeatures.Count > 0)
                .OrderByDescending(t => t.RiskLevel).ToList();

            foreach (var target in riskyTargets)
            {
                var riskLabel = target.RiskLevel.ToString().ToUpper();
                lines.Add($"--- [{riskLabel}] {target.Name} ---");

                var grouped = target.UnsupportedFeatures
                    .OrderByDescending(f => f.Category == FeatureCategory.Syntax)
                    .ThenBy(f => f.Name)
                    .ToList();

                foreach (var f in grouped)
                {
                    var catLabel = f.Category == FeatureCategory.Syntax ? "SYNTAX" : "API";
                    lines.Add($"  [{catLabel}] {f.Name}");
                    lines.Add($"    Requires: Chrome {f.ChromeMin}+, Safari {f.SafariMin}+, Firefox {f.FirefoxMin}+");
                    lines.Add($"    Found: {f.Occurrences} time(s) in {string.Join(", ", f.FoundIn.Take(3))}");
                    if (f.MdnUrl != null)
                        lines.Add($"    MDN: {f.MdnUrl}");
                }
                lines.Add("");
            }
        }

        // Assessment and recommendation
        var atRisk = Targets.Where(t => t.UnsupportedFeatures.Count > 0).ToList();
        if (atRisk.Count == 0)
        {
            lines.Add("ASSESSMENT: All target browsers should be compatible with this site's JavaScript, but there could of course be other problems.");
        }
        else
        {
            var hasSyntaxRisk = atRisk.Any(t => t.UnsupportedFeatures.Any(f => f.Category == FeatureCategory.Syntax));
            var browserNames = string.Join(" and ", atRisk.Select(t => t.Name));

            if (hasSyntaxRisk)
            {
                lines.Add($"ASSESSMENT: It is a risk that this site won't work on {browserNames}.");
                lines.Add("Syntax-level incompatibilities were found — these cause the entire script to fail to load,");
                lines.Add("meaning the site will likely be broken or non-functional.");
                lines.Add($"RECOMMENDATION: Test with BrowserStack or a physical device running {browserNames}. Note that the browser version is the vanilla one when OS was launched, so most users have newer versions.");
            }
            else
            {
                lines.Add($"ASSESSMENT: There is a moderate risk of issues on {browserNames}.");
                lines.Add("API-level incompatibilities were found — these cause errors only if specific code paths are executed by the software.");
                lines.Add($"RECOMMENDATION: Test key user flows with BrowserStack or a physical device running {browserNames}. Note that the browser version is the vanilla one when OS was launched, so most users have newer versions.");
            }
        }

        lines.Add("============================================");
        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }
}
