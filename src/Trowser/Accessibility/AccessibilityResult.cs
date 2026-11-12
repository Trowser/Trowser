namespace Trowser.Accessibility;

/// <summary>
/// Impact severity of an accessibility violation.
/// </summary>
public enum Impact
{
    Minor,
    Moderate,
    Serious,
    Critical
}

/// <summary>
/// An element node affected by a violation.
/// </summary>
public class AccessibilityNode
{
    /// <summary>HTML snippet of the affected element.</summary>
    public string Html { get; init; } = "";

    /// <summary>CSS selectors targeting the element.</summary>
    public List<string> Target { get; init; } = new();

    /// <summary>Description of what needs to be fixed.</summary>
    public string FailureSummary { get; init; } = "";

    public override string ToString()
    {
        var selector = Target.Count > 0 ? Target[0] : "(unknown)";
        return $"{selector}: {FailureSummary}";
    }
}

/// <summary>
/// A single accessibility rule violation found by axe-core.
/// </summary>
public class AccessibilityViolation
{
    /// <summary>Rule ID (e.g., "color-contrast", "image-alt").</summary>
    public string RuleId { get; init; } = "";

    /// <summary>Impact severity: minor, moderate, serious, or critical.</summary>
    public Impact Impact { get; init; }

    /// <summary>Short description of the rule.</summary>
    public string Description { get; init; } = "";

    /// <summary>Help text explaining how to fix.</summary>
    public string Help { get; init; } = "";

    /// <summary>URL to detailed documentation.</summary>
    public string HelpUrl { get; init; } = "";

    /// <summary>WCAG tags (e.g., "wcag2a", "wcag2aa", "wcag143").</summary>
    public List<string> Tags { get; init; } = new();

    /// <summary>Elements affected by this violation.</summary>
    public List<AccessibilityNode> Nodes { get; init; } = new();

    /// <summary>Number of affected elements.</summary>
    public int Count => Nodes.Count;

    /// <summary>WCAG level derived from tags (A, AA, AAA, or unknown).</summary>
    public string WcagLevel
    {
        get
        {
            if (Tags.Any(t => t.StartsWith("wcag2aaa") || t == "wcag2aaa")) return "AAA";
            if (Tags.Any(t => t.StartsWith("wcag2aa") || t == "wcag2aa")) return "AA";
            if (Tags.Any(t => t.StartsWith("wcag2a") || t == "wcag2a" || t.StartsWith("wcag21a"))) return "A";
            return "?";
        }
    }

    /// <summary>WCAG criteria IDs found in tags (e.g., "1.4.3", "2.4.1").</summary>
    public List<string> WcagCriteria
    {
        get
        {
            var criteria = new List<string>();
            foreach (var tag in Tags)
            {
                // Tags like "wcag143" mean WCAG 1.4.3
                if (tag.StartsWith("wcag") && tag.Length >= 7)
                {
                    var digits = tag[4..];
                    if (digits.All(char.IsDigit) && digits.Length >= 3)
                    {
                        criteria.Add($"{digits[0]}.{digits[1]}.{digits[2..]}");
                    }
                }
            }
            return criteria;
        }
    }

    public override string ToString()
    {
        return $"[{Impact.ToString().ToUpper()}] {RuleId}: {Help} ({Count} element(s))";
    }
}

/// <summary>
/// Complete results from an accessibility audit run.
/// </summary>
public class AccessibilityResult
{
    /// <summary>URL of the page that was tested.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the audit.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Rules that found violations.</summary>
    public List<AccessibilityViolation> Violations { get; init; } = new();

    /// <summary>Rules that passed.</summary>
    public List<AccessibilityPass> Passes { get; init; } = new();

    /// <summary>Rules that could not be fully checked (manual review needed).</summary>
    public List<AccessibilityIncomplete> Incomplete { get; init; } = new();

    /// <summary>Total number of violations found.</summary>
    public int ViolationCount => Violations.Count;

    /// <summary>Total number of elements with violations.</summary>
    public int AffectedElementCount => Violations.Sum(v => v.Count);

    /// <summary>Total number of rules that passed.</summary>
    public int PassCount => Passes.Count;

    /// <summary>True if no violations were found.</summary>
    public bool IsClean => Violations.Count == 0;

    /// <summary>Get violations filtered by minimum impact level.</summary>
    public List<AccessibilityViolation> GetByMinImpact(Impact minImpact)
    {
        return Violations.Where(v => v.Impact >= minImpact).ToList();
    }

    /// <summary>Get violations for a specific WCAG level (A, AA, AAA).</summary>
    public List<AccessibilityViolation> GetByWcagLevel(string level)
    {
        return Violations.Where(v =>
            v.Tags.Any(t => t.Contains($"wcag2{level.ToLowerInvariant()}"))).ToList();
    }

    /// <summary>Get only critical and serious violations.</summary>
    public List<AccessibilityViolation> GetCritical()
    {
        return Violations.Where(v => v.Impact >= Impact.Serious).ToList();
    }

    /// <summary>
    /// Format a detailed report of the accessibility audit.
    /// </summary>
    public string Format(bool includeNodes = true, Impact? minImpact = null)
    {
        var lines = new List<string>();

        lines.Add("=== WCAG Accessibility Report (powered by axe-core) ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        var violations = minImpact.HasValue
            ? Violations.Where(v => v.Impact >= minImpact.Value).ToList()
            : Violations;

        if (violations.Count == 0)
        {
            lines.Add("No violations found! The page passes automated accessibility checks.");
            lines.Add("");
            lines.Add($"Rules passed: {PassCount}");
            if (Incomplete.Count > 0)
                lines.Add($"Rules needing manual review: {Incomplete.Count}");
        }
        else
        {
            // Summary by impact
            var critical = violations.Count(v => v.Impact == Impact.Critical);
            var serious = violations.Count(v => v.Impact == Impact.Serious);
            var moderate = violations.Count(v => v.Impact == Impact.Moderate);
            var minor = violations.Count(v => v.Impact == Impact.Minor);

            lines.Add($"VIOLATIONS: {violations.Count} rule(s) failed, affecting {violations.Sum(v => v.Count)} element(s)");
            lines.Add("");

            if (critical > 0) lines.Add($"  CRITICAL: {critical}");
            if (serious > 0) lines.Add($"  SERIOUS:  {serious}");
            if (moderate > 0) lines.Add($"  MODERATE: {moderate}");
            if (minor > 0) lines.Add($"  MINOR:    {minor}");
            lines.Add("");

            // Detail each violation
            var sortedViolations = violations
                .OrderByDescending(v => v.Impact)
                .ThenBy(v => v.RuleId)
                .ToList();

            for (var i = 0; i < sortedViolations.Count; i++)
            {
                var v = sortedViolations[i];
                var impactLabel = v.Impact.ToString().ToUpper();
                var wcagInfo = v.WcagCriteria.Count > 0
                    ? $" (WCAG {string.Join(", ", v.WcagCriteria)})"
                    : "";

                lines.Add($"--- [{impactLabel}] {v.RuleId}{wcagInfo} ---");
                lines.Add($"  {v.Help}");
                lines.Add($"  {v.Description}");
                lines.Add($"  Elements affected: {v.Count}");
                lines.Add($"  More info: {v.HelpUrl}");

                if (includeNodes && v.Nodes.Count > 0)
                {
                    lines.Add("  Affected elements:");
                    foreach (var node in v.Nodes.Take(5))
                    {
                        var selector = node.Target.Count > 0 ? node.Target[0] : "?";
                        lines.Add($"    - {selector}");
                        if (!string.IsNullOrEmpty(node.Html))
                        {
                            var html = node.Html.Length > 100 ? node.Html[..97] + "..." : node.Html;
                            lines.Add($"      {html}");
                        }
                    }
                    if (v.Nodes.Count > 5)
                    {
                        lines.Add($"    ... and {v.Nodes.Count - 5} more");
                    }
                }

                lines.Add("");
            }

            lines.Add($"Rules passed: {PassCount}");
            if (Incomplete.Count > 0)
                lines.Add($"Rules needing manual review: {Incomplete.Count}");
        }

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// A rule that passed during the accessibility audit.
/// </summary>
public class AccessibilityPass
{
    public string RuleId { get; init; } = "";
    public string Description { get; init; } = "";
    public string Help { get; init; } = "";
    public List<string> Tags { get; init; } = new();
    public int NodeCount { get; init; }
}

/// <summary>
/// A rule that could not be fully evaluated (needs manual review).
/// </summary>
public class AccessibilityIncomplete
{
    public string RuleId { get; init; } = "";
    public string Description { get; init; } = "";
    public string Help { get; init; } = "";
    public List<string> Tags { get; init; } = new();
    public int NodeCount { get; init; }
}
