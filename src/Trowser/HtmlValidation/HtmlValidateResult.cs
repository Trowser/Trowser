namespace Trowser.HtmlValidation;

/// <summary>
/// Severity of an HTML validation message.
/// </summary>
public enum HtmlSeverity
{
    Warning = 1,
    Error = 2
}

/// <summary>
/// A single validation message from html-validate.
/// </summary>
public class HtmlValidateMessage
{
    /// <summary>Rule that triggered this message (e.g., "wcag/h37", "element-required-attributes").</summary>
    public string RuleId { get; init; } = "";

    /// <summary>Error or Warning.</summary>
    public HtmlSeverity Severity { get; init; }

    /// <summary>Human-readable description of the issue.</summary>
    public string Message { get; init; } = "";

    /// <summary>Line number in the HTML source (1-based).</summary>
    public int Line { get; init; }

    /// <summary>Column number in the HTML source (1-based).</summary>
    public int Column { get; init; }

    /// <summary>Byte offset in source.</summary>
    public int Offset { get; init; }

    /// <summary>End position size (length of the offending token).</summary>
    public int Size { get; init; }

    /// <summary>Optional URL to rule documentation.</summary>
    public string? RuleUrl { get; init; }

    /// <summary>Category inferred from the rule ID.</summary>
    public string Category => RuleId switch
    {
        _ when RuleId.StartsWith("wcag/") => "Accessibility",
        "area-alt" or "aria-hidden-body" or "aria-label-misuse" or
        "empty-heading" or "empty-title" or "hidden-focusable" or
        "input-missing-label" or "meta-refresh" or "multiple-labeled-controls" or
        "no-abstract-role" or "no-autoplay" or "no-implicit-button-type" or
        "no-redundant-aria-label" or "no-redundant-role" or "prefer-native-element" or
        "svg-focusable" or "tel-non-breaking" or "text-content" or
        "unique-landmark" => "Accessibility",

        "deprecated" or "deprecated-class" or "deprecated-rule" or
        "no-conditional-comment" or "no-deprecated-attr" => "Deprecated",

        "autocomplete-password" or "require-csp-nonce" or "require-sri" => "Security",

        "element-permitted-content" or "element-permitted-occurrences" or
        "element-permitted-order" or "element-permitted-parent" or
        "element-required-ancestor" or "element-required-attributes" or
        "element-required-content" or "input-attributes" or
        "no-multiple-main" or "script-element" or "void-content" or
        "attribute-allowed-values" or "attribute-misuse" => "Content Model",

        "doctype-html" or "heading-level" or "missing-doctype" or
        "no-dup-id" or "no-missing-references" or "no-utf8-bom" or
        "valid-for" => "Document",

        "close-order" or "element-name" or "no-dup-attr" or "no-dup-class" or
        "no-raw-characters" or "unrecognized-char-ref" or "valid-autocomplete" or
        "valid-id" or "attr-delimiter" or "attr-spacing" or "close-attr" or
        "form-dup-name" or "map-dup-name" or "map-id-name" or "script-type" or
        "no-redundant-for" => "HTML Syntax",

        _ => "Style"
    };

    public override string ToString() =>
        $"[{(Severity == HtmlSeverity.Error ? "ERROR" : "WARN")}] line {Line}:{Column} {Message} ({RuleId})";
}

/// <summary>
/// Results from an html-validate analysis.
/// </summary>
public class HtmlValidateResult
{
    /// <summary>URL that was validated.</summary>
    public string Url { get; init; } = "";

    /// <summary>Timestamp of the validation.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>All validation messages.</summary>
    public List<HtmlValidateMessage> Messages { get; init; } = new();

    /// <summary>Number of errors.</summary>
    public int ErrorCount => Messages.Count(m => m.Severity == HtmlSeverity.Error);

    /// <summary>Number of warnings.</summary>
    public int WarningCount => Messages.Count(m => m.Severity == HtmlSeverity.Warning);

    /// <summary>True if no errors (warnings are acceptable).</summary>
    public bool IsValid => ErrorCount == 0;

    /// <summary>Total message count.</summary>
    public int TotalCount => Messages.Count;

    /// <summary>Get messages filtered by severity.</summary>
    public List<HtmlValidateMessage> GetErrors() =>
        Messages.Where(m => m.Severity == HtmlSeverity.Error).ToList();

    /// <summary>Get messages filtered by category.</summary>
    public List<HtmlValidateMessage> GetByCategory(string category) =>
        Messages.Where(m => m.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>Get messages filtered by rule ID.</summary>
    public List<HtmlValidateMessage> GetByRule(string ruleId) =>
        Messages.Where(m => m.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>
    /// Format a human-readable validation report.
    /// </summary>
    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== HTML Validation Report (powered by html-validate) ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (Messages.Count == 0)
        {
            lines.Add("No HTML validation issues found. The markup is valid.");
            lines.Add("=================================");
            return string.Join(Environment.NewLine, lines);
        }

        lines.Add($"RESULTS: {ErrorCount} error(s), {WarningCount} warning(s)");
        lines.Add("");

        if (includeDetails)
        {
            var grouped = Messages
                .GroupBy(m => m.Category)
                .OrderByDescending(g => g.Max(m => (int)m.Severity))
                .ThenBy(g => g.Key);

            foreach (var group in grouped)
            {
                var errors = group.Count(m => m.Severity == HtmlSeverity.Error);
                var warnings = group.Count(m => m.Severity == HtmlSeverity.Warning);
                var countLabel = errors > 0 && warnings > 0
                    ? $"{errors} error(s), {warnings} warning(s)"
                    : errors > 0 ? $"{errors} error(s)" : $"{warnings} warning(s)";

                lines.Add($"--- {group.Key} ({countLabel}) ---");

                foreach (var msg in group.OrderByDescending(m => m.Severity).ThenBy(m => m.Line))
                {
                    var sevLabel = msg.Severity == HtmlSeverity.Error ? "ERROR" : "WARN";
                    var truncMsg = msg.Message.Length > 120
                        ? msg.Message[..117] + "..."
                        : msg.Message;
                    lines.Add($"  [{sevLabel}] line {msg.Line}:{msg.Column} {truncMsg} ({msg.RuleId})");
                }

                lines.Add("");
            }
        }

        if (ErrorCount > 0)
            lines.Add($"ASSESSMENT: {ErrorCount} error(s) found -- HTML markup has issues that should be fixed.");
        else
            lines.Add($"ASSESSMENT: {WarningCount} warning(s) only. Markup is acceptable but could be improved.");

        lines.Add("=================================");
        return string.Join(Environment.NewLine, lines);
    }
}
