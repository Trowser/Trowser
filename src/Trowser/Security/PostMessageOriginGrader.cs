using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>Static origin-check grading for postMessage handlers (shared with client-surface).</summary>
public static class PostMessageOriginGrader
{
    public sealed class OriginGrade
    {
        public string Grade { get; init; } = "unknown";
        public string? CheckKind { get; init; }
        public List<string> Literals { get; init; } = [];
        public bool SourceTruncated { get; init; }
    }

    private static readonly Regex OriginPropertyRef = new(
        @"\b(?:event|e|msg|message)\.origin\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex StrictLiteral = new(
        @"\b(?:event|e|msg|message)\.origin\s*(!==?|===?)\s*['""](https?://[^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Compare message origin to location.origin or a runtime variable (not a string literal).</summary>
    private static readonly Regex RuntimeOriginCompare = new(
        @"\b(?:event|e|msg|message)\.origin\s*(===|!==|==|!=)\s*(?!['""])(?:window\.)?(?:location\.origin|[a-zA-Z_$][\w$]*(?:\.origin)?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex WeakOnOrigin = new(
        @"\b(?:event|e|msg|message)\.origin\s*\.\s*(indexOf|includes|startsWith|endsWith|match)\s*\(",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AllowlistIncludes = new(
        @"(?:allowlist|allowed|trusted|whitelist|origins)\s*\.\s*(includes|indexOf)\s*\(\s*(?:event|e|msg|message)\.origin",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DelegatedOriginFn = new(
        @"\b(?:isTrusted|trustOrigin|checkOrigin|validateOrigin|verifyOrigin|allowedOrigin|isAllowedOrigin|isValidOrigin)\s*\(\s*(?:event|e|msg|message)\.origin",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HostnameOnlyOriginGate = new(
        @"(?:\bhostname\b\s*(===|!==|==|!=)|\.\s*hostname\s*(===|!==|==|!=)|new\s+URL\s*\([^)]*(?:event|e|msg|message)\.origin)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MessageSourceGate = new(
        @"(\(\s*\{[^}]*\bsource\b|\b(?:event|e|msg|message)\.source\b)[^;]{0,120}(===|!==|==|!=)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DataOnlyGate = new(
        @"(\(\s*\{[^}]*\bdata\b|\b(?:event|e|msg|message)\.data\b)[^;]{0,120}(===|!==|==|!=)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>e.data.type / e.data.field comparisons without an origin check (schema-gated handlers).</summary>
    private static readonly Regex DataPropertyGate = new(
        @"\b(?:event|e|msg|message)\.data\.[a-zA-Z_$][\w$]*\s*(===|!==|==|!=)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string GradeOriginCheck(string? handlerSource) => Analyze(handlerSource).Grade;

    public static OriginGrade Analyze(string? handlerSource)
    {
        if (string.IsNullOrWhiteSpace(handlerSource))
            return new OriginGrade { Grade = "unknown" };

        var (window, truncated) = ExtractOriginWindow(handlerSource);

        if (MessageSourceGate.IsMatch(window))
        {
            return new OriginGrade
            {
                Grade = "strict",
                CheckKind = "message-source-ref",
                SourceTruncated = truncated
            };
        }

        if (!OriginUsedInValidation(window))
        {
            if (DataOnlyGate.IsMatch(window) || DataPropertyGate.IsMatch(window))
            {
                return new OriginGrade
                {
                    Grade = "none",
                    CheckKind = "data-gate-only",
                    SourceTruncated = truncated
                };
            }

            if (OriginPropertyRef.IsMatch(window))
            {
                return new OriginGrade
                {
                    Grade = "none",
                    CheckKind = "origin-referenced-not-validated",
                    SourceTruncated = truncated
                };
            }

            if (LooksOpaqueMinified(window))
            {
                return new OriginGrade
                {
                    Grade = "unknown",
                    CheckKind = "opaque-minified",
                    SourceTruncated = truncated
                };
            }

            return new OriginGrade { Grade = "none", SourceTruncated = truncated };
        }

        if (DelegatedOriginFn.IsMatch(window))
        {
            return new OriginGrade
            {
                Grade = "weak",
                CheckKind = "delegated-origin-fn",
                Literals = ExtractStringLiterals(window),
                SourceTruncated = truncated
            };
        }

        if (HostnameOnlyOriginGate.IsMatch(window)
            && !StrictLiteral.IsMatch(window)
            && !RuntimeOriginCompare.IsMatch(window))
        {
            return new OriginGrade
            {
                Grade = "weak",
                CheckKind = "hostname-only",
                Literals = ExtractStringLiterals(window),
                SourceTruncated = truncated
            };
        }

        if (WeakOnOrigin.IsMatch(window)
            || window.Contains("origin.indexOf", StringComparison.OrdinalIgnoreCase)
            || Regex.IsMatch(window, @"origin\s*\.\s*match\s*\(", RegexOptions.IgnoreCase)
            || Regex.IsMatch(window, @"new\s+RegExp\s*\(", RegexOptions.IgnoreCase))
        {
            return new OriginGrade
            {
                Grade = "weak",
                CheckKind = "substring-or-regex",
                Literals = ExtractStringLiterals(window),
                SourceTruncated = truncated
            };
        }

        if (AllowlistIncludes.IsMatch(window))
        {
            return new OriginGrade
            {
                Grade = "strict",
                CheckKind = "allowlist-includes",
                Literals = ExtractStringLiterals(window),
                SourceTruncated = truncated
            };
        }

        var strictMatch = StrictLiteral.Match(window);
        if (strictMatch.Success)
        {
            return new OriginGrade
            {
                Grade = "strict",
                CheckKind = "literal-origin-compare",
                Literals = [strictMatch.Groups[2].Value],
                SourceTruncated = truncated
            };
        }

        if ((RuntimeOriginCompare.IsMatch(window)
             || Regex.IsMatch(window,
                 @"(?:window\.)?location\.origin\s*(===|!==|==|!=)\s*\b(?:event|e|msg|message)\.origin\b",
                 RegexOptions.IgnoreCase))
            && !HostnameOnlyOriginGate.IsMatch(window))
        {
            return new OriginGrade
            {
                Grade = "strict",
                CheckKind = "runtime-origin-compare",
                SourceTruncated = truncated
            };
        }

        return new OriginGrade
        {
            Grade = "weak",
            CheckKind = "origin-validation-unclassified",
            Literals = ExtractStringLiterals(window),
            SourceTruncated = truncated
        };
    }

    /// <summary>True when <c>event.origin</c> appears in a comparison or allow-list gate, not merely logged or forwarded.</summary>
    private static bool OriginUsedInValidation(string window)
    {
        if (WeakOnOrigin.IsMatch(window)
            || StrictLiteral.IsMatch(window)
            || RuntimeOriginCompare.IsMatch(window)
            || AllowlistIncludes.IsMatch(window))
            return true;

        if (Regex.IsMatch(window,
                @"(?:window\.)?location\.origin\s*(===|!==|==|!=)\s*\b(?:event|e|msg|message)\.origin\b",
                RegexOptions.IgnoreCase))
            return true;

        if (Regex.IsMatch(window,
                @"\b(?:event|e|msg|message)\.origin\b\s*(===|!==|==|!=)",
                RegexOptions.IgnoreCase))
            return true;

        if (Regex.IsMatch(window,
                @"\b(?:if\s*\(|&&|\|\|)[^;]{0,240}\b(?:event|e|msg|message)\.origin\b",
                RegexOptions.IgnoreCase))
            return true;

        return false;
    }

    public static bool ShouldRunSyntheticScreen(OriginGrade grade) =>
        grade.Grade is "none" or "weak"
        || (grade.Grade == "strict"
            && grade.CheckKind is not ("literal-origin-compare" or "message-source-ref"));

    public static IReadOnlyList<string> ScreeningOrigins(OriginGrade grade, string? victimOrigin)
    {
        var list = new List<string> { "https://evil.trowser.test" };
        foreach (var lit in grade.Literals)
        {
            if (lit.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || lit.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                list.Add(lit);
            else if (!string.IsNullOrWhiteSpace(lit))
                list.Add($"https://{lit}.evil.trowser.test");
        }

        if (grade.Grade == "weak" && grade.Literals.Count > 0)
        {
            var sub = grade.Literals[0];
            list.Add($"https://attacker-{sub}.evil.trowser.test");
        }

        if (!string.IsNullOrEmpty(victimOrigin))
            list.Add(victimOrigin);

        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToList();
    }

    private static (string Window, bool Truncated) ExtractOriginWindow(string src)
    {
        const int maxFull = 2400;
        if (src.Length <= maxFull)
            return (src, false);

        var idx = Regex.Match(src, @"\b(?:event|e|msg|message)\.origin\b", RegexOptions.IgnoreCase).Index;
        if (idx < 0)
            idx = src.IndexOf(".origin", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return (src[..800], true);

        var start = Math.Max(0, idx - 400);
        var len = Math.Min(src.Length - start, 900);
        var window = src.Substring(start, len);
        return (window + " /*…truncated…*/", true);
    }

    /// <summary>CDP often returns a wrapper (zone.js / framework) with no visible origin logic.</summary>
    private static bool LooksOpaqueMinified(string src)
    {
        if (src.Length > 220) return false;
        if (MessageSourceGate.IsMatch(src) || DataOnlyGate.IsMatch(src) || OriginUsedInValidation(src))
            return false;

        if (Regex.IsMatch(src, @"function\s*\(\s*[a-z]\s*\)\s*\{\s*return\s+[A-Z]\w*\(this\s*,", RegexOptions.IgnoreCase))
            return true;

        return false;
    }

    private static List<string> ExtractStringLiterals(string window)
    {
        var list = new List<string>();
        foreach (Match m in Regex.Matches(window, @"['""]([^'""]{2,120})['""]"))
        {
            var v = m.Groups[1].Value;
            if (v.Contains("http", StringComparison.OrdinalIgnoreCase)
                || v.Length is >= 3 and <= 64)
                list.Add(v);
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToList();
    }
}
