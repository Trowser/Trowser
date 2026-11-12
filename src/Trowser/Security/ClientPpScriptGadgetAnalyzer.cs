using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Heuristic static analysis for application prototype-pollution gadgets in script bundles
/// (e.g. config keys read from <c>{}</c> and passed to <c>script.src</c> / <c>innerHTML</c>).
/// </summary>
public static class ClientPpScriptGadgetAnalyzer
{
    public sealed class Candidate
    {
        public string ScriptUrl { get; init; } = "";
        public string PropertyName { get; init; } = "";
        public string Sink { get; init; } = "";
        public string Snippet { get; init; } = "";
    }

    private static readonly Regex SrcAssign = new(
        @"(?<obj>\w+)\.src\s*=\s*(?<cfg>\w+)\.(?<prop>\w+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex InnerHtmlAssign = new(
        @"(?<obj>\w+)\.innerHTML\s*=\s*(?<cfg>\w+)\.(?<prop>\w+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly Regex LocationAssign = new(
        @"(?:location\.(?:href\s*=|assign\s*\()|(?<obj>\w+)\.location\s*=)\s*(?<cfg>\w+)\.(?<prop>\w+)",
        RegexOptions.Compiled, TimeSpan.FromSeconds(2));

    private static readonly HashSet<string> IgnoredProperties = new(StringComparer.OrdinalIgnoreCase)
    {
        "length", "prototype", "constructor", "toString", "valueOf", "src", "href", "innerHTML"
    };

    public static IReadOnlyList<Candidate> FindCandidates(string scriptUrl, string scriptText)
    {
        if (string.IsNullOrWhiteSpace(scriptText)) return [];

        var list = new List<Candidate>();
        CollectMatches(scriptUrl, scriptText, SrcAssign, "script.src", list);
        CollectMatches(scriptUrl, scriptText, InnerHtmlAssign, "innerHTML", list);
        CollectMatches(scriptUrl, scriptText, LocationAssign, "location", list);

        return list
            .GroupBy(c => c.PropertyName, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
    }

    private static void CollectMatches(
        string scriptUrl,
        string text,
        Regex pattern,
        string sinkLabel,
        List<Candidate> output)
    {
        foreach (Match m in pattern.Matches(text))
        {
            if (!m.Success) continue;
            var prop = m.Groups["prop"].Value;
            if (prop.Length < 2 || IgnoredProperties.Contains(prop)) continue;
            if (!PropertyLooksInherited(text, prop)) continue;

            var snippet = text.AsSpan(Math.Max(0, m.Index - 20), Math.Min(text.Length - Math.Max(0, m.Index - 20), 120))
                .ToString()
                .Replace('\r', ' ')
                .Replace('\n', ' ');

            output.Add(new Candidate
            {
                ScriptUrl = scriptUrl,
                PropertyName = prop,
                Sink = sinkLabel,
                Snippet = snippet
            });
        }
    }

    /// <summary>True when the property is consumed from an object but not assigned as a literal key in the script.</summary>
    private static bool PropertyLooksInherited(string text, string propName)
    {
        if (Regex.IsMatch(text, $@"(?<![\w$]){Regex.Escape(propName)}\s*:", RegexOptions.None, TimeSpan.FromSeconds(2)))
            return false;
        return Regex.IsMatch(text, @"=\s*\{", RegexOptions.None, TimeSpan.FromSeconds(2));
    }
}
