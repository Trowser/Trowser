using System.Text;
using System.Text.RegularExpressions;
using Trowser.SessionLog;

namespace Trowser;

/// <summary>
/// A lightweight, reflective coverage lens. It does NOT ask the tester to fill in a model —
/// it derives what was exercised purely from the in-memory journal (pages navigated,
/// interactive elements acted on) crossed with the quality characteristics touched
/// (inferred from journal tags and the kinds of actions/quicktests run).
///
/// Deliberately session-level and best-effort: the goal is awareness ("what haven't I
/// looked at yet?"), not precise measurement. Shared by the Journal panel, GET /api/coverage,
/// and the browser_coverage MCP tool so a human and an AI see the same view.
/// </summary>
public class CoverageService
{
    /// <summary>
    /// Quality characteristics, mirroring the vocabulary used by
    /// <see cref="InspirationService"/>. Kept as an explicit list here so coverage output is
    /// stable regardless of inspiration-file contents.
    /// </summary>
    public static readonly string[] QualityCharacteristics =
    [
        "capability", "reliability", "usability", "charisma", "security",
        "performance", "IT-bility", "compatibility", "standards",
        "supportability", "testability", "maintainability", "portability"
    ];

    /// <summary>A small core set used for gentle, dismissible nudges when untouched.</summary>
    private static readonly string[] CoreCharacteristics = ["capability", "usability", "security", "performance"];

    // Substrings (matched against an entry's summary/details/type/tags) that imply a characteristic
    // was exercised. Conservative on purpose — false positives dilute the signal.
    private static readonly (string Needle, string Characteristic)[] Signals =
    [
        ("accessibility", "usability"),
        ("a11y", "usability"),
        ("aria", "usability"),
        ("contrast", "usability"),
        ("responsive", "compatibility"),
        ("performance", "performance"),
        ("perf", "performance"),
        ("timing", "performance"),
        ("security", "security"),
        ("audit", "security"),
        ("attack", "security"),
        ("inject", "security"),
        ("xss", "security"),
        ("sqli", "security"),
        ("csrf", "security"),
        ("bola", "security"),
        ("idor", "security"),
        ("chain", "security"),
        ("redteam", "security"),
        ("osv", "security"),
        ("crypto", "security"),
        ("saml", "security"),
        ("standards", "standards"),
        ("compliance", "standards"),
        ("html-validate", "standards"),
    ];

    private static readonly Regex UrlRegex = new(@"https?://[^\s""'<>\\]+", RegexOptions.Compiled);

    public CoverageSnapshot Build(IReadOnlyList<SessionLogger.JournalEntry> entries, string? currentUrl)
    {
        var pages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var interactionDescriptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var quality = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var q in QualityCharacteristics) quality[q] = 0;

        int interactions = 0;
        int bugs = 0, observations = 0, testIdeas = 0;

        if (!string.IsNullOrWhiteSpace(currentUrl))
            AddPage(pages, currentUrl);

        foreach (var e in entries)
        {
            var kind = (e.Kind ?? e.Type ?? "").ToLowerInvariant();

            switch (kind)
            {
                case NoteKinds.Bug: bugs++; break;
                case NoteKinds.Observation: observations++; break;
                case NoteKinds.TestIdea: testIdeas++; break;
            }

            // Pages: explicit Url plus any URL mentioned in navigate action summaries/details.
            if (!string.IsNullOrWhiteSpace(e.Url)) AddPage(pages, e.Url!);
            var haystack = $"{e.Summary} {e.Details}";
            if (haystack.Contains("navigate", StringComparison.OrdinalIgnoreCase))
                foreach (Match m in UrlRegex.Matches(haystack)) AddPage(pages, m.Value);

            // Interactions: GUI/API actions that act on an element.
            if (e.Type == "action" && IsInteraction(e.Summary))
            {
                interactions++;
                var desc = string.IsNullOrWhiteSpace(e.Details) ? e.Summary : e.Details!;
                if (!string.IsNullOrWhiteSpace(desc)) interactionDescriptions.Add(desc.Trim());
            }

            // Quality signals: explicit tags first, then keyword inference.
            if (e.Tags != null)
                foreach (var tag in e.Tags)
                    if (quality.ContainsKey(tag)) quality[tag]++;

            var signalHay = $"{e.Type} {e.Summary} {e.Details} {(e.Tags != null ? string.Join(" ", e.Tags) : "")}".ToLowerInvariant();
            foreach (var (needle, characteristic) in Signals)
                if (signalHay.Contains(needle)) quality[characteristic]++;
        }

        var qualityList = QualityCharacteristics
            .Select(q => new QualityCoverage(q, quality[q] > 0, quality[q]))
            .ToList();

        var nudges = new List<string>();
        foreach (var core in CoreCharacteristics)
            if (quality.TryGetValue(core, out var c) && c == 0)
                nudges.Add($"No {core} testing recorded yet — consider a {core} quicktest or probe.");
        if (pages.Count <= 1)
            nudges.Add("Only one page exercised — try navigating other key flows.");

        return new CoverageSnapshot
        {
            CurrentUrl = currentUrl,
            Pages = pages.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).Take(100).ToList(),
            PagesVisited = pages.Count,
            Interactions = interactions,
            DistinctElementsExercised = interactionDescriptions.Count,
            Quality = qualityList,
            QualityTouched = qualityList.Count(q => q.Touched),
            QualityTotal = qualityList.Count,
            Bugs = bugs,
            Observations = observations,
            TestIdeas = testIdeas,
            Nudges = nudges
        };
    }

    private static bool IsInteraction(string summary)
    {
        if (string.IsNullOrEmpty(summary)) return false;
        return summary.Contains("/api/click", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/type", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/select", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/hover", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/key", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/fill", StringComparison.OrdinalIgnoreCase)
            || summary.Contains("/api/press", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddPage(HashSet<string> pages, string url)
    {
        var normalized = NormalizeUrl(url);
        if (!string.IsNullOrEmpty(normalized)) pages.Add(normalized);
    }

    private static string NormalizeUrl(string url)
    {
        url = url.Trim().Trim('"', '\'');
        if (string.IsNullOrEmpty(url)) return "";
        if (url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("about:", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("trowser:", StringComparison.OrdinalIgnoreCase))
            return "";
        try
        {
            var u = new Uri(url);
            // Drop the fragment so /page and /page#section count as one page.
            return $"{u.Scheme}://{u.Authority}{u.AbsolutePath}".TrimEnd('/');
        }
        catch { return url; }
    }
}

/// <summary>Coverage of a single quality characteristic.</summary>
public record QualityCoverage(string Name, bool Touched, int Evidence);

/// <summary>An immutable, serialization-friendly snapshot of the coverage lens.</summary>
public class CoverageSnapshot
{
    public string? CurrentUrl { get; init; }
    public List<string> Pages { get; init; } = new();
    public int PagesVisited { get; init; }
    public int Interactions { get; init; }
    public int DistinctElementsExercised { get; init; }
    public List<QualityCoverage> Quality { get; init; } = new();
    public int QualityTouched { get; init; }
    public int QualityTotal { get; init; }
    public int Bugs { get; init; }
    public int Observations { get; init; }
    public int TestIdeas { get; init; }
    public List<string> Nudges { get; init; } = new();

    /// <summary>Compact one-line summary for the Journal panel header.</summary>
    public string ToSummaryLine() =>
        $"Coverage: {PagesVisited} page{(PagesVisited == 1 ? "" : "s")} • " +
        $"{Interactions} interaction{(Interactions == 1 ? "" : "s")} • " +
        $"{QualityTouched}/{QualityTotal} quality characteristics";

    /// <summary>Multi-line detail for a hover tooltip.</summary>
    public string ToTooltip()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Pages visited: {PagesVisited}");
        sb.AppendLine($"Interactions: {Interactions} ({DistinctElementsExercised} distinct elements)");
        var touched = Quality.Where(q => q.Touched).Select(q => q.Name).ToList();
        var untouched = Quality.Where(q => !q.Touched).Select(q => q.Name).ToList();
        sb.AppendLine($"Quality touched: {(touched.Count > 0 ? string.Join(", ", touched) : "none")}");
        sb.AppendLine($"Not yet touched: {(untouched.Count > 0 ? string.Join(", ", untouched) : "none")}");
        if (Nudges.Count > 0)
        {
            sb.AppendLine();
            foreach (var n in Nudges) sb.AppendLine($"• {n}");
        }
        return sb.ToString().TrimEnd();
    }

    /// <summary>Anonymous object shaped for JSON (REST) and text (MCP) responses.</summary>
    public object ToPayload() => new
    {
        currentUrl = CurrentUrl,
        pagesVisited = PagesVisited,
        pages = Pages,
        interactions = Interactions,
        distinctElementsExercised = DistinctElementsExercised,
        quality = Quality.Select(q => new { name = q.Name, touched = q.Touched, evidence = q.Evidence }),
        qualityTouched = QualityTouched,
        qualityTotal = QualityTotal,
        findings = new { bugs = Bugs, observations = Observations, testIdeas = TestIdeas },
        nudges = Nudges
    };
}
