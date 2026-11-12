using Trowser.Security;

namespace Trowser.Laws;

public sealed class LawDefinition
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? SiteFilter { get; init; }
    public LawTriggerKind Trigger { get; init; }
    public string? TriggerPattern { get; init; }
    public LawCostClass Cost { get; init; } = LawCostClass.Page;
    public Severity Severity { get; init; } = Severity.Medium;
    public HashSet<string> Tags { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public bool ConfirmOnFail { get; init; } = true;
    public string? SourceFile { get; init; }

    public Func<PageFacts, bool>? PageWhen { get; init; }
    public Func<PageFacts, bool>? PageExpect { get; init; }
    public Func<PageFacts, bool>? PageForbid { get; init; }

    public Func<ResponseFacts, bool>? ResponseWhen { get; init; }
    public Func<ResponseFacts, bool>? ResponseExpect { get; init; }
    public Func<ResponseFacts, bool>? ResponseForbid { get; init; }

    public Func<ConsoleFacts, bool>? ConsoleWhen { get; init; }
    public Func<ConsoleFacts, bool>? ConsoleExpect { get; init; }
    public Func<ConsoleFacts, bool>? ConsoleForbid { get; init; }

    public DateTime? LastEvaluatedUtc { get; set; }

    /// <summary>Page, Action and Timer Laws all evaluate <see cref="PageFacts"/> predicates.</summary>
    public bool UsesPageFacts => Trigger is LawTriggerKind.Page or LawTriggerKind.Action or LawTriggerKind.Timer;
    public LawVerdict? LastVerdict { get; set; }
    public string? LastFailDetail { get; set; }
    public string? LastFailUrl { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public int NotApplicableCount { get; set; }
}
