using Trowser.Security;

namespace Trowser.Laws;

public enum LawVerdict
{
    Pass,
    Fail,
    NotApplicable,
    Error,
    SkippedBudget
}

public enum LawTriggerKind
{
    Page,
    Response,
    Console,
    Timer,
    Action
}

public enum LawCostClass
{
    Page,
    Response,
    Console,
    Heavy
}

/// <summary>Which registered Laws <see cref="LawService.CheckLawsAsync"/> evaluates.</summary>
public enum LawCheckScope
{
    /// <summary>Embedded, user files, and any other loaded Laws (not script-console ephemera).</summary>
    AllLoaded,

    /// <summary>Laws declared via <c>Law(...)</c> in the current Script Console run only.</summary>
    ScriptConsoleDeclared
}

public sealed class LawCheckResult
{
    public required string LawId { get; init; }
    public required string Name { get; init; }
    public LawVerdict Verdict { get; init; }
    public string? Message { get; init; }
    /// <summary>Facts read during evaluation (page/response), when available.</summary>
    public string? Evidence { get; init; }
    /// <summary>Human-readable failure summary (<see cref="Message"/> + <see cref="Evidence"/>).</summary>
    public string? Detail { get; init; }
    public Severity Severity { get; init; } = Severity.Medium;
    public string? SourceFile { get; init; }
    public string? ContextUrl { get; init; }
}

public sealed class LawCheckSummary
{
    public List<LawCheckResult> Results { get; init; } = [];
    public int ResponseEntriesChecked { get; init; }
    public int ConsoleEntriesChecked { get; init; }
    public int Passed => Results.Count(r => r.Verdict == LawVerdict.Pass);
    public int Failed => Results.Count(r => r.Verdict == LawVerdict.Fail);
    public int NotApplicable => Results.Count(r => r.Verdict == LawVerdict.NotApplicable);
    public int Errors => Results.Count(r => r.Verdict == LawVerdict.Error);
    public int Skipped => Results.Count(r => r.Verdict == LawVerdict.SkippedBudget);
}
