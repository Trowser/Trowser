namespace Trowser.Laws;

public sealed class ShadowHeavyRunReport
{
    public bool Ran { get; init; }
    public string? SkippedReason { get; init; }
    public int LawsEvaluated { get; init; }
    public int LawFailures { get; init; }
    public int LawPasses { get; init; }
    public int LawNotApplicable { get; init; }
    public int LawErrors { get; init; }
    public int HeavyQuicktestsRun { get; init; }
    public string? PageUrl { get; init; }

    public string SummaryLine
    {
        get
        {
            if (!Ran && !string.IsNullOrEmpty(SkippedReason))
                return $"Shadow Heavy skipped: {SkippedReason}";
            if (!Ran)
                return "Shadow Heavy did not run.";
            var qt = HeavyQuicktestsRun > 0 ? $", {HeavyQuicktestsRun} heavy quicktest(s)" : "";
            var extra = LawNotApplicable + LawErrors > 0
                ? $", {LawNotApplicable} N/A, {LawErrors} error(s)"
                : "";
            return $"Shadow Heavy: {LawsEvaluated} Law(s) checked, {LawFailures} failed, {LawPasses} passed{extra}{qt}.";
        }
    }

    public static ShadowHeavyRunReport Skipped(string reason) =>
        new() { Ran = false, SkippedReason = reason };
}
