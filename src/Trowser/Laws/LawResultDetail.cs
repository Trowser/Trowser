namespace Trowser.Laws;

internal static class LawResultDetail
{
    public static string? Format(string? message, string? evidence)
    {
        if (string.IsNullOrWhiteSpace(message) && string.IsNullOrWhiteSpace(evidence))
            return null;
        if (string.IsNullOrWhiteSpace(evidence))
            return message;
        if (string.IsNullOrWhiteSpace(message))
            return evidence;
        return message + " — " + evidence;
    }

    public static LawCheckResult WithDetail(LawCheckResult r) =>
        new()
        {
            LawId = r.LawId,
            Name = r.Name,
            Verdict = r.Verdict,
            Message = r.Message,
            Evidence = r.Evidence,
            Severity = r.Severity,
            SourceFile = r.SourceFile,
            ContextUrl = r.ContextUrl,
            Detail = Format(r.Message, r.Evidence)
        };

    public static LawCheckResult Merge(LawCheckResult prev, LawCheckResult next)
    {
        if (next.Verdict == LawVerdict.NotApplicable)
            return prev;
        if (prev.Verdict == LawVerdict.NotApplicable)
            return WithDetail(next);

        var keep = VerdictRank(next.Verdict) >= VerdictRank(prev.Verdict) ? next : prev;
        var other = ReferenceEquals(keep, next) ? prev : next;

        if (keep.Verdict != other.Verdict || keep.Verdict is not (LawVerdict.Fail or LawVerdict.Error))
            return WithDetail(keep);

        var urlNote = !string.IsNullOrWhiteSpace(other.ContextUrl) && other.ContextUrl != keep.ContextUrl
            ? other.ContextUrl
            : null;
        var extra = Format(other.Message, other.Evidence);
        var evidence = keep.Evidence;
        if (!string.IsNullOrWhiteSpace(extra))
            evidence = string.IsNullOrWhiteSpace(evidence) ? extra : evidence + " | " + extra;
        if (urlNote != null)
            evidence = string.IsNullOrWhiteSpace(evidence) ? $"@ {urlNote}" : evidence + $" | @ {urlNote}";

        return WithDetail(new LawCheckResult
        {
            LawId = keep.LawId,
            Name = keep.Name,
            Verdict = keep.Verdict,
            Message = keep.Message,
            Evidence = evidence,
            Severity = keep.Severity,
            SourceFile = keep.SourceFile,
            ContextUrl = keep.ContextUrl ?? other.ContextUrl
        });
    }

    private static int VerdictRank(LawVerdict v) => v switch
    {
        LawVerdict.Fail => 4,
        LawVerdict.Error => 3,
        LawVerdict.SkippedBudget => 2,
        LawVerdict.Pass => 1,
        _ => 0
    };
}
