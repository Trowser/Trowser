using Trowser.Laws;

namespace Trowser.Automation;

public partial class AutomationContext
{
    public LawService? Laws { get; set; }

    public void Site(string hostPattern, string? defaultPagePathPattern = null) =>
        Laws?.Site(hostPattern, defaultPagePathPattern);

    public LawBuilder Law(string name)
    {
        if (Laws == null)
            throw new InvalidOperationException("Law service is not available.");
        return Laws.Law(name);
    }

    /// <param name="allLoaded">When true, evaluate every loaded Law (embedded + user files). Default: Laws declared in this Script Console run only.</param>
    public async Task<LawCheckSummary> CheckLaws(string? nameFilter = null, bool report = true, bool allLoaded = false)
    {
        if (Laws == null)
            throw new InvalidOperationException("Law service is not available.");
        var scope = allLoaded ? LawCheckScope.AllLoaded : LawCheckScope.ScriptConsoleDeclared;
        var summary = await Laws.CheckLawsAsync(nameFilter, scope, ct: ScriptCancellation);
        if (report)
            PrintLawCheckSummary(summary, scope);
        return summary;
    }

    public async Task AssertLaws(string? nameFilter = null, bool allLoaded = false)
    {
        if (Laws == null)
            throw new InvalidOperationException("Law service is not available.");
        var summary = await CheckLaws(nameFilter, report: true, allLoaded);
        var failures = summary.Results.Where(r => r.Verdict == LawVerdict.Fail).ToList();
        if (failures.Count == 0)
            return;

        var msg = string.Join("; ", failures.Select(f => f.Name));
        throw new InvalidOperationException($"Law assertion failed: {msg}");
    }

    public void PrintLawCheckSummary(LawCheckSummary summary, LawCheckScope scope = LawCheckScope.ScriptConsoleDeclared)
    {
        if (summary.Results.Count == 0)
        {
            var hint = scope == LawCheckScope.ScriptConsoleDeclared
                ? "Laws: none declared in this script (add Law(...) above, or use CheckLaws(allLoaded: true))."
                : "Laws: no loaded page Laws matched (check name filter or OnPage patterns).";
            Log(hint, "#888888");
            return;
        }

        foreach (var r in summary.Results.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            var color = r.Verdict switch
            {
                LawVerdict.Pass => "#4EC9B0",
                LawVerdict.Fail => "#F44747",
                LawVerdict.Error => "#F44747",
                LawVerdict.NotApplicable => "#888888",
                LawVerdict.SkippedBudget => "#CCA700",
                _ => "#CCCCCC"
            };
            var line = r.Verdict switch
            {
                LawVerdict.Pass => $"[Law PASS] {r.Name}",
                LawVerdict.Fail => $"[Law FAIL] {r.Name}" + (string.IsNullOrEmpty(r.Detail) ? "" : $": {r.Detail}"),
                LawVerdict.NotApplicable => $"[Law N/A] {r.Name}" + (string.IsNullOrEmpty(r.Message) ? "" : $": {r.Message}"),
                LawVerdict.Error => $"[Law ERROR] {r.Name}: {r.Message}",
                LawVerdict.SkippedBudget => $"[Law SKIPPED] {r.Name} (budget)",
                _ => $"[Law] {r.Name}: {r.Verdict}"
            };
            Log(line, color);
        }

        var summaryColor = summary.Failed > 0 || summary.Errors > 0 ? "#F44747" : "#569CD6";
        Log(
            $"Laws summary: {summary.Passed} passed, {summary.Failed} failed, {summary.NotApplicable} N/A, {summary.Errors} error(s)",
            summaryColor);
    }

    public Task LoadLaws(string path)
    {
        if (Laws == null)
            throw new InvalidOperationException("Law service is not available.");
        return Laws.LoadLaws(path, ScriptCancellation);
    }

    public IReadOnlyList<LawCheckResult> GetLawResults() =>
        Laws?.LastResults ?? [];

    public Task RunShadowHeavy()
    {
        if (Laws == null)
            throw new InvalidOperationException("Law service is not available.");
        return Laws.RunShadowHeavyAsync(ScriptCancellation);
    }

    /// <summary>After stress tests (monkey / Monkey Trowser), run all loaded Laws and fail on violations.</summary>
    internal async Task AssertLawsAfterStressAsync(string label)
    {
        if (Laws == null)
            return;

        var summary = await Laws.CheckLawsAsync(scope: LawCheckScope.AllLoaded, ct: ScriptCancellation);
        PrintLawCheckSummary(summary, LawCheckScope.AllLoaded);

        if (summary.Failed > 0 || summary.Errors > 0)
        {
            throw new InvalidOperationException(
                $"Law assertion failed after {label}: {summary.Failed} failed, {summary.Errors} error(s)");
        }
    }
}
