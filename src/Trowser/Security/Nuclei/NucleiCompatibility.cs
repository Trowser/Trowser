namespace Trowser.Security.Nuclei;

public sealed record NucleiCompatibilitySummary(
    int RunnableCount,
    int SkippedCount,
    int FilesScanned,
    IReadOnlyDictionary<string, int> SkippedByReason)
{
    public static NucleiCompatibilitySummary FromLoad(NucleiRunner.TemplateLoad load)
    {
        var skippedByReason = load.Skipped
            .GroupBy(s => s.Reason, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        return new NucleiCompatibilitySummary(
            load.Templates.Count,
            load.Skipped.Count,
            load.Templates.Count + load.Skipped.Count,
            skippedByReason);
    }
}
