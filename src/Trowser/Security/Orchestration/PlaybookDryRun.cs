namespace Trowser.Security.Orchestration;

/// <summary>Shared dry-run step builders for playbook catalogs.</summary>
public static class PlaybookDryRun
{
    public static DryRunStep CrawlLight(PlaybookRequest request, int maxCrawlPages, bool shared = false, string? description = null)
    {
        description ??= shared
            ? $"Shared BFS crawl within scope.host (max {maxCrawlPages} pages)"
            : $"BFS crawl within scope.host (max {maxCrawlPages} pages)";
        return new DryRunStep
        {
            Name = "crawl-light",
            Description = description,
            HttpVerbs = "GET",
            WritesSideEffects = false,
            SkippedByCurrentSafetyMode = !request.IncludeCrawl,
            SkipReason = !request.IncludeCrawl ? "crawl=false" : null
        };
    }
}
