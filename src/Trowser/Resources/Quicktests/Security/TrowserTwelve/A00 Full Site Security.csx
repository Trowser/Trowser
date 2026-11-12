// @title A00 Full Site Security
// @shadow never
// @effects mutates
// Full site security assessment: runs all Trowser Twelve playbooks in sequence,
// correlates findings across categories, and produces attack-chain candidates.
// This is the "one-call site assessment" — start here for a comprehensive view.
// Browse the target application first so the network log is populated.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Full Site Security: {title}");
Log($"URL: {url}");
Log("");

var result = await PrintPlaybookReport("full",
    safetyMode: "safe",
    depth: "standard",
    maxSeconds: 600,
    maxRequests: 2000);

Log("");
Log($"Completed: {result.StepsExecuted.Count} steps, safety={result.SafetyMode}, depth={result.Depth}");
if (result.NextActions.Count > 0)
{
    Log("");
    Log("Suggested next actions:");
    foreach (var action in result.NextActions)
        Log($"  → {action.Action}: {action.Rationale}");
}
