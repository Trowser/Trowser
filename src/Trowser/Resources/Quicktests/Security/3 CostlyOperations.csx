// @title 3 Costly Operations
// @shadow never
// @effects mutates
// Single-request cost risks from captured traffic (passive). Re-run with safetyMode "active"
// and checks including confirm-page-size, confirm-image-edge, confirm-multi-id for bounded validation.

var url = await GetCurrentUrl();
Log($"Costly operations scan: {await GetTitle()}");
Log($"URL: {url}");
Log("");

var result = await RunCostlyOperations(new CostlyOperationsProbe.CostlyOperationsOptions
{
    RegisterChainFindings = false
});

Log($"=== {result.Message} ===");
Log($"Examined {result.EntriesExamined} entries | checks: {string.Join(", ", result.ChecksRun)}");
Log("");

foreach (var group in result.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key))
{
    Log($"--- {group.Key.ToUpperInvariant()} ({group.Count()}) ---");
    foreach (var f in group)
    {
        Log($"  [{f.Confidence}] {f.Title}");
        Log($"    {f.Endpoint}");
        Log($"    {f.Detail}");
        if (!string.IsNullOrEmpty(f.RelatedProbe))
            Log($"    related: {f.RelatedProbe}");
    }
    Log("");
}

if (result.InferredLeads.Count > 0)
{
    Log($"--- INFERRED LEADS ({result.InferredLeads.Count}) ---");
    foreach (var f in result.InferredLeads.Take(20))
        Log($"  [{f.CheckId}] {f.Title} — {f.Endpoint}");
    Log("");
}

Log("Confirms (optional): confirm-page-size, confirm-image-edge, confirm-multi-id with safetyMode active/safe.");
Log("");

foreach (var f in result.Findings.Where(x => x.Severity is "high" or "critical"
                                               && x.Confidence is "observed" or "confirmed"))
{
    Assert.Fail($"Costly operation: {f.Title} — {f.Endpoint}");
}

Assert.Pass(result.Message);
