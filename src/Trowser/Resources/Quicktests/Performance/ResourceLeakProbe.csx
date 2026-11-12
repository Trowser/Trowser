// @title Resource Leak Probe
// @shadow never
// @effects mutates
// Resource comparison quicktest — manual or scripted actions between before/after.
//
// GC: baseline and final both force GC via CDP before measuring (see report "after GC" lines).
// During the pause window below, interact freely; growth you cause is what gets compared.
//
// Manual: click Script Console Pause, do your steps in the browser, Resume when done.
// Or replace Sleep with scripted Click/Type/Navigate (pattern A in comments).
//
// Pattern B — automated reload stress (uncomment):
//   await PrintResourceProbeReport(new ResourceProbeOptions { ReloadBetweenIterations = true, Iterations = 5 });

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Resource comparison: {title}");
Log($"URL: {url}");
Log("");

var baseline = await CheckResourceSnapshot();
Log($"Baseline (after GC): heap {baseline.JsHeapUsedBytes / 1024.0:F0} KB | nodes {baseline.DomNodes} | listeners {baseline.JsEventListeners}");
Log("");
Log("Do your steps now — Pause in Script Console, or wait out the timer below.");
Log("(Script keeps running; the browser stays interactive during Sleep.)");
await Sleep(30000);

Log("");
Log("Waiting for network/DOM to settle, then final snapshot (GC again)...");
await WaitForIdle(500, 5000);

var result = await PrintResourceComparisonReport(baseline, new ResourceProbeOptions
{
    SettleMs = 1000,
    GcBeforeFinal = true
});

Log("");
var notable = result.Findings.Where(f => f.Severity >= Severity.Medium).ToList();
if (notable.Count == 0)
    Log("No medium-or-higher findings — growth within thresholds (or expected for this workflow).");
else
    Log($"{notable.Count} finding(s) worth reviewing — see report above.");
