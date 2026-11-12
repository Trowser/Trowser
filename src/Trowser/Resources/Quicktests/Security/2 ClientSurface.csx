// @title 2 Client Surface
// @shadow never
// @effects mutates
// Browser-side triage from the client-surface map. Lists which client bug classes
// are worth a follow-up scanner and which can be skipped on this page.
// Does not run XS-Leaks, DOM XSS probes, gadget chains, or CSTI.
// May reload the page once so the runtime sensor sees the load. Browse key flows first.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Client surface: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Browser-side clues");
var surface = await PrintClientSurfaceReport();
var pursue = surface.Risks.Count(r => r.Status == "pursue");
var lead = surface.Risks.Count(r => r.Status == "lead");
var manual = surface.Risks.Count(r => r.Status == "manual");
var dismiss = surface.Risks.Count(r => r.Status == "dismiss");
Assert.Pass($"Triage only — {pursue} to pursue, {lead} lead(s), {manual} manual, {dismiss} dismissed. No follow-up scanners were run.");
