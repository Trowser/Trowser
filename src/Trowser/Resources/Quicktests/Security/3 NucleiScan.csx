// @title 3 Nuclei Scan
// @shadow never
// @effects mutates
// Nuclei template scan: runs curated HTTP nuclei templates (embedded subset and/or your own)
// against one or more targets. Read-only GET templates run under default safe mode; only run on
// targets you are permitted to test.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Nuclei template scan: {title}");
Log($"URL: {url}");
Log("");

// Inventory the templates that will run (no HTTP sent) so you can pick applicable ones.
Assert.Section("Available nuclei templates");
foreach (var t in ListNucleiTemplates())
    Log($"  {t.Id} [{t.Severity}] tags={string.Join(",", t.Tags)} methods={string.Join(",", t.Methods)} ({t.Source})");

Assert.Section("Embedded nuclei templates (exposure / misconfig probes)");
await AssertNucleiClean(minSeverity: "medium");
await PrintNucleiReport(includeDetails: true);

// --- Optional: preview selection without sending HTTP ---
// var preview = await RunNucleiScan(tags: new[] { "exposure" }, dryRun: true);
// Log($"Would run: {string.Join(", ", preview.SelectedTemplateIds)}");

// --- Optional: filter by tags (array) and severity ---
// await PrintNucleiReport(tags: new[] { "exposure", "misconfig" }, minSeverity: "low");

// --- Optional: per-template trace + follow redirects (e.g. open-redirect templates keep followRedirects:false) ---
// await PrintNucleiReport(verboseTemplateTrace: true);

// --- Optional: scan several base URLs in one run ---
// await PrintNucleiReport(targetUrls: new[] { "https://a.example.com", "https://b.example.com" });

// --- Optional: bring your own templates ---
// Drop *.yaml Nuclei HTTP templates in a folder and point templatesDir at it. Set
// includeBuiltinTemplates: false to run ONLY your templates. (Also honors the
// TROWSER_NUCLEI_TEMPLATES env var or a nuclei-templates/ folder beside the exe.)
// await PrintNucleiReport(templatesDir: @"C:\my-nuclei-templates", includeBuiltinTemplates: false);
