// @title 3 Auto Scan
// @shadow never
// @effects mutates
// Auto-scan: discovers endpoints from network traffic, then runs targeted security scanners
// (SQLi, IDOR, CSRF, path-traversal, mass-assignment, NoSQL, LDAP, XSS, SSTI, etc.).
// Browse the target application first to populate the network log before running this test.
// NOTE: This test sends active probes — real requests to the server.
//
// Scan depth (scanDepth): quick | standard | thorough
//   quick     — fewer endpoints & payloads per scanner (fast smoke pass)
//   standard  — balanced default
//   thorough  — full payload sets incl. time-based NoSQL, experimental Redis/CouchDB pairs
//
// --- Single scanner (uncomment ONE block below) — all payloads for that scanner, nothing else ---
// Available scanners (AutoScanOptions flag → result Scanner id):
//   IncludeSqli                  → sqli
//   IncludeIdor                  → idor
//   IncludeCsrf                  → csrf
//   IncludePathTraversal         → path-traversal
//   IncludeMassAssignment        → mass-assignment
//   IncludeMassAssignmentPatch   → mass-assignment-patch
//   IncludeMassAssignmentRegister→ mass-assignment-register
//   IncludeBflaAdminProbe        → bfla-admin
//   IncludeSsrf                  → ssrf
//   IncludeOpenRedirect          → open-redirect
//   IncludeCacheDeception        → cache-deception
//   IncludeCacheMap              → cache-map
//   IncludeSsti (+ polyglot/stored)→ ssti, ssti-polyglot, ssti-stored
//   IncludeCsti                  → csti
//   IncludeXss                   → xss
//   IncludeXssDom                → xss-dom
//   IncludeXssStored             → xss-stored
//   IncludeParserProbe           → parser-probe
//   IncludeDeserializationScan   → deserialization-scan
//   IncludeFileUploadScan        → file-upload-scan
//   IncludeNextJsRscScan         → nextjs-rsc-scan
//   IncludeCmdCanary             → cmd-canary
//   IncludeNosql                 → nosql
//   IncludeLdap                  → ldap
//   IncludePrototypePollution    → prototype-pollution
//   IncludeSqliLoginSweep        → sqli-login-sweep
//   IncludeJwtAcceptanceSweep    → jwt-acceptance-sweep
//   IncludeRestScaffold          → rest-scaffold
//   IncludePathFilterBypass      → path-filter-bypass
//   IncludeAuthBypassPivot       → auth-bypass-pivot
//
// var nosqliOnly = new AutoScanPipeline.AutoScanOptions { ScanDepth = "thorough" };
// nosqliOnly.DisableAllScanners();
// nosqliOnly.IncludeNosql = true;
// var nosqliResult = await RunAutoScanWithOptions(nosqliOnly);
// await PrintAutoScanReport(nosqliResult, includeDetails: true);

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Auto-scan: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Attack Surface Discovery & Targeted Scanning");
await AssertAutoScanClean(minSeverity: "medium");
await PrintAutoScanReport(includeDetails: true);
