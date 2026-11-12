// @title 3 Swaggering
// @shadow never
// @effects mutates
// Swaggering — session-authenticated OpenAPI pass (not Postman: uses your WebView login).
// Log in first, optionally open Swagger UI so the spec appears in traffic.
// Default: depth thorough (~20 min), safetyMode active (mutating POST/PUT/PATCH).
// Staging / authorized targets only.
//
// What it actually sends (per documented operation, with your cookies):
//   smoke — minimal/example request; flags HTTP 5xx, slow responses, stack traces in body
//   auth-delta — same call without cookies when spec says "secured"; flags anonymous 2xx
//   forced-error — malformed JSON POST on write operations
//   missing-field — omit each top-level body field (when schema known)
//   cost-edge — high limit/pageSize query values where spec has no max
//   injection-micro — one light SQLi-style string on a query param (hint only)
//   shadow-paths — GET routes seen in traffic/JS but not in OpenAPI
//   auto-scan — injection scanners on merged surface (thorough depth)
//   spec-limits — passive OpenAPI hints (unbounded arrays/limits), no extra HTTP
//
// Toggles at top:
//   depth: quick | standard | thorough
//   safetyMode: passive (spec parse only) | safe (GET only) | active | aggressive

var depth = "thorough";
var safetyMode = "active";

var url = await GetCurrentUrl();
Log($"Swaggering: {await GetTitle()}");
Log($"URL: {url}");
Log("Ensure you are logged in. This exercises documented API operations with your session cookies.");
Log("");

Assert.Section("Swaggering (OpenAPI + session)");

var result = await PrintSwaggeringReport(new SwaggeringOrchestrator.SwaggeringOptions
{
    SafetyMode = Trowser.Security.Orchestration.SafetyModeExtensions.Parse(safetyMode),
    Depth = depth,
    IncludeOpenApiProbes = true,
    IncludeSpecsFromNetwork = true,
    IncludeDeleteMethods = false,
    RegisterChainFindings = false
});

foreach (var f in result.Findings.Where(x => x.Severity is "high" or "critical"))
    Assert.Fail($"Swaggering: {f.Title} — {f.Url}");

Assert.Pass(result.Message);
