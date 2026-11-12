// @title 2 Jwt Analysis
// @shadow never
// @effects mutates
// JWT analysis: discovers JWT-shaped tokens in cookies (including HttpOnly), localStorage,
// and sessionStorage; decodes header/payload and flags hygiene issues (alg none, expired exp, etc.).
// Navigate and authenticate first if tokens only exist after login.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"JWT analysis: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("JWT token hygiene");
await AssertJwtAnalysisClean(minSeverity: "medium");
await PrintJwtAnalysisReport(includePayload: false);
