// @title 3 Graphql Analysis
// @shadow never
// @effects mutates
// GraphQL security: auto-detects endpoint from network log (graphql URL or application/graphql),
// then runs introspection, batching, alias amplification, depth/limit probes, field suggestions, etc.
// Sends real probing queries — authorize first if the API requires auth. Pass custom headers via scripting if needed.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"GraphQL security analysis: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("GraphQL endpoint probes");
await AssertGraphqlAnalysisClean(minSeverity: "medium");
await PrintGraphqlAnalysisReport(includeDetails: true);
