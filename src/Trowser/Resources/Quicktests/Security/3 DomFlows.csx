// @title 3 Dom Flows
// @shadow never
// @effects mutates
// DOM XSS flow graph: every observed point where attacker-controlled data
// becomes a dangerous sink (innerHTML, eval, location, script, …) and whether
// it executed. Browse the page first so the sensor sees real source reads.
// For planted canaries, change mode to "probe" and set safetyMode active in REST/MCP.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"DOM XSS flows: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Observe source → sink → consequence");
await PrintDomFlowsReport("observe");
await AssertDomFlowsClean();
