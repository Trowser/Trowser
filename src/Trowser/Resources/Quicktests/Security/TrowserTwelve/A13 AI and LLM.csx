// @title A13 AI and LLM
// @shadow never
// @effects mutates
// A13 AI & LLM Security (OWASP LLM Top 10 application-layer)
// Tests: discovery, corpus red-team (LLM01–03 + LLM05–07 + LLM09), RAG/memory poison (LLM04),
// unbounded consumption (LLM10), output→sink tracing, WebMCP abuse.
// Browse the target application first — if it has AI/chat features, interact with them
// so the network log captures LLM API traffic.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"A13 AI & LLM Security: {title}");
Log($"URL: {url}");
Log("");

await PrintPlaybookReport("a13-llm", safetyMode: "safe", depth: "standard");
