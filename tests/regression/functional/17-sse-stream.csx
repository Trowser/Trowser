var streamUrl = $"{FixtureOrigin}/sse/fixture-stream";
var pageHtml = """
<!DOCTYPE html><html><body>
<script>
  var es = new EventSource("/sse/fixture-stream");
  es.onmessage = function(e) { window.__sse = (window.__sse||[]).concat(e.data); };
</script>
</body></html>
""";

MockResponse($"{FixtureOrigin}/sse/page", 200, pageHtml,
    headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

var sseBody = """
id: evt-1
event: greet
data: {"msg":"hello-sse"}

id: evt-2
data: line1
data: line2

""";

MockResponse(streamUrl, 200, sseBody,
    headers: new Dictionary<string, string> { ["Content-Type"] = "text/event-stream; charset=utf-8" });

await Navigate($"{FixtureOrigin}/sse/page");
await WaitForIdle(800, 8000);

var net = GetPageNetworkLog().Where(e => e.IsEventStream).ToList();
Assert.True(net.Count >= 1, "At least one event-stream network row");

var parsed = Trowser.Automation.SseParser.Parse(sseBody);
Assert.True(parsed.Count >= 2, "Fixture parser sees multiple events");

var audit = await RunSseAuditAsync(new Trowser.Security.Sse.SseAuditor.AuditOptions
{
    Checks = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "sensitive-data", "coverage" }
});
Assert.NotNull(audit.Coverage);
