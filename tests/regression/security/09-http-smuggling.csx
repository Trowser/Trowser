// Security: HTTP smuggling oracles (offline — no live desync fixture).
// (1) Dynamic-body TE-TE must not alert (status class unchanged).
// (2) Via-only passive is not elevated.
// (3) Differential payload builders stay PortSwigger-shaped.

await ResetBrowserState();

Assert.Section("TE-TE dynamic body is not desync");
Assert.False(
    HttpRequestSmugglingScanner.TeTeResponsesIndicateDesync(200, 200),
    "Same 2xx status is not TE-TE desync even if HTML bodies would differ");
Assert.True(
    HttpRequestSmugglingScanner.TeTeResponsesIndicateDesync(200, 404),
    "2xx vs 4xx is a framing signal");
Assert.True(
    HttpRequestSmugglingScanner.TeTeResponsesIndicateDesync(200, 500),
    "2xx vs 5xx is a framing signal");
Assert.False(
    HttpRequestSmugglingScanner.TeTeResponsesIndicateDesync(200, 201),
    "2xx vs 2xx is HTML/API churn, not desync");
Assert.False(
    HttpRequestSmugglingScanner.TeTeResponsesIndicateDesync(404, 403),
    "4xx vs 4xx is not a status-class change");
Assert.Pass("TE-TE oracle ignores body equality and same-class status");

Assert.Section("Via-only passive is not elevated");
var viaOnly = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    ["Via"] = "1.1 varnish",
    ["CF-RAY"] = "abc123-AMS",
    ["Server"] = "cloudflare"
};
var viaPassive = HttpRequestSmugglingScanner.AnalyzePassive(viaOnly, "HTTP/2 or HTTP/1.1", "cloudflare");
Log($"Via-only: risk={viaPassive.Risk} indicators={viaPassive.Indicators.Count} context={viaPassive.Context.Count} proxy={viaPassive.ProxyDetected}");
Assert.True(viaPassive.IsClean, "Via/CDN must not elevate passive smuggling risk");
Assert.False(viaPassive.Risk is "medium" or "high", "Via-only risk is not medium/high");
Assert.Equal(0, viaPassive.Indicators.Count, "Via-only has no framing indicators");
Assert.True(viaPassive.ProxyDetected, "Via/CDN still recorded as proxy context");
Assert.False(
    HttpRequestSmugglingScanner.IsUnambiguousHttp1("HTTP/2 or HTTP/1.1"),
    "Ambiguous HTTP/2 or HTTP/1.1 string is not HTTP/1.1");
Assert.True(
    HttpRequestSmugglingScanner.IsUnambiguousHttp1("HTTP/1.1"),
    "Plain HTTP/1.1 is unambiguous");

Assert.Section("Ambiguous response framing does elevate");
var teCl = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
{
    ["Transfer-Encoding"] = "chunked",
    ["Content-Length"] = "12"
};
var framing = HttpRequestSmugglingScanner.AnalyzePassive(teCl, "HTTP/1.1", null);
Assert.Equal("high", framing.Risk, "TE+CL response framing is high");
Assert.True(framing.HasAmbiguousFraming, "HasAmbiguousFraming");
Assert.True(HttpRequestSmugglingScanner.ResponseHasAmbiguousFraming(teCl), "Shared framing helper");

Assert.Section("PortSwigger-shaped differential payloads");
var origin = new Uri("https://trowser-regression.test/login");
var clTe = HttpRequestSmugglingScanner.BuildClTeDifferentialRequest(origin, "/trowser-smuggle-deadbeef");
Log("CL.TE prefix (first lines):");
foreach (var line in clTe.Replace("\r\n", "\n").Split('\n').Take(8))
    Log("  " + line);
Assert.True(clTe.Contains("Transfer-Encoding: chunked"), "CL.TE has TE chunked");
Assert.True(clTe.Contains("Content-Length:"), "CL.TE has Content-Length");
Assert.True(clTe.Contains("GET /trowser-smuggle-deadbeef HTTP/1.1"), "CL.TE prefixes unique canary GET");
Assert.True(clTe.Contains("X-Ignore: X"), "CL.TE ends with X-Ignore: X (no trailing CRLF after X)");
Assert.False(clTe.TrimEnd().EndsWith("X\r\n") || clTe.EndsWith("X\r\n\r\n"), "CL.TE must not CRLF after X-Ignore value");

var teClReq = HttpRequestSmugglingScanner.BuildTeClDifferentialRequest(origin, "/trowser-smuggle-deadbeef");
Log("TE.CL prefix (first lines):");
foreach (var line in teClReq.Replace("\r\n", "\n").Split('\n').Take(8))
    Log("  " + line);
Assert.True(teClReq.Contains("Transfer-Encoding: chunked"), "TE.CL has TE chunked");
Assert.True(teClReq.Contains("Content-Length: 4"), "TE.CL outer Content-Length is 4 (chunk-size line)");
Assert.True(teClReq.Contains("POST /trowser-smuggle-deadbeef HTTP/1.1"), "TE.CL smuggles canary POST");
Assert.Pass("Differential payload builders stay PortSwigger-shaped");
