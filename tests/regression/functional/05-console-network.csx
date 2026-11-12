// Functional: console + network log capture.

await ResetBrowserState();

var url = FixtureUrl("/logs");
var html = MinimalHtml("Logs",
    @"<h1>Logs</h1>
      <script>
        // Delayed network call (console hook is injected post-navigation; see below).
        setTimeout(function() { fetch('/api/ping-log').then(function(){}); }, 200);
      </script>");
SetupPage(url, html, ScriptableHeaders());
SetupApi("*/api/ping-log*", statusCode: 200, body: "{\"pong\":true}");
await Navigate(url);
await WaitForIdle();

// Console capture is normally injected on NavigationCompleted only when IsSuccess=true.
// Mocked HTTPS hosts can report navigation errors, so install the same hook explicitly,
// then emit messages for the oracle.
await ExecuteJs(@"
(function() {
  if (window.__trowserConsoleHooked) return 'already';
  window.__trowserConsoleHooked = true;
  const origLog = console.log, origWarn = console.warn, origError = console.error, origInfo = console.info;
  function capture(level, args) {
    try {
      var msg = Array.from(args).map(a => {
        if (typeof a === 'string') return a;
        try { return JSON.stringify(a); } catch { return String(a); }
      }).join(' ');
      window.chrome.webview.postMessage(JSON.stringify({
        type: '__trowser_console', level: level, message: msg
      }));
    } catch(e) {}
  }
  console.log = function() { capture('log', arguments); origLog.apply(console, arguments); };
  console.warn = function() { capture('warning', arguments); origWarn.apply(console, arguments); };
  console.error = function() { capture('error', arguments); origError.apply(console, arguments); };
  console.info = function() { capture('info', arguments); origInfo.apply(console, arguments); };
  return 'hooked';
})()");
await ExecuteJs("console.log('hello-regression'); console.error('planted-error'); 'ok'");
await Sleep(800);

Assert.Section("Console log");
var consoleEntries = GetConsoleLog();
Assert.True(consoleEntries.Count >= 1, $"Console has entries (got {consoleEntries.Count})");
var blob = string.Join("\n", consoleEntries.Select(e => e.Message + " " + e.ToString()));
Log($"Console blob: {blob.Substring(0, Math.Min(400, blob.Length))}");
Assert.True(
    blob.Contains("hello-regression", StringComparison.OrdinalIgnoreCase)
    || blob.Contains("planted-error", StringComparison.OrdinalIgnoreCase),
    "Console captured planted messages");

Assert.Section("Network log");
var net = GetNetworkLog();
Assert.True(net.Count >= 1, $"Network log has entries (got {net.Count})");
var api = net.FirstOrDefault(e => (e.Url ?? "").Contains("/api/ping-log", StringComparison.OrdinalIgnoreCase));
Assert.NotNull(api, "Network log contains /api/ping-log");
if (api != null)
{
    Assert.Equal(200, api.StatusCode, "API status is 200 from mock");
    Log($"API entry: {api.Method} {api.Url} status={api.StatusCode}");
}
