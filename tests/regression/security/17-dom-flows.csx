// Security: DOM flow graph — observe source→sink→consequence chains.

await ResetBrowserState();

Assert.Section("Observe flows after postMessage → innerHTML");
var html = MinimalHtml("Flows",
    @"<div id=""out""></div>
      <script>
        window.addEventListener('message', function(e) {
          document.getElementById('out').innerHTML = String(e.data);
        });
      </script>");
SetupPage(FixtureUrl("/flows"), html, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/flows"));
await WaitForIdle();
await InstallRuntimeSensorAsync();

await ExecuteJs("""
  setTimeout(function() {
    window.dispatchEvent(new MessageEvent('message', {
      data: '<img src=x onerror=alert(1)>',
      origin: 'https://evil.trowser.test'
    }));
  }, 150);
  return 'scheduled';
  """);

var observed = await RunDomFlowsAsync("observe", waitMs: 400);
Log(observed.Summary);
Assert.True(observed.Chains.Count >= 1, "at least one flow chain");
Assert.True(observed.Chains.Any(c => c.Sink.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)),
    "innerHTML sink in flow chain");

Assert.Section("client-surface embeds domFlows");
var surface = await MapClientSurfaceAsync(installSensor: false, waitMs: 100);
Assert.True(surface.DomFlows.Count >= 1, "client-surface includes domFlows");

Assert.Section("storage probe on static page — no exploitable self-calibration exec");
await ResetBrowserState();
ClearMocks();
var staticHtml = MinimalHtml("Static", "<h1>No scripts</h1><p>Static control page.</p>");
SetupPage(FixtureUrl("/static-storage-probe"), staticHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/static-storage-probe"));
await WaitForIdle();
await InstallRuntimeSensorAsync();

var probed = await RunDomFlowsAsync("probe", sources: new[] { "storage" });
Log($"storage probe: {probed.Summary} exploitable={probed.ExploitableChainCount}");
Assert.True(probed.ExploitableChainCount == 0,
    "storage probe must not report exploitable exec from Trowser self-injection on a static page");
Assert.True(!probed.Chains.Any(c => c.Tier == "exploitable" && c.Consequence == "exec"),
    "no exploitable exec chains from storage probe self-test");

Assert.Section("hash-router probe mutates existing q param (not only trowser_q)");
await ResetBrowserState();
ClearMocks();
var hashHtml = MinimalHtml("HashProbe",
    @"<div id=""out""></div>
      <script>
        function applyHashQ() {
          var h = location.hash || '';
          var q = h.indexOf('q=');
          if (q < 0) return;
          var val = h.slice(q + 2).split('&')[0];
          try { val = decodeURIComponent(val); } catch(e) {}
          document.getElementById('out').innerHTML = val;
        }
        applyHashQ();
        window.addEventListener('hashchange', applyHashQ);
      </script>");
SetupPage(FixtureUrl("/hash-probe"), hashHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/hash-probe") + "#/search?q=apple");
await WaitForIdle();
await InstallRuntimeSensorAsync();
var hashProbed = await RunDomFlowsAsync("probe", sources: new[] { "url-query" });
Log($"hash probe: {hashProbed.Summary} exploitable={hashProbed.ExploitableChainCount}");
Assert.True(hashProbed.Chains.Any(c => c.Sink.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)),
    "probe should drive hash q= into innerHTML (mutate existing param, not only trowser_q)");

Assert.Section("setAttribute href with script substring is hygiene/inert not exploitable exec");
await ResetBrowserState();
ClearMocks();
var hrefHtml = MinimalHtml("HrefSet",
    @"<a id=""lnk""></a>
      <script>
        var u = '/catalog?searchTerm=' + encodeURIComponent(location.search.split('term=')[1] || '');
        document.getElementById('lnk').setAttribute('href', u);
      </script>");
SetupPage(FixtureUrl("/href-set"), hrefHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/href-set") + "?term=%3Cscript%3Ealert(1)%3C%2Fscript%3E");
await WaitForIdle();
await InstallRuntimeSensorAsync();
await Task.Delay(300);
var hrefFlows = await RunDomFlowsAsync("observe", waitMs: 200);
Log(hrefFlows.Summary);
Assert.True(!hrefFlows.Chains.Any(c => c.Tier == "exploitable" && c.Consequence == "exec" && c.Sink == "setAttribute"),
    "href setAttribute must not grade as exploitable exec");

Assert.Section("observe only counts events since this call (not stale session buffer)");
await ExecuteJs("document.getElementById('lnk').setAttribute('href', '/still-stale');");
await Task.Delay(200);
var secondObserve = await RunDomFlowsAsync("observe", waitMs: 100);
Assert.True(secondObserve.EventCount < hrefFlows.EventCount + 500,
    "second observe should slice since mark, not replay entire sensor history");
