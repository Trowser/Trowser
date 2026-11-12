// Security: client-side prototype pollution — vulnerable merge vs clean twin.

await ResetBrowserState();

Assert.Section("Vulnerable URL merge → pollution");
var vuln = MinimalHtml("PP Vuln",
    @"<script>
        // Naive merge of query into Object.prototype (classic client PP)
        (function(){
          var q = location.search.slice(1);
          if (!q) return;
          var parts = q.split('&');
          for (var i=0;i<parts.length;i++){
            var kv = parts[i].split('=');
            var key = decodeURIComponent(kv[0]||'');
            var val = decodeURIComponent(kv[1]||'');
            var m = key.match(/^__proto__\[([^\]]+)\]$/);
            if (m) { Object.prototype[m[1]] = val; }
          }
        })();
      </script>
      <div id=""out""></div>");
ClearMocks();
MockResponse(FixtureUrl("/pp-vuln"), statusCode: 200, body: vuln, headers: ScriptableHeaders());
MockResponse(FixtureUrl("/pp-vuln?*"), statusCode: 200, body: vuln, headers: ScriptableHeaders());
await Navigate(FixtureUrl("/pp-vuln"));
await WaitForIdle();
var bad = await ScanClientPrototypePollutionAsync(FixtureUrl("/pp-vuln"), tryGadgets: false);
Log($"vuln findings={bad.Findings.Count} probes={bad.Probes.Count}");
foreach (var p in bad.Probes)
    Log($"  {p.Vector}: polluted={p.Polluted} err={p.Error}");
ExpectFindings(bad.Findings.Count, "client-prototype-pollution");
Assert.True(bad.Probes.Any(p => p.Polluted), "At least one vector polluted Object.prototype");

Assert.Section("Clean twin → no pollution");
ClearMocks();
var clean = MinimalHtml("PP Clean",
    @"<script>
        // Safe: only allowlisted keys into a plain object
        (function(){
          var allowed = {q:1,page:1};
          var out = {};
          var q = location.search.slice(1);
          q.split('&').forEach(function(part){
            var kv = part.split('=');
            var key = decodeURIComponent(kv[0]||'');
            if (allowed[key]) out[key] = decodeURIComponent(kv[1]||'');
          });
          window.__params = out;
        })();
      </script>");
MockResponse(FixtureUrl("/pp-clean"), statusCode: 200, body: clean, headers: ScriptableHeaders());
MockResponse(FixtureUrl("/pp-clean?*"), statusCode: 200, body: clean, headers: ScriptableHeaders());
await Navigate(FixtureUrl("/pp-clean"));
await WaitForIdle();
var good = await ScanClientPrototypePollutionAsync(FixtureUrl("/pp-clean"), tryGadgets: false);
Log($"clean findings={good.Findings.Count}");
Assert.True(good.Findings.Count < bad.Findings.Count || good.Findings.Count == 0,
    "Clean twin has fewer/zero PP findings");
Assert.True(good.Coverage.ZeroResultReason != null || good.Findings.Count == 0,
    "Clean result includes coverage reason or is empty findings");
