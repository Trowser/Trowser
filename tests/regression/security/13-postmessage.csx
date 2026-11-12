// Security: postMessage listener origin-check grading + synthetic fuzz.

await ResetBrowserState();

Assert.Section("No origin check → finding");
var noCheck = MinimalHtml("PM None",
    @"<div id=""out""></div>
      <script>
        window.addEventListener('message', function(e) {
          document.getElementById('out').innerHTML = e.data;
        });
      </script>");
SetupPage(FixtureUrl("/pm-none"), noCheck, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-none"));
await WaitForIdle();
await Task.Delay(200);
var noneResult = await AuditPostMessageAsync("safe", fuzz: true, maxPayloads: 4);
Log($"none: listeners={noneResult.Listeners.Count} findings={noneResult.Findings.Count}");
foreach (var l in noneResult.Listeners)
    Log($"  listener originCheck={l.OriginCheck}");
Assert.True(noneResult.Listeners.Any(l => l.OriginCheck == "none")
            || noneResult.Findings.Any(f => f.Category == "postmessage"),
    "Missing origin check detected");
Assert.True(noneResult.Coverage.ZeroResultReason == null || noneResult.Findings.Count > 0
            || noneResult.Listeners.Count > 0, "coverage not a dead end");

Assert.Section("Strict origin check → no critical sink finding from foreign origin");
ClearMocks();
var strict = MinimalHtml("PM Strict",
    @"<div id=""out""></div>
      <script>
        window.addEventListener('message', function(e) {
          if (e.origin !== 'https://trusted.example') return;
          document.getElementById('out').innerHTML = e.data;
        });
      </script>");
SetupPage(FixtureUrl("/pm-strict"), strict, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-strict"));
await WaitForIdle();
await Task.Delay(200);
var strictResult = await AuditPostMessageAsync("safe", fuzz: true, maxPayloads: 4);
Log($"strict: listeners={strictResult.Listeners.Count} findings={strictResult.Findings.Count}");
Assert.True(strictResult.Listeners.Any(l => l.OriginCheck == "strict")
            || !strictResult.Findings.Any(f => f.Severity == "critical"),
    "Strict listener graded or no critical sink reach");

Assert.Section("Weak origin check graded");
ClearMocks();
var weak = MinimalHtml("PM Weak",
    @"<script>
        window.addEventListener('message', function(e) {
          if (e.origin.indexOf('example') >= 0) { /* weak */ }
        });
      </script>");
SetupPage(FixtureUrl("/pm-weak"), weak, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-weak"));
await WaitForIdle();
await Task.Delay(200);
var weakResult = await AuditPostMessageAsync("safe", fuzz: false);
Assert.True(weakResult.Listeners.Any(l => l.OriginCheck is "weak" or "none"),
    "Weak/none origin check graded");

Assert.Section("active attacker iframe blocked — no critical sink finding from browser chrome");
await ResetBrowserState();
ClearMocks();
SetupPage(FixtureUrl("/pm-active-chrome"), noCheck, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-active-chrome"));
await WaitForIdle();
// Do not mock https://evil.trowser.test/pm-attacker — iframe fails to load; sinks must not become critical.
var activeChrome = await AuditPostMessageAsync("active", fuzz: false);
var activeCritical = activeChrome.Findings.Count(f => f.Severity == "critical");
Log($"active blocked iframe: findings={activeChrome.Findings.Count} critical={activeCritical}");
Assert.True(!activeChrome.Findings.Any(f =>
        f.Severity == "critical"
        && f.Title.Contains("Attacker-origin", StringComparison.OrdinalIgnoreCase)),
    "blocked attacker iframe must not produce critical app sink finding");

Assert.Section("active child-iframe — confirmed sink on none origin check");
ClearMocks();
// No frame-src in CSP — ScriptableHeaders blocks evil.trowser.test child iframes (default-src 'self').
SetupPage(FixtureUrl("/pm-active-tp"), noCheck, VulnerableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-active-tp"));
await WaitForIdle();
await Task.Delay(200);
var activeTp = await AuditPostMessageAsync("active", fuzz: false, maxPayloads: 4);
var tpCritical = activeTp.Findings.Count(f => f.Severity == "critical");
Log($"active true-positive fixture: findings={activeTp.Findings.Count} critical={tpCritical} techniques={activeTp.Techniques.Count}");
Assert.True(activeTp.Findings.Any(f =>
        f.Severity == "critical"
        && f.Title.Contains("Attacker-origin", StringComparison.OrdinalIgnoreCase)),
    "Mocked child-iframe should confirm trusted cross-origin sink reach");
Assert.True(activeTp.Techniques.Any(t => t.Verdict == "sink-reached"),
    "Technique row should record sink-reached");

Assert.Section("Schema-gated handler — generic trowser type ignored");
ClearMocks();
var schemaGate = MinimalHtml("PM Schema",
    @"<div id=""out""></div>
      <script>
        window.addEventListener('message', function(e) {
          if (e.data && e.data.type === 'resize') {
            document.getElementById('out').innerHTML = e.data.html;
          }
        });
      </script>");
SetupPage(FixtureUrl("/pm-schema"), schemaGate, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/pm-schema"));
await WaitForIdle();
await Task.Delay(200);
// Safe mode: static grade only — active child-iframe proof may send schema-matching payloads by design.
var schemaResult = await AuditPostMessageAsync("safe", fuzz: false);
Assert.True(!schemaResult.Findings.Any(f => f.Severity == "critical"),
    "Schema-gated handler should not critical without matching type payload");

Assert.Section("Synthetic fuzz does not emit critical");
Assert.True(!noneResult.Findings.Any(f =>
        f.Severity == "critical"
        && f.Extra != null
        && f.Extra.TryGetValue("screening", out var scr)
        && scr is true),
    "Synthetic screening must not produce critical findings");
