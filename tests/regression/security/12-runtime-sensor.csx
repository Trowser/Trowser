// Security: shared runtime sensor — sinks, listeners, inventory on zero payload hits.

await ResetBrowserState();

Assert.Section("Sensor captures innerHTML sink + message listener");
var html = MinimalHtml("Sensor",
    @"<div id=""out""></div>
      <script>
        window.addEventListener('message', function(e) {
          document.getElementById('out').innerHTML = String(e.data);
        });
        // Also fire a sink from URL hash for inventory
        if (location.hash) {
          document.getElementById('out').innerHTML = location.hash.slice(1);
        }
      </script>");
SetupPage(FixtureUrl("/sensor"), html, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/sensor"));
await WaitForIdle();
await InstallRuntimeSensorAsync();
await ExecuteJs("document.getElementById('out').innerHTML = '<b>direct</b>'");
await ExecuteJs("window.dispatchEvent(new MessageEvent('message',{data:'<i>via-pm</i>',origin:'https://evil.trowser.test'}))");
await Task.Delay(300);

var surface = await MapClientSurfaceAsync(installSensor: false, waitMs: 200);
Log($"Sinks: {string.Join(", ", surface.Sinks.Select(s => s.Name))}");
Log($"Listeners: {surface.Listeners.Count}");
Assert.True(surface.Sinks.Any(s => s.Name == "innerHTML"), "innerHTML sink observed");
Assert.True(surface.Listeners.Any(l => l.Type == "message"),
    "message listener surface reported");
Assert.True(surface.NextActions.Count > 0, "nextActions present");
Assert.True(surface.Coverage.Instrumented.Count > 0, "instrumented inventory present");

Assert.Section("trace-input monitorSinks returns inventory even without payload match");
ClearMocks();
SetupPage(FixtureUrl("/trace-sink"), MinimalHtml("Trace",
    @"<input id=""q"" /><button id=""go"">Go</button>
      <div id=""out""></div>
      <script>
        document.getElementById('go').onclick = function() {
          document.getElementById('out').innerHTML = 'static';
        };
      </script>"), ScriptableHeaders());
await Navigate(FixtureUrl("/trace-sink"));
await WaitForIdle();
var trace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.Form,
    TargetSelector = "#q",
    SubmitSelector = "#go",
    Payload = "<script>alert(1)</script>",
    MonitorSinks = true,
    AutoBypass = false,
    ProbeUrlSources = false
});
Assert.True(trace.Sinks != null && trace.Sinks.Monitored, "sinks monitored");
Assert.True(trace.Sinks!.Instrumented.Count > 0, "instrumented list returned on zero/mismatched hits");
Log($"hitCount={trace.Sinks.HitCount} zeroReason={trace.Sinks.ZeroResultReason} sinksSeen={string.Join(",", trace.Sinks.SinksSeen)}");

Assert.Section("trace-input window-name reload keeps sensor and detects innerHTML");
ClearMocks();
SetupPage(FixtureUrl("/trace-wn"), MinimalHtml("TraceWN",
    @"<div id=""out""></div><script>document.getElementById('out').innerHTML = window.name;</script>"),
    ScriptableHeaders());
await Navigate(FixtureUrl("/trace-wn"));
await WaitForIdle();
var wnTrace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.WindowName,
    Payload = "<img src=x onerror=alert(1)>",
    MonitorSinks = true,
    AutoBypass = false
});
Assert.True(wnTrace.Sinks != null && wnTrace.Sinks.PayloadReachedSink,
    "window-name reload should reach innerHTML sink with payload");
Assert.True(wnTrace.Verdict.Severity >= Severity.High,
    $"expected high/critical verdict, got {wnTrace.Verdict.Severity}");

Assert.Section("trace-input inert script via innerHTML — not CRITICAL without execution");
await ResetBrowserState();
ClearMocks();
var inertHtml = MinimalHtml("InertScript",
    @"<div id=""out""></div>
      <script>
        function applyHashQ() {
          var h = location.hash || '';
          var q = h.indexOf('q=');
          if (q < 0) return;
          var val = h.slice(q + 2).split('&')[0];
          try { val = decodeURIComponent(val.replace(/\+/g, ' ')); } catch(e) {}
          document.getElementById('out').innerHTML = val;
        }
        applyHashQ();
        window.addEventListener('hashchange', applyHashQ);
      </script>");
SetupPage(FixtureUrl("/trace-inert"), inertHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/trace-inert") + "#/search?q=baseline");
await WaitForIdle();
var inertTrace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.UrlQuery,
    QueryParam = "q",
    BaseUrl = FixtureUrl("/trace-inert") + "#/search",
    Payload = "<script>alert(1)</script>",
    MonitorSinks = true,
    AutoBypass = false,
    TwoPhase = false,
    QueryEncode = UrlPayloadEncodeMode.None,
    ProbeUrlSources = false
});
Assert.True(inertTrace.Dom?.PayloadRendered == true && inertTrace.Dom.Dangerous,
    "payload should render as inert script-content in DOM");
Log($"inert verdict={inertTrace.Verdict.Severity} exec={inertTrace.Sinks?.ExecutionConfirmed} ctx={inertTrace.Dom?.Context}");
Assert.True(inertTrace.Verdict.Severity == Severity.High,
    "inert script DOM should cap at HIGH without execution oracle");
Assert.True(inertTrace.Verdict.Severity != Severity.Critical,
    "must not claim CRITICAL for inert innerHTML script");
Assert.True(inertTrace.Sinks?.ExecutionConfirmed != true, "execution oracle must not fire");

Assert.Section("twoPhase explicit script payload confirms with event-handler on executable innerHTML");
await ResetBrowserState();
ClearMocks();
var execHashHtml = MinimalHtml("ExecHash",
    @"<div id=""out""></div>
      <script>
        function applyHashQ() {
          var h = location.hash || '';
          var q = h.indexOf('q=');
          if (q < 0) return;
          var val = h.slice(q + 2).split('&')[0];
          try { val = decodeURIComponent(val.replace(/\+/g, ' ')); } catch(e) {}
          document.getElementById('out').innerHTML = val;
        }
        applyHashQ();
        window.addEventListener('hashchange', applyHashQ);
      </script>");
SetupPage(FixtureUrl("/trace-exec-hash"), execHashHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/trace-exec-hash") + "#/search?q=baseline");
await WaitForIdle();
var execHashTrace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.UrlQuery,
    QueryParam = "q",
    BaseUrl = FixtureUrl("/trace-exec-hash") + "#/search",
    Payload = "<script>alert(1)</script>",
    MonitorSinks = true,
    AutoBypass = false,
    TwoPhase = true,
    QueryEncode = UrlPayloadEncodeMode.None,
    ProbeUrlSources = false
});
Log($"execHash twoPhase verdict={execHashTrace.Verdict.Severity} exec={execHashTrace.Sinks?.ExecutionConfirmed}");
Assert.True(execHashTrace.Verdict.Severity == Severity.Critical,
    "twoPhase should upgrade script primary to img/onerror confirm and reach CRITICAL when oracle fires");

Assert.Section("trace-input form selector miss surfaces formInteractionFailed");
await ResetBrowserState();
ClearMocks();
SetupPage(FixtureUrl("/trace-form-miss"), MinimalHtml("FM", "<input id=\"q\" />"), ScriptableHeaders());
await Navigate(FixtureUrl("/trace-form-miss"));
await WaitForIdle();
var missTrace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.Form,
    TargetSelector = "[name='input']",
    SubmitSelector = "#nope",
    Payload = "<script>alert(1)</script>",
    MonitorSinks = false,
    AutoBypass = false,
    ProbeUrlSources = false,
    TwoPhase = false
});
Assert.True(missTrace.Injection.FormInteractionFailed, "missing selector must set formInteractionFailed");
Assert.True(missTrace.Injection.TargetElementsMatched == 0, "targetElementsMatched should be 0");
Assert.True(missTrace.Injection.FormInteractionFailureReason?.Contains("0 elements") == true,
    "failure reason should mention zero matches");

Assert.Section("trace-input search box → API query is info not high XSS");
await ResetBrowserState();
ClearMocks();
var searchApiBase = FixtureUrl("/api/list/search?searchText=");
MockResponse(FixtureUrl("/api/list/search?searchText=probe"), statusCode: 200, body: "{\"hits\":[]}", headers: JsonHeaders());
var searchHtml = MinimalHtml("SearchStaff",
    @"<input id=""q"" type=""search"" />
      <button id=""go"">Search</button>
      <div id=""out""></div>
      <script>
        document.getElementById('go').onclick = function() {
          var t = document.getElementById('q').value;
          fetch('" + searchApiBase + @"' + encodeURIComponent(t))
            .then(function(r){ return r.text(); })
            .then(function(body){ document.getElementById('out').textContent = body; });
        };
      </script>");
SetupPage(FixtureUrl("/staff/search-staff"), searchHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/staff/search-staff"));
await WaitForIdle();
var probe = "https://example.test/trowser-probe";
var searchTrace = await TraceInputAsync(new TraceInputOptions
{
    Source = TraceSourceType.Form,
    TargetSelector = "#q",
    SubmitSelector = "#go",
    Payload = probe,
    MonitorSinks = true,
    AutoBypass = false,
    TwoPhase = false,
    ProbeUrlSources = false
});
Log($"search trace verdict={searchTrace.Verdict.Severity} payloadReached={searchTrace.Sinks?.PayloadReachedSink}");
Assert.True(searchTrace.Verdict.Severity < Severity.High,
    "search/API query parameter taint should not grade as high XSS");
Assert.True(searchTrace.Verdict.Severity != Severity.Critical, "must not be critical");

Assert.Section("xss-scan skips blind hash q/search/query when app ignores hash params");
await ResetBrowserState();
ClearMocks();
var apiSearch = FixtureUrl("/api/search?term=");
var angularSearch = MinimalHtml("AngularSearch",
    @"<input id=""q"" /><button id=""go"">Go</button>
      <script>
        document.getElementById('go').onclick = function() {
          fetch('" + apiSearch + @"' + encodeURIComponent(document.getElementById('q').value));
        };
      </script>");
SetupPage(FixtureUrl("/staff/search-staff"), angularSearch, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/staff/search-staff") + "#/route");
await WaitForIdle();
var xssScan = await RunXssScan(new XssScanRunner.XssScanOptions
{
    IncludeReflected = false,
    IncludeDom = true,
    IncludeGenericScaffold = true,
    MaxCandidates = 10,
    Depth = "standard"
});
var domFindings = xssScan.Findings.Where(f => f.Category == "xss-dom").ToList();
Log($"xss-scan dom findings={domFindings.Count} candidates={xssScan.CandidatesProbed}");
Assert.True(!domFindings.Any(f =>
        f.Param == "q" || f.Param == "search" || f.Param == "query"),
    "must not report DOM XSS on guessed hash params the app never reads");
