// Functional: WaitForElement / WaitForRequest with delayed mocks.

await ResetBrowserState();

Assert.Section("WaitForElement after delayed script injection");
var url = FixtureUrl("/wait");
var html = MinimalHtml("Wait",
    @"<h1>Waiting</h1>
      <div id=""host""></div>
      <script>
        setTimeout(function() {
          var el = document.createElement('div');
          el.id = 'late';
          el.textContent = 'arrived';
          document.getElementById('host').appendChild(el);
        }, 400);
      </script>");
SetupPage(url, html, ScriptableHeaders());
await Navigate(url);
await WaitForElement("#late", 5000);
Assert.Equal("arrived", await GetText("#late"), "Late element appeared");

Assert.Section("WaitForRequest against delayed API mock");
ClearMocks();
SetupPage(FixtureUrl("/wait2"), MinimalHtml("Wait2",
    @"<h1>W2</h1>
      <script>
        setTimeout(function() {
          fetch('/api/delayed').then(function(r){ return r.json(); }).then(function(j){
            document.title = 'got-' + j.ok;
          });
        }, 200);
      </script>"), ScriptableHeaders());
SetupApi("*/api/delayed*", statusCode: 200, body: "{\"ok\":true}", delayMs: 100);
await Navigate(FixtureUrl("/wait2"));
await WaitForRequest("/api/delayed", 5000);
Assert.Pass("WaitForRequest saw delayed API call");
await Sleep(400);
Assert.Contains("got-true", await GetTitle(), "Page updated after fetch");
