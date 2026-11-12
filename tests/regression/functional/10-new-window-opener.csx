// Functional: window.open preserves window.opener (NewWindow assignment).

await ResetBrowserState();

Assert.Section("window.open child can see opener");
var parentUrl = FixtureUrl("/opener-parent");
var childUrl = FixtureUrl("/opener-child");
ClearMocks();
MockResponse(parentUrl, statusCode: 200,
    body: MinimalHtml("Parent",
        $@"<h1>Parent</h1>
           <button id=""open"">Open</button>
           <script>
             document.getElementById('open').onclick = function() {{
               window.open('{childUrl}', '_blank');
             }};
           </script>"),
    headers: ScriptableHeaders());
MockResponse(childUrl, statusCode: 200,
    body: MinimalHtml("Child",
        @"<h1>Child</h1>
          <div id=""status""></div>
          <script>
            document.getElementById('status').textContent =
              (window.opener && !window.opener.closed) ? 'has-opener' : 'no-opener';
          </script>"),
    headers: ScriptableHeaders());

await Navigate(parentUrl);
await WaitForIdle();
var tabsBefore = Tabs.Count;
await Click("#open");
await Task.Delay(1500);
await WaitForIdle();

Assert.True(Tabs.Count > tabsBefore, "window.open created a new tab");
SwitchTab(Tabs.Count - 1);
await WaitForIdle();
await Task.Delay(500);
var status = UnquoteJson(await ExecuteJs(
    "(function(){ var el=document.getElementById('status'); return el ? el.textContent : 'missing'; })()"));
Log($"Child opener status: {status}");
Assert.Equal("has-opener", status, "Child tab preserves window.opener");
