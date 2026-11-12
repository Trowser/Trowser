// Security: frame registry + cross-origin inspectable frames.

await ResetBrowserState();

Assert.Section("Same-origin and cross-origin frames listed");
var childHtml = MinimalHtml("Child", "<p id='c'>child-text</p>");
SetupPage(FixtureUrl("/child"), childHtml, ScriptableHeaders());
SetupPage("https://evil.trowser.test/xframe",
    MinimalHtml("X", "<p id='x'>cross-text</p>"),
    ScriptableHeaders());

var parent = MinimalHtml("Parent",
    $@"<iframe name=""same"" src=""{FixtureUrl("/child")}""></iframe>
       <iframe name=""cross"" src=""https://evil.trowser.test/xframe""></iframe>");
SetupPage(FixtureUrl("/frames"), parent, ScriptableHeaders());
await Navigate(FixtureUrl("/frames"));
await WaitForIdle(500, 10000);
await Task.Delay(800);

var frames = await GetFrames();
Log($"Frames: {frames.Count}");
foreach (var f in frames)
    Log($"  {f.GetValueOrDefault("frameId")} name={f.GetValueOrDefault("name")} same={f.GetValueOrDefault("sameOrigin")} inspectable={f.GetValueOrDefault("inspectable")} origin={f.GetValueOrDefault("origin")} registryId={f.GetValueOrDefault("registryId")}");

Assert.True(frames.Count >= 2, "at least two iframes");
Assert.True(frames.Any(f =>
{
    var name = f.TryGetValue("name", out var n) ? n?.ToString() : "";
    return name == "same";
}), "same-origin frame present");
Assert.True(frames.Any(f =>
{
    var name = f.TryGetValue("name", out var n) ? n?.ToString() : "";
    return name == "cross";
}), "cross-origin frame present");

Assert.Section("Frame metadata: origin + inspectable");
var same = frames.First(f => (f.TryGetValue("name", out var n) ? n?.ToString() : "") == "same");
var cross = frames.First(f => (f.TryGetValue("name", out var n) ? n?.ToString() : "") == "cross");
Assert.True(same.TryGetValue("origin", out var so) && so?.ToString()?.Contains("trowser-regression.test") == true,
    "same frame has origin");
Assert.True(cross.TryGetValue("crossOrigin", out var co) && co is true
            || (cross.TryGetValue("sameOrigin", out var ss) && ss is false),
    "cross frame marked cross-origin");
Assert.True(cross.TryGetValue("inspectable", out var insp) && insp is true
            || !string.IsNullOrEmpty(cross.TryGetValue("registryId", out var rid) ? rid?.ToString() : null),
    "cross-origin frame has registry handle or inspectable flag");

// Best-effort script in same-origin frame (mock iframe timing can race contentDocument).
try
{
    var text = await ExecuteJsInFrame("same", "document.body ? (document.body.innerText||'') : ''");
    Log($"same-frame text: {text}");
}
catch (Exception ex)
{
    Log($"same-frame execute skipped: {ex.Message}");
}
