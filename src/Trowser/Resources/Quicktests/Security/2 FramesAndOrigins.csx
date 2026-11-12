// @title 2 Frames And Origins
// @shadow never
// @effects mutates
// List browsing contexts: iframes (including cross-origin) with origin,
// inspectable, and outOfScope flags. Use ExecuteJsInFrame / execute-js frame=
// to read inspectable cross-origin frames.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Frames & origins: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Frame tree");
var frames = await GetFrames();
Log($"{frames.Count} frame(s)");
foreach (var f in frames)
{
    f.TryGetValue("frameId", out var fid);
    f.TryGetValue("name", out var name);
    f.TryGetValue("origin", out var origin);
    f.TryGetValue("sameOrigin", out var same);
    f.TryGetValue("inspectable", out var inspectable);
    f.TryGetValue("outOfScope", out var oos);
    Log($"  {fid} name={name} origin={origin} sameOrigin={same} inspectable={inspectable} outOfScope={oos}");
}

Assert.Pass(frames.Count == 0
    ? "No iframes on this page"
    : $"{frames.Count} frame(s) listed (cross-origin rows are inspectable when a WebView2 handle is registered)");
