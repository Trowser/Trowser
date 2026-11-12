// @title Responsive Accessibility
// @shadow light
// @effects none
// WCAG AA accessibility check across all responsive viewport sizes

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Responsive accessibility check: {title}");
Log($"URL: {url}");
Log("");

var presets = new[] { "SmallPhone", "BigPhone", "LandscapePhone", "SmallPad", "BigPad", "Desktop", "BigDesktop" };

foreach (var preset in presets)
{
    Assert.Section(preset);
    await SetViewport(preset);
    await Sleep(500);

    var (w, h) = await GetViewportSize();
    Log($"Testing {preset} ({w}×{h})...");

    await AssertAccessible("AA");
//    Assert.Equal(0, GetConsoleErrors().Count, $"No JS errors at {preset}");
}

await ResetViewport();
Log("");
Log("Responsive accessibility check complete.");
