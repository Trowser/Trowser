// @title Screen Reader Texts
// @shadow light
// @effects none
// Screen reader strings: alt, aria-*, title, SVG title/desc (including shadow DOM).

var text = await GetScreenReaderTexts();
Log($"URL: {await GetCurrentUrl()}");
Log($"Lines: {(string.IsNullOrEmpty(text) ? 0 : text.Split('\n').Length)}");
Log("");

foreach (var line in text.Split('\n', StringSplitOptions.None))
    Log(line);
