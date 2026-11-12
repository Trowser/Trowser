// @title Get All Page Strings
// @shadow light
// @effects none
// Every text node on the page (including hidden/off-screen), one line per segment — for proof-reading.

var all = await GetAllPageText();
Log($"URL: {await GetCurrentUrl()}");
Log($"Segments: {(string.IsNullOrEmpty(all) ? 0 : all.Split('\n').Length)}");
Log("");

foreach (var line in all.Split('\n', StringSplitOptions.None))
    Log(line);
