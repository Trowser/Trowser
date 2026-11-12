// @title Required Forbidden Strings
// @shadow light
// @effects none
// Check if strings must or must not be on a page.

using System.Net;

var forbidden = new[]
{
    "unknown error",
    "exception"
};

var required = new[]
{
    "company_name",
    "user_name"
};

var raw = await GetAllPageText();
// or use this instead if you want to look at the source code
// var raw = await GetPageSource();
var all = WebUtility.HtmlDecode(raw);

Log($"URL: {await GetCurrentUrl()}");

var segments = string.IsNullOrEmpty(all) ? 0 : all.Split('\n').Length;
Log($"Segments: {segments}");
Log("");

// --- Forbidden check ---
var foundForbidden = new List<string>();

foreach (var f in forbidden)
{
    if (all.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0)
        foundForbidden.Add(f);
}

// --- Required check ---
var missingRequired = new List<string>();

foreach (var r in required)
{
    if (all.IndexOf(r, StringComparison.OrdinalIgnoreCase) < 0)
        missingRequired.Add(r);
}

// --- Logging ---
if (foundForbidden.Any())
{
    Log("FORBIDDEN strings found:");
    foreach (var f in foundForbidden)
        Log($" - {f}");
}
else
{
    Log("No forbidden strings found.");
}

Log("");

if (missingRequired.Any())
{
    Log("REQUIRED strings missing:");
    foreach (var r in missingRequired)
        Log($" - {r}");
}
else
{
    Log("All required strings are present.");
}