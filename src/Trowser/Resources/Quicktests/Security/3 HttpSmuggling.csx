// @title 3 Http Smuggling
// @shadow never
// @effects mutates
// HTTP request smuggling: one origin-level raw-TCP scan against the current page.
// Act only on confirmed differential-response (repeated canary 404).
// Timing / CL-CL / HEADER / TE obfuscation are architecture notes, not bugs.
// confirmBackend is implicit in scripting; blocked in --safe mode.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"HTTP smuggling probe: {title}");
Log($"URL: {url}");
Log("For the most reliable results, use BurpSuite HTTP Request Smuggler");
Log("");

Assert.Section("Request smuggling probing");
var result = await RunHttpSmugglingScan();
PrintHttpSmugglingReport(result);
if (string.Equals(result.Verdict, "confirmed", StringComparison.OrdinalIgnoreCase))
    Assert.Fail($"Confirmed HTTP request smuggling (differential 404) on {url}");
else
    Assert.Pass($"verdict={result.Verdict} (confirmed={result.ConfirmedFindings.Count()} notes={result.NoteFindings.Count()})");
