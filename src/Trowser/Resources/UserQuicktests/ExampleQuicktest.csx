// === Example user quicktest ===
// A quicktest is just a Trowser C# script (.csx). Drop your own .csx files into this
// folder and they appear under the Quicktests button in the "UserScripts" submenu.
//
// Clicking a UserScripts item loads the script into the Script Console so you can read
// it and press Run. The same globals available to built-in quicktests are available here
// (Log, Assert, navigation, DOM inspection, network, etc.). See README.md in this folder
// and trowserkit/scripting-reference.md for the full API.
//
// This example does a tiny, safe health check of whatever page is currently open.

await WaitForIdle(100, 5000);
await WaitForElement("body", 15000);

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Example quicktest on: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Page basics");
Assert.NotEmpty(url, "Page has a URL");
Assert.NotEmpty(title, "Page has a title");

var headings = await GetHeadings();
Assert.True(headings.Any(h => h["level"] == "h1"), "Page has an h1 heading");
Log($"  Headings: {headings.Count}, Links: {(await GetLinks()).Count}, Images: {(await GetImages()).Count}");

Assert.Section("No obvious errors");
var consoleErrors = GetPageConsoleErrors();
Assert.Equal(0, consoleErrors.Count, $"No JavaScript console errors ({consoleErrors.Count} found)");

var netErrors = Network.FindPageErrors();
Assert.Equal(0, netErrors.Count, $"No HTTP errors ({netErrors.Count} found)");
