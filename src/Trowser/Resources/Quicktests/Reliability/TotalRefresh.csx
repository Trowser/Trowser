// @title Total Refresh
// @shadow never
// @effects mutates
// Refresh the current page 100 times and check for errors

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Refresh stress test: {title}");
Log($"URL: {url}");
Log("");

var errorsBefore = GetConsoleErrors().Count;
var networkErrorsBefore = Network.FindErrors().Count;

for (int i = 1; i <= 100; i++)
{
    await Navigate(url);
    await WaitForIdle(300, 5000);

    if (i % 10 == 0)
        Log($"  Refresh {i}/100 complete");
}

var newConsoleErrors = GetConsoleErrors().Count - errorsBefore;
var newNetworkErrors = Network.FindErrors().Count - networkErrorsBefore;

Log("");
Log($"Results after 100 refreshes:");
Log($"  New console errors: {newConsoleErrors}");
Log($"  New network errors: {newNetworkErrors}");

Assert.Equal(0, newConsoleErrors, "No new console errors after 100 refreshes");
Assert.Equal(0, newNetworkErrors, "No new network errors after 100 refreshes");

var finalTitle = await GetTitle();
Assert.Equal(title, finalTitle, "Page title unchanged after refreshes");
