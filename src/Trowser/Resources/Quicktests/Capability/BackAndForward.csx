// @title Back And Forward
// @shadow light
// @effects none
// Navigate Back 10 times, then Forward 10 times, verify page is unchanged

var originalUrl = await GetCurrentUrl();
var originalTitle = await GetTitle();
Log($"Starting page: {originalTitle}");
Log($"URL: {originalUrl}");
Log("");

Log("Going Back 10 times...");
for (int i = 1; i <= 10; i++)
{
    await GoBack();
    await Sleep(300);
}
await WaitForIdle(500, 5000);

var backUrl = await GetCurrentUrl();
Log($"  Reached: {backUrl}");
Log("");

Log("Going Forward 10 times...");
for (int i = 1; i <= 10; i++)
{
    await GoForward();
    await Sleep(300);
}
await WaitForIdle(500, 5000);

var finalUrl = await GetCurrentUrl();
var finalTitle = await GetTitle();
Log($"  Reached: {finalUrl}");
Log("");

Assert.Equal(originalUrl, finalUrl, "URL is the same after Back+Forward");
Assert.Equal(originalTitle, finalTitle, "Title is the same after Back+Forward");
