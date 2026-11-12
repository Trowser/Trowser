// Functional: navigation against mocked documents (incl. 404/500).

await ResetBrowserState();

Assert.Section("Navigate mocked document");
var url = FixtureUrl("/hello");
var html = MinimalHtml("Hello Fixture", "<h1>Hello Fixture</h1><p>Welcome to regression.</p>");
SetupPage(url, html, SecureHeaders());
await Navigate(url);
await WaitForIdle();

Assert.Contains("trowser-regression.test", await GetCurrentUrl(), "URL is fixture host");
Assert.Equal("Hello Fixture", await GetTitle(), "Title from mock");
Assert.Contains("Welcome to regression", await GetPageText(), "Page text from mock");
Assert.Contains("<h1>", await GetPageSource(), "Page source has h1");

Assert.Section("404 and 500 mocked pages");
ClearMocks();
SetupPage(FixtureUrl("/missing"), MinimalHtml("Not Found", "<h1>404</h1>"), SecureHeaders(), statusCode: 404);
await Navigate(FixtureUrl("/missing"));
await WaitForIdle();
Assert.Contains("404", await GetPageText(), "404 body served");

ClearMocks();
SetupPage(FixtureUrl("/boom"), MinimalHtml("Error", "<h1>500</h1><p>Server Error</p>"),
    SecureHeaders(), statusCode: 500);
await Navigate(FixtureUrl("/boom"));
await WaitForIdle();
Assert.Contains("Server Error", await GetPageText(), "500 body served");

Assert.Section("Back / Forward");
ClearMocks();
SetupPage(FixtureUrl("/a"), MinimalHtml("Page A", "<h1>A</h1>"), SecureHeaders());
SetupPage(FixtureUrl("/b"), MinimalHtml("Page B", "<h1>B</h1>"), SecureHeaders());
// Re-register both — ClearMocks wiped; need both for history navigations
ClearMocks();
MockResponse(FixtureUrl("/a"), statusCode: 200, body: MinimalHtml("Page A", "<h1>A</h1>"), headers: SecureHeaders());
MockResponse(FixtureUrl("/b"), statusCode: 200, body: MinimalHtml("Page B", "<h1>B</h1>"), headers: SecureHeaders());
await Navigate(FixtureUrl("/a"));
await WaitForIdle();
await Navigate(FixtureUrl("/b"));
await WaitForIdle();
Assert.Equal("Page B", await GetTitle(), "On page B");
await GoBack();
await WaitForIdle();
Assert.Equal("Page A", await GetTitle(), "GoBack to A");
await GoForward();
await WaitForIdle();
Assert.Equal("Page B", await GetTitle(), "GoForward to B");
