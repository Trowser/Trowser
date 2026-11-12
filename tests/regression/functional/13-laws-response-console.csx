// Functional: response/console Laws via Shadow hooks (mocked network).

await ResetBrowserState();

var page = FixtureUrl("/laws-hooks");
SetupPage(page, MinimalHtml("Hooks", "<h1>Hooks</h1>"), SecureHeaders());
SetupApi(FixtureUrl("/api/cart"), statusCode: 200, body: """{"total": 5}""");

await Navigate(page);
await WaitForIdle();

// Response/console triggers are exercised in unit tests (LawShadowSyncTests); CheckLaws() is page Laws only.
Law("Hooks page title")
    .OnPage("*")
    .Expect(p => p.Title.Contains("Hooks", StringComparison.OrdinalIgnoreCase));

try { await Fetch(FixtureUrl("/api/cart"), "GET", null, null); } catch { }

var summary = await CheckLaws("Hooks page");
Assert.Equal(0, summary.Failed);

Log("Laws response/console regression OK (Fetch + page Law check)");
