// Functional: Law declare + CheckLaws on a mocked page (Script Console path).

await ResetBrowserState();

var url = FixtureUrl("/law-title");
SetupPage(url, MinimalHtml("LawTitle", "<h1>Regression Title</h1>"), SecureHeaders());
await Navigate(url);
await WaitForIdle();

Law("Page shows expected heading")
    .OnPage("*")
    .Expect(p => p.Text("h1").Contains("Regression"));

var summary = await CheckLaws("Page shows expected");
Assert.Equal(0, summary.Failed);
Assert.True(summary.Results.Any(r => r.Verdict.ToString() == "Pass"));

Law("Intentional fail for oracle")
    .OnPage("*")
    .Expect(p => p.Text("h1").Contains("NOT PRESENT"));

var failSummary = await CheckLaws("Intentional");
Assert.Equal(1, failSummary.Failed);

Log("Laws script check OK");
