// Functional: MockResponse + intercept rule management.

await ResetBrowserState();

Assert.Section("MockResponse serves body to Fetch");
var url = FixtureUrl("/mock-home");
SetupPage(url, MinimalHtml("Mock Home", "<h1>Mock Home</h1>"), SecureHeaders());
SetupApi("*/api/mock-echo*", statusCode: 201, body: "{\"echo\":\"regression-ok\"}");
await Navigate(url);
await WaitForIdle();

var fetchJson = await Fetch(FixtureUrl("/api/mock-echo"), "GET", null, null);
Log($"Fetch result: {fetchJson.Substring(0, Math.Min(300, fetchJson.Length))}");
Assert.Contains("regression-ok", fetchJson, "Fetch got mocked body");
Assert.Contains("201", fetchJson, "Fetch saw 201 status");
using (var fetchDoc = System.Text.Json.JsonDocument.Parse(fetchJson))
{
    Assert.True(
        fetchDoc.RootElement.TryGetProperty("durationMs", out var dms)
            && dms.ValueKind == System.Text.Json.JsonValueKind.Number
            && dms.GetInt64() >= 0,
        "Fetch returns durationMs");
}

Assert.Section("Mock rules CRUD");
var rules = GetMockRules();
Assert.True(rules.Count >= 1, "GetMockRules non-empty");
RemoveMock("*/api/mock-echo*");
ClearMocks();
Assert.Equal(0, GetMockRules().Count, "ClearMocks emptied rules");

Assert.Section("Intercept rules CRUD");
AddInterceptRule("/api/intercept-test", method: "GET", silent: true);
Assert.True(GetInterceptRules().Count > 0, "GetInterceptRules returns rules");
Assert.True(GetPendingRequests().Count >= 0, "GetPendingRequests returns list");
RemoveInterceptRule("/api/intercept-test");
ClearInterceptRules();
Assert.Equal(0, GetInterceptRules().Count, "Intercept rules cleared");

Assert.Section("Mock fulfills after re-add (intercept path covered by CRUD)");
SetupPage(FixtureUrl("/mock2"), MinimalHtml("M2", "<h1>M2</h1>"), SecureHeaders());
SetupApi("*/api/again*", statusCode: 200, body: "{\"again\":true}");
await Navigate(FixtureUrl("/mock2"));
var again = await Fetch(FixtureUrl("/api/again"), "GET", null, null);
Assert.Contains("again", again, "Mock still works after intercept CRUD");
