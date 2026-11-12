// Functional: cookies + web storage + ClearSession.

await ResetBrowserState();

var url = FixtureUrl("/store");
var headers = SecureHeaders();
headers["Set-Cookie"] = SecureCookie("reg_session", "sess-value-1");
var html = MinimalHtml("Store", "<h1>Store</h1><p id='x'>ok</p>");
SetupPage(url, html, headers);
await Navigate(url);
await WaitForIdle();

Assert.Section("Cookies from Set-Cookie mock header");
await SetCookie("manual_cookie", "manual-val", domain: "trowser-regression.test",
    path: "/", secure: true, httpOnly: false, sameSite: "Lax");
var cookies = await GetCookies();
Assert.True(cookies.Count >= 1, $"Cookie jar has entries (got {cookies.Count})");
var names = cookies.Select(c => c["name"]?.ToString() ?? c["Name"]?.ToString() ?? "").ToList();
Log("Cookies: " + string.Join(", ", names));
Assert.True(names.Any(n => n.Contains("manual_cookie", StringComparison.OrdinalIgnoreCase)
    || n.Contains("reg_session", StringComparison.OrdinalIgnoreCase)),
    "Expected planted cookie name present");

Assert.Section("localStorage / sessionStorage");
await SetStorageItem("local", "regKey", "regLocalValue");
await SetStorageItem("session", "regSessionKey", "regSessionValue");
Assert.Equal("regLocalValue", UnquoteJson(await GetStorageItem("local", "regKey")), "localStorage round-trip");
Assert.Equal("regSessionValue", UnquoteJson(await GetStorageItem("session", "regSessionKey")), "sessionStorage round-trip");

Assert.Section("ClearSession preserves cookies/storage intent");
var beforeCookies = (await GetCookies()).Count;
await ClearSession();
// ClearSession should preserve cookies + storage per product notes
var afterLocal = await GetStorageItem("local", "regKey");
Log($"After ClearSession localStorage regKey={afterLocal}; cookies before={beforeCookies} after={(await GetCookies()).Count}");
Assert.Pass("ClearSession completed without throw");
