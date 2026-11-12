// @title 4 Total Logout Test
// @shadow never
// @effects mutates
// TotalLogoutTest — semi-manual check that logout actually kills the session.
// This test tampers with your cookies and storage, so you might need to restart Trowser afterwards.
//
// Prerequisites: you are logged in, and the current URL is an authenticated-only page
// (dashboard, account, settings — not the login screen).
//
// Flow:
//   1. Capture cookies, localStorage, sessionStorage, and IndexedDB (best effort).
//   2. Pause so you can log out in the browser.
//   3. Re-apply the captured client state and open the original URL.
//      FAIL if that URL (origin + path) is still loaded; PASS if redirected away.
//   4. Hand over: try to log in again. Silent re-auth means logout was not total
//      (IdP/SSO/remember-me still alive).
//
// Not in SurpriseMe (interactive pause). Edit logoutPauseSeconds if 15s is tight.

var logoutPauseSeconds = 15;

var snapshotJs = @"
(function(){
  var text = (document.body && (document.body.innerText || '')) || '';
  var html = document.documentElement ? document.documentElement.outerHTML : '';
  return JSON.stringify({
    title: document.title || '',
    url: location.href,
    origin: location.origin,
    hasPassword: !!document.querySelector('input[type=""password""]'),
    logoutVisible: /log\s*out|sign\s*out|sign\s*off/i.test(text),
    text: text.slice(0, 4000),
    html: html.slice(0, 80000)
  });
})()
";

string Str(Dictionary<string, object> d, string key)
{
    if (!d.TryGetValue(key, out var v) || v == null) return "";
    return v.ToString() ?? "";
}

bool Flag(Dictionary<string, object> d, string key)
{
    if (!d.TryGetValue(key, out var v) || v == null) return false;
    if (v is bool b) return b;
    return bool.TryParse(v.ToString(), out var parsed) && parsed;
}

bool LooksAuthKey(string key)
{
    var k = key.ToLowerInvariant();
    return k.Contains("token") || k.Contains("jwt") || k.Contains("session")
        || k.Contains("auth") || k.Contains("access") || k.Contains("refresh")
        || k.Contains("oauth") || k.Contains("oidc") || k.Contains("sid")
        || k.Contains("id_token") || k.Contains("user");
}

string UrlPath(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return url;
    return u.AbsolutePath.TrimEnd('/').ToLowerInvariant();
}

bool SameOrigin(string a, string b)
{
    if (!Uri.TryCreate(a, UriKind.Absolute, out var ua)) return false;
    if (!Uri.TryCreate(b, UriKind.Absolute, out var ub)) return false;
    return string.Equals(ua.GetLeftPart(UriPartial.Authority), ub.GetLeftPart(UriPartial.Authority),
        StringComparison.OrdinalIgnoreCase);
}

// Same document for the oracle: origin + path. Query/hash are ignored so tracking params do not count as a redirect.
bool SamePage(string a, string b) =>
    SameOrigin(a, b) && string.Equals(UrlPath(a), UrlPath(b), StringComparison.Ordinal);

JsonElement ParseJsJson(string raw)
{
    if (string.IsNullOrWhiteSpace(raw) || raw == "null")
        return JsonDocument.Parse("{}").RootElement.Clone();
    raw = raw.Trim();
    if (raw.Length >= 2 && raw[0] == '"')
        raw = JsonSerializer.Deserialize<string>(raw) ?? raw;
    using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(raw) ? "{}" : raw);
    return doc.RootElement.Clone();
}

async Task<JsonElement> SnapshotAsync()
{
    var raw = await ExecuteJs(snapshotJs);
    return ParseJsJson(raw);
}

string SnapStr(JsonElement el, string name)
{
    return el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
        ? p.GetString() ?? ""
        : "";
}

Log("=== TotalLogoutTest ===", "#569CD6");
Log("Semi-manual: capture session → you log out → replay client auth → check original URL.", "#888888");
Log("");

var originalUrl = await GetCurrentUrl();
var originalTitle = await GetTitle();

if (string.IsNullOrWhiteSpace(originalUrl)
    || originalUrl.StartsWith("about:", StringComparison.OrdinalIgnoreCase)
    || originalUrl.StartsWith("edge:", StringComparison.OrdinalIgnoreCase)
    || originalUrl.StartsWith("chrome:", StringComparison.OrdinalIgnoreCase))
{
    Log("Open an authenticated page first (not a blank tab), then run this quicktest.", "#F44747");
    return;
}

Uri.TryCreate(originalUrl, UriKind.Absolute, out var originalUri);
var originalHost = originalUri?.Host ?? "";

var before = await SnapshotAsync();
var beforeHtml = SnapStr(before, "html");

if (AuthAccessHeuristics.LooksLikeLoginPage(beforeHtml))
{
    Log("This page looks like a login screen. Navigate to a URL that requires a session, then run again.", "#F44747");
    return;
}

Log($"Protected URL: {originalUrl}", "#888888");
Log($"Title: {originalTitle}", "#888888");
Log("");

Assert.Section("Capture authenticated client state");

List<Dictionary<string, object>> cookies = new();
try { cookies = await GetCookies(); }
catch (Exception ex) { Log($"Cookie capture failed: {ex.Message}", "#CCA700"); }

Dictionary<string, string> local = new();
Dictionary<string, string> session = new();
try { local = await GetAllStorage("local"); }
catch (Exception ex) { Log($"localStorage capture failed: {ex.Message}", "#CCA700"); }
try { session = await GetAllStorage("session"); }
catch (Exception ex) { Log($"sessionStorage capture failed: {ex.Message}", "#CCA700"); }

var idbSnap = (AutomationContext.IndexedDbSnapshot?)null;
var idbRaw = "";
try
{
    idbSnap = await GetIndexedDb(limit: 40);
    idbRaw = JsonSerializer.Serialize(new
    {
        ok = true,
        dbs = idbSnap.Databases.Select(db => new
        {
            name = db.Name,
            version = db.Version,
            stores = db.Stores.Select(st => new
            {
                name = st.Name,
                keyPath = st.KeyPath,
                records = st.Records.Select(r =>
                {
                    // Restore path expects parsed JSON values when possible.
                    object? val = r.Value;
                    if (r.Value != null)
                    {
                        try { val = JsonSerializer.Deserialize<JsonElement>(r.Value); }
                        catch { val = r.Value; }
                    }
                    return val;
                }).ToList(),
                keys = st.Records.Select(r => r.Key).ToList()
            }).ToList()
        }).ToList()
    });
}
catch (Exception ex) { Log($"IndexedDB capture failed: {ex.Message}", "#CCA700"); }

var idb = ParseJsJson(string.IsNullOrWhiteSpace(idbRaw) ? "{\"ok\":true,\"dbs\":[]}" : idbRaw);
var idbCount = idbSnap?.DatabaseCount ?? 0;
var idbStoreCount = idbSnap?.Databases.Sum(d => d.Stores.Count) ?? 0;

Log($"Captured cookies: {cookies.Count}", "#888888");
foreach (var c in cookies)
{
    var name = Str(c, "name");
    var flags = new List<string>();
    if (Flag(c, "httpOnly")) flags.Add("HttpOnly");
    if (Flag(c, "secure")) flags.Add("Secure");
    var ss = Str(c, "sameSite");
    if (!string.IsNullOrEmpty(ss)) flags.Add("SameSite=" + ss);
    var hint = LooksAuthKey(name) ? "  (auth-looking)" : "";
    Log($"  cookie {name}  {string.Join(" ", flags)}{hint}", "#888888");
}

Log($"Captured localStorage: {local.Count} key(s)", "#888888");
foreach (var key in local.Keys)
    Log($"  local {(LooksAuthKey(key) ? key + "  (auth-looking)" : key)}", "#888888");

Log($"Captured sessionStorage: {session.Count} key(s)", "#888888");
foreach (var key in session.Keys)
    Log($"  session {(LooksAuthKey(key) ? key + "  (auth-looking)" : key)}", "#888888");

Log($"Captured IndexedDB: {idbCount} database(s), {idbStoreCount} store(s) via GetIndexedDb", "#888888");
if (idbSnap != null)
{
    foreach (var db in idbSnap.Databases)
        Log($"  idb {db.Name}", "#888888");
}

if (cookies.Count == 0 && local.Count == 0 && session.Count == 0 && idbCount == 0)
    Log("Nothing captured. Auth may live only in memory (Authorization header). Replay will be weak — the login handover still applies.", "#CCA700");

Log("");
Log($"Log out now in the browser. Pausing {logoutPauseSeconds} seconds…", "#CCA700");
for (var left = logoutPauseSeconds; left > 0; left -= 5)
{
    Log($"  {left} second(s) remaining — finish logout.", "#CCA700");
    await Sleep(Math.Min(5, left) * 1000);
}

Log("");
Assert.Section("Replay captured authentication");

var restoredCookies = 0;
foreach (var c in cookies)
{
    var name = Str(c, "name");
    if (string.IsNullOrEmpty(name)) continue;
    var domain = Str(c, "domain");
    if (string.IsNullOrEmpty(domain)) domain = originalHost;
    var path = Str(c, "path");
    if (string.IsNullOrEmpty(path)) path = "/";
    var sameSite = Str(c, "sameSite");
    if (string.IsNullOrEmpty(sameSite)) sameSite = "lax";
    try
    {
        await SetCookie(name, Str(c, "value"),
            domain: domain, path: path,
            secure: Flag(c, "secure"), httpOnly: Flag(c, "httpOnly"),
            sameSite: sameSite);
        restoredCookies++;
    }
    catch (Exception ex)
    {
        Log($"  Could not restore cookie {name}: {ex.Message}", "#CCA700");
    }
}
Log($"Restored {restoredCookies}/{cookies.Count} cookie(s).", "#888888");

try
{
    await Navigate(originalUrl);
    await WaitForIdle(500, 10000);
}
catch (Exception ex)
{
    Log($"Navigate to original URL failed: {ex.Message}", "#CCA700");
}

var afterNavUrl = await GetCurrentUrl();
var onOrigin = SameOrigin(afterNavUrl, originalUrl) || string.Equals(afterNavUrl, originalUrl, StringComparison.OrdinalIgnoreCase);

if (!onOrigin)
{
    Log($"After cookie replay the browser left the origin ({afterNavUrl}). Restoring web storage on this page would write the wrong origin — skipping storage restore.", "#CCA700");
}
else
{
    foreach (var kv in local)
    {
        try { await SetStorageItem("local", kv.Key, kv.Value); }
        catch (Exception ex) { Log($"  localStorage {kv.Key}: {ex.Message}", "#CCA700"); }
    }
    foreach (var kv in session)
    {
        try { await SetStorageItem("session", kv.Key, kv.Value); }
        catch (Exception ex) { Log($"  sessionStorage {kv.Key}: {ex.Message}", "#CCA700"); }
    }
    Log($"Restored localStorage ({local.Count}) and sessionStorage ({session.Count}).", "#888888");

    if (idbCount > 0 && !string.IsNullOrWhiteSpace(idbRaw) && idbRaw != "null")
    {
        var dumpLiteral = JsonSerializer.Serialize(idbRaw.Trim().StartsWith("\"")
            ? JsonSerializer.Deserialize<string>(idbRaw) ?? idbRaw
            : idbRaw);
        var restoreIdbJs = $@"
(async function(){{
  var dump;
  try {{ dump = JSON.parse({dumpLiteral}); }} catch (e) {{ return JSON.stringify({{ok:false, error:String(e)}}); }}
  if (!dump || !dump.dbs) return JSON.stringify({{ok:true, restored:0}});
  var restored = 0;
  for (var i = 0; i < dump.dbs.length; i++) {{
    var info = dump.dbs[i];
    if (!info.name) continue;
    var db = await new Promise(function(res){{
      try {{
        var r = indexedDB.open(info.name);
        r.onsuccess = function(){{ res(r.result); }};
        r.onerror = function(){{ res(null); }};
        r.onblocked = function(){{ res(null); }};
      }} catch (e) {{ res(null); }}
    }});
    if (!db) continue;
    var stores = info.stores || [];
    for (var s = 0; s < stores.length; s++) {{
      var st = stores[s];
      if (!st.name || !db.objectStoreNames.contains(st.name)) continue;
      try {{
        var tx = db.transaction(st.name, 'readwrite');
        var store = tx.objectStore(st.name);
        var recs = st.records || [];
        var keys = st.keys || [];
        for (var r = 0; r < recs.length; r++) {{
          try {{
            if (store.keyPath) store.put(recs[r]);
            else if (keys[r] !== undefined) store.put(recs[r], keys[r]);
            else store.put(recs[r]);
            restored++;
          }} catch (e) {{}}
        }}
        await new Promise(function(res){{ tx.oncomplete = function(){{ res(); }}; tx.onerror = function(){{ res(); }}; }});
      }} catch (e) {{}}
    }}
    db.close();
  }}
  return JSON.stringify({{ok:true, restored:restored}});
}})()
";
        try
        {
            var idbResult = ParseJsJson(await ExecuteJs(restoreIdbJs, 20000));
            var n = idbResult.TryGetProperty("restored", out var r) && r.ValueKind == JsonValueKind.Number
                ? r.GetInt32() : 0;
            Log($"Restored IndexedDB records (best effort): {n}.", "#888888");
        }
        catch (Exception ex)
        {
            Log($"IndexedDB restore skipped: {ex.Message}", "#CCA700");
        }
    }

    try
    {
        await Reload();
        await WaitForIdle(500, 10000);
    }
    catch (Exception ex)
    {
        Log($"Reload after storage restore failed: {ex.Message}", "#CCA700");
        try { await Navigate(originalUrl); await WaitForIdle(500, 10000); }
        catch { /* already logged */ }
    }
}

var afterUrl = await GetCurrentUrl();
var afterTitle = await GetTitle();

Log("");
Log($"Original URL: {originalUrl}", "#888888");
Log($"After replay — URL: {afterUrl}", "#888888");
Log($"After replay — title: {afterTitle}", "#888888");

Log("");
Assert.Section("Session invalidation result");

if (SamePage(afterUrl, originalUrl))
{
    Log("SESSION STILL VALID — after logout, replaying client auth still loads the original URL.", "#F44747");
    Assert.Fail("Logout is not total: original URL still loaded after replaying captured cookies/storage");
}
else
{
    Log($"Redirected away from the original URL to {afterUrl}. Replay did not restore the authenticated page.", "#4EC9B0");
    Assert.Pass("Original URL was not kept after logout + client-state replay");
}

Log("");
Log("Now you try to login, if you don't have to provide credentials, the logout isn't total.", "#CCA700");
