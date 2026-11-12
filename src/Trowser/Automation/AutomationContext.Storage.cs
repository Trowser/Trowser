using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region SSL Scripting Methods

    /// <summary>Add a client certificate from a .pfx/.p12 file. Returns certificate info.</summary>
    public SslCertificateInfo SslAddCertificate(string filePath, string password, string? alias = null)
    {
        if (SslManager == null) throw new InvalidOperationException("SSL Manager not initialized.");
        return SslManager.AddCertificate(filePath, password, alias);
    }

    /// <summary>Set the active client certificate by alias. Pass null to clear.</summary>
    public SslCertificateInfo? SslSetActive(string? alias)
    {
        if (SslManager == null) throw new InvalidOperationException("SSL Manager not initialized.");
        return SslManager.SetActive(alias);
    }

    /// <summary>Remove a client certificate by alias.</summary>
    public bool SslRemove(string alias)
    {
        if (SslManager == null) throw new InvalidOperationException("SSL Manager not initialized.");
        return SslManager.RemoveCertificate(alias);
    }

    /// <summary>List all client certificates (without secrets).</summary>
    public List<SslCertificateInfo> SslListCertificates()
    {
        if (SslManager == null) throw new InvalidOperationException("SSL Manager not initialized.");
        return SslManager.ListCertificates();
    }

    /// <summary>Get the active client certificate info, or null if none.</summary>
    public SslCertificateInfo? SslGetActive()
    {
        if (SslManager == null) throw new InvalidOperationException("SSL Manager not initialized.");
        return SslManager.GetActive();
    }

    #endregion

    #region Cookie Management

    public async Task<List<Dictionary<string, object>>> GetCookies()
    {
        var webView = ActiveTab.WebView;
        try
        {
            var url = await GetCurrentUrl();
            var cookieList = await await webView.Dispatcher.InvokeAsync(async () =>
                await webView.CoreWebView2.CookieManager.GetCookiesAsync(url));

            return cookieList.Select(FormatCookie).ToList();
        }
        catch (Exception ex) when (
            ex is InvalidCastException ||
            ex is System.Runtime.InteropServices.COMException ||
            ex is System.Runtime.InteropServices.InvalidComObjectException ||
            ex.Message.Contains("ICoreWebView2Cookie"))
        {
            return await GetCookiesViaJavaScript();
        }
    }

    private async Task<List<Dictionary<string, object>>> GetCookiesViaJavaScript()
    {
        // First, try CDP Network.getCookies which includes HttpOnly cookies
        try
        {
            return await GetCookiesViaCdp();
        }
        catch
        {
            // Final fallback: document.cookie (cannot see HttpOnly cookies)
        }

        var raw = await RunJs("document.cookie");
        if (string.IsNullOrWhiteSpace(raw))
            return new List<Dictionary<string, object>>();

        return raw.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair =>
            {
                var eq = pair.IndexOf('=');
                var name = eq >= 0 ? pair[..eq].Trim() : pair.Trim();
                var value = eq >= 0 ? pair[(eq + 1)..].Trim() : "";
                return new Dictionary<string, object>
                {
                    ["name"] = name, ["value"] = value, ["domain"] = "", ["path"] = "/",
                    ["secure"] = false, ["httpOnly"] = false, ["sameSite"] = "lax", ["session"] = true
                };
            })
            .Where(c => !string.IsNullOrEmpty(c["name"]?.ToString()))
            .ToList();
    }

    private async Task<List<Dictionary<string, object>>> GetCookiesViaCdp()
    {
        var webView = ActiveTab.WebView;
        var url = await GetCurrentUrl();
        var urls = new[] { url };
        var json = System.Text.Json.JsonSerializer.Serialize(new { urls });

        var resultJson = await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Network.getCookies", json));

        using var doc = System.Text.Json.JsonDocument.Parse(resultJson);
        var cookies = new List<Dictionary<string, object>>();

        if (doc.RootElement.TryGetProperty("cookies", out var cookiesArray))
        {
            foreach (var c in cookiesArray.EnumerateArray())
            {
                var name = c.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                var value = c.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                var domain = c.TryGetProperty("domain", out var d) ? d.GetString() ?? "" : "";
                var path = c.TryGetProperty("path", out var p) ? p.GetString() ?? "/" : "/";
                var secure = c.TryGetProperty("secure", out var s) && s.GetBoolean();
                var httpOnly = c.TryGetProperty("httpOnly", out var h) && h.GetBoolean();
                var sameSite = c.TryGetProperty("sameSite", out var ss) ? ss.GetString()?.ToLower() ?? "lax" : "lax";
                var expires = c.TryGetProperty("expires", out var exp) ? exp.GetDouble() : -1;
                var isSession = expires <= 0;

                var cookie = new Dictionary<string, object>
                {
                    ["name"] = name, ["value"] = value, ["domain"] = domain, ["path"] = path,
                    ["secure"] = secure, ["httpOnly"] = httpOnly, ["sameSite"] = sameSite, ["session"] = isSession
                };

                if (!isSession)
                {
                    var dt = DateTimeOffset.FromUnixTimeSeconds((long)expires).UtcDateTime;
                    cookie["expires"] = dt.ToString("O");
                }

                cookies.Add(cookie);
            }
        }

        return cookies;
    }

    public async Task<Dictionary<string, object>?> GetCookie(string name)
    {
        var cookies = await GetCookies();
        return cookies.FirstOrDefault(c => c["name"]?.ToString() == name);
    }

    public async Task SetCookie(string name, string value,
        string? domain = null, string? path = null,
        bool? secure = null, bool? httpOnly = null, string? sameSite = null)
    {
        var webView = ActiveTab.WebView;
        var url = await GetCurrentUrl();
        var uri = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u : null;
        var cookieDomain = domain ?? uri?.Host ?? "localhost";
        var cookiePath = path ?? "/";

        await webView.Dispatcher.InvokeAsync(() =>
        {
            var cookie = webView.CoreWebView2.CookieManager.CreateCookie(name, value, cookieDomain, cookiePath);
            if (secure.HasValue) cookie.IsSecure = secure.Value;
            if (httpOnly.HasValue) cookie.IsHttpOnly = httpOnly.Value;
            if (sameSite != null)
            {
                cookie.SameSite = sameSite.ToLower() switch
                {
                    "none" => CoreWebView2CookieSameSiteKind.None,
                    "strict" => CoreWebView2CookieSameSiteKind.Strict,
                    _ => CoreWebView2CookieSameSiteKind.Lax
                };
            }
            webView.CoreWebView2.CookieManager.AddOrUpdateCookie(cookie);
        });
    }

    public async Task DeleteCookie(string name, string? domain = null, string? path = null)
    {
        var webView = ActiveTab.WebView;
        var url = await GetCurrentUrl();
        var uri = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u : null;
        var cookieDomain = domain ?? uri?.Host ?? "";
        var cookiePath = path ?? "/";

        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.CookieManager.DeleteCookiesWithDomainAndPath(name, cookieDomain, cookiePath);
        });
    }

    public async Task ClearCookies()
    {
        var webView = ActiveTab.WebView;
        await webView.Dispatcher.InvokeAsync(() =>
        {
            webView.CoreWebView2.CookieManager.DeleteAllCookies();
        });
    }

    private static Dictionary<string, object> FormatCookie(CoreWebView2Cookie c)
    {
        var isSession = c.Expires == default || c.Expires == DateTime.MinValue;
        var result = new Dictionary<string, object>
        {
            ["name"] = c.Name, ["value"] = c.Value, ["domain"] = c.Domain, ["path"] = c.Path,
            ["secure"] = c.IsSecure, ["httpOnly"] = c.IsHttpOnly,
            ["sameSite"] = c.SameSite.ToString().ToLower(), ["session"] = isSession,
            ["_sameSiteExplicit"] = false
        };
        if (!isSession)
            result["expires"] = c.Expires.ToUniversalTime().ToString("O");
        return result;
    }

    #endregion

    #region Web Storage (localStorage / sessionStorage)

    private string ResolveStorageType(string type)
    {
        return type.ToLowerInvariant() switch
        {
            "local" or "localstorage" => "localStorage",
            "session" or "sessionstorage" => "sessionStorage",
            _ => throw new ArgumentException($"Invalid storage type: '{type}'. Use 'local' or 'session'.")
        };
    }

    public async Task<Dictionary<string, string>> GetAllStorage(string type)
    {
        if (IsIndexedDbType(type))
        {
            EnsureWebStoragePageContext();
            return await GetIndexedDbFlat();
        }

        EnsureWebStoragePageContext();
        var storageObj = ResolveStorageType(type);
        var js = $"(function(){{var s={storageObj};var r={{}};for(var i=0;i<s.length;i++){{var k=s.key(i);r[k]=s.getItem(k);}}return JSON.stringify(r);}})()";
        var result = await RunJs(js);
        if (string.IsNullOrEmpty(result) || result == "null")
            return new Dictionary<string, string>();

        using var doc = JsonDocument.Parse(result);
        var dict = new Dictionary<string, string>();
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.GetString() ?? "";
        return dict;
    }

    public async Task<string?> GetStorageItem(string type, string key)
    {
        if (IsIndexedDbType(type))
        {
            EnsureWebStoragePageContext();
            var flat = await GetIndexedDbFlat();
            return flat.TryGetValue(key, out var v) ? v : null;
        }
        EnsureWebStoragePageContext();
        var storageObj = ResolveStorageType(type);
        var escapedKey = JsonEscape(key);
        var js = $"JSON.stringify({storageObj}.getItem({escapedKey}))";
        var result = await RunJs(js);
        return result == "null" ? null : result;
    }

    public async Task SetStorageItem(string type, string key, string value)
    {
        if (IsIndexedDbType(type))
            throw new InvalidOperationException("IndexedDB write via set is not supported; use page scripts or delete/clear.");
        var storageObj = ResolveStorageType(type);
        var escapedKey = JsonEscape(key);
        var escapedValue = JsonEscape(value);
        await RunJs($"{storageObj}.setItem({escapedKey},{escapedValue})");
    }

    public async Task DeleteStorageItem(string type, string key)
    {
        if (IsIndexedDbType(type))
        {
            // key formats: "dbName" (delete DB) or "dbName/storeName" (clear store)
            var parts = key.Split('/', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length == 0)
                throw new ArgumentException("For indexeddb delete, key must be 'dbName' or 'dbName/storeName'.");
            if (parts.Length == 1)
                await DeleteIndexedDb(parts[0]);
            else
                await ClearIndexedDbStore(parts[0], parts[1]);
            return;
        }
        var storageObj = ResolveStorageType(type);
        var escapedKey = JsonEscape(key);
        await RunJs($"{storageObj}.removeItem({escapedKey})");
    }

    public async Task ClearStorage(string type)
    {
        if (IsIndexedDbType(type))
        {
            await ClearIndexedDbAsync();
            return;
        }
        var storageObj = ResolveStorageType(type);
        await RunJs($"{storageObj}.clear()");
    }

    #endregion

    #region IndexedDB

    private const int IndexedDbDefaultLimit = 200;
    private const int IndexedDbMaxValueChars = 2_000;
    private const int IndexedDbMaxTotalChars = 200_000;

    public sealed class IndexedDbRecord
    {
        public string? Key { get; init; }
        public string? Value { get; init; }
        public bool Truncated { get; init; }
    }

    public sealed class IndexedDbStore
    {
        public string Name { get; set; } = "";
        public object? KeyPath { get; set; }
        public List<IndexedDbRecord> Records { get; set; } = new();
        public int RecordCount { get; set; }
        public bool Truncated { get; set; }
    }

    public sealed class IndexedDbDatabase
    {
        public string Name { get; set; } = "";
        public long Version { get; set; }
        public List<IndexedDbStore> Stores { get; set; } = new();
    }

    public sealed class IndexedDbSnapshot
    {
        public string Origin { get; set; } = "";
        public List<IndexedDbDatabase> Databases { get; set; } = new();
        public int DatabaseCount => Databases.Count;
        public int RecordCount => Databases.Sum(d => d.Stores.Sum(s => s.RecordCount));
        public bool Truncated { get; set; }
        public string Method { get; set; } = "js";
    }

    private static bool IsIndexedDbType(string type) =>
        type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
        || type.Equals("idb", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Dump IndexedDB for the current page origin. Prefer CDP when available; fall back to page JS
    /// (same approach as TotalLogoutTest) for reliable value serialization.
    /// </summary>
    public async Task<IndexedDbSnapshot> GetIndexedDb(
        string? dbFilter = null,
        string? storeFilter = null,
        int? limit = null)
    {
        var pageLimit = Math.Clamp(limit ?? IndexedDbDefaultLimit, 1, 2_000);
        var origin = await GetSecurityOriginAsync();

        try
        {
            var viaCdp = await TryGetIndexedDbViaCdpAsync(origin, dbFilter, storeFilter, pageLimit);
            if (viaCdp != null)
                return viaCdp;
        }
        catch
        {
            // Fall through to JS dump.
        }

        return await GetIndexedDbViaJsAsync(origin, dbFilter, storeFilter, pageLimit);
    }

    /// <summary>Flatten IndexedDB into key→value pairs for scanners (db/store/key path).</summary>
    public async Task<Dictionary<string, string>> GetIndexedDbFlat(
        string? dbFilter = null,
        string? storeFilter = null,
        int? limit = null)
    {
        var snap = await GetIndexedDb(dbFilter, storeFilter, limit);
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var db in snap.Databases)
        {
            foreach (var store in db.Stores)
            {
                foreach (var rec in store.Records)
                {
                    var key = $"indexedDB:{db.Name}/{store.Name}/{rec.Key ?? "?"}";
                    dict[key] = rec.Value ?? "";
                }
            }
        }
        return dict;
    }

    public async Task ClearIndexedDbStore(string databaseName, string storeName)
    {
        if (string.IsNullOrWhiteSpace(databaseName))
            throw new ArgumentException("databaseName is required.", nameof(databaseName));
        if (string.IsNullOrWhiteSpace(storeName))
            throw new ArgumentException("storeName is required.", nameof(storeName));

        var origin = await GetSecurityOriginAsync();
        try
        {
            await CallIndexedDbCdpAsync("IndexedDB.clearObjectStore", new
            {
                securityOrigin = origin,
                databaseName,
                objectStoreName = storeName
            });
            return;
        }
        catch
        {
            // JS fallback
        }

        var dbEsc = JsonEscape(databaseName);
        var storeEsc = JsonEscape(storeName);
        var js = $@"
(async function(){{
  var db = await new Promise(function(res, rej){{
    var r = indexedDB.open({dbEsc});
    r.onsuccess = function(){{ res(r.result); }};
    r.onerror = function(){{ rej(r.error); }};
  }});
  await new Promise(function(res, rej){{
    var tx = db.transaction([{storeEsc}], 'readwrite');
    tx.objectStore({storeEsc}).clear();
    tx.oncomplete = function(){{ res(true); }};
    tx.onerror = function(){{ rej(tx.error); }};
  }});
  db.close();
  return 'OK';
}})()";
        await RunJsAsync(js);
    }

    public async Task DeleteIndexedDb(string databaseName)
    {
        if (string.IsNullOrWhiteSpace(databaseName))
            throw new ArgumentException("databaseName is required.", nameof(databaseName));

        var origin = await GetSecurityOriginAsync();
        try
        {
            await CallIndexedDbCdpAsync("IndexedDB.deleteDatabase", new
            {
                securityOrigin = origin,
                databaseName
            });
            return;
        }
        catch
        {
            // JS fallback
        }

        var dbEsc = JsonEscape(databaseName);
        var js = $@"
(async function(){{
  await new Promise(function(res, rej){{
    var r = indexedDB.deleteDatabase({dbEsc});
    r.onsuccess = function(){{ res(true); }};
    r.onerror = function(){{ rej(r.error); }};
    r.onblocked = function(){{ res(true); }};
  }});
  return 'OK';
}})()";
        await RunJsAsync(js);
    }

    public async Task ClearIndexedDbAsync(string? dbFilter = null)
    {
        var snap = await GetIndexedDb(dbFilter, null, 1);
        foreach (var db in snap.Databases)
            await DeleteIndexedDb(db.Name);
    }

    private async Task<string> GetSecurityOriginAsync()
    {
        var url = await GetCurrentUrl();
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return uri.GetLeftPart(UriPartial.Authority);
        var originJson = await RunJs("location.origin");
        return string.IsNullOrWhiteSpace(originJson) ? "null" : originJson.Trim('"');
    }

    private async Task<string> CallIndexedDbCdpAsync(string method, object args)
    {
        var webView = ActiveTab.WebView;
        var json = JsonSerializer.Serialize(args);
        return await await webView.Dispatcher.InvokeAsync(async () =>
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync(method, json));
    }

    private async Task<IndexedDbSnapshot?> TryGetIndexedDbViaCdpAsync(
        string origin, string? dbFilter, string? storeFilter, int pageLimit)
    {
        // Enable domain (noop if unsupported).
        try
        {
            await CallIndexedDbCdpAsync("IndexedDB.enable", new { });
        }
        catch
        {
            /* optional */
        }

        string namesJson;
        try
        {
            namesJson = await CallIndexedDbCdpAsync("IndexedDB.requestDatabaseNames", new
            {
                securityOrigin = origin
            });
        }
        catch
        {
            return null;
        }

        using var namesDoc = JsonDocument.Parse(namesJson);
        if (!namesDoc.RootElement.TryGetProperty("databaseNames", out var namesArr)
            || namesArr.ValueKind != JsonValueKind.Array)
            return null;

        var snap = new IndexedDbSnapshot { Origin = origin, Method = "cdp" };
        var totalChars = 0;
        var truncated = false;

        foreach (var nameEl in namesArr.EnumerateArray())
        {
            var dbName = nameEl.GetString() ?? "";
            if (string.IsNullOrEmpty(dbName)) continue;
            if (!string.IsNullOrEmpty(dbFilter)
                && dbName.IndexOf(dbFilter, StringComparison.OrdinalIgnoreCase) < 0)
                continue;

            string dbJson;
            try
            {
                dbJson = await CallIndexedDbCdpAsync("IndexedDB.requestDatabase", new
                {
                    securityOrigin = origin,
                    databaseName = dbName
                });
            }
            catch
            {
                continue;
            }

            using var dbDoc = JsonDocument.Parse(dbJson);
            if (!dbDoc.RootElement.TryGetProperty("databaseWithObjectStores", out var dbInfo))
                continue;

            var version = dbInfo.TryGetProperty("version", out var ver) ? ver.GetInt64() : 0;
            var db = new IndexedDbDatabase { Name = dbName, Version = version };

            if (dbInfo.TryGetProperty("objectStores", out var stores)
                && stores.ValueKind == JsonValueKind.Array)
            {
                foreach (var storeEl in stores.EnumerateArray())
                {
                    var storeName = storeEl.TryGetProperty("name", out var sn) ? sn.GetString() ?? "" : "";
                    if (string.IsNullOrEmpty(storeName)) continue;
                    if (!string.IsNullOrEmpty(storeFilter)
                        && storeName.IndexOf(storeFilter, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    object? keyPath = null;
                    if (storeEl.TryGetProperty("keyPath", out var kp))
                        keyPath = kp.ValueKind == JsonValueKind.String ? kp.GetString() : kp.GetRawText();

                    var store = new IndexedDbStore { Name = storeName, KeyPath = keyPath };
                    try
                    {
                        var dataJson = await CallIndexedDbCdpAsync("IndexedDB.requestData", new
                        {
                            securityOrigin = origin,
                            databaseName = dbName,
                            objectStoreName = storeName,
                            skipCount = 0,
                            pageSize = pageLimit
                        });
                        using var dataDoc = JsonDocument.Parse(dataJson);
                        if (dataDoc.RootElement.TryGetProperty("objectStoreDataEntries", out var entries)
                            && entries.ValueKind == JsonValueKind.Array)
                        {
                            var hasMore = dataDoc.RootElement.TryGetProperty("hasMore", out var hm) && hm.GetBoolean();
                            store.Truncated = hasMore;
                            if (hasMore) truncated = true;
                            foreach (var entry in entries.EnumerateArray())
                            {
                                var key = entry.TryGetProperty("key", out var k)
                                    ? DescribeRemoteObject(k) : null;
                                var valueRaw = entry.TryGetProperty("value", out var v)
                                    ? DescribeRemoteObject(v) : null;
                                var valueTrunc = TruncateIdbValue(valueRaw, out var wasTrunc);
                                if (wasTrunc) truncated = true;
                                totalChars += valueTrunc?.Length ?? 0;
                                if (totalChars > IndexedDbMaxTotalChars)
                                {
                                    truncated = true;
                                    store.Truncated = true;
                                    break;
                                }
                                store.Records.Add(new IndexedDbRecord
                                {
                                    Key = key,
                                    Value = valueTrunc,
                                    Truncated = wasTrunc
                                });
                            }
                        }
                    }
                    catch
                    {
                        // Store unreadable via CDP — leave empty.
                    }

                    store.RecordCount = store.Records.Count;
                    db.Stores.Add(store);
                    if (totalChars > IndexedDbMaxTotalChars) break;
                }
            }

            snap.Databases.Add(db);
            if (totalChars > IndexedDbMaxTotalChars) break;
        }

        snap.Truncated = truncated;
        return snap;
    }

    private static string? DescribeRemoteObject(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.String) return el.GetString();
        if (el.TryGetProperty("value", out var v))
        {
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Number => v.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => null,
                _ => v.GetRawText()
            };
        }
        if (el.TryGetProperty("description", out var d))
            return d.GetString();
        if (el.TryGetProperty("unserializableValue", out var u))
            return u.GetString();
        return el.GetRawText();
    }

    private static string? TruncateIdbValue(string? value, out bool truncated)
    {
        truncated = false;
        if (value == null) return null;
        if (value.Length <= IndexedDbMaxValueChars) return value;
        truncated = true;
        return value[..IndexedDbMaxValueChars] + "…";
    }

    private async Task<IndexedDbSnapshot> GetIndexedDbViaJsAsync(
        string origin, string? dbFilter, string? storeFilter, int pageLimit)
    {
        var dbFilterEsc = dbFilter == null ? "null" : JsonEscape(dbFilter);
        var storeFilterEsc = storeFilter == null ? "null" : JsonEscape(storeFilter);
        var js = $@"
(async function(){{
  var dbFilter = {dbFilterEsc};
  var storeFilter = {storeFilterEsc};
  var pageLimit = {pageLimit};
  var maxVal = {IndexedDbMaxValueChars};
  var maxTotal = {IndexedDbMaxTotalChars};
  var total = 0;
  var truncated = false;
  function trunc(v){{
    if (v == null) return null;
    var s;
    try {{ s = typeof v === 'string' ? v : JSON.stringify(v); }}
    catch(e) {{ s = String(v); }}
    if (s.length > maxVal) {{ truncated = true; return s.substring(0, maxVal) + '\u2026'; }}
    return s;
  }}
  if (!indexedDB.databases) return JSON.stringify({{ok:true, dbs:[], truncated:false, method:'js'}});
  var infos = await indexedDB.databases();
  var out = [];
  for (var i = 0; i < infos.length; i++) {{
    var name = infos[i].name;
    if (!name) continue;
    if (dbFilter && name.toLowerCase().indexOf(String(dbFilter).toLowerCase()) < 0) continue;
    var db = await new Promise(function(res){{
      try {{
        var r = indexedDB.open(name);
        r.onsuccess = function(){{ res(r.result); }};
        r.onerror = function(){{ res(null); }};
        r.onblocked = function(){{ res(null); }};
      }} catch (e) {{ res(null); }}
    }});
    if (!db) {{ out.push({{name:name, version:0, stores:[]}}); continue; }}
    var stores = [];
    var storeNames = Array.prototype.slice.call(db.objectStoreNames);
    for (var s = 0; s < storeNames.length; s++) {{
      var storeName = storeNames[s];
      if (storeFilter && storeName.toLowerCase().indexOf(String(storeFilter).toLowerCase()) < 0) continue;
      try {{
        var rec = await new Promise(function(res){{
          var tx = db.transaction(storeName, 'readonly');
          var store = tx.objectStore(storeName);
          var req = store.getAll();
          var keyReq = store.getAllKeys();
          var recs = null, keys = null, done = 0;
          function finish(){{
            if (++done < 2) return;
            var records = recs || [];
            var ks = keys || [];
            var storeTrunc = false;
            if (records.length > pageLimit) {{ storeTrunc = true; truncated = true; records = records.slice(0, pageLimit); ks = ks.slice(0, pageLimit); }}
            var mapped = [];
            for (var r = 0; r < records.length; r++) {{
              var val = trunc(records[r]);
              total += (val || '').length;
              if (total > maxTotal) {{ truncated = true; storeTrunc = true; break; }}
              mapped.push({{key: trunc(ks[r]), value: val, truncated: (val||'').length >= maxVal}});
            }}
            res({{name:storeName, keyPath: store.keyPath, records: mapped, recordCount: mapped.length, truncated: storeTrunc}});
          }}
          req.onsuccess = function(){{ recs = req.result; finish(); }};
          req.onerror = function(){{ recs = []; finish(); }};
          keyReq.onsuccess = function(){{ keys = keyReq.result; finish(); }};
          keyReq.onerror = function(){{ keys = []; finish(); }};
        }});
        stores.push(rec);
      }} catch (e) {{
        stores.push({{name:storeName, records:[], recordCount:0, truncated:false}});
      }}
      if (total > maxTotal) break;
    }}
    var ver = db.version;
    db.close();
    out.push({{name:name, version: ver, stores:stores}});
    if (total > maxTotal) break;
  }}
  return JSON.stringify({{ok:true, dbs:out, truncated:truncated, method:'js'}});
}})()";

        var raw = await RunJsAsync(js);
        var snap = new IndexedDbSnapshot { Origin = origin, Method = "js" };
        if (string.IsNullOrWhiteSpace(raw) || raw == "null")
            return snap;

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        snap.Truncated = root.TryGetProperty("truncated", out var tr) && tr.GetBoolean();
        if (root.TryGetProperty("method", out var m) && m.GetString() is { } method)
            snap.Method = method;

        if (root.TryGetProperty("dbs", out var dbs) && dbs.ValueKind == JsonValueKind.Array)
        {
            foreach (var dbEl in dbs.EnumerateArray())
            {
                var db = new IndexedDbDatabase
                {
                    Name = dbEl.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                    Version = dbEl.TryGetProperty("version", out var v) && v.TryGetInt64(out var vl) ? vl : 0
                };
                if (dbEl.TryGetProperty("stores", out var stores) && stores.ValueKind == JsonValueKind.Array)
                {
                    foreach (var storeEl in stores.EnumerateArray())
                    {
                        object? keyPath = null;
                        if (storeEl.TryGetProperty("keyPath", out var kp))
                        {
                            keyPath = kp.ValueKind switch
                            {
                                JsonValueKind.String => kp.GetString(),
                                JsonValueKind.Null => null,
                                _ => kp.GetRawText()
                            };
                        }
                        var store = new IndexedDbStore
                        {
                            Name = storeEl.TryGetProperty("name", out var sn) ? sn.GetString() ?? "" : "",
                            KeyPath = keyPath,
                            Truncated = storeEl.TryGetProperty("truncated", out var st) && st.GetBoolean()
                        };
                        if (storeEl.TryGetProperty("records", out var recs) && recs.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var rec in recs.EnumerateArray())
                            {
                                store.Records.Add(new IndexedDbRecord
                                {
                                    Key = rec.TryGetProperty("key", out var rk) ? rk.GetString() : null,
                                    Value = rec.TryGetProperty("value", out var rv) ? rv.GetString() : null,
                                    Truncated = rec.TryGetProperty("truncated", out var rt) && rt.GetBoolean()
                                });
                            }
                        }
                        store.RecordCount = store.Records.Count;
                        db.Stores.Add(store);
                    }
                }
                snap.Databases.Add(db);
            }
        }

        return snap;
    }

    #endregion

    #region Clear All (test session reset)

    /// <summary>
    /// Reset all test session state: console, network log, cookies, mocks, intercepts,
    /// assertions, network throttle, viewport override, and web storage.
    /// Use between test sessions or to recover from leftover state.
    /// </summary>
    public class ClearAllResult
    {
        public List<string> Cleared { get; init; } = new();
        public List<string> Preserved { get; init; } = new();
        public string Summary
        {
            get
            {
                var msg = $"Cleared: {string.Join(", ", Cleared)} ({Cleared.Count} items)";
                if (Preserved.Count > 0)
                    msg += $". Preserved: {string.Join(", ", Preserved)}";
                return msg;
            }
        }
    }

    /// <summary>
    /// Reset all test session state.
    /// <paramref name="preserve"/> lists categories to keep intact:
    /// "cookies", "storage" (both localStorage and sessionStorage), "mocks", "intercepts",
    /// "throttle", "viewport", "vpx" (VPX import + cross-playbook dedup findings).
    /// </summary>
    public async Task<ClearAllResult> ClearAll(HashSet<string>? preserve = null)
    {
        preserve ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var cleared = new List<string>();
        var preserved = new List<string>();

        ClearConsoleLog();
        cleared.Add("console");

        ClearNetworkLog();
        cleared.Add("network");

        if (!preserve.Contains("mocks")) { ClearMocks(); cleared.Add("mocks"); }
        else preserved.Add("mocks");

        if (!preserve.Contains("intercepts")) { ClearInterceptRules(); cleared.Add("intercepts"); }
        else preserved.Add("intercepts");

        Assert.Reset();
        cleared.Add("assertions");

        ClearRefGenerationSnapshots();
        cleared.Add("refGenerationSnapshots");

        ActiveTab.RuntimeEvents.Clear();
        cleared.Add("runtime-events");

        if (!preserve.Contains("cookies"))
        {
            try { await ClearCookies(); cleared.Add("cookies"); }
            catch { /* WebView2 cookie manager may not be available */ }
        }
        else preserved.Add("cookies");

        if (!preserve.Contains("throttle"))
        {
            try { await ClearNetworkThrottle(); cleared.Add("throttle"); }
            catch { /* ignore if no throttle was set */ }
        }
        else preserved.Add("throttle");

        if (!preserve.Contains("viewport"))
        {
            try { await ResetViewport(); cleared.Add("viewport"); }
            catch { /* ignore if no viewport override was set */ }
        }
        else preserved.Add("viewport");

        if (!preserve.Contains("emulation"))
        {
            try { await ClearEmulation(); cleared.Add("emulation"); }
            catch { /* ignore */ }
        }
        else preserved.Add("emulation");

        if (!preserve.Contains("downloads"))
        {
            try { ClearDownloads(deleteFiles: false); cleared.Add("downloads"); }
            catch { /* ignore */ }
        }
        else preserved.Add("downloads");

        if (!preserve.Contains("trace"))
        {
            try { ClearTrace(); cleared.Add("trace"); }
            catch { /* ignore */ }
        }
        else preserved.Add("trace");

        if (!preserve.Contains("storage"))
        {
            try { await RunJs("localStorage.clear()"); cleared.Add("localStorage"); }
            catch { /* page may not support storage */ }

            try { await RunJs("sessionStorage.clear()"); cleared.Add("sessionStorage"); }
            catch { /* page may not support storage */ }

            try { await ClearIndexedDbAsync(); cleared.Add("indexedDB"); }
            catch { /* page may not support IndexedDB */ }
        }
        else preserved.Add("storage");

        if (!preserve.Contains("vpx"))
        {
            ClearVpxSessionState();
            cleared.Add("vpx");
        }
        else preserved.Add("vpx");

        return new ClearAllResult { Cleared = cleared, Preserved = preserved };
    }

    /// <summary>
    /// Lighter reset — clears only test artifacts (console, network log, assertions, mocks,
    /// intercepts, throttle, viewport) but leaves cookies and web storage untouched.
    /// </summary>
    public async Task<ClearAllResult> ClearSession()
    {
        return await ClearAll(new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "cookies", "storage" });
    }

    #endregion
}
