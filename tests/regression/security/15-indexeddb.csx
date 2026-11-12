// Security: IndexedDB as a general store — dump, audit, clear.

await ResetBrowserState();

Assert.Section("Seed IndexedDB and dump via GetIndexedDb");
var seedHtml = MinimalHtml("IDB",
    @"<script>
      (async function(){
        var req = indexedDB.open('trowser_reg_db', 1);
        req.onupgradeneeded = function(){
          var db = req.result;
          if (!db.objectStoreNames.contains('tokens')) db.createObjectStore('tokens');
        };
        req.onsuccess = function(){
          var db = req.result;
          var tx = db.transaction('tokens', 'readwrite');
          tx.objectStore('tokens').put('eyJhbGciOiJub25lIn0.eyJzdWIiOiJyZWctdXNlciJ9.', 'access_token');
          tx.oncomplete = function(){ document.title = 'idb-ready'; db.close(); };
        };
      })();
    </script>");
SetupPage(FixtureUrl("/idb"), seedHtml, ScriptableHeaders());
await Navigate(FixtureUrl("/idb"));
await WaitForIdle();
for (var i = 0; i < 30; i++)
{
    if ((await GetTitle()).Contains("idb-ready")) break;
    await Task.Delay(100);
}

var snap = await GetIndexedDb(dbFilter: "trowser_reg_db");
Log($"IndexedDB method={snap.Method} dbs={snap.DatabaseCount} records={snap.RecordCount}");
Assert.True(snap.DatabaseCount >= 1, "at least one IndexedDB database");
Assert.True(snap.RecordCount >= 1, "at least one IndexedDB record");

var flat = await GetIndexedDbFlat(dbFilter: "trowser_reg_db");
Assert.True(flat.Values.Any(v => v.Contains("eyJ", StringComparison.Ordinal)), "JWT-like value in IndexedDB flat dump");

Assert.Section("Storage audit includes IndexedDB");
var audit = await CheckStorageSecurity();
Log($"Storage findings: {audit.FindingCount}; IndexedDB records={audit.IndexedDbRecordCount}");
Assert.True(audit.IndexedDbRecordCount >= 1, "audit saw IndexedDB records");
Assert.True(audit.Findings.Any(f =>
        f.StorageType.Equals("indexedDB", StringComparison.OrdinalIgnoreCase)
        || (f.ValueSnippet ?? "").Contains("eyJ", StringComparison.Ordinal)
        || f.Key.Contains("indexedDB", StringComparison.OrdinalIgnoreCase)),
    "IndexedDB-related finding present");

Assert.Section("Clear IndexedDB store");
await ClearIndexedDbStore("trowser_reg_db", "tokens");
var after = await GetIndexedDb(dbFilter: "trowser_reg_db");
var store = after.Databases.SelectMany(d => d.Stores).FirstOrDefault(s => s.Name == "tokens");
Assert.True(store == null || store.RecordCount == 0, "store cleared");
