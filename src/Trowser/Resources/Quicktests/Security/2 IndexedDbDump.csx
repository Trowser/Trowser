// @title 2 Indexed Db Dump
// @shadow never
// @effects mutates
// Dump IndexedDB for the current origin, then run the storage audit
// (localStorage + sessionStorage + IndexedDB tokens/JWTs/PII).
// Navigate first; log in if the app only writes IndexedDB after auth.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"IndexedDB + web storage: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("IndexedDB dump");
await PrintIndexedDbReport();

Log("");
Assert.Section("Storage audit (includes IndexedDB)");
await AssertStorageSecurity(minSeverity: Severity.Medium);
await PrintStorageSecurityReport();
