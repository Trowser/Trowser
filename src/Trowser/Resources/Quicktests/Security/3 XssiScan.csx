// @title 3 Xssi Scan
// @shadow never
// @effects mutates
// XSSI / JSONP scan: script-includable JSON arrays, callback wrappers, and global assignments
// from the network log (session cookies on re-GET). Hygiene-tier leads — not browser proof.
// Browse authenticated API/JSONP traffic first. Follow-up when client-surface XSSI row is lead.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"XSSI / JSONP scan: {title}");
Log($"URL: {url}");
Log("Browse key flows so script/JSON responses appear in the network log.");
Log("");

Assert.Section("Script-includable responses");
var result = await PrintXssiScanReport();
if (result.Findings.Count == 0)
    Assert.Pass($"No XSSI indicators across {result.UrlsProbed} URL(s).");
else
    Assert.Pass($"{result.Findings.Count} XSSI-related lead(s) across {result.UrlsProbed} URL(s) — confirm with cross-origin script include.");
