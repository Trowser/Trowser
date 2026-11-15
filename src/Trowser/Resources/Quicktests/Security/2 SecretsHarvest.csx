// @title 2 Secrets Harvest
// @shadow never
// @effects mutates
// Secrets harvest: unified credential/secret scan across JS bundles, cookies, storage,
// network responses, request URLs (JWTs, including OIDC id_token_hint), visible page text, and source maps.
// NOTE: This test fetches external JS scripts for analysis.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Secrets harvest: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Secrets & Credential Exposure");
await AssertSecretsClean(minSeverity: "medium");
await PrintSecretsHarvestReport(includeDetails: true);
