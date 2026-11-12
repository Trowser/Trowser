using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Batch vulnerability lookup via osv.dev (npm, PyPI, Packagist, Maven, etc.).
/// </summary>
public static class OsvClient
{
    private const string BatchUrl = "https://api.osv.dev/v1/querybatch";

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(20)
    };

    public static async Task<List<OsvVulnerabilityHit>> LookupAsync(
        IReadOnlyList<DeclaredDependency> dependencies,
        int maxPackages = 200,
        CancellationToken ct = default)
    {
        var deduped = ManifestParser.Dedupe(dependencies, maxPackages);
        if (deduped.Count == 0) return [];

        var queries = deduped.Select(d => new
        {
            package = new { name = d.Name, ecosystem = d.Ecosystem },
            version = d.Version ?? ""
        }).ToList();

        var payload = JsonSerializer.Serialize(new { queries });
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var resp = await Http.PostAsync(BatchUrl, content, ct);
        if (!resp.IsSuccessStatusCode) return [];

        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            return [];

        var hits = new List<OsvVulnerabilityHit>();
        var i = 0;
        foreach (var entry in results.EnumerateArray())
        {
            if (i >= deduped.Count) break;
            var dep = deduped[i++];
            var ids = new List<string>();
            if (entry.TryGetProperty("vulns", out var vulns) && vulns.ValueKind == JsonValueKind.Array)
            {
                foreach (var v in vulns.EnumerateArray())
                {
                    if (v.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String)
                        ids.Add(idEl.GetString() ?? "");
                }
            }
            if (ids.Count == 0) continue;

            hits.Add(new OsvVulnerabilityHit
            {
                Package = dep.Name,
                Version = dep.Version,
                Ecosystem = dep.Ecosystem,
                SourceFile = dep.SourceFile,
                AdvisoryIds = ids,
                Severity = ids.Count >= 3 ? "high" : ids.Count >= 1 ? "medium" : "low"
            });
        }

        return hits.OrderByDescending(h => h.AdvisoryIds.Count).ToList();
    }
}
