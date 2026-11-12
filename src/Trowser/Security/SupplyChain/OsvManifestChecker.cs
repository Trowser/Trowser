namespace Trowser.Security.SupplyChain;

/// <summary>
/// OSV enrichment for raw manifest bodies (no web fetch required).
/// </summary>
public static class OsvManifestChecker
{
    public sealed class OsvCheckResult
    {
        public string FileName { get; init; } = "";
        public string Ecosystem { get; init; } = "";
        public int DependencyCount { get; init; }
        public int VulnerableCount { get; init; }
        public List<DeclaredDependency> Dependencies { get; init; } = [];
        public List<OsvVulnerabilityHit> Findings { get; init; } = [];
        public string? ParseError { get; init; }
    }

    public static async Task<OsvCheckResult> CheckAsync(
        string manifestBody,
        string fileName,
        string? ecosystem = null,
        int maxPackages = 200,
        CancellationToken ct = default)
    {
        fileName = string.IsNullOrWhiteSpace(fileName) ? "package.json" : fileName.Trim();
        ecosystem ??= ManifestParser.ResolveEcosystem(fileName) ?? "npm";

        if (string.IsNullOrWhiteSpace(manifestBody))
        {
            return new OsvCheckResult
            {
                FileName = fileName,
                Ecosystem = ecosystem,
                ParseError = "manifest body is empty."
            };
        }

        List<DeclaredDependency> dependencies;
        try
        {
            dependencies = ManifestParser.Parse(manifestBody, fileName, ecosystem);
        }
        catch (Exception ex)
        {
            return new OsvCheckResult
            {
                FileName = fileName,
                Ecosystem = ecosystem,
                ParseError = ex.Message
            };
        }

        var hits = await OsvClient.LookupAsync(dependencies, maxPackages, ct);
        return new OsvCheckResult
        {
            FileName = fileName,
            Ecosystem = ecosystem,
            DependencyCount = dependencies.Count,
            VulnerableCount = hits.Count,
            Dependencies = dependencies.Take(50).ToList(),
            Findings = hits
        };
    }
}
