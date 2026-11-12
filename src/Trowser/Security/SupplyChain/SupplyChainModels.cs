namespace Trowser.Security.SupplyChain;

public sealed class DeclaredDependency
{
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string SourceFile { get; init; } = "";
}

public sealed class LeakedManifest
{
    public string Url { get; init; } = "";
    public string FileName { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public int ByteLength { get; init; }
    public string FetchMethod { get; init; } = "direct";
    public List<DeclaredDependency> Dependencies { get; init; } = [];
}

public sealed class OsvVulnerabilityHit
{
    public string Package { get; init; } = "";
    public string Version { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string SourceFile { get; init; } = "";
    public List<string> AdvisoryIds { get; init; } = [];
    public string Severity { get; init; } = "medium";
}

public sealed class SupplyChainFinding
{
    public string Category { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public string Title { get; init; } = "";
    public string? Endpoint { get; init; }
    public string? Method { get; init; }
    public string? Detail { get; init; }
    public string? Evidence { get; init; }
    public List<string> Tags { get; init; } = [];
}

public sealed class CiCdIssue
{
    public string Category { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public string Description { get; init; } = "";
    public int? LineNumber { get; init; }
}

public sealed class ExposedCiCdFile
{
    public string Url { get; init; } = "";
    public string Path { get; init; } = "";
    public string FileName { get; init; } = "";
    public string Platform { get; init; } = "";
    public int ByteLength { get; init; }
    public List<CiCdIssue> Issues { get; init; } = [];
}

public sealed class SupplyChainScanOptions
{
    public bool IncludeManifestFetch { get; set; } = true;
    public bool IncludePathFilterBypass { get; set; } = true;
    public bool IncludeCiCdProbe { get; set; } = true;
    public bool IncludeBundleDeps { get; set; } = true;
    public bool IncludeSourceMaps { get; set; } = true;
    public bool IncludeCveReachability { get; set; }
    public bool IncludeRetireOsvCrossCheck { get; set; } = true;
    public int MaxOsvPackages { get; set; } = 200;
    public int MaxBundleScripts { get; set; } = 24;
    public int TimeoutMs { get; set; } = 30_000;
    /// <summary>Attach sanitized session cookies to manifest/CI/CD probes (default true).</summary>
    public bool IncludeBrowserCookies { get; set; } = true;
    public IReadOnlyList<string>? ManifestPaths { get; set; }
    public IReadOnlyList<string>? CiCdPaths { get; set; }
}

public sealed class SupplyChainScanResult
{
    public int ElapsedMs { get; init; }
    public bool IsClean { get; init; }
    public int ManifestCount { get; init; }
    public int DeclaredDependencyCount { get; init; }
    public int VulnerableDeclaredCount { get; init; }
    public int MissingSriExternalCount { get; init; }
    public int RetireVulnerableCount { get; init; }
    public int OsvCrossCheckCount { get; init; }
    public int CveReachabilityConfirmedCount { get; init; }
    public int CiCdExposureCount { get; init; }
    public int BundleDependencyCount { get; init; }
    public List<string> Summary { get; init; } = [];
    public List<LeakedManifest> Manifests { get; init; } = [];
    public List<ExposedCiCdFile> CiCdFiles { get; init; } = [];
    public List<DeclaredDependency> BundleDependencies { get; init; } = [];
    public List<OsvVulnerabilityHit> OsvFindings { get; init; } = [];
    public List<SupplyChainFinding> Findings { get; init; } = [];
    public List<ChainEngine.ChainableFinding> ChainFindings { get; init; } = [];
    public object? Retire { get; init; }
    public object? ThirdParty { get; init; }
    public object? Sri { get; init; }
}
