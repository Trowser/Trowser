using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.ThirdParty;

namespace Trowser.Security.SupplyChain;

/// <summary>
/// Supply-chain scan: Retire.js, third-party/SRI, manifest fetch + OSV, CVE reachability, cross-checks.
/// </summary>
public static class SupplyChainScanner
{
    public static async Task<SupplyChainScanResult> RunAsync(
        AutomationContext ctx,
        SupplyChainScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var summary = new List<string>();
        var findings = new List<SupplyChainFinding>();
        var chainFindings = new List<ChainableFinding>();

        var retire = await ctx.CheckSecurity();
        var thirdParty = await ctx.CheckThirdParty();
        var firewall = await new FirewallTester(ctx).RunAsync(["sri"], verbose: false);

        var retireVuln = retire.VulnerableCount;
        if (retireVuln > 0)
        {
            summary.Add($"Retire.js: {retireVuln} vulnerable library/libraries on page.");
            foreach (var lib in retire.Libraries.Where(l => l.IsVulnerable))
            {
                var cves = lib.Vulnerabilities.SelectMany(v => v.CVEs).Take(3).ToList();
                findings.Add(new SupplyChainFinding
                {
                    Category = "vulnerable-component",
                    Severity = lib.Vulnerabilities.Max(v => v.Severity).ToString().ToLowerInvariant(),
                    Title = $"{lib.Name} {lib.Version}: known CVE(s)",
                    Endpoint = retire.Url,
                    Detail = string.Join(", ", cves),
                    Evidence = lib.DetectionMethod,
                    Tags = ["retire.js", lib.Name]
                });
                chainFindings.Add(ToChainFinding("supplychain-retire", "vulnerable-component", findings[^1]));
            }
        }

        var missingSri = thirdParty.Resources
            .Where(r => !r.HasSri && r.Type is "script" or "stylesheet" && r.Url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (missingSri.Count > 0)
        {
            summary.Add($"Third-party: {missingSri.Count} external script/stylesheet load(s) without SRI.");
            foreach (var r in missingSri.Take(10))
            {
                findings.Add(new SupplyChainFinding
                {
                    Category = "missing-sri",
                    Severity = "medium",
                    Title = $"Third-party {r.Type} without SRI: {ShortUrl(r.Url)}",
                    Endpoint = r.Url,
                    Detail = "CDN compromise could substitute arbitrary script content.",
                    Tags = ["sri", r.Type, "external-script"]
                });
                chainFindings.Add(ToChainFinding($"supplychain-sri-{ShortUrl(r.Url)}", "missing-sri", findings[^1]));
            }
        }

        if (firewall.Sri?.Findings.Count > 0)
            summary.Add($"Firewall-test SRI: {firewall.Sri.Findings.Count} missing-SRI finding(s).");

        var manifests = new List<LeakedManifest>();
        if (options.IncludeManifestFetch)
        {
            var pageUrl = await ctx.GetCurrentUrl();
            manifests = await ManifestFetcher.FetchAsync(
                ctx, pageUrl, options.ManifestPaths, options.IncludePathFilterBypass, options.TimeoutMs,
                options.IncludeBrowserCookies, ct);

            foreach (var m in manifests)
            {
                summary.Add($"Manifest leak: {m.FileName} ({m.Dependencies.Count} dependencies) via {m.FetchMethod}.");
                findings.Add(new SupplyChainFinding
                {
                    Category = "manifest-leak",
                    Severity = "high",
                    Title = $"Dependency manifest exposed: {m.FileName}",
                    Endpoint = m.Url,
                    Detail = $"{m.Dependencies.Count} declared dependencies in {m.Ecosystem} manifest.",
                    Evidence = m.FetchMethod,
                    Tags = ["manifest", m.Ecosystem]
                });
                chainFindings.Add(ToChainFinding($"supplychain-manifest-{m.Url}", "manifest-leak", findings[^1]));
            }
        }

        var ciCdFiles = new List<ExposedCiCdFile>();
        if (options.IncludeCiCdProbe)
        {
            var pageUrl = await ctx.GetCurrentUrl();
            ciCdFiles = await CiCdExposureChecker.FetchAsync(
                ctx, pageUrl, options.CiCdPaths, options.TimeoutMs, options.IncludeBrowserCookies, ct);

            foreach (var file in ciCdFiles)
            {
                var topSeverity = file.Issues.Count > 0
                    ? file.Issues.Max(i => i.Severity) ?? "medium"
                    : "medium";
                summary.Add($"CI/CD exposure: {file.Path} ({file.Platform}, {file.Issues.Count} issue(s)).");
                findings.Add(new SupplyChainFinding
                {
                    Category = "ci-cd-exposure",
                    Severity = topSeverity,
                    Title = $"CI/CD config exposed: {file.FileName}",
                    Endpoint = file.Url,
                    Detail = file.Issues.Count > 0
                        ? string.Join("; ", file.Issues.Take(4).Select(i => i.Description))
                        : "Pipeline configuration file accessible without authentication.",
                    Evidence = file.Platform,
                    Tags = ["ci-cd", file.Platform]
                });
                chainFindings.Add(ToChainFinding($"supplychain-cicd-{file.Url}", "ci-cd-exposure", findings[^1]));

                foreach (var issue in file.Issues)
                {
                    findings.Add(new SupplyChainFinding
                    {
                        Category = $"ci-cd-{issue.Category}",
                        Severity = issue.Severity,
                        Title = issue.Description,
                        Endpoint = file.Url,
                        Detail = issue.LineNumber.HasValue ? $"Line {issue.LineNumber}" : null,
                        Evidence = file.Platform,
                        Tags = ["ci-cd", issue.Category, file.Platform]
                    });
                }
            }
        }

        var bundleDeps = new List<DeclaredDependency>();
        if (options.IncludeBundleDeps)
        {
            var bundleResult = await BundleDependencyExtractor.RunAsync(
                ctx,
                maxScripts: options.MaxBundleScripts,
                includeSourceMaps: options.IncludeSourceMaps,
                timeoutMs: options.TimeoutMs,
                ct: ct);
            bundleDeps = bundleResult.Dependencies;
            summary.AddRange(bundleResult.Summary);

            if (bundleDeps.Count > 0)
            {
                findings.Add(new SupplyChainFinding
                {
                    Category = "bundle-dependencies",
                    Severity = "info",
                    Title = $"{bundleDeps.Count} npm package(s) fingerprinted from JS bundles",
                    Detail = string.Join(", ", bundleDeps.Take(12).Select(d =>
                        string.IsNullOrWhiteSpace(d.Version) ? d.Name : $"{d.Name}@{d.Version}")),
                    Evidence = $"scripts={bundleResult.ScriptsScanned}, maps={bundleResult.SourceMapsScanned}",
                    Tags = ["bundle-fingerprint", "npm"]
                });
            }
        }

        var allDeps = manifests.SelectMany(m => m.Dependencies)
            .Concat(bundleDeps)
            .ToList();
        var osvHits = allDeps.Count > 0
            ? await OsvClient.LookupAsync(allDeps, options.MaxOsvPackages, ct)
            : [];

        foreach (var hit in osvHits)
        {
            findings.Add(new SupplyChainFinding
            {
                Category = "vulnerable-dependency-declared",
                Severity = hit.AdvisoryIds.Count >= 3 ? "high" : "medium",
                Title = $"Vulnerable dependency declared: {hit.Package}@{hit.Version} ({hit.AdvisoryIds.Count} advisories)",
                Endpoint = hit.SourceFile,
                Detail = string.Join(", ", hit.AdvisoryIds.Take(6)),
                Evidence = hit.Ecosystem,
                Tags = ["osv", hit.Package]
            });
            chainFindings.Add(ToChainFinding($"supplychain-osv-{hit.Package}", "vulnerable-dependency-declared", findings[^1]));
        }

        var osvCrossCheckCount = 0;
        if (options.IncludeRetireOsvCrossCheck)
        {
            var crossHits = await CrossCheckRetireWithOsvAsync(ctx, retire, allDeps, options, ct);
            osvCrossCheckCount = crossHits.Count;
            foreach (var hit in crossHits)
            {
                findings.Add(new SupplyChainFinding
                {
                    Category = "vulnerable-dependency-declared",
                    Severity = hit.AdvisoryIds.Count >= 2 ? "high" : "medium",
                    Title = $"OSV cross-check: {hit.Package}@{hit.Version} (not flagged by Retire.js)",
                    Detail = string.Join(", ", hit.AdvisoryIds.Take(6)),
                    Evidence = "retire-osv-crosscheck",
                    Tags = ["osv-crosscheck", hit.Package]
                });
                chainFindings.Add(ToChainFinding($"supplychain-xcheck-{hit.Package}", "vulnerable-dependency-declared", findings[^1]));
            }
            if (osvCrossCheckCount > 0)
                summary.Add($"Retire+OSV cross-check: {osvCrossCheckCount} additional vulnerable package(s).");
        }

        var reachabilityCount = 0;
        if (options.IncludeCveReachability)
        {
            var manifestVersions = allDeps
                .GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First().Version, StringComparer.OrdinalIgnoreCase);

            var reachFindings = await CveReachabilityRunner.RunAsync(
                ctx, manifestVersions, blindRun: manifestVersions.Count == 0, options.TimeoutMs,
                options.IncludeBrowserCookies, ct);
            reachabilityCount = reachFindings.Count;
            findings.AddRange(reachFindings);
            foreach (var rf in reachFindings)
                chainFindings.Add(ToChainFinding($"supplychain-cve-{rf.Title.GetHashCode():x}", rf.Category, rf));
            if (reachabilityCount > 0)
                summary.Add($"CVE reachability: {reachabilityCount} confirmed exploitable primitive(s).");
        }

        foreach (var cf in chainFindings)
            ctx.UpsertVerifiedChainFinding(cf);

        sw.Stop();

        var isClean = retireVuln == 0 && missingSri.Count == 0 && osvHits.Count == 0
                      && reachabilityCount == 0 && osvCrossCheckCount == 0
                      && manifests.Count == 0 && ciCdFiles.Count == 0;

        return new SupplyChainScanResult
        {
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            IsClean = isClean,
            ManifestCount = manifests.Count,
            DeclaredDependencyCount = allDeps.Count,
            VulnerableDeclaredCount = osvHits.Count + osvCrossCheckCount,
            MissingSriExternalCount = missingSri.Count,
            RetireVulnerableCount = retireVuln,
            OsvCrossCheckCount = osvCrossCheckCount,
            CveReachabilityConfirmedCount = reachabilityCount,
            CiCdExposureCount = ciCdFiles.Count,
            BundleDependencyCount = bundleDeps.Count,
            Summary = summary,
            Manifests = manifests,
            CiCdFiles = ciCdFiles,
            BundleDependencies = bundleDeps,
            OsvFindings = osvHits,
            Findings = findings,
            ChainFindings = chainFindings,
            Retire = new
            {
                isClean = retire.IsClean,
                vulnerableCount = retire.VulnerableCount,
                libraryCount = retire.LibraryCount
            },
            ThirdParty = new
            {
                totalCount = thirdParty.TotalCount,
                sriCount = thirdParty.SriCount,
                externalWithoutSri = missingSri.Count,
                sriCoverageRatio = thirdParty.TotalCount > 0
                    ? Math.Round((double)thirdParty.SriCount / thirdParty.TotalCount, 2)
                    : 1.0
            },
            Sri = new
            {
                verdict = firewall.Sri?.Verdict,
                findingCount = firewall.Sri?.Findings.Count ?? 0
            }
        };
    }

    private static async Task<List<OsvVulnerabilityHit>> CrossCheckRetireWithOsvAsync(
        AutomationContext ctx,
        SecurityResult retire,
        IReadOnlyList<DeclaredDependency> manifestDeps,
        SupplyChainScanOptions options,
        CancellationToken ct)
    {
        var retireKeys = retire.Libraries
            .Select(l => $"{l.Name}|{l.Version}".ToLowerInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var candidates = new List<DeclaredDependency>();

        foreach (var d in manifestDeps)
        {
            var key = $"{d.Name}|{d.Version}";
            if (!retireKeys.Contains(key))
                candidates.Add(d);
        }

        var tech = await ctx.CheckTechStack();
        foreach (var det in tech.Detections.Where(d =>
                     d.Category.Equals("JavaScript", StringComparison.OrdinalIgnoreCase)
                     && !string.IsNullOrWhiteSpace(d.Version)))
        {
            var key = $"{det.Name}|{det.Version}";
            if (retireKeys.Contains(key)) continue;
            if (candidates.Any(c => c.Name.Equals(det.Name, StringComparison.OrdinalIgnoreCase))) continue;
            candidates.Add(new DeclaredDependency
            {
                Name = det.Name,
                Version = det.Version!,
                Ecosystem = "npm",
                SourceFile = "tech-stack"
            });
        }

        if (candidates.Count == 0) return [];
        return await OsvClient.LookupAsync(candidates, options.MaxOsvPackages, ct);
    }

    private static ChainableFinding ToChainFinding(string id, string category, SupplyChainFinding f) =>
        new()
        {
            Id = id,
            Source = "supplychain",
            Category = category,
            Severity = f.Severity,
            Title = f.Title,
            Endpoint = f.Endpoint,
            Method = f.Method,
            Detail = f.Detail,
            Evidence = f.Evidence,
            Tags = f.Tags
        };

    private static string ShortUrl(string url)
    {
        try
        {
            var u = new Uri(url);
            var path = u.AbsolutePath;
            return path.Length > 40 ? u.Host + path[..37] + "..." : u.Host + path;
        }
        catch { return url.Length > 48 ? url[..45] + "..." : url; }
    }
}
