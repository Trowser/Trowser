using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
private Task HandlePostSecurityTrustedHeaderBypass(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityTrustedHeaderBypassAsync);

internal async Task<object> BuildSecurityTrustedHeaderBypassAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Trusted-header bypass probes send anonymous requests with spoofed proxy headers");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var options = new Security.TrustedHeaderBypassChecker.BypassOptions
        {
            MaxTargets = body.GetInt("maxTargets", 20),
            TimeoutMs = body.GetInt("timeoutMs", 12_000),
            DiscoverFromAttackSurface = body.GetBool("discoverFromAttackSurface", true),
            Paths = MergeExplicitTargets(body.GetStringList("paths") ?? body.GetStringArray("paths"),
                body.GetStringList("urls") ?? body.GetStringArray("urls")),
            Headers = body.GetStringList("headers") ?? body.GetStringArray("headers"),
            HeaderSets = ParseHeaderSets(body)
        };

        var result = await Security.TrustedHeaderBypassChecker.RunAsync(_context, options);
        return new
        {
            isClean = result.IsClean,
            findingCount = result.Findings.Count,
            targetsAttempted = result.TargetsAttempted,
            targetsTested = result.TargetsTested,
            targetsSkipped = result.TargetsSkipped,
            headersTested = result.HeadersTested,
            findings = result.Findings,
            summary = result.Summary
        };
    }

private Task HandlePostSecurityDefaultCredentialCanary(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityDefaultCredentialCanaryAsync);

internal async Task<object> BuildSecurityDefaultCredentialCanaryAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body, "Default-credential canary sends login attempts");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var loginUrls = MergeExplicitTargets(
            body.GetStringList("loginUrls") ?? body.GetStringArray("loginUrls"),
            body.GetString("loginUrl") is { Length: > 0 } single ? [single] : null);
        var explicitLogin = loginUrls is { Count: > 0 };

        var options = new Security.DefaultCredentialCanary.CanaryOptions
        {
            UserPlaceholder = body.GetString("userPlaceholder") ?? "§USER§",
            PassPlaceholder = body.GetString("passPlaceholder") ?? "§PASS§",
            BodyTemplate = body.GetString("bodyTemplate") ?? body.GetString("body"),
            ContentType = body.GetString("contentType"),
            Method = body.GetString("method") ?? "POST",
            MaxTargets = body.GetInt("maxTargets", 5),
            MaxPairs = body.GetInt("maxPairs", 12),
            DelayMs = body.GetInt("delayMs", 400),
            TimeoutMs = body.GetInt("timeoutMs", 15_000),
            DiscoverFromPage = explicitLogin ? body.GetBool("discoverFromPage", false) : body.GetBool("discoverFromPage", true),
            DiscoverFromNetwork = explicitLogin ? body.GetBool("discoverFromNetwork", false) : body.GetBool("discoverFromNetwork", true),
            IncludeDiscoveredCredentials = body.GetBool("includeDiscoveredCredentials"),
            LoginUrls = loginUrls
        };

        var result = await Security.DefaultCredentialCanary.RunAsync(_context, options);
        return new
        {
            isClean = result.IsClean,
            findingCount = result.Findings.Count,
            targetsTested = result.TargetsTested,
            targetsSkippedSpaShell = result.TargetsSkippedSpaShell,
            discoveredPairsIncluded = result.DiscoveredPairsIncluded,
            credentialSources = result.CredentialSources,
            findings = result.Findings.Select(f => new
            {
                f.Url,
                f.Username,
                password = "***",
                f.Severity,
                f.Category,
                f.Title,
                f.Detail,
                f.Status
            }).ToList(),
            attempts = result.Attempts,
            summary = result.Summary,
            note = "Successful pairs are redacted in findings.password; see server log or re-run with explicit loginUrls for controlled verification."
        };
    }

private Task HandlePostSourceMaps(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSourceMapsAsync);

internal async Task<object> BuildSourceMapsAsync(JsonBody body)
    {
        var result = await _context.CheckSourceMaps();
        return new
        {
            isClean = result.IsClean,
            findingCount = result.FindingCount,
            findings = result.Findings.Select(f => new
            {
                severity = f.Severity.ToString().ToLower(),
                category = f.Category,
                description = f.Description,
                url = f.Url,
                detail = f.Detail,
                recommendation = f.Recommendation
            }).ToList(),
            summary = result.Format(includeDetails: false)
        };
    }

private Task HandlePostSecuritySupplyChainScan(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecuritySupplyChainScanAsync);

internal async Task<object> BuildSecuritySupplyChainScanAsync(JsonBody body)
    {
        if (body.GetBool("includeCveReachability"))
        {
            var gateError = SafetyGate.RequireActive(body, "CVE reachability sends exploit primitives to your server");
            if (gateError != null)
                throw new ApiCommandException(400, gateError.Value);
        }

        var options = new Security.SupplyChain.SupplyChainScanOptions
        {
            IncludeManifestFetch = body.GetBool("includeManifestFetch", true),
            IncludePathFilterBypass = body.GetBool("includePathFilterBypass", true),
            IncludeCiCdProbe = body.GetBool("includeCiCdProbe", true),
            IncludeBundleDeps = body.GetBool("includeBundleDeps", true),
            IncludeSourceMaps = body.GetBool("includeSourceMaps", true),
            IncludeCveReachability = body.GetBool("includeCveReachability", SafetyGate.Resolve(body).AllowsWriteVerbs()),
            IncludeRetireOsvCrossCheck = body.GetBool("includeRetireOsvCrossCheck", true),
            MaxOsvPackages = Math.Clamp(body.GetInt("maxOsvPackages", 200), 1, 500),
            MaxBundleScripts = Math.Clamp(body.GetInt("maxBundleScripts", 24), 1, 80),
            TimeoutMs = body.GetInt("timeoutMs", 30_000),
            IncludeBrowserCookies = body.GetBool("includeBrowserCookies", true)
        };

        try
        {
            var result = await _context.RunSupplyChainScan(options);
            return new
            {
                isClean = result.IsClean,
                elapsedMs = result.ElapsedMs,
                manifestCount = result.ManifestCount,
                declaredDependencyCount = result.DeclaredDependencyCount,
                vulnerableDeclaredCount = result.VulnerableDeclaredCount,
                missingSriExternalCount = result.MissingSriExternalCount,
                retireVulnerableCount = result.RetireVulnerableCount,
                osvCrossCheckCount = result.OsvCrossCheckCount,
                cveReachabilityConfirmedCount = result.CveReachabilityConfirmedCount,
                ciCdExposureCount = result.CiCdExposureCount,
                bundleDependencyCount = result.BundleDependencyCount,
                summary = result.Summary,
                retire = result.Retire,
                thirdParty = result.ThirdParty,
                sri = result.Sri,
                manifests = result.Manifests.Select(m => new
                {
                    m.Url,
                    m.FileName,
                    m.Ecosystem,
                    m.ByteLength,
                    m.FetchMethod,
                    dependencyCount = m.Dependencies.Count,
                    dependencies = m.Dependencies.Take(25).Select(d => new { d.Name, d.Version, d.Ecosystem })
                }),
                ciCdFiles = result.CiCdFiles.Select(f => new
                {
                    f.Url,
                    f.Path,
                    f.FileName,
                    f.Platform,
                    f.ByteLength,
                    issueCount = f.Issues.Count,
                    issues = f.Issues.Take(10).Select(i => new { i.Category, i.Severity, i.Description, i.LineNumber })
                }),
                bundleDependencies = result.BundleDependencies.Take(50).Select(d => new { d.Name, d.Version, d.SourceFile }),
                osvFindings = result.OsvFindings.Select(o => new
                {
                    o.Package,
                    o.Version,
                    o.Ecosystem,
                    o.SourceFile,
                    advisoryCount = o.AdvisoryIds.Count,
                    advisories = o.AdvisoryIds.Take(10),
                    o.Severity
                }),
                findings = result.Findings.Select(f => new
                {
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Endpoint,
                    f.Method,
                    f.Detail,
                    f.Evidence,
                    f.Tags
                }),
                chainFindingCount = result.ChainFindings.Count
            };
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }

private Task HandlePostSecurityOsvCheck(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityOsvCheckAsync);

internal async Task<object> BuildSecurityOsvCheckAsync(JsonBody body)
    {
        var manifest = body.GetString("manifest");
        if (string.IsNullOrWhiteSpace(manifest))
            throw new ApiCommandException(400, "Missing required field: manifest (raw manifest body).");

        var fileName = body.GetString("fileName") ?? "package.json";
        var ecosystem = body.GetString("ecosystem");
        var maxPackages = Math.Clamp(body.GetInt("maxPackages", 200), 1, 500);

        try
        {
            var result = await Security.SupplyChain.OsvManifestChecker.CheckAsync(
                manifest, fileName, ecosystem, maxPackages, _context.OperationCancellation);

            if (!string.IsNullOrEmpty(result.ParseError))
                throw new ApiCommandException(400, result.ParseError);

            return new
            {
                fileName = result.FileName,
                ecosystem = result.Ecosystem,
                dependencyCount = result.DependencyCount,
                vulnerableCount = result.VulnerableCount,
                isClean = result.VulnerableCount == 0,
                dependencies = result.Dependencies.Select(d => new { d.Name, d.Version, d.Ecosystem }),
                findings = result.Findings.Select(o => new
                {
                    o.Package,
                    o.Version,
                    o.Ecosystem,
                    advisoryCount = o.AdvisoryIds.Count,
                    advisories = o.AdvisoryIds.Take(15),
                    o.Severity
                })
            };
        }
        catch (ApiCommandException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ApiCommandException(500, ex.Message);
        }
    }

private Task HandlePostSecurityJsAudit(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityJsAuditAsync);

internal async Task<object> BuildSecurityJsAuditAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireAtLeast(
            SafetyGate.Resolve(body),
            SafetyMode.Safe,
            "JS asset audit fetches script URLs already referenced on the page");
        if (gateError != null)
            throw new ApiCommandException(400, gateError.Value);

        var maxScripts = body.GetInt("maxScripts", 32);
        var maxBytesPerFile = body.GetInt("maxBytesPerFile", 524288);
        var sameOriginOnly = body.GetBool("sameOriginOnly");
        var timeoutMs = body.GetInt("timeoutMs", 20000);

        var result = await JavaScriptStaticAudit.RunAsync(_context, maxScripts, maxBytesPerFile, sameOriginOnly, timeoutMs, CancellationToken.None);
        return new
        {
            result.ScriptsDiscovered,
            result.ScriptsFetched,
            result.Summary,
            assets = result.Assets.Select(a => new
            {
                a.Url,
                a.ByteLength,
                a.Error,
                hits = a.Hits.Select(h => new { h.Category, h.Pattern, h.Offset, h.Snippet })
            })
        };
    }

private Task HandlePostSecurityTlsIntrospection(HttpListenerRequest request, HttpListenerResponse response) =>
    RespondAsync(request, response, BuildSecurityTlsIntrospectionAsync);

internal async Task<object> BuildSecurityTlsIntrospectionAsync(JsonBody body)
    {
        return await Security.TlsIntrospectionChecker.RunAsync(_context,
            new Security.TlsIntrospectionChecker.IntrospectionOptions
            {
                MaxOrigins = body.GetInt("maxOrigins", 8),
                ConnectTimeoutMs = body.GetInt("connectTimeoutMs", 8000),
                CertExpiryWarningDays = body.GetInt("certExpiryWarningDays", 30),
                IncludeNetworkOrigins = body.GetBool("includeNetworkOrigins", true),
                IncludeLegacyTlsProbes = body.GetBool("includeLegacyTlsProbes", true)
            });
    }
}
