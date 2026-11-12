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
using Trowser.Security.Nuclei;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Security (Retire.js)

    private SecurityChecker GetSecurityChecker() => new SecurityChecker(ActiveTab.WebView);

    public async Task<SecurityResult> CheckSecurity()
    {
        using var linked = LinkCheckerCancellation();
        return await GetSecurityChecker().RunAsync(linked.Token);
    }

    public async Task<SecurityResult> PrintSecurityReport(
        bool includeDetails = true, bool checkForUpdates = true)
    {
        var result = await GetSecurityChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.Contains("VULNERABLE"))
                _logColored(line, "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("vulnerabilit"))
                    _logColored(line, "#F44747");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("DETECTED LIBRARIES") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No known vulnerabilities"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        if (checkForUpdates)
            await LogSecurityUpdateNotice();

        return result;
    }

    public async Task AssertSecure(Severity? minSeverity = null, string? message = null)
    {
        _logColored("Security scan powered by Retire.js", "#888888");
        var result = await GetSecurityChecker().RunAsync();
        var desc = message ?? "No known JavaScript vulnerabilities";

        var vulnerable = minSeverity.HasValue
            ? result.GetByMinSeverity(minSeverity.Value)
            : result.Vulnerable;

        if (vulnerable.Count == 0)
        {
            Assert.Pass($"{desc} ({result.LibraryCount} library/libraries scanned)");
        }
        else
        {
            var totalVulns = vulnerable.Sum(l => l.Vulnerabilities.Count);
            Assert.Fail($"{desc}: {vulnerable.Count} library/libraries with {totalVulns} vulnerability/vulnerabilities");
            foreach (var lib in vulnerable.OrderByDescending(l => l.HighestSeverity))
            {
                var sevLabel = lib.HighestSeverity?.ToString().ToUpper() ?? "?";
                var cves = lib.Vulnerabilities
                    .SelectMany(v => v.CVEs)
                    .Distinct()
                    .Take(3);
                var cveStr = cves.Any() ? $" ({string.Join(", ", cves)})" : "";
                _logColored($"    [{sevLabel}] {lib.Name} {lib.Version}{cveStr}", "#F44747");
            }
        }
    }

    public async Task<RepositoryUpdateInfo> CheckSecurityUpdates()
    {
        return await SecurityChecker.CheckForUpdatesAsync();
    }

    private async Task LogSecurityUpdateNotice()
    {
        try
        {
            var update = await SecurityChecker.CheckForUpdatesAsync();

            _logColored($"Vulnerability database: {update.Source}" +
                (update.CurrentDate.HasValue ? $", dated {update.CurrentDate.Value:yyyy-MM-dd}" : ""),
                "#888888");

            if (update.UpdateAvailable)
            {
                _logColored("", "#888888");
                _logColored("A newer vulnerability database is available!", "#CCA700");
                _logColored($"  Latest update: {update.LatestDate:yyyy-MM-dd}", "#CCA700");
                _logColored($"  To update, download the latest file and place it here:", "#CCA700");
                _logColored($"  {update.LocalPath}", "#CCA700");
                _logColored($"  Download: {RepositoryUpdateInfo.DownloadUrl}", "#CCA700");
            }
            else if (update.Error != null)
            {
                _logColored($"Could not check for updates: {update.Error}", "#888888");
            }
        }
        catch
        {
            // Never let update check failures affect the scan
        }
    }

    // --- Security Headers ---

    private HeadersChecker GetHeadersChecker() => new HeadersChecker(ActiveTab.WebView);

    public async Task<HeadersResult> CheckSecurityHeaders()
    {
        using var linked = LinkCheckerCancellation();
        var url = await GetCurrentUrl();
        if (!string.IsNullOrEmpty(url))
        {
            var entry = HeadersChecker.FindNavigationDocumentEntry(ActiveTab.Network.PageEntries, url);
            if (entry != null)
            {
                var fromLog = HeadersChecker.AnalyzeFromHeaders(url, entry.ResponseHeaders);
                return await GetHeadersChecker().EnrichCspEvaluationAsync(fromLog, linked.Token);
            }
        }

        return await GetHeadersChecker().RunAsync(pageUrl =>
        {
            ActiveTab.MarkSyntheticRequest("HEAD", pageUrl);
            ActiveTab.MarkSyntheticRequest("GET", pageUrl);
        }, linked.Token);
    }

    /// <summary>Audit security headers for an arbitrary URL (subresource / JSON endpoint) via server-side fetch.</summary>
    public async Task<HeadersResult> CheckSecurityHeadersForUrl(string url, int timeoutMs = 12_000)
    {
        if (string.IsNullOrWhiteSpace(url))
            throw new ArgumentException("url is required", nameof(url));

        var resp = await SecurityProbeHttp.FetchAsync(
            this, url, "HEAD", null, null, timeoutMs, includeBrowserCookies: true);
        if (resp.Status is 405 or 501 or 0)
            resp = await SecurityProbeHttp.FetchAsync(
                this, url, "GET", null, null, timeoutMs, includeBrowserCookies: true);

        if (resp.Status == 0)
        {
            return new HeadersResult
            {
                Url = url,
                Timestamp = DateTime.UtcNow,
                FetchError = "Failed to fetch URL for header audit.",
                Findings = []
            };
        }

        var dict = new Dictionary<string, string>(resp.ResponseHeaders, StringComparer.OrdinalIgnoreCase);
        return HeadersChecker.AnalyzeFromHeaders(url, dict);
    }

    public async Task<XssiScanProbe.XssiScanResult> RunXssiScanAsync(XssiScanProbe.XssiOptions options) =>
        await new XssiScanProbe(this).RunAsync(options);

    public async Task<XssiScanProbe.XssiScanResult> PrintXssiScanReport(
        IReadOnlyList<string>? urls = null,
        int maxUrls = 12,
        int timeoutMs = 12_000,
        bool includeNetworkLog = true)
    {
        var options = new XssiScanProbe.XssiOptions
        {
            Urls = urls,
            MaxUrls = maxUrls,
            TimeoutMs = timeoutMs,
            IncludeNetworkLog = includeNetworkLog
        };
        var result = await RunXssiScanAsync(options);
        _logColored(result.Message, result.Findings.Count > 0 ? "#CCA700" : "#4EC9B0");
        foreach (var f in result.Findings)
        {
            var color = f.Severity is "high" or "critical" ? "#F44747" : "#CCA700";
            _logColored($"[{f.Severity.ToUpper()}] {f.Title}", color);
            _logColored($"  {f.Method} {f.Endpoint}", "#888888");
            if (!string.IsNullOrEmpty(f.Evidence))
                _logColored($"  {f.Evidence}", "#CCCCCC");
        }

        if (result.NextActions.Count > 0)
        {
            _logColored("Next:", "#569CD6");
            foreach (var a in result.NextActions)
                _logColored($"  {a}", "#569CD6");
        }

        return result;
    }

    public async Task<HeadersResult> PrintSecurityHeadersReport(bool includeDetails = true)
    {
        var result = await GetHeadersChecker().RunAsync();
        var report = result.Format(includeDetails);

        if (!result.FetchSucceeded)
        {
            foreach (var line in report.Split(Environment.NewLine))
                _logColored(line, "#CCA700");
            return result;
        }

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("high-severity") || line.Contains("immediate"))
                    _logColored(line, "#F44747");
                else if (line.Contains("medium-severity"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("FINDINGS") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No security header issues"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertSecurityHeaders(Severity? minSeverity = null, string? message = null)
    {
        var result = await GetHeadersChecker().RunAsync();
        var desc = message ?? "Security headers should be properly configured";

        if (!result.FetchSucceeded)
        {
            _logColored(
                $"HTTP security headers check skipped (could not fetch headers): {result.FetchError}",
                "#CCA700");
            Assert.Pass($"{desc} (skipped — {result.FetchError})");
            return;
        }

        var flagged = minSeverity.HasValue
            ? result.GetByMinSeverity(minSeverity.Value)
            : result.Findings;

        if (flagged.Count == 0)
        {
            Assert.Pass($"{desc} ({result.RawHeaders.Count} headers checked)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} issue(s) found");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                _logColored($"    [{sevLabel}] {f.Header}: {f.Description}", "#F44747");
            }
        }
    }

    private CorsChecker GetCorsChecker() => new CorsChecker(ActiveTab.WebView);

    public async Task<CorsResult> CheckCors()
    {
        using var linked = LinkCheckerCancellation();
        return await GetCorsChecker().RunAsync(linked.Token);
    }

    public async Task<CorsSweep.SweepResult> CheckCorsSweep(CorsSweep.SweepOptions? options = null)
    {
        options ??= new CorsSweep.SweepOptions();
        return await CorsSweep.RunAsync(this, GetCorsChecker(), options);
    }

    public async Task<CorsResult> PrintCorsReport(bool includeDetails = true)
    {
        var result = await GetCorsChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("Critical") || line.Contains("authenticated"))
                    _logColored(line, "#F44747");
                else if (line.Contains("permissive"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("ISSUES") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No CORS misconfigurations"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertCors(Severity? minSeverity = null, string? message = null)
    {
        var result = await GetCorsChecker().RunAsync();
        var desc = message ?? "CORS should be properly configured";

        var issues = minSeverity.HasValue
            ? result.Issues.Where(f => f.Severity >= minSeverity).ToList()
            : result.Issues;

        if (issues.Count == 0)
        {
            Assert.Pass($"{desc} ({result.Findings.Count} origin(s) tested)");
        }
        else
        {
            Assert.Fail($"{desc}: {issues.Count} issue(s) found");
            foreach (var f in issues.OrderByDescending(f => f.Severity))
            {
                var sevLabel = f.Severity?.ToString().ToUpper() ?? "?";
                _logColored($"    [{sevLabel}] Origin {f.Origin}: {f.Description}", "#F44747");
            }
        }
    }

    public async Task AssertDiscover(string wordlist = "common", string basePath = "/",
        int delayMs = 0, string? message = null, bool spaMode = true, string? spaProbePath = null)
    {
        var scanner = new EndpointScanner(this);
        var result = await scanner.RunAsync(wordlist, basePath, delayMs, spaMode, spaProbePath);
        var desc = message ?? "No sensitive endpoints should be publicly accessible";

        var accessible = result.Discovered.Where(d => d.StatusCode >= 200 && d.StatusCode < 300).ToList();
        if (accessible.Count == 0)
        {
            Assert.Pass($"{desc} ({result.ScannedCount} paths scanned)");
        }
        else
        {
            Assert.Fail($"{desc}: {accessible.Count} accessible endpoint(s) found");
            foreach (var ep in accessible.OrderBy(e => e.Path))
            {
                var info = ep.ContentType != null ? $" [{ep.ContentType}]" : "";
                _logColored($"    {ep.StatusCode} {ep.Path}{info}", "#F44747");
            }
        }
    }

    public async Task<DiscoverResult> DiscoverEndpoints(string wordlist = "common", string basePath = "/",
        int delayMs = 0, bool spaMode = true, string? spaProbePath = null)
    {
        var scanner = new EndpointScanner(this);
        return await scanner.RunAsync(wordlist, basePath, delayMs, spaMode, spaProbePath);
    }

    public async Task<DiscoverResult> PrintDiscoverReport(string wordlist = "common",
        string basePath = "/", bool includeDetails = true, int delayMs = 0, bool spaMode = true,
        string? spaProbePath = null)
    {
        var scanner = new EndpointScanner(this);
        var result = await scanner.RunAsync(wordlist, basePath, delayMs, spaMode, spaProbePath);
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("Accessible") || line.Contains("200 "))
                _logColored(line, "#CCA700");
            else if (line.Contains("Forbidden") || line.Contains("403 "))
                _logColored(line, "#569CD6");
            else if (line.Contains("Auth Required") || line.Contains("401 "))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No interesting endpoints"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    #endregion

    #region DOM XSS Audit

    private XssAudit.XssChecker GetXssChecker() => new XssAudit.XssChecker(ActiveTab.WebView);

    public async Task<XssAudit.XssResult> CheckXss(bool probeDomOpenRedirects = false)
    {
        using var linked = LinkCheckerCancellation();
        var result = await GetXssChecker().RunAsync(linked.Token);
        if (!probeDomOpenRedirects)
            return result;
        return await Security.DomOpenRedirectProber.ProbeAsync(this, result);
    }

    public async Task<XssAudit.XssResult> PrintXssReport(bool includeDetails = true)
    {
        var result = await GetXssChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.Contains("[INFO]"))
                _logColored(line, "#888888");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("high-severity") || line.Contains("immediate"))
                    _logColored(line, "#F44747");
                else if (line.Contains("medium-severity"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("FINDINGS") || line.StartsWith("---") || line.StartsWith("BY CATEGORY"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No static DOM XSS patterns") || line.Contains("No DOM XSS issues"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertXssClean(XssAudit.XssSeverity? minSeverity = null, string? message = null)
    {
        var result = await GetXssChecker().RunAsync();
        var desc = message ?? "No DOM XSS risks should be present";

        var flagged = minSeverity.HasValue
            ? result.GetByMinSeverity(minSeverity.Value)
            : result.Findings.Where(f => f.Severity >= XssAudit.XssSeverity.Low).ToList();

        if (flagged.Count == 0)
        {
            Assert.Pass($"{desc} ({result.FindingCount} items checked)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} issue(s) found");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
            {
                var sevLabel = f.Severity.ToString().ToUpper();
                _logColored($"    [{sevLabel}] {f.Category}: {f.Description}", "#F44747");
            }
        }
    }

    #endregion

    #region Mixed Content

    private MixedContent.MixedContentChecker GetMixedContentChecker() => new MixedContent.MixedContentChecker(ActiveTab.WebView);

    public async Task<MixedContent.MixedContentResult> CheckMixedContent()
    {
        using var linked = LinkCheckerCancellation();
        return await GetMixedContentChecker().RunAsync(linked.Token);
    }

    public async Task<MixedContent.MixedContentResult> PrintMixedContentReport(bool includeDetails = true)
    {
        var result = await GetMixedContentChecker().RunAsync();
        var report = result.Format(includeDetails);
        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("No mixed content") || line.Contains("not applicable") || line.Contains("Mixed Content Audit"))
                    _logColored(line, "#4EC9B0");
                else
                    _logColored(line, "#F44747");
            }
            else if (line.StartsWith("FINDINGS") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }
        return result;
    }

    public async Task AssertNoMixedContent(MixedContent.MixedContentSeverity? minSeverity = null, string? message = null)
    {
        var result = await GetMixedContentChecker().RunAsync();

        if (!result.IsHttps)
        {
            Assert.Pass(message ?? "Mixed content check: page is HTTP (not applicable)");
            return;
        }

        var findings = minSeverity.HasValue
            ? result.Findings.Where(f => f.Severity <= minSeverity.Value).ToList()
            : result.Findings;
        var desc = message ?? "No mixed content (HTTP resources on HTTPS page)";

        if (findings.Count == 0)
            Assert.Pass($"{desc} (page is HTTPS, all resources use HTTPS)");
        else
        {
            Assert.Fail($"{desc}: {findings.Count} mixed content issue(s) found");
            foreach (var f in findings.Take(10))
            {
                var color = f.Severity == MixedContent.MixedContentSeverity.High ? "#F44747" : "#CCA700";
                _logColored($"    [{f.Severity.ToString().ToUpper()}] <{f.Tag} {f.Attribute}=\"{f.Url}\">", color);
            }
        }
    }

    #endregion

    #region Source Map & Debug Mode Audit

    private Security.SourceMapChecker GetSourceMapChecker() => new Security.SourceMapChecker(ActiveTab.WebView);

    public async Task<Security.SourceMapResult> CheckSourceMaps()
    {
        return await GetSourceMapChecker().RunAsync();
    }

    public async Task<Security.SourceMapResult> PrintSourceMapReport(bool includeDetails = true)
    {
        var result = await GetSourceMapChecker().RunAsync();
        var report = result.Format(includeDetails);

        foreach (var line in report.Split(Environment.NewLine))
        {
            if (line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
                _logColored(line, line.Contains("found") ? "#CCA700" : "#4EC9B0");
            else if (line.Contains("No source maps"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertNoSourceMaps(Severity? minSeverity = null, string? message = null)
    {
        var result = await GetSourceMapChecker().RunAsync();
        var desc = message ?? "No source maps or debug indicators should be exposed";

        var flagged = minSeverity.HasValue
            ? result.Findings.Where(f => f.Severity >= minSeverity.Value).ToList()
            : result.Findings;

        if (flagged.Count == 0)
        {
            Assert.Pass(desc);
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
            {
                var color = f.Severity >= Severity.High ? "#F44747" : "#CCA700";
                _logColored($"    [{f.Severity.ToString().ToUpper()}] {f.Category}: {f.Description}", color);
            }
        }
    }

    #endregion

    #region Cookie Security Audit

    public async Task<Security.CookieAuditResult> CheckCookieSecurity()
    {
        var url = await GetCurrentUrl();
        var cookies = await GetCookies();
        var reconciled = Security.CookieAuditChecker.MergeNetworkSetCookies(url, cookies, Network.Entries);
        var docCookieLine = await RunJs("document.cookie || ''");
        Security.CookieAuditChecker.MergeDocumentCookieNames(url, cookies, docCookieLine);
        return new Security.CookieAuditChecker().Run(url, cookies, reconciled);
    }

    public async Task<Security.SessionIdAnalysisResult> AnalyzeSessionIds(
        string? cookieName = null,
        IReadOnlyList<string>? extraSamples = null,
        bool pageNetworkOnly = false)
    {
        var result = await Security.SessionIdSampleCollector.CollectAndAnalyzeAsync(
            this,
            new Security.SessionIdSampleCollector.CollectOptions
            {
                CookieName = cookieName,
                ExtraSamples = extraSamples,
                PageNetworkOnly = pageNetworkOnly
            });
        return result.Analysis;
    }

    public async Task<Security.CookieAuditResult> PrintCookieSecurityReport(bool includeDetails = true)
    {
        var result = await CheckCookieSecurity();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[HIGH]") || line.Contains("[CRITICAL]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("high-severity") || line.Contains("immediate"))
                    _logColored(line, "#F44747");
                else if (line.Contains("medium-severity"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("FINDINGS") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No cookie security issues"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertCookieSecurity(Severity? minSeverity = null, string? message = null)
    {
        var result = await CheckCookieSecurity();
        var desc = message ?? "No cookie security issues should be present";

        var flagged = minSeverity.HasValue
            ? result.GetByMinSeverity(minSeverity.Value)
            : result.Findings;

        if (flagged.Count == 0)
        {
            Assert.Pass($"{desc} ({result.CookieCount} cookie(s) checked)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} issue(s) found");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
            {
                var color = f.Severity >= Severity.High ? "#F44747" : "#CCA700";
                _logColored($"    [{f.Severity.ToString().ToUpper()}] {f.CookieName}: {f.Description}", color);
            }
        }
    }

    #endregion

    #region Web Storage Security Audit

    public async Task<Security.StorageAuditResult> CheckStorageSecurity()
    {
        var url = await GetCurrentUrl();
        var localStorage = await GetAllStorage("local");
        var sessionStorage = await GetAllStorage("session");
        Dictionary<string, string>? indexedDb = null;
        try { indexedDb = await GetIndexedDbFlat(); }
        catch { /* IndexedDB may be unavailable */ }
        return new Security.StorageAuditChecker().Run(url, localStorage, sessionStorage, indexedDb);
    }

    public async Task<Security.StorageAuditResult> PrintStorageSecurityReport(bool includeDetails = true)
    {
        var result = await CheckStorageSecurity();
        var report = result.Format(includeDetails);

        foreach (var line in report.Split(Environment.NewLine))
        {
            if (line.Contains("[HIGH]") || line.Contains("[CRITICAL]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("high-severity") || line.Contains("immediate"))
                    _logColored(line, "#F44747");
                else if (line.Contains("medium-severity"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.Contains("No storage security issues") || line.Contains("No web storage data"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertStorageSecurity(Security.Severity? minSeverity = null, string? message = null)
    {
        var result = await CheckStorageSecurity();
        var desc = message ?? "No web storage security issues should be present";

        var flagged = minSeverity.HasValue
            ? result.Findings.Where(f => f.Severity >= minSeverity.Value).ToList()
            : result.Findings;

        if (flagged.Count == 0)
        {
            Assert.Pass($"{desc} (local: {result.LocalStorageCount}, session: {result.SessionStorageCount} keys)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} issue(s) found");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
            {
                var color = f.Severity >= Security.Severity.High ? "#F44747" : "#CCA700";
                _logColored($"    [{f.Severity.ToString().ToUpper()}] {f.StorageType}.{f.Key}: {f.Description}", color);
            }
        }
    }

    public Security.AttackSurfaceResult CheckAttackSurface(
        bool includeParameters = true,
        bool includeAuth = true,
        bool includeResponsePatterns = true,
        string? hostFilter = null,
        bool includeDataUrls = false)
    {
        var mapper = new Security.AttackSurfaceMapper();
        return mapper.Analyze(Network.Entries, includeParameters, includeAuth, includeResponsePatterns, hostFilter,
            includeDataUrls);
    }

    public async Task<Security.AttackSurfaceResult> PrintAttackSurfaceReport(
        bool includeDetails = true,
        bool includeParameters = true,
        bool includeAuth = true,
        bool includeResponsePatterns = true,
        string? hostFilter = null,
        bool includeDataUrls = false)
    {
        if (Network.Entries.Count == 0)
        {
            _logColored("No network traffic in the log — browse the app first, then re-run.", "#CCA700");
            return new Security.AttackSurfaceResult();
        }

        var result = CheckAttackSurface(includeParameters, includeAuth, includeResponsePatterns, hostFilter,
            includeDataUrls);
        var navUrl = await GetCurrentUrl().ConfigureAwait(false);

        using (var enrichCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation))
        {
            await Security.AttackSurfaceEnrichment.RunAsync(
                result,
                this,
                Network.Entries.ToList(),
                navUrl,
                new Security.AttackSurfaceEnrichment.Options(),
                enrichCts.Token).ConfigureAwait(false);
        }

        if (result.Enrichment is { Enabled: true })
            result.Source += "+api-discovery";

        result.SecurityTxt =
            await SecurityTxtProbe.CheckCurrentDocumentHostAsync(Network.Entries, navUrl)
                .ConfigureAwait(false);

        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.StartsWith('[') && line.Contains(']'))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("==="))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("---"))
                _logColored(line, "#4FC1FF");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task<Security.HttpMethodsSecurityResult> CheckHttpMethods(string? url = null)
    {
        var target = url ?? await GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(target))
            throw new InvalidOperationException("No URL — navigate first or pass url.");
        return await Security.HttpMethodsSecurityProbe.RunAsync(target);
    }

    public async Task<Security.HttpMethodsSecurityResult> PrintHttpMethodsReport(string? url = null,
        bool includeDetails = true)
    {
        var result = await CheckHttpMethods(url);
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains('!') || line.Contains("TRACE enabled") || line.Contains("PUT allowed") ||
                line.Contains("DELETE allowed"))
                _logColored(line, "#F44747");
            else if (line.StartsWith("==="))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertHttpMethodsClean(string? url = null, string? message = null)
    {
        var result = await CheckHttpMethods(url);
        var desc = message ?? "Document URL should not expose risky HTTP methods (TRACE/unchecked PUT/DELETE)";

        if (result.SecurityIssues.Count == 0)
            Assert.Pass(desc);
        else
        {
            Assert.Fail($"{desc}: {result.SecurityIssues.Count} issue(s)");
            foreach (var issue in result.SecurityIssues)
                _logColored($"    {issue}", "#F44747");
        }
    }

    /// <summary>
    /// Returns the most recent decodable SAML message from the network log, or null if none.
    /// </summary>
    public Security.SamlDecodeResult? TryDecodeSamlFromNetwork(string? urlFilter = null)
    {
        if (Network.Entries.Count == 0)
            return null;
        try
        {
            return Security.SamlDecoder.DecodeFromNetwork(Network, urlFilter);
        }
        catch
        {
            return null;
        }
    }

    public Task<Security.SamlDecodeResult?> PrintSamlFromNetworkReport(string? urlFilter = null,
        bool includeXml = false)
    {
        var result = TryDecodeSamlFromNetwork(urlFilter);
        if (result == null)
        {
            if (Network.Entries.Count == 0)
                _logColored("Network log is empty — complete a SAML flow, then re-run.", "#CCA700");
            else
                _logColored("No SAMLRequest/SAMLResponse found in the network log.", "#CCA700");
            return Task.FromResult<Security.SamlDecodeResult?>(null);
        }

        foreach (var line in result.Format(includeXml).Split(Environment.NewLine))
        {
            if (line.Contains("[HIGH]") || line.Contains("[CRITICAL]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("==="))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return Task.FromResult<Security.SamlDecodeResult?>(result);
    }

    public Task AssertSamlSecurity(Security.Severity? minSeverity = null, string? urlFilter = null,
        string? message = null)
    {
        var result = TryDecodeSamlFromNetwork(urlFilter);
        var desc = message ?? "Latest SAML message in the log should have no notable security findings";

        if (result == null)
        {
            Assert.Pass("No SAML in network log (skipped)");
            return Task.CompletedTask;
        }

        var flagged = minSeverity.HasValue
            ? result.SecurityFindings.Where(f => f.Severity >= minSeverity.Value).ToList()
            : result.SecurityFindings;

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.MessageType})");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged.OrderByDescending(f => f.Severity))
                _logColored($"    [{f.Severity}] {f.Category}: {f.Description}", "#F44747");
        }

        return Task.CompletedTask;
    }

    public async Task<Security.AutoScanPipeline.AutoScanResult> RunAutoScan(
        string? host = null,
        int maxEndpointsPerScanner = 5,
        int timeoutMs = 15000,
        bool includeSqli = true,
        bool includeIdor = true,
        bool includeCsrf = true,
        bool includePathTraversal = true,
        bool includeSsrf = true,
        bool includeMassAssignment = true,
        string? minPriority = null,
        string? scanDepth = null,
        string? payloadProfile = null)
    {
        var options = new Security.AutoScanPipeline.AutoScanOptions
        {
            Host = host,
            MaxEndpointsPerScanner = maxEndpointsPerScanner,
            TimeoutMs = timeoutMs,
            IncludeSqli = includeSqli,
            IncludeIdor = includeIdor,
            IncludeCsrf = includeCsrf,
            IncludePathTraversal = includePathTraversal,
            IncludeSsrf = includeSsrf,
            IncludeMassAssignment = includeMassAssignment,
            MinPriority = minPriority,
            ScanDepth = scanDepth ?? Security.AutoScanDepthProfile.Standard,
            PayloadProfile = PayloadProfileExtensions.Parse(payloadProfile),
            ConfirmBackend = true
        };
        var scanResult = await Security.AutoScanPipeline.RunAsync(this, options);
        // RunAsync already merges via FindingsMode; keep legacy callers on append semantics.
        return scanResult;
    }

    /// <summary>Run auto-scan with full <see cref="Security.AutoScanPipeline.AutoScanOptions"/> control (single scanner, depth, etc.).</summary>
    public async Task<Security.AutoScanPipeline.AutoScanResult> RunAutoScanWithOptions(
        Security.AutoScanPipeline.AutoScanOptions options)
    {
        options.ConfirmBackend = true;
        return await Security.AutoScanPipeline.RunAsync(this, options);
    }

    public async Task<Security.AutoScanPipeline.AutoScanResult> PrintAutoScanReport(
        bool includeDetails = true,
        string? host = null,
        int maxEndpointsPerScanner = 5,
        int timeoutMs = 15000,
        bool includeSqli = true,
        bool includeIdor = true,
        bool includeCsrf = true,
        bool includePathTraversal = true,
        bool includeSsrf = true,
        bool includeMassAssignment = true,
        string? minPriority = null,
        string? scanDepth = null,
        string? payloadProfile = null)
    {
        if (Network.Entries.Count == 0)
        {
            _logColored("No network traffic in the log — browse the app first, then re-run.", "#CCA700");
            return new Security.AutoScanPipeline.AutoScanResult();
        }

        var result = await RunAutoScan(host, maxEndpointsPerScanner, timeoutMs,
            includeSqli, includeIdor, includeCsrf, includePathTraversal, includeSsrf, includeMassAssignment,
            minPriority, scanDepth, payloadProfile);

        PrintAutoScanResultLines(result, includeDetails);
        return result;
    }

    public Task PrintAutoScanReport(
        Security.AutoScanPipeline.AutoScanResult result,
        bool includeDetails = true)
    {
        PrintAutoScanResultLines(result, includeDetails);
        return Task.CompletedTask;
    }

    private void PrintAutoScanResultLines(Security.AutoScanPipeline.AutoScanResult result, bool includeDetails)
    {
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else if (line.TrimStart().StartsWith('!'))
                _logColored(line, "#F44747");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task AssertAutoScanClean(
        string? host = null,
        int maxEndpointsPerScanner = 5,
        string? minSeverity = null,
        string? message = null)
    {
        var result = await RunAutoScan(host, maxEndpointsPerScanner);
        var desc = message ?? "Auto-scan should find no vulnerabilities";

        var flagged = string.IsNullOrEmpty(minSeverity) ? result.Findings : result.GetByMinSeverity(minSeverity);

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.EndpointsScanned} endpoints, {string.Join("+", result.ScannersRun)})");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpper()}] [{f.Scanner}] {f.Title} — {f.Endpoint}", "#F44747");
        }
    }

    public async Task<SwaggeringOrchestrator.SwaggeringResult> PrintSwaggeringReport(
        SwaggeringOrchestrator.SwaggeringOptions? options = null)
    {
        options ??= new SwaggeringOrchestrator.SwaggeringOptions
        {
            SafetyMode = Security.Orchestration.SafetyMode.Active,
            Depth = SwaggeringDepthProfile.Thorough
        };

        var result = await RunSwaggering(options);
        _logColored("=== Swaggering ===", "#4EC9B0");
        _logColored(result.Message, "#CCCCCC");
        _logColored(
            $"Depth: {result.Depth} | ops: {result.OperationsInCatalog} | requests: {result.RequestsSent} | {result.ElapsedMs}ms",
            "#888888");
        if (result.SpecSources.Count > 0)
            _logColored($"Specs: {string.Join(", ", result.SpecSources.Take(5))}", "#888888");
        if (result.Warnings.Count > 0)
        {
            _logColored($"Warnings ({result.Warnings.Count}):", "#CCA700");
            foreach (var w in result.Warnings.Take(12))
                _logColored($"  ! {w}", "#CCA700");
        }
        if (result.InventorySummary != null)
            _logColored(
                $"Inventory — documented: {result.InventorySummary.DocumentedCount}, shadow: {result.InventorySummary.ShadowCount}",
                "#888888");

        foreach (var f in result.Findings.OrderByDescending(x => x.Severity))
        {
            var color = f.Severity is "critical" or "high" ? "#F44747" : f.Severity == "medium" ? "#CCA700" : "#569CD6";
            _logColored($"[{f.Severity.ToUpper()}] [{f.Phase}] {f.Title}", color);
            _logColored($"  {f.Method} {f.Url}", "#888888");
            if (!string.IsNullOrEmpty(f.Detail))
                _logColored($"  {f.Detail}", "#888888");
        }

        if (result.CostlyFindings.Count > 0)
        {
            _logColored($"--- Spec cost hints ({result.CostlyFindings.Count}) ---", "#CCA700");
            foreach (var c in result.CostlyFindings.Take(15))
                _logColored($"  [{c.Severity}] {c.Title}", "#CCA700");
        }

        if (result.AutoScan is { Findings.Count: > 0 })
        {
            _logColored($"--- Auto-scan ({result.AutoScan.Findings.Count} finding(s)) ---", "#4EC9B0");
            foreach (var a in result.AutoScan.Findings.Where(x => x.Severity is "high" or "critical").Take(20))
                _logColored($"  [{a.Severity}] [{a.Scanner}] {a.Title} — {a.Endpoint}", "#F44747");
        }

        return result;
    }

    public async Task<Security.SecretsHarvestPipeline.HarvestResult> RunSecretsHarvest(
        bool includeJsBundles = true,
        bool includeCookiesAndStorage = true,
        bool includeNetworkResponses = true,
        bool includePageText = true,
        bool includeSourceMaps = true,
        int maxJsScripts = 20,
        int maxNetworkResponses = 100,
        int timeoutMs = 30000)
    {
        var options = new Security.SecretsHarvestPipeline.HarvestOptions
        {
            IncludeJsBundles = includeJsBundles,
            IncludeCookiesAndStorage = includeCookiesAndStorage,
            IncludeNetworkResponses = includeNetworkResponses,
            IncludePageText = includePageText,
            IncludeSourceMaps = includeSourceMaps,
            MaxJsScripts = maxJsScripts,
            MaxNetworkResponses = maxNetworkResponses,
            TimeoutMs = timeoutMs
        };
        return await Security.SecretsHarvestPipeline.RunAsync(this, options);
    }

    public async Task<Security.SecretsHarvestPipeline.HarvestResult> PrintSecretsHarvestReport(
        bool includeDetails = true,
        bool includeJsBundles = true,
        bool includeCookiesAndStorage = true,
        bool includeNetworkResponses = true,
        bool includePageText = true,
        bool includeSourceMaps = true,
        int maxJsScripts = 20,
        int maxNetworkResponses = 100,
        int timeoutMs = 30000)
    {
        var result = await RunSecretsHarvest(includeJsBundles, includeCookiesAndStorage,
            includeNetworkResponses, includePageText, includeSourceMaps,
            maxJsScripts, maxNetworkResponses, timeoutMs);

        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else if (line.TrimStart().StartsWith('!'))
                _logColored(line, "#F44747");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertSecretsClean(
        string? minSeverity = null,
        string? message = null)
    {
        var result = await RunSecretsHarvest();
        var desc = message ?? "Secrets harvest should find no exposed secrets or credentials";

        var flagged = string.IsNullOrEmpty(minSeverity) ? result.Findings : result.GetByMinSeverity(minSeverity);

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({string.Join(", ", result.SourcesScanned)})");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpper()}] [{f.Source}] {f.Description} — {f.Location}", "#F44747");
        }
    }

    public async Task<Security.FirewallResult> RunFirewallTest(
        IReadOnlyCollection<string>? tests = null,
        bool verbose = false)
    {
        HashSet<string>? testSet = null;
        if (tests is { Count: > 0 })
            testSet = new HashSet<string>(tests, StringComparer.OrdinalIgnoreCase);
        return await new Security.FirewallTester(this).RunAsync(testSet, verbose);
    }

    /// <summary>Install the shared client-side runtime sensor on the current document.</summary>
    public Task InstallRuntimeSensorAsync() =>
        Security.Runtime.RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(this);

    /// <summary>Register the runtime sensor for the next navigation (hooks before page scripts).</summary>
    public Task PrepareRuntimeSensorForNavigationAsync() =>
        Security.Runtime.RuntimeSensorInstaller.PrepareForNextNavigationAsync(this);

    public Task<Security.ClientSurfaceResult> MapClientSurfaceAsync(
        bool installSensor = true,
        int waitMs = 400,
        bool reloadForSensor = true,
        bool reset = false,
        bool scopeToCurrentDocument = true) =>
        new Security.ClientSurfaceMapper(this).MapAsync(
            installSensor, waitMs, reloadForSensor, reset, scopeToCurrentDocument);

    /// <summary>
    /// Maps the client surface and prints the triage checklist (pursue / lead / manual / dismiss).
    /// Does not run the follow-up scanners.
    /// </summary>
    public Task<Security.ClientSurfaceResult> PrintClientSurfaceReport(
        bool installSensor = true,
        int waitMs = 400,
        bool reloadForSensor = true,
        bool reset = false,
        bool scopeToCurrentDocument = true) =>
        PrintClientSurfaceReportCore(installSensor, waitMs, reloadForSensor, reset, scopeToCurrentDocument);

    private async Task<Security.ClientSurfaceResult> PrintClientSurfaceReportCore(
        bool installSensor,
        int waitMs,
        bool reloadForSensor,
        bool reset,
        bool scopeToCurrentDocument)
    {
        var result = await MapClientSurfaceAsync(
            installSensor, waitMs, reloadForSensor, reset, scopeToCurrentDocument);
        _logColored("=== Client surface (triage, no active probes) ===", "#4EC9B0");
        _logColored($"URL: {result.Url}", "#CCCCCC");
        if (!result.LoadObserved)
            _logColored("Sensor was installed for this call. Runtime rows marked lead may need another pass after browsing.", "#CCA700");
        var order = new[] { "pursue", "lead", "manual", "dismiss" };
        foreach (var status in order)
        {
            var rows = result.Risks.Where(r => r.Status == status).ToList();
            if (rows.Count == 0) continue;
            var color = status switch
            {
                "pursue" => "#F44747",
                "lead" => "#CCA700",
                "manual" => "#569CD6",
                _ => "#888888"
            };
            _logColored("", "#CCCCCC");
            _logColored(status.ToUpperInvariant(), color);
            foreach (var row in rows)
            {
                _logColored($"  {row.Title}", color);
                _logColored($"    {row.Reason}", "#CCCCCC");
                if (!string.IsNullOrWhiteSpace(row.FollowUp))
                    _logColored($"    next: {row.FollowUp}", "#569CD6");
            }
        }
        return result;
    }

    /// <summary>Observe or probe DOM XSS flow chains (source→sink→consequence).</summary>
    public Task<Security.DomFlow.DomFlowGraph.DomFlowResult> RunDomFlowsAsync(
        string mode = "observe", int waitMs = 400, IReadOnlyList<string>? sources = null, string? canary = null,
        bool waitForSpa = true, bool restoreUrlAfterProbe = true)
    {
        var graph = new Security.DomFlow.DomFlowGraph(this);
        if (string.Equals(mode, "probe", StringComparison.OrdinalIgnoreCase)
            || string.Equals(mode, "active", StringComparison.OrdinalIgnoreCase))
            return graph.ProbeAsync(sources, canary, restoreUrlAfterProbe);
        return graph.ObserveAsync(waitMs, waitForSpa);
    }

    /// <summary>XS-Leaks differential scan across victim states.</summary>
    public Task<Security.XsLeaks.XsLeakScanner.XsLeakResult> RunXsLeaksAsync(
        Security.XsLeaks.XsLeakScanner.XsLeakOptions options, string safetyMode = "safe")
    {
        var mode = Security.Orchestration.SafetyModeExtensions.Parse(safetyMode);
        return new Security.XsLeaks.XsLeakScanner(this).RunAsync(options, mode);
    }

    public Task<Security.GadgetChains.GadgetChainScanner.GadgetChainResult> RunGadgetChainsAsync(
        Security.GadgetChains.GadgetChainScanner.GadgetChainOptions options,
        string safetyMode = "active")
    {
        var mode = Security.Orchestration.SafetyModeExtensions.Parse(safetyMode);
        return new Security.GadgetChains.GadgetChainScanner(this).RunAsync(options, mode);
    }

    public Task<Security.Runtime.GadgetRadarService.RadarReadResult> ReadGadgetRadarAsync() =>
        new Security.Runtime.GadgetRadarService(this).ReadAsync();

    public Task StartGadgetRadarAsync(bool perturbing = false, IReadOnlyList<string>? protoKeys = null) =>
        new Security.Runtime.GadgetRadarService(this).StartAsync(perturbing, protoKeys);

    public Task StopGadgetRadarAsync() =>
        new Security.Runtime.GadgetRadarService(this).StopAsync();

    public async Task<Security.DomFlow.DomFlowGraph.DomFlowResult> PrintDomFlowsReport(
        string mode = "observe", int waitMs = 400, IReadOnlyList<string>? sources = null)
    {
        var result = await RunDomFlowsAsync(mode, waitMs, sources);
        _logColored($"=== DOM XSS flow graph ({result.Mode}) ===", "#4EC9B0");
        _logColored($"URL: {result.Url}", "#CCCCCC");
        _logColored(result.Summary, result.ExploitableChainCount > 0 ? "#F44747" : "#CCCCCC");
        foreach (var c in result.Chains
                     .OrderByDescending(x => x.Tier == "exploitable")
                     .ThenByDescending(x => x.Consequence == "exec")
                     .Take(40))
        {
            var color = c.Tier == "exploitable" || c.Consequence == "exec" ? "#F44747"
                : c.Consequence is "nav-hijack" or "request-forgery" or "executable-markup" ? "#CCA700"
                : c.Tier == "noise" ? "#666666"
                : "#CCCCCC";
            _logColored(
                $"  [{c.Confidence}/{c.Consequence}] {c.Source} → {c.Sink}" +
                (string.IsNullOrEmpty(c.Framework) ? "" : $" ({c.Framework})"),
                color);
            if (!string.IsNullOrEmpty(c.SinkData))
                _logColored($"    sink: {TruncateForLog(c.SinkData, 160)}", "#888888");
        }
        foreach (var a in result.NextActions)
            _logColored($"  next: {a}", "#569CD6");
        return result;
    }

    public async Task AssertDomFlowsClean(string? minConsequence = "exec", string? message = null)
    {
        var result = await RunDomFlowsAsync("observe");
        var desc = message ?? "No confirmed executable DOM XSS flows";
        var flagged = result.Chains.Where(c =>
            minConsequence == "exec"
                ? c.Consequence == "exec"
                : c.Consequence is not "inert").ToList();
        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.Chains.Count} observed chain(s))");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} chain(s)");
            foreach (var c in flagged.Take(12))
                _logColored($"    {c.Source} → {c.Sink} ({c.Consequence}/{c.Confidence})", "#F44747");
        }
    }

    public async Task PrintIndexedDbReport(string? dbFilter = null, int limit = 40)
    {
        var snap = await GetIndexedDb(dbFilter, null, limit);
        _logColored($"=== IndexedDB ({snap.Origin}, method={snap.Method}) ===", "#4EC9B0");
        if (snap.DatabaseCount == 0)
        {
            _logColored("No IndexedDB databases.", "#4EC9B0");
            return;
        }
        _logColored($"{snap.DatabaseCount} database(s), {snap.RecordCount} record(s)" +
                    (snap.Truncated ? " (truncated)" : ""), "#CCCCCC");
        foreach (var db in snap.Databases)
        {
            _logColored($"  DB {db.Name} v{db.Version}", "#CCCCCC");
            foreach (var st in db.Stores)
            {
                _logColored($"    store {st.Name} ({st.RecordCount})", "#888888");
                foreach (var rec in st.Records.Take(8))
                    _logColored($"      {rec.Key} = {TruncateForLog(rec.Value, 120)}", "#888888");
            }
        }
    }

    public async Task<Security.XsLeaks.XsLeakScanner.XsLeakResult> PrintXsLeaksReport(
        Security.XsLeaks.XsLeakScanner.XsLeakOptions options, string safetyMode = "safe")
    {
        var result = await RunXsLeaksAsync(options, safetyMode);
        _logColored("=== XS-Leaks differential scan ===", "#4EC9B0");
        if (!string.IsNullOrEmpty(result.StateGenerationStrategy))
            _logColored($"states: {result.StateGenerationStrategy} — {result.StateGenerationDetail}", "#888888");
        foreach (var w in result.Warnings)
            _logColored($"warning: {w}", "#CCA700");
        _logColored(result.Summary, result.DistinguishableCount > 0 ? "#F44747" : "#CCCCCC");
        _logColored($"cookieMode: {result.CookieMode}", "#888888");
        foreach (var t in result.Techniques)
        {
            var color = t.Verdict == "distinguishable" && t.Tier == SecurityFindingTier.Exploitable ? "#F44747"
                : t.Verdict == "probable" && t.Tier == SecurityFindingTier.Exploitable ? "#CCA700"
                : t.Verdict is "distinguishable" or "probable" ? "#569CD6"
                : "#888888";
            _logColored($"  {t.Technique}: {t.Verdict} ({t.Tier}) — {t.Detail}", color);
            if (t.MitigatedBy.Count > 0)
                _logColored($"    mitigatedBy: {string.Join(", ", t.MitigatedBy)}", "#569CD6");
            if (!string.IsNullOrEmpty(t.MitigationReason))
                _logColored($"    mitigation: {t.MitigationReason}", "#569CD6");
        }
        foreach (var a in result.NextActions)
            _logColored($"  next: {a}", "#569CD6");
        return result;
    }

    private static string TruncateForLog(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= max ? s : s[..max] + "…";
    }

    public Task<Security.PostMessageAuditResult> AuditPostMessageAsync(
        string safetyMode = "safe", bool fuzz = true, int maxPayloads = 8) =>
        AuditPostMessageAsync(new Security.PostMessageAuditOptions
        {
            SafetyMode = safetyMode,
            Fuzz = fuzz,
            MaxPayloads = maxPayloads
        });

    public Task<Security.PostMessageAuditResult> AuditPostMessageAsync(Security.PostMessageAuditOptions options) =>
        new Security.PostMessageAuditor(this).RunAsync(options);

    public async Task<Security.PostMessageAuditResult> PrintPostMessageAuditReport(
        Security.PostMessageAuditOptions options)
    {
        var result = await AuditPostMessageAsync(options);
        var pageUrl = await GetCurrentUrl();
        _logColored("=== postMessage audit ===", "#4EC9B0");
        _logColored($"URL: {pageUrl}", "#CCCCCC");
        var headline = result.Findings.Count > 0
            ? $"{result.Findings.Count} finding(s), {result.Listeners.Count} listener(s)"
            : $"{result.Listeners.Count} listener(s), no confirmed sink reach";
        _logColored(headline, result.Findings.Any(f => f.Severity is "high" or "critical") ? "#F44747" : "#CCCCCC");
        foreach (var l in result.Listeners.Take(24))
        {
            _logColored($"  listener {l.ListenerId} origin={l.OriginCheck}", "#888888");
            if (!string.IsNullOrEmpty(l.HandlerPreview))
                _logColored($"    {TruncateForLog(l.HandlerPreview, 120)}", "#666666");
        }
        foreach (var t in result.Techniques.Take(16))
        {
            var color = t.Verdict is "confirmed" or "reachable" ? "#F44747" : "#888888";
            _logColored($"  {t.TechniqueId}: {t.Verdict} ({t.Tier}) - {t.Detail}", color);
        }
        foreach (var a in result.NextActions)
            _logColored($"  next: {a}", "#569CD6");
        return result;
    }

    public Task<Security.ClientPpScanResult> ScanClientPrototypePollutionAsync(
        string? baseUrl = null, bool tryGadgets = true) =>
        new Security.ClientPrototypePollutionScanner(this).RunAsync(baseUrl, tryGadgets);

    public Task<Security.InputTraceResult> TraceInputAsync(Security.TraceInputOptions options) =>
        new Security.InputTracer(this).TraceAsync(options);

    /// <summary>
    /// First-class DOM XSS audit: client surface, passive DOM patterns, dom-flow probe, and trace-input on URL vectors.
    /// </summary>
    public Task<Security.DomXssAuditResult> RunDomXssAuditAsync(
        Security.DomXssAuditRunner.DomXssAuditOptions? options = null,
        CancellationToken ct = default) =>
        new Security.DomXssAuditRunner(this).RunAsync(options ?? new Security.DomXssAuditRunner.DomXssAuditOptions(), ct);

    public async Task<Security.FirewallResult> PrintFirewallTestReport(
        bool includeDetails = true,
        IReadOnlyCollection<string>? tests = null)
    {
        var result = await RunFirewallTest(tests, verbose: includeDetails);
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("bypassed", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertFirewallTestClean(
        IReadOnlyCollection<string>? tests = null,
        string? message = null)
    {
        var result = await RunFirewallTest(tests);
        var desc = message ?? "Client-side defenses (CSP/SRI/sandbox/Permissions-Policy) should block bypass attempts";

        if (result.DefensesIneffective == 0)
            Assert.Pass($"{desc} (verdict: {result.OverallVerdict}, tested: {result.DefensesTested})");
        else
        {
            Assert.Fail($"{desc}: {result.DefensesIneffective} defense(s) ineffective (bypassed)");
            foreach (var line in result.Format(verbose: false).Split(Environment.NewLine))
            {
                if (line.Contains("bypassed", StringComparison.OrdinalIgnoreCase) || line.Contains('['))
                    _logColored(line, "#F44747");
            }
        }
    }

    public async Task<Security.HttpSecurityProbes.JwtAnalyzeResult> RunJwtAnalysis(
        IReadOnlyList<string>? explicitTokens = null) =>
        await Security.HttpSecurityProbes.RunJwtAnalyzeAsync(this, explicitTokens, ScriptCancellation);

    public async Task<Security.HttpSecurityProbes.JwtAnalyzeResult> PrintJwtAnalysisReport(
        bool includePayload = false,
        IReadOnlyList<string>? explicitTokens = null)
    {
        var result = await RunJwtAnalysis(explicitTokens);
        foreach (var line in result.Format(includePayload).Split(Environment.NewLine))
        {
            if (line.Contains('!') || line.Contains("[sensitive claim]", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertJwtAnalysisClean(
        string? minSeverity = null,
        IReadOnlyList<string>? explicitTokens = null,
        string? message = null)
    {
        var result = await RunJwtAnalysis(explicitTokens);
        var desc = message ?? "JWT tokens should have no notable security hygiene issues";
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);

        if (result.Tokens.Count == 0)
        {
            Assert.Pass("No JWT-shaped tokens found (skipped)");
            return;
        }

        var flaggedTokens = 0;
        foreach (var t in result.Tokens)
        {
            var maxRank = t.Issues.Select(JwtIssueRank).DefaultIfEmpty(0).Max();
            if (t.SensitiveClaims.Count > 0)
                maxRank = Math.Max(maxRank, 3);
            if (maxRank >= minRank)
                flaggedTokens++;
        }

        if (flaggedTokens == 0)
            Assert.Pass($"{desc} ({result.Tokens.Count} token(s) checked)");
        else
        {
            Assert.Fail($"{desc}: {flaggedTokens} of {result.Tokens.Count} token(s) flagged");
            foreach (var line in result.Format(includePayload: false).Split(Environment.NewLine))
                if (line.Contains('!') || line.Contains("sensitive", StringComparison.OrdinalIgnoreCase))
                    _logColored(line, "#F44747");
        }
    }

    public async Task<Security.OidcSessionAnalyzer.SessionResult> RunOidcSessionReport()
    {
        IReadOnlyList<Security.OidcSessionAnalyzer.CookieInfo>? cookies = null;
        try
        {
            cookies = Security.OidcSessionAnalyzer.CookieInfo.FromDictionaries(await GetCookies());
        }
        catch
        {
            /* cookie jar unavailable */
        }

        return Security.OidcSessionAnalyzer.Analyze(Network.Entries, cookies);
    }

    public async Task<Security.OidcSessionAnalyzer.SessionResult> PrintOidcSessionReport()
    {
        var result = await RunOidcSessionReport();
        foreach (var line in Security.OidcSessionAnalyzer.Format(result).Split(Environment.NewLine))
        {
            if (line.Contains("[HIGH]") || line.Contains("[CRITICAL]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("FINDINGS") || line.StartsWith("EVIDENCE")
                     || line.StartsWith("NEXT") || line.StartsWith("NOT TESTABLE"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }
        return result;
    }

    public async Task AssertOidcSessionClean(string? minSeverity = null, string? message = null)
    {
        var result = await RunOidcSessionReport();
        var desc = message ?? "OIDC session visible to the browser should have no notable security findings";
        if (!result.Observed)
        {
            Assert.Pass("No OIDC session detected from network log or cookies (skipped)");
            return;
        }

        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);
        var flagged = string.IsNullOrEmpty(minSeverity)
            ? result.Findings
            : result.Findings.Where(f => MinSeverityRankFromString(f.Severity) >= minRank).ToList();

        if (flagged.Count == 0)
        {
            if (result.Findings.Count == 0)
                Assert.Pass($"{desc} ({result.Binding}, no findings)");
            else
                Assert.Pass(
                    $"{desc} ({result.Binding}; {result.Findings.Count} lower-severity finding(s) below {minSeverity ?? "any"} threshold)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpperInvariant()}] {f.Title}", "#F44747");
        }
    }

    public async Task<Security.OidcAnalyzer.OidcResult> RunOidcAnalysis(
        string? issuer = null,
        bool autoDetect = true,
        bool probeEndpoints = true,
        bool testDynamicRegistration = false,
        bool testGrantTypes = false,
        string? clientId = null,
        bool validateRpTokens = true,
        int timeoutMs = 20000)
    {
        var options = new Security.OidcAnalyzer.OidcOptions
        {
            Issuer = issuer,
            AutoDetect = autoDetect,
            ProbeEndpoints = probeEndpoints,
            TestDynamicRegistration = testDynamicRegistration,
            TestGrantTypes = testGrantTypes,
            ClientId = clientId,
            ValidateRpTokens = validateRpTokens,
            TimeoutMs = timeoutMs
        };
        return await Security.OidcAnalyzer.RunAsync(this, options, ScriptCancellation);
    }

    public async Task<Security.OidcAnalyzer.OidcResult> PrintOidcAnalysisReport(
        bool includeDetails = true,
        string? issuer = null,
        bool autoDetect = true,
        bool probeEndpoints = true,
        bool testDynamicRegistration = false,
        bool testGrantTypes = false,
        string? clientId = null,
        bool validateRpTokens = true,
        int timeoutMs = 20000)
    {
        var result = await RunOidcAnalysis(issuer, autoDetect, probeEndpoints, testDynamicRegistration, testGrantTypes,
            clientId, validateRpTokens, timeoutMs);
        foreach (var line in Security.OidcAnalyzer.Format(result).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("!!!") || line.Contains("allowed"))
                _logColored(line, line.Contains("OK ", StringComparison.Ordinal) ? "#569CD6" : "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("---") || line.StartsWith("FINDINGS"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith('!') || line.Contains("! "))
                _logColored(line, "#CCA700");
            else
                _logColored(line, "#CCCCCC");
        }

        if (includeDetails && result.RawConfiguration != null)
        {
            _logColored("--- Raw openid-configuration (summary) ---", "#569CD6");
            var raw = result.RawConfiguration.Value.GetRawText();
            if (raw.Length > 4000)
                raw = raw[..4000] + "…";
            foreach (var line in raw.Split(Environment.NewLine))
                _logColored(line, "#808080");
        }

        return result;
    }

    public async Task AssertOidcAnalysisClean(
        string? minSeverity = null,
        string? issuer = null,
        bool testGrantTypes = false,
        string? message = null)
    {
        var result = await RunOidcAnalysis(issuer, autoDetect: string.IsNullOrEmpty(issuer),
            testGrantTypes: testGrantTypes);
        var desc = message ?? "OIDC provider configuration should have no notable security findings";
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);

        if (!result.ConfigurationFound)
        {
            if (string.IsNullOrEmpty(result.Issuer) && result.Session is not { Observed: true })
            {
                Assert.Pass("No OIDC issuer detected from network log (skipped)");
                return;
            }

            if (result.Session is { Observed: true } || result.Dossier != null)
            {
                var flaggedNoDiscovery = string.IsNullOrEmpty(minSeverity)
                    ? result.Findings.Where(f => f.Category != "discovery").ToList()
                    : result.Findings.Where(f => f.Category != "discovery"
                        && MinSeverityRankFromString(f.Severity) >= minRank).ToList();
                if (flaggedNoDiscovery.Count == 0)
                {
                    Assert.Pass($"{desc} (no discovery document; session/dossier checks only)");
                    return;
                }

                Assert.Fail($"{desc}: {flaggedNoDiscovery.Count} finding(s) without provider discovery");
                foreach (var f in flaggedNoDiscovery)
                    _logColored($"    [{f.Severity.ToUpper()}] {f.Title}", "#F44747");
                return;
            }

            Assert.Fail($"{desc}: could not fetch configuration — {string.Join("; ", result.Errors)}");
            return;
        }

        var flagged = string.IsNullOrEmpty(minSeverity)
            ? result.Findings
            : result.Findings.Where(f => MinSeverityRankFromString(f.Severity) >= minRank).ToList();

        if (flagged.Count == 0)
        {
            if (result.Findings.Count == 0)
                Assert.Pass($"{desc} (no findings)");
            else
                Assert.Pass(
                    $"{desc} ({result.Findings.Count} lower-severity finding(s) below {minSeverity ?? "any"} threshold)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpper()}] {f.Title}", "#F44747");
        }
    }

    public async Task<Security.OAuthFlowTester.OAuthFlowResult> RunOAuthFlowTest(
        bool passiveOnly = true,
        string? authorizationUrl = null,
        string? tokenEndpoint = null,
        string? clientId = null,
        string? redirectUri = null,
        string? issuer = null,
        bool autoDetect = true,
        bool useCanaryTokenExchange = false,
        int timeoutMs = 15000)
    {
        var options = new Security.OAuthFlowTester.OAuthFlowOptions
        {
            PassiveOnly = passiveOnly,
            AuthorizationUrl = authorizationUrl,
            TokenEndpoint = tokenEndpoint,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Issuer = issuer,
            AutoDetect = autoDetect,
            UseCanaryTokenExchange = useCanaryTokenExchange,
            TimeoutMs = timeoutMs
        };
        return await Security.OAuthFlowTester.RunAsync(this, options, ScriptCancellation);
    }

    public async Task<Security.OAuthFlowTester.OAuthFlowResult> PrintOAuthFlowReport(
        bool passiveOnly = true,
        bool includeDetails = true,
        string? authorizationUrl = null,
        string? clientId = null,
        int timeoutMs = 15000)
    {
        var result = await RunOAuthFlowTest(passiveOnly, authorizationUrl, clientId: clientId, timeoutMs: timeoutMs);
        foreach (var line in Security.OAuthFlowTester.Format(result).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("CAPTURED") || line.StartsWith("PROBES"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        if (includeDetails && result.Dossier != null)
        {
            _logColored("--- Session dossier ---", "#569CD6");
            _logColored($"binding={result.Dossier.Binding} clientId={result.Dossier.ClientId ?? "(unknown)"}", "#888888");
            foreach (var action in result.Dossier.NextActions.Take(6))
                _logColored("  next: " + action, "#888888");
        }

        return result;
    }

    public async Task AssertOAuthFlowClean(string? minSeverity = null, bool passiveOnly = true, string? message = null)
    {
        var result = await RunOAuthFlowTest(passiveOnly);
        var desc = message ?? "OAuth/OIDC front-channel flow should have no notable security findings";
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);
        var flagged = string.IsNullOrEmpty(minSeverity)
            ? result.Findings
            : result.Findings.Where(f => MinSeverityRankFromString(f.Severity) >= minRank).ToList();

        if (result.CapturedFlows.Count == 0 && result.Dossier?.Binding == "bff")
        {
            Assert.Pass($"{desc} (BFF login — no authorize flow in browser)");
            return;
        }

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.Findings.Count} finding(s) below threshold or none)");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpper()}] {f.Title}", "#F44747");
        }
    }

    public async Task<Security.GraphqlAnalyzer.GraphqlResult> RunGraphqlAnalysis(
        string? url = null,
        Dictionary<string, string>? headers = null,
        bool autoDetect = true,
        int timeoutMs = 30000,
        bool skipIntrospection = false,
        bool skipBatching = false,
        bool skipAmplification = false,
        bool skipDepthProbe = false,
        bool skipLimitProbe = false,
        bool skipFieldSuggestion = false,
        bool skipDraftAccess = false,
        bool includeCostAnalysis = false)
    {
        var options = new Security.GraphqlAnalyzer.GraphqlOptions
        {
            Url = url,
            Headers = headers,
            AutoDetect = autoDetect,
            TimeoutMs = timeoutMs,
            SkipIntrospection = skipIntrospection,
            SkipBatching = skipBatching,
            SkipAmplification = skipAmplification,
            SkipDepthProbe = skipDepthProbe,
            SkipLimitProbe = skipLimitProbe,
            SkipFieldSuggestion = skipFieldSuggestion,
            SkipDraftAccess = skipDraftAccess,
            IncludeCostAnalysis = includeCostAnalysis
        };
        return await Security.GraphqlAnalyzer.RunAsync(this, options, ScriptCancellation);
    }

    public async Task<Security.GraphqlAnalyzer.GraphqlResult> PrintGraphqlAnalysisReport(
        bool includeDetails = true,
        string? url = null,
        Dictionary<string, string>? headers = null,
        bool autoDetect = true,
        int timeoutMs = 30000)
    {
        var result = await RunGraphqlAnalysis(url, headers, autoDetect, timeoutMs);
        foreach (var line in Security.GraphqlAnalyzer.Format(result).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("---") || line.StartsWith("SCHEMA"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith('!'))
                _logColored(line, "#CCA700");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertGraphqlAnalysisClean(
        string? minSeverity = null,
        string? url = null,
        Dictionary<string, string>? headers = null,
        string? message = null)
    {
        var result = await RunGraphqlAnalysis(url, headers);
        var desc = message ?? "GraphQL endpoint should have no notable security findings";
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);

        if (result.Errors.Count > 0 && string.IsNullOrEmpty(result.Url))
        {
            Assert.Pass("No GraphQL endpoint detected from network log (skipped)");
            return;
        }

        var flagged = string.IsNullOrEmpty(minSeverity)
            ? result.Findings
            : result.Findings.Where(f => MinSeverityRankFromString(f.Severity) >= minRank).ToList();

        if (flagged.Count == 0)
        {
            if (result.Findings.Count == 0)
                Assert.Pass($"{desc} at {result.Url}");
            else
                Assert.Pass(
                    $"{desc} at {result.Url} ({result.Findings.Count} lower-severity finding(s) below {minSeverity ?? "any"} threshold)");
        }
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s)");
            foreach (var f in flagged)
                _logColored($"    [{f.Severity.ToUpper()}] {f.Title}", "#F44747");
        }
    }

    public async Task<Security.JavaScriptStaticAudit.JsAuditResult> RunJavaScriptStaticAudit(
        int maxScripts = 32,
        int maxBytesPerFile = 524_288,
        bool sameOriginOnly = false,
        int timeoutMs = 20_000) =>
        await Security.JavaScriptStaticAudit.RunAsync(this, maxScripts, maxBytesPerFile, sameOriginOnly, timeoutMs,
            ScriptCancellation);

    public async Task<Security.JavaScriptStaticAudit.JsAuditResult> PrintJavaScriptStaticAuditReport(
        bool includeDetails = true,
        int maxScripts = 32,
        int maxBytesPerFile = 524_288,
        bool sameOriginOnly = false,
        int timeoutMs = 20_000)
    {
        var result = await RunJavaScriptStaticAudit(maxScripts, maxBytesPerFile, sameOriginOnly, timeoutMs);
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("email-credential", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#F44747");
            else if (line.Contains("internal-or-private", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#CCA700");
            else if (line.Contains("debug-or-test", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertJavaScriptStaticAuditClean(
        string? minSeverity = null,
        string? message = null)
    {
        var result = await RunJavaScriptStaticAudit();
        var desc = message ?? "External JS bundles should not contain high-signal secret/debug patterns";
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);

        var flaggedHits = 0;
        foreach (var asset in result.Assets)
        {
            foreach (var hit in asset.Hits.Where(h => h.Category != "truncation"))
            {
                if (JsAuditHitRank(hit.Category) >= minRank)
                    flaggedHits++;
            }
        }

        if (flaggedHits == 0)
            Assert.Pass($"{desc} ({result.ScriptsFetched} script(s) scanned)");
        else
        {
            Assert.Fail($"{desc}: {flaggedHits} pattern hit(s) at or above threshold");
            foreach (var line in result.Format(includeDetails: true).Split(Environment.NewLine))
                if (line.Contains('[') && line.Contains(']'))
                    _logColored(line, "#F44747");
        }
    }

    public async Task<NucleiRunner.NucleiScanResult> RunNucleiScan(
        string? targetUrl = null,
        IReadOnlyList<string>? tags = null,
        string? minSeverity = null,
        int maxTemplates = 50,
        int timeoutMs = 10_000,
        string safetyMode = "safe",
        bool registerChainFindings = true,
        IReadOnlyList<string>? targetUrls = null,
        string? templatesDir = null,
        bool includeBuiltinTemplates = true,
        bool followRedirects = false,
        bool dryRun = false,
        bool verboseTemplateTrace = false,
        bool includeBrowserCookies = true)
    {
        var hasList = targetUrls is { Count: > 0 };
        if (string.IsNullOrWhiteSpace(targetUrl) && !hasList)
            targetUrl = await GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(targetUrl) && !hasList)
            throw new InvalidOperationException("No URL — navigate first or pass targetUrl/targetUrls.");

        var mode = SafetyModeExtensions.Parse(safetyMode);

        var selected = NucleiRunner.LoadTemplates(tags, minSeverity, maxTemplates, templatesDir, includeBuiltinTemplates);
        if (selected.Count == 0)
            throw new InvalidOperationException(
                "No templates matched — check tags/severity filters, templatesDir path, or includeBuiltinTemplates.");

        // A dry run sends no HTTP, so the probe/write-verb safety gates do not apply.
        if (!dryRun)
        {
            if (!mode.AllowsProbes())
                throw new InvalidOperationException("Nuclei scan requires safetyMode 'safe' or higher.");
            if (NucleiRunner.SelectedTemplatesRequireWriteVerbs(selected) && !mode.AllowsWriteVerbs())
                throw new InvalidOperationException("Selected nuclei templates require safetyMode 'active' or 'aggressive'.");
        }

        var options = new NucleiRunner.NucleiScanOptions
        {
            TargetUrl = targetUrl ?? "",
            TargetUrls = targetUrls,
            Tags = tags,
            MinSeverity = minSeverity,
            MaxTemplates = maxTemplates,
            TimeoutMs = timeoutMs,
            SafetyMode = mode,
            RegisterChainFindings = registerChainFindings,
            TemplatesDir = templatesDir,
            IncludeBuiltinTemplates = includeBuiltinTemplates,
            FollowRedirects = followRedirects,
            DryRun = dryRun,
            VerboseTemplateTrace = verboseTemplateTrace,
            IncludeBrowserCookies = includeBrowserCookies
        };
        return await NucleiRunner.RunAsync(options, this, ScriptCancellation);
    }

    /// <summary>List the runnable nuclei templates (id/name/severity/tags/methods/source) without scanning.</summary>
    public List<NucleiRunner.TemplateInfo> ListNucleiTemplates(
        string? templatesDir = null,
        bool includeBuiltinTemplates = true)
        => NucleiRunner.GetTemplateInventory(templatesDir, includeBuiltinTemplates);

    public async Task<NucleiRunner.NucleiScanResult> PrintNucleiReport(
        bool includeDetails = true,
        string? targetUrl = null,
        IReadOnlyList<string>? tags = null,
        string? minSeverity = null,
        int maxTemplates = 50,
        int timeoutMs = 10_000,
        string safetyMode = "safe",
        bool registerChainFindings = true,
        IReadOnlyList<string>? targetUrls = null,
        string? templatesDir = null,
        bool includeBuiltinTemplates = true,
        bool followRedirects = false,
        bool dryRun = false,
        bool verboseTemplateTrace = false,
        bool includeBrowserCookies = true)
    {
        var result = await RunNucleiScan(targetUrl, tags, minSeverity, maxTemplates, timeoutMs, safetyMode,
            registerChainFindings, targetUrls, templatesDir, includeBuiltinTemplates,
            followRedirects, dryRun, verboseTemplateTrace, includeBrowserCookies);
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("[CRITICAL]") || line.Contains("[HIGH]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW]") || line.Contains("[INFO]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertNucleiClean(
        string? minSeverity = "medium",
        string? targetUrl = null,
        IReadOnlyList<string>? tags = null,
        string? message = null)
    {
        var result = await RunNucleiScan(targetUrl, tags, minSeverity: null);
        var desc = message ?? "Nuclei template scan should find no notable exposures";
        var flagged = string.IsNullOrEmpty(minSeverity)
            ? result.Findings
            : result.GetByMinSeverity(minSeverity);

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.TemplatesRun} probe(s), {result.TemplatesLoaded} template(s) loaded)");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} match(es)");
            foreach (var f in flagged.OrderByDescending(f => MinSeverityRankFromString(f.Severity)))
                _logColored($"    [{f.Severity.ToUpper()}] {f.TemplateName} — {f.Url}", "#F44747");
        }
    }

    public async Task<Security.HttpRequestSmugglingScanner.SmugglingResult> RunHttpSmugglingScan(
        string? url = null,
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 10000,
        int delayThresholdMs = 3000,
        bool teObfuscations = true)
    {
        var target = url ?? await GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(target))
            throw new InvalidOperationException("No URL — navigate first or pass url.");
        return await Security.HttpRequestSmugglingScanner.RunAsync(target, techniques, timeoutMs, delayThresholdMs,
            teObfuscations, ScriptCancellation);
    }

    public void PrintHttpSmugglingReport(Security.HttpRequestSmugglingScanner.SmugglingResult result)
    {
        foreach (var line in result.Format().Split(Environment.NewLine))
        {
            if (line.StartsWith("Verdict:", StringComparison.Ordinal) &&
                line.Contains("confirmed", StringComparison.OrdinalIgnoreCase) &&
                !line.Contains("unconfirmed", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#F44747");
            else if (line.Contains("[HIGH]") || line.Contains("[CRITICAL]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]"))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("---") || line.StartsWith("Verdict:", StringComparison.Ordinal))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task<Security.HttpRequestSmugglingScanner.SmugglingResult> PrintHttpSmugglingReport(
        string? url = null,
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 10000,
        int delayThresholdMs = 3000,
        bool teObfuscations = true)
    {
        var result = await RunHttpSmugglingScan(url, techniques, timeoutMs, delayThresholdMs, teObfuscations);
        PrintHttpSmugglingReport(result);
        return result;
    }

    public async Task AssertHttpSmugglingClean(
        string? minSeverity = null,
        string? url = null,
        string? message = null,
        string? findingCategory = null,
        bool confirmedOnly = false)
    {
        var result = await RunHttpSmugglingScan(url);
        var desc = message ?? (confirmedOnly
            ? "HTTP request smuggling should not be confirmed (differential 404)"
            : "HTTP request smuggling probes should not indicate elevated risk");
        var minRank = string.IsNullOrEmpty(minSeverity) ? 0 : MinSeverityRankFromString(minSeverity);

        IEnumerable<Security.HttpRequestSmugglingScanner.SmugglingFinding> query = confirmedOnly
            ? result.ConfirmedFindings
            : result.Findings;

        if (!string.IsNullOrEmpty(minSeverity) && !confirmedOnly)
            query = query.Where(f => MinSeverityRankFromString(f.Severity) >= minRank);
        if (!string.IsNullOrEmpty(findingCategory))
            query = query.Where(f => f.FindingCategory.Equals(findingCategory, StringComparison.OrdinalIgnoreCase));

        var flagged = query.ToList();

        if (flagged.Count == 0)
            Assert.Pass($"{desc} (verdict={result.Verdict}, {result.ProbesRun} probes)");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s) (verdict={result.Verdict})");
            foreach (var f in flagged)
            {
                _logColored($"    [{f.Severity.ToUpper()}] {f.Technique}: {f.Description}", "#F44747");
                void LogRaw(string label, string? raw)
                {
                    if (string.IsNullOrEmpty(raw)) return;
                    _logColored($"    {label}:", "#888888");
                    foreach (var line in raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n', StringSplitOptions.None))
                        _logColored($"      {line}", "#888888");
                }

                LogRaw("Probe (raw HTTP)", f.RawProbeRequest);
                LogRaw("Timing baseline GET", f.RawTimingBaselineRequest);
                LogRaw("Canonical chunked reference", f.RawCanonicalReferenceRequest);
            }
        }
    }

    private static int MinSeverityRankFromString(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            "info" => 0,
            "informational" => 0,
            "observation" => 0,
            _ => 2
        };

    private static int JwtIssueRank(string issue)
    {
        if (issue.Contains("'none'", StringComparison.Ordinal))
            return 4;
        if (issue.Contains("past", StringComparison.Ordinal))
            return 1;
        if (issue.Contains("HS256", StringComparison.Ordinal) || issue.Contains("RS256", StringComparison.Ordinal))
            return 2;
        return 2;
    }

    private static int JsAuditHitRank(string category) =>
        category switch
        {
            "credential-like-assignment" or "email-credential-proximity" => 3,
            "internal-or-private-url" => 2,
            "debug-or-test-tuning" => 1,
            _ => 0
        };

    #endregion

    #region Tech Stack Detection

    private Security.TechStackDetector GetTechStackDetector() =>
        new Security.TechStackDetector(ActiveTab.WebView, Network);

    public async Task<Security.TechStackResult> CheckTechStack()
    {
        using var linked = LinkCheckerCancellation();
        return await GetTechStackDetector().RunAsync(linked.Token);
    }

    public async Task<Security.TechStackResult> PrintTechStackReport(bool includeDetails = true)
    {
        var result = await GetTechStackDetector().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("WAF") || line.Contains("SECURITY NOTE"))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("DETECTED") || line.StartsWith("CACHE"))
                _logColored(line, "#569CD6");
            else if (line.EndsWith(":") && line == line.ToUpperInvariant())
                _logColored(line, "#569CD6");
            else if (line.TrimStart().StartsWith("Evidence:"))
                _logColored(line, "#808080");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertNoWaf(string? message = null)
    {
        var result = await GetTechStackDetector().RunAsync();
        var desc = message ?? "No WAF detected (payloads may reach the server unfiltered)";
        var wafs = result.Waf;

        if (wafs.Count == 0)
            Assert.Pass(desc);
        else
            Assert.Fail($"{desc}: detected {string.Join(", ", wafs.Select(w => w.Name))}");
    }

    #endregion

    #region Third-Party Inventory

    private ThirdParty.ThirdPartyChecker GetThirdPartyChecker() =>
        new ThirdParty.ThirdPartyChecker(ActiveTab.WebView);

    public async Task<ThirdParty.ThirdPartyResult> CheckThirdParty()
    {
        using var linked = LinkCheckerCancellation();
        return await GetThirdPartyChecker().RunAsync(linked.Token);
    }

    public async Task<ThirdParty.ThirdPartyResult> PrintThirdPartyReport(bool includeDetails = true)
    {
        var result = await GetThirdPartyChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.StartsWith("ASSESSMENT", StringComparison.Ordinal))
            {
                if (line.Contains("[LOW/informative]", StringComparison.OrdinalIgnoreCase))
                    _logColored(line, "#569CD6");
                else if (line.Contains("declare Subresource Integrity", StringComparison.OrdinalIgnoreCase))
                    _logColored(line, "#4EC9B0");
                else
                    _logColored(line, "#569CD6");
            }
            else if (line.Contains("[WARNING]", StringComparison.Ordinal))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("==="))
            {
                if (line.Contains("No third-party", StringComparison.OrdinalIgnoreCase))
                    _logColored(line, "#4EC9B0");
                else
                    _logColored(line, "#569CD6");
            }
            else if (line.StartsWith("DOMAINS", StringComparison.Ordinal)
                     || line.StartsWith("RESOURCES BY", StringComparison.Ordinal)
                     || line.StartsWith("OVERVIEW", StringComparison.Ordinal))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.IndexOf("No third-party resources", StringComparison.OrdinalIgnoreCase) >= 0)
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertThirdPartySecure(string? message = null)
    {
        var result = await GetThirdPartyChecker().RunAsync();
        var desc = message ?? "Third-party resource review (SRI)";
        var withoutSri = result.Resources.Where(r => !r.HasSri && r.Type is "script" or "stylesheet").ToList();

        if (withoutSri.Count == 0)
        {
            Assert.Pass($"{desc}: SRI present on all third-party scripts/stylesheets ({result.TotalCount} third-party resource(s) total)");
            return;
        }

        _logColored(
            $"[LOW/informative] {withoutSri.Count} third-party script/stylesheet load(s) omit SRI — typical; optional hardening vs CDN/host tampering.",
            "#569CD6");
        foreach (var r in withoutSri.Take(10))
            _logColored($"    [{r.Type}] {r.Url}", "#CCCCCC");

        Assert.Pass($"{desc} completed ({result.TotalCount} third-party resource(s); {withoutSri.Count} script/stylesheet without SRI — informational only)");
    }

    #endregion

    #region Orchestration (Trowser Twelve playbooks)

    /// <summary>
    /// Run a security playbook by ID and return the full response.
    /// Available playbook IDs: a01-access, a02-misconfig, a03-supplychain, a04-crypto,
    /// a05-injection, a06-design, a07-authn, a09-opsec, a11-ssrf, a12-availability,
    /// a13-llm, a14-other, full.
    /// </summary>
    public async Task<PlaybookResponse> RunPlaybookAsync(
        string playbookId,
        string safetyMode = "safe",
        string depth = "standard",
        string format = "markdown",
        string? host = null,
        int maxSeconds = 120,
        int maxRequests = 800,
        bool includeCrawl = false,
        string? targetUrl = null,
        string? targetMethod = null,
        string? payloadProfile = null,
        CancellationToken ct = default)
    {
        if (PlaybookRegistry == null || OrchestrateIdentityStore == null || OrchestrateChainCatalog == null)
            throw new InvalidOperationException("Playbook orchestration is not initialized.");

        var playbook = PlaybookRegistry.Get(playbookId)
            ?? throw new ArgumentException(
                $"Unknown playbook: '{playbookId}'. Available: {string.Join(", ", PlaybookRegistry.All.Keys)}");

        var request = new PlaybookRequest
        {
            Scope = new PlaybookScope
            {
                Host = host,
                TargetUrl = targetUrl,
                TargetMethod = targetMethod
            },
            IncludeCrawl = includeCrawl,
            SafetyMode = SafetyModeExtensions.Parse(safetyMode),
            Depth = PlaybookDepthProfile.Parse(depth),
            PayloadProfile = PayloadProfileExtensions.Parse(payloadProfile),
            Budget = new BudgetLimits { MaxSeconds = maxSeconds, MaxRequests = maxRequests },
            Format = format,
            EmitSuggestedProofs = true,
            PersistVpx = true
        };

        var runner = new PlaybookRunner(this, OrchestrateIdentityStore, OrchestrateChainCatalog);
        return await runner.RunAsync(playbook, request, ct);
    }

    /// <summary>
    /// Run a playbook and render the markdown report to the output pane.
    /// Returns the response for further inspection (e.g. findings count, assertions).
    /// </summary>
    public async Task<PlaybookResponse> PrintPlaybookReport(
        string playbookId,
        string safetyMode = "safe",
        string depth = "standard",
        string? host = null,
        int maxSeconds = 120,
        int maxRequests = 800,
        bool includeCrawl = false,
        string? targetUrl = null,
        string? targetMethod = null,
        string? payloadProfile = null,
        CancellationToken ct = default)
    {
        var depthProfile = PlaybookDepthProfile.Resolve(PlaybookDepthProfile.Parse(depth));
        var targetNote = string.IsNullOrWhiteSpace(targetUrl) ? "" : $", target={targetMethod ?? "*"} {targetUrl}";
        var crawlNote = includeCrawl ? "" : ", includeCrawl=false";
        Log($"Running playbook '{playbookId}' (depth={depthProfile.ToLabel()}, safety={safetyMode}{crawlNote}{targetNote}, ~{depthProfile.TimeHintSeconds}s)...");

        var result = await RunPlaybookAsync(playbookId, safetyMode, depth, "markdown",
            host, maxSeconds, maxRequests, includeCrawl, targetUrl, targetMethod, payloadProfile, ct);

        if (!string.IsNullOrEmpty(result.Markdown))
        {
            foreach (var line in result.Markdown.Split('\n'))
            {
                var trimmed = line.TrimEnd('\r');
                if (trimmed.Contains("CRITICAL") || trimmed.Contains("HIGH") || trimmed.StartsWith("## ⛔") || trimmed.StartsWith("## 🔴"))
                    _logColored(trimmed, "#F44747");
                else if (trimmed.Contains("MEDIUM") || trimmed.StartsWith("## 🟡"))
                    _logColored(trimmed, "#CCA700");
                else if (trimmed.Contains("LOW") || trimmed.Contains("INFO") || trimmed.StartsWith("## 🔵") || trimmed.StartsWith("## 🟢"))
                    _logColored(trimmed, "#569CD6");
                else if (trimmed.StartsWith("# ") || trimmed.StartsWith("## ") || trimmed.StartsWith("---"))
                    _logColored(trimmed, "#4EC9B0");
                else if (trimmed.StartsWith("> ⚠") || trimmed.StartsWith("⚠"))
                    _logColored(trimmed, "#CCA700");
                else
                    _logColored(trimmed, "#CCCCCC");
            }
        }

        if (result.Warnings.Count > 0)
        {
            _logColored("", "#CCCCCC");
            foreach (var w in result.Warnings)
                _logColored($"⚠ {w}", "#CCA700");
        }

        return result;
    }

    /// <summary>
    /// Assert that a playbook finds no vulnerabilities at or above the given severity.
    /// </summary>
    public async Task AssertPlaybookClean(
        string playbookId,
        string safetyMode = "safe",
        string depth = "standard",
        string? minSeverity = "medium",
        string? message = null,
        string? host = null,
        CancellationToken ct = default)
    {
        var result = await RunPlaybookAsync(playbookId, safetyMode, depth, "vpx-compact",
            host, ct: ct);

        var desc = message ?? $"Playbook '{playbookId}' should find no vulnerabilities";
        var findingCount = result.StepsExecuted.Sum(s =>
            s.Metrics.TryGetValue("findings", out var v) && v is int n ? n : 0);

        if (findingCount == 0 || result.AssertionsAdded == 0)
            Assert.Pass($"{desc} ({result.StepsExecuted.Count} steps, {result.SafetyMode} mode)");
        else
            Assert.Fail($"{desc}: findings detected ({result.StepsExecuted.Count} steps, {result.SafetyMode} mode)");
    }

    #endregion
}
