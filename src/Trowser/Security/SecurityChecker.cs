using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Info about whether a newer vulnerability database is available.
/// </summary>
public class RepositoryUpdateInfo
{
    public bool UpdateAvailable { get; init; }
    public string Source { get; init; } = "";
    public DateTime? CurrentDate { get; init; }
    public DateTime? LatestDate { get; init; }
    public string LocalPath { get; init; } = "";
    public string? Error { get; init; }

    public const string DownloadUrl =
        "https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json";
}

/// <summary>
/// Scans the current page for JavaScript libraries with known vulnerabilities
/// using the Retire.js vulnerability repository.
/// Follows the same inject-and-poll pattern as AccessibilityChecker.
/// </summary>
public class SecurityChecker
{
    private readonly WebView2 _webView;

    private static string? _repositoryJson;
    private static string _repositorySource = "embedded";
    private static DateTime? _repositoryDate;

    private static DateTime? _lastUpdateCheck;
    private static RepositoryUpdateInfo? _cachedUpdateInfo;
    private static readonly TimeSpan UpdateCheckCacheTtl = TimeSpan.FromHours(12);

    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(8),
        DefaultRequestHeaders = { { "User-Agent", $"Trowser/{App.Version}" } }
    };

    public SecurityChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Which source the vulnerability repository was loaded from: "local file" or "embedded".
    /// </summary>
    public static string RepositorySource => _repositorySource;

    /// <summary>
    /// Path where a local override file can be placed.
    /// </summary>
    public static string LocalRepositoryPath =>
        Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, "jsrepository.json");

    /// <summary>
    /// Scan the current page for JavaScript libraries with known vulnerabilities.
    /// </summary>
    /// <param name="includeFileContent">
    /// Fetch same-origin script bodies and apply Retire.js <c>filecontent</c> extractors.
    /// Explicit scans (REST/MCP/script) default on. Shadow leaves this off to avoid
    /// re-downloading bundles on every navigation.
    /// </param>
    public async Task<SecurityResult> RunAsync(
        CancellationToken cancellationToken = default,
        bool includeFileContent = true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var repoJson = await GetRepositoryJsonAsync();
        var callbackId = $"__trowser_retire_{Guid.NewGuid():N}";

        var scanScript = BuildScannerScript(callbackId, repoJson, includeFileContent);
        var startResult = await WebViewUiScript.RunAsync(_webView, scanScript, cancellationToken,
            operationLabel: "Security scan");

        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start security scan. Result: {startResult}");
        }

        // Func/uri/filename are synchronous. Filecontent fetches script bodies.
        var timeoutSeconds = includeFileContent ? 25 : 10;
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Security scan");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Security scan");

                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Security scan");
                break;
            }
            await Task.Delay(50, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException(
                $"Security scan did not complete within {timeoutSeconds} seconds.");
        }

        return ParseResults(json, includeFileContent);
    }

    #region Scanner JavaScript

    private static string BuildScannerScript(string callbackId, string repoJson, bool includeFileContent)
    {
        // The version placeholder in retire.js repo patterns
        const string versionRegex = "([0-9][0-9.a-z_\\\\-]+)";
        var extraFuncsJson = JsonSerializer.Serialize(RetireJsExtractorOverlay.ExtraFuncExtractors);
        var extraFileContentJson = JsonSerializer.Serialize(RetireJsExtractorOverlay.ExtraFileContentExtractors);
        var includeFileContentJs = includeFileContent ? "true" : "false";

        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    try {{
        var repo = {repoJson};
        var VERSION_RE = '{versionRegex}';
        var extraFuncs = {extraFuncsJson};
        var extraFileContent = {extraFileContentJson};
        var includeFileContent = {includeFileContentJs};

        for (var extraName in extraFuncs) {{
            if (!repo[extraName] || !repo[extraName].extractors) continue;
            var existing = repo[extraName].extractors.func || [];
            repo[extraName].extractors.func = existing.concat(extraFuncs[extraName]);
        }}
        for (var extraFcName in extraFileContent) {{
            if (!repo[extraFcName] || !repo[extraFcName].extractors) continue;
            var existingFc = repo[extraFcName].extractors.filecontent || [];
            repo[extraFcName].extractors.filecontent = existingFc.concat(extraFileContent[extraFcName]);
        }}

        var results = {{
            url: location.href,
            timestamp: new Date().toISOString(),
            libraries: [],
            scriptInventory: [],
            fileContentScanned: false
        }};

        // Collect all loaded script URLs
        var scriptUrls = [];
        var scripts = document.getElementsByTagName('script');
        for (var i = 0; i < scripts.length; i++) {{
            if (scripts[i].src) scriptUrls.push(scripts[i].src);
        }}
        // Also from Resource Timing (catches dynamically loaded scripts)
        try {{
            var resources = performance.getEntriesByType('resource');
            for (var i = 0; i < resources.length; i++) {{
                if (resources[i].initiatorType === 'script') {{
                    if (scriptUrls.indexOf(resources[i].name) === -1)
                        scriptUrls.push(resources[i].name);
                }}
            }}
        }} catch(e) {{}}

        // Version comparison: returns -1, 0, or 1
        function cmpVer(a, b) {{
            var pa = a.replace(/[^0-9.]/g, '.').split('.').map(Number);
            var pb = b.replace(/[^0-9.]/g, '.').split('.').map(Number);
            var len = Math.max(pa.length, pb.length);
            for (var i = 0; i < len; i++) {{
                var na = pa[i] || 0, nb = pb[i] || 0;
                if (na < nb) return -1;
                if (na > nb) return 1;
            }}
            return 0;
        }}

        function isVulnerable(version, vuln) {{
            if (vuln.atOrAbove && cmpVer(version, vuln.atOrAbove) < 0) return false;
            if (vuln.below && cmpVer(version, vuln.below) >= 0) return false;
            return true;
        }}

        function replaceVersion(pattern) {{
            return pattern.replace(/§§version§§/g, VERSION_RE);
        }}

        // Try func extractors -- evaluate JS expressions in page context
        function tryFunc(funcs) {{
            if (!funcs) return null;
            for (var i = 0; i < funcs.length; i++) {{
                try {{
                    var v = (new Function('return (' + funcs[i] + ')'))();
                    if (v && typeof v === 'string' && /^[0-9]/.test(v)) return v;
                    if (v && typeof v === 'number') return String(v);
                }} catch(e) {{}}
            }}
            return null;
        }}

        // Try URI extractors -- match against full script URLs
        function tryUri(uris, urls) {{
            if (!uris) return null;
            for (var i = 0; i < uris.length; i++) {{
                try {{
                    var re = new RegExp(replaceVersion(uris[i]));
                    for (var j = 0; j < urls.length; j++) {{
                        var m = urls[j].match(re);
                        if (m) {{
                            for (var k = 1; k < m.length; k++) {{
                                if (m[k] && /^[0-9]/.test(m[k])) return m[k];
                            }}
                        }}
                    }}
                }} catch(e) {{}}
            }}
            return null;
        }}

        // Try filename extractors -- match against just the filename part
        function tryFilename(patterns, urls) {{
            if (!patterns) return null;
            for (var i = 0; i < patterns.length; i++) {{
                try {{
                    var re = new RegExp(replaceVersion(patterns[i]));
                    for (var j = 0; j < urls.length; j++) {{
                        var fname = urls[j].split('/').pop().split('?')[0].split('#')[0];
                        var m = fname.match(re);
                        if (m) {{
                            for (var k = 1; k < m.length; k++) {{
                                if (m[k] && /^[0-9]/.test(m[k])) return m[k];
                            }}
                        }}
                    }}
                }} catch(e) {{}}
            }}
            return null;
        }}

        function tryFilecontent(patterns, texts) {{
            if (!patterns || !texts || !texts.length) return null;
            for (var i = 0; i < patterns.length; i++) {{
                try {{
                    var re = new RegExp(replaceVersion(patterns[i]));
                    for (var t = 0; t < texts.length; t++) {{
                        var m = texts[t].match(re);
                        if (m) {{
                            for (var k = 1; k < m.length; k++) {{
                                if (m[k] && /^[0-9]/.test(m[k])) return m[k];
                            }}
                        }}
                    }}
                }} catch(e) {{}}
            }}
            return null;
        }}

        function collectInlineTexts() {{
            var texts = [];
            for (var i = 0; i < scripts.length; i++) {{
                if (!scripts[i].src && scripts[i].textContent)
                    texts.push(scripts[i].textContent);
            }}
            return texts;
        }}

        function buildInventory() {{
            var sizeByUrl = {{}};
            try {{
                var resources = performance.getEntriesByType('resource');
                for (var i = 0; i < resources.length; i++) {{
                    if (resources[i].initiatorType === 'script') {{
                        sizeByUrl[resources[i].name] =
                            resources[i].encodedBodySize || resources[i].transferSize || 0;
                    }}
                }}
            }} catch(e) {{}}
            var inventory = [];
            for (var i = 0; i < scriptUrls.length; i++) {{
                inventory.push({{
                    url: scriptUrls[i],
                    encodedBodySize: sizeByUrl[scriptUrls[i]] || 0
                }});
            }}
            return inventory;
        }}

        function addLibrary(libName, lib, version, method) {{
            var libResult = {{
                name: libName,
                version: version,
                detectionMethod: method,
                vulnerabilities: []
            }};
            if (lib.vulnerabilities) {{
                for (var i = 0; i < lib.vulnerabilities.length; i++) {{
                    var vuln = lib.vulnerabilities[i];
                    if (isVulnerable(version, vuln)) {{
                        libResult.vulnerabilities.push({{
                            severity: vuln.severity || 'unknown',
                            summary: (vuln.identifiers && vuln.identifiers.summary) || '',
                            cves: (vuln.identifiers && vuln.identifiers.CVE) || [],
                            cwes: vuln.cwe || [],
                            info: vuln.info || [],
                            below: vuln.below || null,
                            atOrAbove: vuln.atOrAbove || null
                        }});
                    }}
                }}
            }}
            results.libraries.push(libResult);
        }}

        var detected = {{}};

        function runPass(contentTexts) {{
            for (var libName in repo) {{
                if (libName === 'retire-example' || detected[libName]) continue;
                var lib = repo[libName];
                if (!lib || !lib.extractors) continue;

                var version = null;
                var method = null;

                version = tryFunc(lib.extractors.func);
                if (version) method = 'func';

                if (!version) {{
                    version = tryUri(lib.extractors.uri, scriptUrls);
                    if (version) method = 'uri';
                }}

                if (!version) {{
                    version = tryFilename(lib.extractors.filename, scriptUrls);
                    if (version) method = 'filename';
                }}

                if (!version && contentTexts) {{
                    version = tryFilecontent(lib.extractors.filecontent, contentTexts);
                    if (version) method = 'filecontent';
                }}

                if (!version) continue;
                detected[libName] = true;
                addLibrary(libName, lib, version, method);
            }}
        }}

        function finish() {{
            window['{callbackId}'] = JSON.stringify(results);
            window['{callbackId}_done'] = true;
        }}

        results.scriptInventory = buildInventory();

        var inlineTexts = collectInlineTexts();
        runPass(inlineTexts.length ? inlineTexts : null);

        if (!includeFileContent || scriptUrls.length === 0) {{
            finish();
            return 'STARTED';
        }}

        var maxFiles = 16;
        var maxBytes = 1500000;
        var slice = scriptUrls.slice(0, maxFiles);
        Promise.all(slice.map(function(url) {{
            return fetch(url, {{ credentials: 'include', cache: 'force-cache' }})
                .then(function(r) {{ return r.ok ? r.text() : null; }})
                .then(function(t) {{
                    if (!t) return null;
                    return t.length > maxBytes ? t.substring(0, maxBytes) : t;
                }})
                .catch(function() {{ return null; }});
        }})).then(function(arr) {{
            var texts = inlineTexts.slice();
            for (var i = 0; i < arr.length; i++) {{
                if (arr[i]) texts.push(arr[i]);
            }}
            results.fileContentScanned = texts.length > inlineTexts.length;
            runPass(texts.length ? texts : null);
            finish();
        }}).catch(function() {{
            finish();
        }});
    }} catch(e) {{
        window['{callbackId}'] = JSON.stringify({{ error: e.message || String(e) }});
        window['{callbackId}_done'] = true;
    }}

    return 'STARTED';
}})()";
    }

    #endregion

    #region Repository Loading

    private static async Task<string> GetRepositoryJsonAsync()
    {
        if (_repositoryJson != null) return _repositoryJson;

        // Try local override file next to the executable first
        var localPath = LocalRepositoryPath;
        if (File.Exists(localPath))
        {
            _repositoryJson = await File.ReadAllTextAsync(localPath);
            _repositorySource = "local file";
            _repositoryDate = File.GetLastWriteTimeUtc(localPath);
            return _repositoryJson;
        }

        // Fall back to embedded resource
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.jsrepository.json");

        if (stream == null)
        {
            throw new InvalidOperationException(
                "Retire.js repository not found as embedded resource. " +
                "Ensure jsrepository.json is in Resources/ and marked as EmbeddedResource in the .csproj.");
        }

        using var reader = new StreamReader(stream);
        _repositoryJson = await reader.ReadToEndAsync();
        _repositorySource = "embedded";
        var exePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, "Trowser.exe");
        _repositoryDate = File.Exists(exePath) ? File.GetLastWriteTimeUtc(exePath) : DateTime.UtcNow;
        return _repositoryJson;
    }

    /// <summary>
    /// Force reload the repository from disk on next scan (e.g. after the user drops in a new file).
    /// </summary>
    public static void ReloadRepository()
    {
        _repositoryJson = null;
        _repositorySource = "embedded";
        _repositoryDate = null;
        _cachedUpdateInfo = null;
        _lastUpdateCheck = null;
    }

    #endregion

    #region Update Check

    /// <summary>
    /// Check if a newer vulnerability database is available on GitHub.
    /// Uses the GitHub API, caches the result for 12 hours, and fails gracefully if offline.
    /// </summary>
    public static async Task<RepositoryUpdateInfo> CheckForUpdatesAsync()
    {
        // Ensure repo is loaded so we know our current date
        await GetRepositoryJsonAsync();

        // Return cached result if recent enough
        if (_cachedUpdateInfo != null && _lastUpdateCheck.HasValue &&
            DateTime.UtcNow - _lastUpdateCheck.Value < UpdateCheckCacheTtl)
        {
            return _cachedUpdateInfo;
        }

        var localPath = LocalRepositoryPath;

        try
        {
            // Ask GitHub for the latest commit that touched jsrepository.json
            var apiUrl = "https://api.github.com/repos/RetireJS/retire.js/commits" +
                         "?path=repository/jsrepository.json&per_page=1";

            var response = await Http.GetStringAsync(apiUrl);
            using var doc = JsonDocument.Parse(response);
            var commits = doc.RootElement;

            if (commits.GetArrayLength() > 0)
            {
                var commitDate = commits[0]
                    .GetProperty("commit")
                    .GetProperty("committer")
                    .GetProperty("date")
                    .GetDateTime();

                var updateAvailable = !_repositoryDate.HasValue ||
                                      commitDate > _repositoryDate.Value.AddHours(1);

                _cachedUpdateInfo = new RepositoryUpdateInfo
                {
                    UpdateAvailable = updateAvailable,
                    Source = _repositorySource,
                    CurrentDate = _repositoryDate,
                    LatestDate = commitDate,
                    LocalPath = localPath
                };
            }
            else
            {
                _cachedUpdateInfo = new RepositoryUpdateInfo
                {
                    UpdateAvailable = false,
                    Source = _repositorySource,
                    CurrentDate = _repositoryDate,
                    LocalPath = localPath
                };
            }
        }
        catch (Exception ex)
        {
            _cachedUpdateInfo = new RepositoryUpdateInfo
            {
                UpdateAvailable = false,
                Source = _repositorySource,
                CurrentDate = _repositoryDate,
                LocalPath = localPath,
                Error = ex.Message
            };
        }

        _lastUpdateCheck = DateTime.UtcNow;
        return _cachedUpdateInfo;
    }

    #endregion

    #region Result Parsing

    private static SecurityResult ParseResults(string json, bool includeFileContent)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"Security scan error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";

        var libraries = new List<DetectedLibrary>();
        if (root.TryGetProperty("libraries", out var libsArray))
        {
            foreach (var lib in libsArray.EnumerateArray())
            {
                libraries.Add(ParseLibrary(lib));
            }
        }

        var inventory = new List<ScriptInventoryEntry>();
        if (root.TryGetProperty("scriptInventory", out var invArray) &&
            invArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in invArray.EnumerateArray())
            {
                var scriptUrl = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                var size = 0L;
                if (item.TryGetProperty("encodedBodySize", out var sz) &&
                    sz.TryGetInt64(out var parsed))
                    size = parsed;
                inventory.Add(new ScriptInventoryEntry(scriptUrl, size));
            }
        }

        var fileContentScanned = includeFileContent &&
            root.TryGetProperty("fileContentScanned", out var fcs) &&
            fcs.ValueKind == JsonValueKind.True;

        var caveats = RetireJsExtractorOverlay.BuildCaveats(inventory, libraries.Count);
        var hasBundled = inventory.Any(s =>
            RetireJsExtractorOverlay.LooksBundled(s.Url, s.EncodedBodySize));

        return new SecurityResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Libraries = libraries,
            Caveats = caveats.ToList(),
            HasBundledScripts = hasBundled,
            FileContentScanned = fileContentScanned
        };
    }

    private static DetectedLibrary ParseLibrary(JsonElement lib)
    {
        var vulns = new List<LibraryVulnerability>();

        if (lib.TryGetProperty("vulnerabilities", out var vulnsArray))
        {
            foreach (var v in vulnsArray.EnumerateArray())
            {
                vulns.Add(new LibraryVulnerability
                {
                    Severity = ParseSeverity(
                        v.TryGetProperty("severity", out var sev) ? sev.GetString() : null),
                    Summary = v.TryGetProperty("summary", out var sum) ? sum.GetString() ?? "" : "",
                    CVEs = ParseStringArray(v, "cves"),
                    CWEs = ParseStringArray(v, "cwes"),
                    Info = ParseStringArray(v, "info"),
                    Below = v.TryGetProperty("below", out var bel) ? bel.GetString() : null,
                    AtOrAbove = v.TryGetProperty("atOrAbove", out var aoa) ? aoa.GetString() : null,
                });
            }
        }

        return new DetectedLibrary
        {
            Name = lib.TryGetProperty("name", out var name) ? name.GetString() ?? "" : "",
            Version = lib.TryGetProperty("version", out var ver) ? ver.GetString() ?? "" : "",
            DetectionMethod = lib.TryGetProperty("detectionMethod", out var dm)
                ? dm.GetString() ?? "" : "",
            Vulnerabilities = vulns
        };
    }

    private static Severity ParseSeverity(string? severity)
    {
        return severity?.ToLowerInvariant() switch
        {
            "critical" => Severity.Critical,
            "high" => Severity.High,
            "medium" => Severity.Medium,
            "low" => Severity.Low,
            _ => Severity.Low
        };
    }

    private static List<string> ParseStringArray(JsonElement element, string propertyName)
    {
        var list = new List<string>();
        if (element.TryGetProperty(propertyName, out var array) &&
            array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                var value = item.GetString();
                if (value != null) list.Add(value);
            }
        }
        return list;
    }

    #endregion

    #region Helpers
    private static string UnwrapJsonString(string jsonResult)
        => Trowser.Automation.WebViewScriptResult.UnwrapJsonString(jsonResult);


    #endregion
}
