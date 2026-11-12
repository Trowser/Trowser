using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Compatibility;

/// <summary>
/// Scans JavaScript loaded on the current page for modern language features
/// that may not be supported in older target browsers (iOS 15, Android 10, etc.).
/// Detects both syntax-level features (which cause parse errors and break the entire
/// script) and API-level features (which cause runtime errors only when called).
/// Uses the vanilla version for the release of OS, which causes overly careful reporting.
/// </summary>
public class CompatibilityChecker
{
    private readonly WebView2 _webView;

    public CompatibilityChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Default target browsers to check compatibility against.
    /// </summary>
    public static readonly List<(string Name, string Engine, string Version)> DefaultTargets =
    [
        ("iOS 15 (Safari 15.0)", "safari", "15.0"),
        ("Android 10 (Chrome 74)", "chrome", "74"),
    ];

    /// <summary>
    /// Maps iOS version to the Safari version it ships with.
    /// Safari is the only browser engine allowed on iOS, so this is the baseline.
    /// </summary>
    internal static readonly Dictionary<int, string> IosSafariVersions = new()
    {
        [13] = "13.0",
        [14] = "14.0",
        [15] = "15.0",
        [16] = "16.0",
        [17] = "17.0",
        [18] = "18.0",
    };

    /// <summary>
    /// Maps Android OS version to the Chrome WebView version it shipped with.
    /// This is the worst-case baseline; most devices auto-update WebView via Play Store.
    /// </summary>
    internal static readonly Dictionary<int, string> AndroidChromeVersions = new()
    {
        [7] = "51",
        [8] = "58",
        [9] = "69",
        [10] = "74",
        [11] = "83",
        [12] = "95",
        [13] = "107",
        [14] = "118",
        [15] = "131",
    };

    /// <summary>
    /// Build a target list from iOS and Android version numbers.
    /// </summary>
    public static List<(string Name, string Engine, string Version)> BuildTargets(
        int? minIos = null, int? minAndroid = null)
    {
        var targets = new List<(string Name, string Engine, string Version)>();

        if (minIos.HasValue)
        {
            var ios = minIos.Value;
            if (IosSafariVersions.TryGetValue(ios, out var safariVersion))
                targets.Add(($"iOS {ios} (Safari {safariVersion})", "safari", safariVersion));
            else
                targets.Add(($"iOS {ios} (Safari {ios}.0)", "safari", $"{ios}.0"));
        }

        if (minAndroid.HasValue)
        {
            var android = minAndroid.Value;
            if (AndroidChromeVersions.TryGetValue(android, out var chromeVersion))
                targets.Add(($"Android {android} (Chrome {chromeVersion})", "chrome", chromeVersion));
            else
                targets.Add(($"Android {android}", "chrome", "69"));
        }

        return targets.Count > 0 ? targets : DefaultTargets;
    }

    /// <summary>
    /// Scan the current page for modern JavaScript features and check compatibility.
    /// </summary>
    public async Task<CompatibilityResult> RunAsync(
        List<(string Name, string Engine, string Version)>? targets = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        targets ??= DefaultTargets;

        var callbackId = $"__trowser_compat_{Guid.NewGuid():N}";
        var scanScript = BuildScannerScript(callbackId);
        var startResult = await WebViewUiScript.RunAsync(_webView, scanScript, cancellationToken,
            operationLabel: "Compatibility scan");

        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start compatibility scan. Result: {startResult}");
        }

        var deadline = DateTime.UtcNow.AddSeconds(30);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Compatibility scan");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Compatibility scan");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Compatibility scan");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("Compatibility scan did not complete within 30 seconds.");
        }

        return ParseResults(json, targets);
    }

    #region Scanner JavaScript

    private static string BuildScannerScript(string callbackId)
    {
        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    (async function() {{
    try {{
        // Feature detection database: pattern, name, category, browser min versions
        // category: 's' = syntax (parse error), 'a' = API (runtime error)
        // versions: [chrome, safari, firefox]
        var features = [
            // --- ES2020 Syntax ---
            {{ id: 'optional-chaining', name: 'Optional chaining (?.)',
               pattern: '\\?\\.(?![0-9])', category: 's',
               chrome: '80', safari: '13.1', firefox: '80',
               mdn: 'Web/JavaScript/Reference/Operators/Optional_chaining' }},

            {{ id: 'nullish-coalescing', name: 'Nullish coalescing (??)',
               pattern: '\\?\\?(?!=)', category: 's',
               chrome: '80', safari: '13.1', firefox: '72',
               mdn: 'Web/JavaScript/Reference/Operators/Nullish_coalescing' }},

            // --- ES2021 Syntax ---
            {{ id: 'logical-assignment', name: 'Logical assignment (??=, ||=, &&=)',
               pattern: '\\?\\?=|\\|\\|=|&&=', category: 's',
               chrome: '85', safari: '14', firefox: '79',
               mdn: 'Web/JavaScript/Reference/Operators/Logical_nullish_assignment' }},

            {{ id: 'numeric-separator', name: 'Numeric separator (1_000)',
               pattern: '(?<![a-zA-Z_$])\\d+_\\d+', category: 's',
               chrome: '75', safari: '13', firefox: '70',
               mdn: 'Web/JavaScript/Reference/Lexical_grammar#numeric_separators' }},

            // --- ES2022 Syntax ---
            {{ id: 'private-class-fields', name: 'Private class fields (#field)',
               pattern: '(?:this\\.#|\\s#)[a-zA-Z_]\\w*', category: 's',
               chrome: '74', safari: '14.1', firefox: '90',
               mdn: 'Web/JavaScript/Reference/Classes/Private_properties' }},

            {{ id: 'class-static-block', name: 'Class static initialization block',
               pattern: 'static\\s*\\{{', category: 's',
               chrome: '91', safari: '16.4', firefox: '93',
               mdn: 'Web/JavaScript/Reference/Classes/Static_initialization_blocks' }},

            {{ id: 'top-level-await', name: 'Top-level await',
               pattern: null, category: 's',
               chrome: '89', safari: '15', firefox: '89',
               mdn: 'Web/JavaScript/Reference/Operators/await#top_level_await' }},

            // --- ES2023 Syntax ---
            {{ id: 'hashbang', name: 'Hashbang (#!) comments',
               pattern: '^#!', category: 's',
               chrome: '74', safari: '13.1', firefox: '67',
               mdn: 'Web/JavaScript/Reference/Lexical_grammar#hashbang_comments' }},

            // --- ES2020 APIs ---
            {{ id: 'promise-allsettled', name: 'Promise.allSettled()',
               pattern: 'Promise\\.allSettled\\s*\\(', category: 'a',
               chrome: '76', safari: '13', firefox: '71',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Promise/allSettled' }},

            {{ id: 'globalthis', name: 'globalThis',
               pattern: '\\bglobalThis\\b', category: 'a',
               chrome: '71', safari: '12.1', firefox: '65',
               mdn: 'Web/JavaScript/Reference/Global_Objects/globalThis' }},

            {{ id: 'string-matchall', name: 'String.prototype.matchAll()',
               pattern: '\\.matchAll\\s*\\(', category: 'a',
               chrome: '73', safari: '13', firefox: '67',
               mdn: 'Web/JavaScript/Reference/Global_Objects/String/matchAll' }},

            {{ id: 'import-meta', name: 'import.meta',
               pattern: 'import\\.meta', category: 'a',
               chrome: '64', safari: '11.1', firefox: '62',
               mdn: 'Web/JavaScript/Reference/Operators/import.meta' }},

            // --- ES2021 APIs ---
            {{ id: 'promise-any', name: 'Promise.any()',
               pattern: 'Promise\\.any\\s*\\(', category: 'a',
               chrome: '85', safari: '14', firefox: '79',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Promise/any' }},

            {{ id: 'string-replaceall', name: 'String.prototype.replaceAll()',
               pattern: '\\.replaceAll\\s*\\(', category: 'a',
               chrome: '85', safari: '13.1', firefox: '77',
               mdn: 'Web/JavaScript/Reference/Global_Objects/String/replaceAll' }},

            {{ id: 'weakref', name: 'WeakRef',
               pattern: '\\bWeakRef\\b', category: 'a',
               chrome: '84', safari: '14.1', firefox: '79',
               mdn: 'Web/JavaScript/Reference/Global_Objects/WeakRef' }},

            {{ id: 'finalization-registry', name: 'FinalizationRegistry',
               pattern: '\\bFinalizationRegistry\\b', category: 'a',
               chrome: '84', safari: '14.1', firefox: '79',
               mdn: 'Web/JavaScript/Reference/Global_Objects/FinalizationRegistry' }},

            // --- ES2022 APIs ---
            {{ id: 'array-at', name: 'Array/String .at() method',
               pattern: '\\.at\\s*\\(\\s*-?\\d', category: 'a',
               chrome: '92', safari: '15.4', firefox: '90',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Array/at' }},

            {{ id: 'object-hasown', name: 'Object.hasOwn()',
               pattern: 'Object\\.hasOwn\\s*\\(', category: 'a',
               chrome: '93', safari: '15.4', firefox: '92',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Object/hasOwn' }},

            {{ id: 'error-cause', name: 'Error cause option',
               pattern: 'cause\\s*:', category: 'a',
               chrome: '93', safari: '15', firefox: '91',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Error/cause' }},

            {{ id: 'structuredclone', name: 'structuredClone()',
               pattern: '\\bstructuredClone\\s*\\(', category: 'a',
               chrome: '98', safari: '15.4', firefox: '94',
               mdn: 'Web/API/structuredClone' }},

            // --- ES2023 APIs ---
            {{ id: 'array-findlast', name: 'Array findLast() / findLastIndex()',
               pattern: '\\.(findLast|findLastIndex)\\s*\\(', category: 'a',
               chrome: '97', safari: '15.4', firefox: '104',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Array/findLast' }},

            {{ id: 'array-tosorted', name: 'Array toSorted() / toReversed() / toSpliced()',
               pattern: '\\.(toSorted|toReversed|toSpliced)\\s*\\(', category: 'a',
               chrome: '110', safari: '16', firefox: '115',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Array/toSorted' }},

            {{ id: 'array-with', name: 'Array .with() method',
               pattern: '\\.with\\s*\\(\\s*\\d', category: 'a',
               chrome: '110', safari: '16', firefox: '115',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Array/with' }},

            // --- ES2024 APIs ---
            {{ id: 'object-groupby', name: 'Object.groupBy() / Map.groupBy()',
               pattern: '(?:Object|Map)\\.groupBy\\s*\\(', category: 'a',
               chrome: '117', safari: '17.4', firefox: '119',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Object/groupBy' }},

            {{ id: 'promise-withresolvers', name: 'Promise.withResolvers()',
               pattern: 'Promise\\.withResolvers\\s*\\(', category: 'a',
               chrome: '119', safari: '17.2', firefox: '121',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Promise/withResolvers' }},

            // --- Web APIs ---
            {{ id: 'abortsignal-timeout', name: 'AbortSignal.timeout()',
               pattern: 'AbortSignal\\.timeout\\s*\\(', category: 'a',
               chrome: '103', safari: '16', firefox: '100',
               mdn: 'Web/API/AbortSignal/timeout_static' }},

            {{ id: 'abortsignal-any', name: 'AbortSignal.any()',
               pattern: 'AbortSignal\\.any\\s*\\(', category: 'a',
               chrome: '116', safari: '17.4', firefox: '124',
               mdn: 'Web/API/AbortSignal/any_static' }},

            {{ id: 'crypto-randomuuid', name: 'crypto.randomUUID()',
               pattern: '(?:crypto\\.randomUUID|randomUUID)\\s*\\(', category: 'a',
               chrome: '92', safari: '15.4', firefox: '95',
               mdn: 'Web/API/Crypto/randomUUID' }},

            {{ id: 'navigator-locks', name: 'Web Locks API (navigator.locks)',
               pattern: 'navigator\\.locks', category: 'a',
               chrome: '69', safari: '15.4', firefox: '96',
               mdn: 'Web/API/Web_Locks_API' }},

            {{ id: 'object-fromentries', name: 'Object.fromEntries()',
               pattern: 'Object\\.fromEntries\\s*\\(', category: 'a',
               chrome: '73', safari: '12.1', firefox: '63',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Object/fromEntries' }},

            {{ id: 'array-flat', name: 'Array flat() / flatMap()',
               pattern: '\\.(flat|flatMap)\\s*\\(', category: 'a',
               chrome: '69', safari: '12', firefox: '62',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Array/flat' }},

            {{ id: 'dialog-element', name: 'Dialog element API (showModal)',
               pattern: '\\.showModal\\s*\\(', category: 'a',
               chrome: '37', safari: '15.4', firefox: '98',
               mdn: 'Web/API/HTMLDialogElement/showModal' }},

            {{ id: 'set-methods', name: 'Set methods (intersection, union, difference)',
               pattern: '\\.(intersection|union|difference|symmetricDifference|isSubsetOf|isSupersetOf|isDisjointFrom)\\s*\\(', category: 'a',
               chrome: '122', safari: '17', firefox: '127',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Set/intersection' }},

            {{ id: 'iterator-helpers', name: 'Iterator helpers (map, filter, take, etc.)',
               pattern: 'Iterator\\.from\\s*\\(', category: 'a',
               chrome: '122', safari: '18', firefox: '131',
               mdn: 'Web/JavaScript/Reference/Global_Objects/Iterator' }}
        ];

        // Collect scripts
        var scripts = [];
        var skipped = [];
        var totalBytes = 0;

        // Inline scripts
        var scriptEls = document.querySelectorAll('script:not([src])');
        for (var i = 0; i < scriptEls.length; i++) {{
            var text = scriptEls[i].textContent || '';
            if (text.trim().length > 10) {{
                scripts.push({{ label: 'inline #' + (i + 1), source: text }});
                totalBytes += text.length;
            }}
        }}

        // External scripts — fetch content
        var scriptUrls = new Set();
        var externalScripts = document.querySelectorAll('script[src]');
        for (var i = 0; i < externalScripts.length; i++) {{
            if (externalScripts[i].src) scriptUrls.add(externalScripts[i].src);
        }}
        try {{
            var resources = performance.getEntriesByType('resource');
            for (var i = 0; i < resources.length; i++) {{
                if (resources[i].initiatorType === 'script') {{
                    scriptUrls.add(resources[i].name);
                }}
            }}
        }} catch(e) {{}}

        var fetchPromises = [];
        scriptUrls.forEach(function(url) {{
            fetchPromises.push(
                fetch(url, {{ credentials: 'omit' }}).then(function(r) {{
                    if (!r.ok) throw new Error(r.status);
                    return r.text().then(function(text) {{
                        return {{ url: url, text: text }};
                    }});
                }}).catch(function() {{
                    skipped.push(url);
                    return null;
                }})
            );
        }});

        var fetched = await Promise.all(fetchPromises);
        for (var i = 0; i < fetched.length; i++) {{
            if (fetched[i]) {{
                var fname = fetched[i].url.split('/').pop().split('?')[0];
                if (fname.length > 40) fname = fname.substring(0, 37) + '...';
                scripts.push({{ label: fname, source: fetched[i].text }});
                totalBytes += fetched[i].text.length;
            }}
        }}

        // Analyze each script for each feature
        var detected = {{}};

        for (var si = 0; si < scripts.length; si++) {{
            var src = scripts[si].source;
            var label = scripts[si].label;

            for (var fi = 0; fi < features.length; fi++) {{
                var feat = features[fi];
                if (!feat.pattern) continue;

                try {{
                    var re = new RegExp(feat.pattern, 'g');
                    var matches = src.match(re);
                    if (matches && matches.length > 0) {{
                        if (!detected[feat.id]) {{
                            detected[feat.id] = {{
                                name: feat.name,
                                category: feat.category,
                                chrome: feat.chrome,
                                safari: feat.safari,
                                firefox: feat.firefox,
                                mdn: feat.mdn,
                                count: 0,
                                foundIn: []
                            }};
                        }}
                        detected[feat.id].count += matches.length;
                        if (detected[feat.id].foundIn.indexOf(label) === -1 &&
                            detected[feat.id].foundIn.length < 5) {{
                            detected[feat.id].foundIn.push(label);
                        }}
                    }}
                }} catch(e) {{}}
            }}
        }}

        // Build result
        var detectedList = [];
        for (var id in detected) {{
            detectedList.push(detected[id]);
        }}

        window['{callbackId}'] = JSON.stringify({{
            url: location.href,
            scriptsAnalyzed: scripts.length,
            totalBytes: totalBytes,
            skipped: skipped,
            features: detectedList
        }});
        window['{callbackId}_done'] = true;

    }} catch(e) {{
        window['{callbackId}'] = JSON.stringify({{ error: e.message || String(e) }});
        window['{callbackId}_done'] = true;
    }}
    }})();

    return 'STARTED';
}})()";
    }

    #endregion

    #region Result Parsing

    private static CompatibilityResult ParseResults(
        string json,
        List<(string Name, string Engine, string Version)> targets)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException(
                $"Compatibility scan error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        var scriptsAnalyzed = root.TryGetProperty("scriptsAnalyzed", out var sa) ? sa.GetInt32() : 0;
        var totalBytes = root.TryGetProperty("totalBytes", out var tb) ? tb.GetInt64() : 0;

        var skipped = new List<string>();
        if (root.TryGetProperty("skipped", out var sk) && sk.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in sk.EnumerateArray())
            {
                var val = s.GetString();
                if (val != null) skipped.Add(ShortenUrl(val));
            }
        }

        var features = new List<DetectedFeature>();
        if (root.TryGetProperty("features", out var fa) && fa.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in fa.EnumerateArray())
            {
                var feature = ParseFeature(f, targets);
                features.Add(feature);
            }
        }

        // Calculate overall minimum versions
        var minChrome = "0";
        var minSafari = "0";
        foreach (var f in features)
        {
            if (CompareVersions(f.ChromeMin, minChrome) > 0) minChrome = f.ChromeMin;
            if (CompareVersions(f.SafariMin, minSafari) > 0) minSafari = f.SafariMin;
        }

        // Build target browser assessments
        var targetResults = new List<TargetBrowser>();
        foreach (var (name, engine, version) in targets)
        {
            var unsupported = features
                .Where(f => !IsFeatureSupported(f, engine, version))
                .ToList();

            var risk = CalculateRisk(unsupported);

            targetResults.Add(new TargetBrowser
            {
                Name = name,
                Engine = engine,
                Version = version,
                UnsupportedFeatures = unsupported,
                RiskLevel = risk
            });
        }

        return new CompatibilityResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            ScriptsAnalyzed = scriptsAnalyzed,
            TotalBytesAnalyzed = totalBytes,
            SkippedScripts = skipped,
            Features = features,
            Targets = targetResults,
            MinChromeRequired = minChrome == "0" ? "any" : minChrome,
            MinSafariRequired = minSafari == "0" ? "any" : minSafari
        };
    }

    private static DetectedFeature ParseFeature(
        JsonElement f,
        List<(string Name, string Engine, string Version)> targets)
    {
        var chromeMin = f.TryGetProperty("chrome", out var c) ? c.GetString() ?? "" : "";
        var safariMin = f.TryGetProperty("safari", out var s) ? s.GetString() ?? "" : "";
        var firefoxMin = f.TryGetProperty("firefox", out var ff) ? ff.GetString() ?? "" : "";
        var mdnPath = f.TryGetProperty("mdn", out var m) ? m.GetString() : null;

        var foundIn = new List<string>();
        if (f.TryGetProperty("foundIn", out var fi) && fi.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in fi.EnumerateArray())
            {
                var val = item.GetString();
                if (val != null) foundIn.Add(val);
            }
        }

        var name_ = f.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        var category = f.TryGetProperty("category", out var cat) && cat.GetString() == "s"
            ? FeatureCategory.Syntax : FeatureCategory.Api;
        var occurrences = f.TryGetProperty("count", out var cnt) ? cnt.GetInt32() : 0;
        var mdnUrl = mdnPath != null
            ? $"https://developer.mozilla.org/en-US/docs/{mdnPath}"
            : null;

        // Determine which targets can't support this feature
        var incompatible = new List<string>();
        foreach (var (tName, engine, version) in targets)
        {
            var requiredVersion = engine.ToLowerInvariant() switch
            {
                "chrome" => chromeMin,
                "safari" => safariMin,
                "firefox" => firefoxMin,
                _ => ""
            };
            if (!string.IsNullOrEmpty(requiredVersion) && CompareVersions(version, requiredVersion) < 0)
                incompatible.Add(tName);
        }

        return new DetectedFeature
        {
            Name = name_,
            Category = category,
            SafariMin = safariMin,
            ChromeMin = chromeMin,
            FirefoxMin = firefoxMin,
            Occurrences = occurrences,
            FoundIn = foundIn,
            MdnUrl = mdnUrl,
            IncompatibleWith = incompatible
        };
    }

    private static bool IsFeatureSupported(DetectedFeature feature, string engine, string version)
    {
        var requiredVersion = engine.ToLowerInvariant() switch
        {
            "chrome" => feature.ChromeMin,
            "safari" => feature.SafariMin,
            "firefox" => feature.FirefoxMin,
            _ => ""
        };

        if (string.IsNullOrEmpty(requiredVersion)) return true;
        return CompareVersions(version, requiredVersion) >= 0;
    }

    private static Severity CalculateRisk(List<DetectedFeature> unsupported)
    {
        if (unsupported.Count == 0) return Severity.Low;

        var hasSyntax = unsupported.Any(f => f.Category == FeatureCategory.Syntax);
        var apiCount = unsupported.Count(f => f.Category == FeatureCategory.Api);

        if (hasSyntax) return Severity.Critical;
        if (apiCount >= 3) return Severity.High;
        if (apiCount >= 1) return Severity.Medium;
        return Severity.Low;
    }

    #endregion

    #region Version Comparison

    /// <summary>
    /// Compare two version strings. Returns -1, 0, or 1.
    /// Handles versions like "15.4", "80", "13.1".
    /// </summary>
    internal static int CompareVersions(string a, string b)
    {
        var pa = ParseVersion(a);
        var pb = ParseVersion(b);
        var len = Math.Max(pa.Length, pb.Length);

        for (int i = 0; i < len; i++)
        {
            var na = i < pa.Length ? pa[i] : 0;
            var nb = i < pb.Length ? pb[i] : 0;
            if (na < nb) return -1;
            if (na > nb) return 1;
        }
        return 0;
    }

    private static int[] ParseVersion(string version)
    {
        if (string.IsNullOrEmpty(version)) return [0];
        var parts = version.Split('.');
        var result = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            int.TryParse(parts[i], out result[i]);
        }
        return result;
    }

    #endregion

    #region Helpers

    private static string ShortenUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            var path = uri.AbsolutePath;
            if (path.Length > 50)
                path = "..." + path[^47..];
            return uri.Host + path;
        }
        catch
        {
            return url.Length > 60 ? url[..57] + "..." : url;
        }
    }

    #endregion
}
