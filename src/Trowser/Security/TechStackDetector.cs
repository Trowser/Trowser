using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects the technology stack of a web application by analyzing HTTP response headers,
/// cookies, DOM patterns, meta tags, and script URLs. Covers ~100 technologies across
/// servers, frameworks, JS libraries, WAFs, CDNs, CMSes, and analytics.
/// </summary>
public class TechStackDetector
{
    private readonly WebView2 _webView;
    private readonly NetworkLog _networkLog;

    public TechStackDetector(WebView2 webView, NetworkLog networkLog)
    {
        _webView = webView;
        _networkLog = networkLog;
    }

    public async Task<TechStackResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var sw = Stopwatch.StartNew();
        var detections = new List<TechStackDetection>();

        var url = await WebViewUiScript.RunAsync(_webView, "location.href", cancellationToken,
            operationLabel: "Tech stack detection");
        var pageHost = Uri.TryCreate(url, UriKind.Absolute, out var pageUri) ? pageUri.Host : null;

        // Run header analysis and DOM analysis in parallel via the WebView
        var headerDetections = DetectFromHeaders(url, out var cacheSummary);
        var cookieDetections = DetectFromCookies(pageHost);
        var networkDetections = DetectFromNetwork(pageHost);

        var domJson = await WebViewUiScript.RunAsync(_webView, BuildDomScanScript(), cancellationToken,
            operationLabel: "Tech stack detection");
        var domDetections = ParseDomDetections(domJson);

        detections.AddRange(headerDetections);
        detections.AddRange(cookieDetections);
        detections.AddRange(networkDetections);
        detections.AddRange(domDetections);

        // Deduplicate: keep the highest-confidence detection per technology name
        var deduped = detections
            .GroupBy(d => d.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var best = g.OrderByDescending(d => d.Confidence).First();
                var allVersions = g.Where(d => d.Version != null).Select(d => d.Version).Distinct().ToList();
                if (best.Version == null && allVersions.Count > 0)
                    return best with { Version = allVersions[0] };
                return best;
            })
            .ToList();

        // Do not claim PHP solely from PHPSESSID (or similar) when a non-PHP server stack is clear
        // (e.g. Server: Werkzeug on a Python app that happens to set a PHPSESSID-looking cookie).
        SuppressConflictingLanguageInferences(deduped);

        deduped = deduped
            .OrderBy(d => d.Category)
            .ThenByDescending(d => d.Confidence)
            .ToList();

        sw.Stop();

        return new TechStackResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            ElapsedMs = sw.ElapsedMilliseconds,
            Detections = deduped,
            Cache = cacheSummary
        };
    }

    #region Header Analysis

    private List<TechStackDetection> DetectFromHeaders(string pageUrl, out CacheIdentifySummary cacheSummary)
    {
        var results = new List<TechStackDetection>();
        string? pageHost = null;
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            pageHost = pageUri.Host;

        // Find the document request from the network log (first-party only)
        var docEntries = _networkLog.Entries
            .Where(e => e.ResourceType is "Document" or "document" &&
                        e.StatusCode > 0 &&
                        e.ResponseHeaders != null &&
                        IsSameHost(e.Url, pageHost))
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        if (docEntries.Count == 0)
        {
            cacheSummary = new CacheIdentifySummary { Detected = false, DocumentStatus = CacheHeaderAnalyzer.DocumentStatusUnknown };
            return results;
        }

        var entry = docEntries.FirstOrDefault(e =>
                       !string.IsNullOrEmpty(pageUrl) &&
                       pageUrl.StartsWith(e.Url.Split('?')[0], StringComparison.OrdinalIgnoreCase))
                   ?? docEntries.First();
        var headers = HttpHeaderUtils.CopyCaseInsensitive(entry.ResponseHeaders);

        foreach (var rule in HeaderRules)
        {
            if (!headers.TryGetValue(rule.Header, out var value)) continue;
            if (rule.Pattern != null && !Regex.IsMatch(value, rule.Pattern, RegexOptions.IgnoreCase)) continue;

            var version = rule.VersionPattern != null
                ? Regex.Match(value, rule.VersionPattern, RegexOptions.IgnoreCase).Groups.Count > 1
                    ? Regex.Match(value, rule.VersionPattern, RegexOptions.IgnoreCase).Groups[1].Value
                    : null
                : null;

            results.Add(new TechStackDetection
            {
                Name = rule.Name,
                Version = version,
                Category = rule.Category,
                Evidence = $"Header {rule.Header}: {Truncate(value, 80)}",
                Source = "response-header",
                Confidence = rule.Confidence
            });
        }

        cacheSummary = CacheHeaderAnalyzer.Analyze(headers);
        if (cacheSummary.DocumentStatus == CacheHeaderAnalyzer.DocumentStatusHit)
        {
            results.Add(new TechStackDetection
            {
                Name = "HTTP cache HIT on document",
                Category = "cache",
                Evidence = CacheHeaderAnalyzer.FormatEvidence(cacheSummary),
                Source = "response-header",
                Confidence = 0.9
            });
        }
        else if (cacheSummary.Detected && cacheSummary.Vendors.Count > 0
                 && !results.Any(d => d.Category == "cache"))
        {
            results.Add(new TechStackDetection
            {
                Name = cacheSummary.Vendors[0] + " cache",
                Category = "cache",
                Evidence = CacheHeaderAnalyzer.FormatEvidence(cacheSummary),
                Source = "response-header",
                Confidence = 0.75
            });
        }

        return results;
    }

    #endregion

    #region Cookie Analysis

    private List<TechStackDetection> DetectFromCookies(string? pageHost)
    {
        var results = new List<TechStackDetection>();

        var cookieEntries = _networkLog.Entries
            .Where(e => e.ResponseHeaders != null && IsSameHost(e.Url, pageHost))
            .SelectMany(e => e.ResponseHeaders!
                .Where(h => h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase))
                .Select(h => h.Value))
            .ToList();

        // Also check request cookies from first-party requests only
        var requestCookies = _networkLog.Entries
            .Where(e => e.RequestHeaders != null && IsSameHost(e.Url, pageHost))
            .SelectMany(e => e.RequestHeaders!
                .Where(h => h.Key.Equals("cookie", StringComparison.OrdinalIgnoreCase))
                .Select(h => h.Value))
            .ToList();

        var allCookieText = string.Join("; ", cookieEntries.Concat(requestCookies));

        foreach (var rule in CookieRules)
        {
            if (Regex.IsMatch(allCookieText, rule.Pattern, RegexOptions.IgnoreCase))
            {
                results.Add(new TechStackDetection
                {
                    Name = rule.Name,
                    Category = rule.Category,
                    Evidence = $"Cookie pattern: {rule.Pattern}",
                    Source = "cookie",
                    Confidence = rule.Confidence
                });
            }
        }

        return results;
    }

    private List<TechStackDetection> DetectFromNetwork(string? pageHost)
    {
        var results = new List<TechStackDetection>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in _networkLog.Entries)
        {
            if (!IsSameHost(entry.Url, pageHost))
                continue;

            var url = entry.Url ?? "";

            if (seen.Add("Socket.IO") &&
                (url.Contains("/socket.io/", StringComparison.OrdinalIgnoreCase) ||
                 (url.Contains("transport=polling", StringComparison.OrdinalIgnoreCase) &&
                  url.Contains("EIO=", StringComparison.OrdinalIgnoreCase))))
            {
                results.Add(new TechStackDetection
                {
                    Name = "Socket.IO",
                    Category = "js-library",
                    Evidence = $"Network URL: {Truncate(url, 80)}",
                    Source = "network-url",
                    Confidence = 0.9
                });
            }

            if (seen.Add("SockJS") && url.Contains("sockjs", StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new TechStackDetection
                {
                    Name = "SockJS",
                    Category = "js-library",
                    Evidence = $"Network URL: {Truncate(url, 80)}",
                    Source = "network-url",
                    Confidence = 0.85
                });
            }

            if (entry.ResponseHeaders == null) continue;

            var headers = HttpHeaderUtils.CopyCaseInsensitive(entry.ResponseHeaders);
            foreach (var rule in HeaderRules)
            {
                if (!headers.TryGetValue(rule.Header, out var value)) continue;
                if (rule.Pattern != null && !Regex.IsMatch(value, rule.Pattern, RegexOptions.IgnoreCase)) continue;

                var key = $"{rule.Name}|{rule.Header}";
                if (!seen.Add(key)) continue;

                var version = rule.VersionPattern != null
                    ? Regex.Match(value, rule.VersionPattern, RegexOptions.IgnoreCase).Groups.Count > 1
                        ? Regex.Match(value, rule.VersionPattern, RegexOptions.IgnoreCase).Groups[1].Value
                        : null
                    : null;

                results.Add(new TechStackDetection
                {
                    Name = rule.Name,
                    Version = version,
                    Category = rule.Category,
                    Evidence = $"Header {rule.Header}: {Truncate(value, 80)} (from {Truncate(url, 60)})",
                    Source = "response-header",
                    Confidence = rule.Confidence * 0.95
                });
            }
        }

        return results;
    }

    #endregion

    #region DOM Scan Script

    private static string BuildDomScanScript()
    {
        return @"
(function() {
    var d = [];

    // --- Meta tags ---
    var metas = document.querySelectorAll('meta[name], meta[property], meta[http-equiv]');
    for (var m of metas) {
        var name = (m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || '').toLowerCase();
        var content = m.getAttribute('content') || '';
        if (name === 'generator') {
            d.push({name: content.split(/[\s\/]/)[0], version: (content.match(/[\d]+\.[\d.]+/) || [null])[0],
                     category: 'cms', evidence: 'meta[name=generator]: ' + content, source: 'meta-tag', confidence: 0.95});
        }
        if (name === 'x-powered-by') {
            d.push({name: content.split(/[\s\/]/)[0], version: (content.match(/[\d]+\.[\d.]+/) || [null])[0],
                     category: 'framework', evidence: 'meta X-Powered-By: ' + content, source: 'meta-tag', confidence: 0.8});
        }
    }

    // --- Script src patterns ---
    var scripts = document.querySelectorAll('script[src]');
    var scriptSrcs = [];
    for (var s of scripts) scriptSrcs.push(s.src);
    try {
        var res = performance.getEntriesByType('resource');
        for (var i = 0; i < res.length; i++) {
            if (res[i].initiatorType === 'script' && scriptSrcs.indexOf(res[i].name) === -1)
                scriptSrcs.push(res[i].name);
        }
    } catch(e) {}
    var srcStr = scriptSrcs.join('\n');

    var scriptRules = [
        {p: /jquery[\/\-.](\d+\.\d+[\d.]*)/i, n: 'jQuery', c: 'js-library'},
        {p: /angular[\/@](\d+\.\d+[\d.]*)/i, n: 'Angular', c: 'js-framework'},
        {p: /angular\.min\.js|angular\.js/i, n: 'AngularJS', c: 'js-framework'},
        {p: /react[\.\-](\d+\.\d+[\d.]*)|react\.production/i, n: 'React', c: 'js-framework'},
        {p: /vue[\.\-@](\d+\.\d+[\d.]*)|vue\.runtime/i, n: 'Vue.js', c: 'js-framework'},
        {p: /next[\/_](\d+\.\d+[\d.]*)|_next\//i, n: 'Next.js', c: 'js-framework'},
        {p: /nuxt/i, n: 'Nuxt.js', c: 'js-framework'},
        {p: /svelte/i, n: 'Svelte', c: 'js-framework'},
        {p: /ember/i, n: 'Ember.js', c: 'js-framework'},
        {p: /backbone/i, n: 'Backbone.js', c: 'js-library'},
        {p: /bootstrap[\/\-.](\d+\.\d+[\d.]*)/i, n: 'Bootstrap', c: 'js-library'},
        {p: /tailwind/i, n: 'Tailwind CSS', c: 'js-library'},
        {p: /lodash|underscore/i, n: 'Lodash/Underscore', c: 'js-library'},
        {p: /moment[\.\-](\d+\.\d+[\d.]*)|moment\.min/i, n: 'Moment.js', c: 'js-library'},
        {p: /axios/i, n: 'Axios', c: 'js-library'},
        {p: /socket\.io/i, n: 'Socket.IO', c: 'js-library'},
        {p: /gtag\/js|googletagmanager/i, n: 'Google Tag Manager', c: 'analytics'},
        {p: /google-analytics|analytics\.js|ga\.js/i, n: 'Google Analytics', c: 'analytics'},
        {p: /hotjar/i, n: 'Hotjar', c: 'analytics'},
        {p: /clarity\.ms/i, n: 'Microsoft Clarity', c: 'analytics'},
        {p: /segment\.com|cdn\.segment/i, n: 'Segment', c: 'analytics'},
        {p: /sentry[\.\-](\d+\.\d+[\d.]*)|sentry\.io/i, n: 'Sentry', c: 'js-library'},
        {p: /cdn\.jsdelivr\.net/i, n: 'jsDelivr', c: 'cdn'},
        {p: /cdnjs\.cloudflare\.com/i, n: 'cdnjs', c: 'cdn'},
        {p: /unpkg\.com/i, n: 'unpkg', c: 'cdn'},
        {p: /polyfill\.io/i, n: 'Polyfill.io', c: 'js-library'},
        {p: /wp-content|wp-includes/i, n: 'WordPress', c: 'cms'},
        {p: /drupal/i, n: 'Drupal', c: 'cms'},
        {p: /joomla/i, n: 'Joomla', c: 'cms'},
        {p: /shopify/i, n: 'Shopify', c: 'cms'},
        {p: /magento/i, n: 'Magento', c: 'cms'},
        {p: /hubspot/i, n: 'HubSpot', c: 'analytics'},
        {p: /recaptcha/i, n: 'Google reCAPTCHA', c: 'js-library'},
        {p: /turnstile/i, n: 'Cloudflare Turnstile', c: 'js-library'},
        {p: /blazor/i, n: 'Blazor', c: 'framework'},
        {p: /webassembly|\.wasm/i, n: 'WebAssembly', c: 'language'}
    ];

    for (var rule of scriptRules) {
        var m = srcStr.match(rule.p);
        if (m) {
            d.push({name: rule.n, version: m[1] || null, category: rule.c,
                     evidence: 'script src match: ' + rule.p.source,
                     source: 'script-src', confidence: 0.85});
        }
    }

    // --- Global JS objects ---
    var globalChecks = [
        {g: 'jQuery', n: 'jQuery', c: 'js-library', v: function(){ return typeof jQuery !== 'undefined' ? jQuery.fn.jquery : null; }},
        {g: 'angular', n: 'AngularJS', c: 'js-framework', v: function(){ return typeof angular !== 'undefined' && angular.version ? angular.version.full : null; }},
        {g: 'ng', n: 'Angular', c: 'js-framework', v: function(){ try { return document.querySelector('[ng-version]')?.getAttribute('ng-version'); } catch(e){return null;} }},
        {g: 'React', n: 'React', c: 'js-framework', v: function(){ return typeof React !== 'undefined' && React.version ? React.version : null; }},
        {g: 'Vue', n: 'Vue.js', c: 'js-framework', v: function(){ return typeof Vue !== 'undefined' && Vue.version ? Vue.version : null; }},
        {g: '__NEXT_DATA__', n: 'Next.js', c: 'js-framework', v: function(){ return typeof __NEXT_DATA__ !== 'undefined' && __NEXT_DATA__.buildId ? 'detected' : null; }},
        {g: '__NUXT__', n: 'Nuxt.js', c: 'js-framework', v: function(){ return typeof __NUXT__ !== 'undefined' ? 'detected' : null; }},
        {g: 'Ember', n: 'Ember.js', c: 'js-framework', v: function(){ return typeof Ember !== 'undefined' && Ember.VERSION ? Ember.VERSION : null; }},
        {g: 'Backbone', n: 'Backbone.js', c: 'js-library', v: function(){ return typeof Backbone !== 'undefined' && Backbone.VERSION ? Backbone.VERSION : null; }},
        {g: '_', n: 'Lodash', c: 'js-library', v: function(){ return typeof _ !== 'undefined' && _.VERSION ? _.VERSION : null; }},
        {g: 'Sentry', n: 'Sentry', c: 'js-library', v: function(){ return typeof Sentry !== 'undefined' && Sentry.SDK_VERSION ? Sentry.SDK_VERSION : null; }},
        {g: 'wp', n: 'WordPress', c: 'cms', v: function(){ return null; }},
        {g: 'Drupal', n: 'Drupal', c: 'cms', v: function(){ return typeof Drupal !== 'undefined' && Drupal.settings ? 'detected' : null; }},
        {g: 'Shopify', n: 'Shopify', c: 'cms', v: function(){ return typeof Shopify !== 'undefined' ? 'detected' : null; }},
        {g: 'dataLayer', n: 'Google Tag Manager', c: 'analytics', v: function(){ return null; }},
        {g: 'ga', n: 'Google Analytics', c: 'analytics', v: function(){ return null; }},
        {g: 'gtag', n: 'Google Analytics 4', c: 'analytics', v: function(){ return null; }},
        {g: 'io', n: 'Socket.IO', c: 'js-library', v: function(){ return typeof io !== 'undefined' && io.version ? io.version : null; }},
        {g: '__REDUX_DEVTOOLS_EXTENSION__', n: 'Redux DevTools', c: 'js-library', v: function(){ return null; }}
    ];

    for (var gc of globalChecks) {
        try {
            if (typeof window[gc.g] !== 'undefined' && window[gc.g] !== null) {
                var ver = null;
                try { ver = gc.v(); } catch(e){}
                d.push({name: gc.n, version: ver, category: gc.c,
                         evidence: 'global: window.' + gc.g,
                         source: 'js-global', confidence: 0.9});
            }
        } catch(e){}
    }

    // Angular (modern) — not gated on window.ng
    try {
        var ngVerEl = document.querySelector('[ng-version]');
        if (ngVerEl) {
            d.push({name: 'Angular', version: ngVerEl.getAttribute('ng-version'),
                     category: 'js-framework', evidence: 'DOM: [ng-version]',
                     source: 'dom', confidence: 0.95});
        } else if (typeof getAllAngularRootElements === 'function') {
            var roots = getAllAngularRootElements();
            if (roots && roots.length > 0) {
                var rv = roots[0].getAttribute && roots[0].getAttribute('ng-version');
                d.push({name: 'Angular', version: rv || null,
                         category: 'js-framework', evidence: 'global: getAllAngularRootElements()',
                         source: 'js-global', confidence: 0.95});
            }
        }
    } catch(e){}

    // --- DOM patterns ---
    // React root
    if (document.querySelector('[data-reactroot], #__next, [data-reactid]'))
        d.push({name: 'React', category: 'js-framework', evidence: 'DOM: data-reactroot / __next / data-reactid', source: 'dom', confidence: 0.85});
    // AngularJS (1.x) — ng-app on body must not imply modern Angular
    if (document.querySelector('[ng-app], [data-ng-app], [ng-controller], .ng-scope'))
        d.push({name: 'AngularJS', category: 'js-framework', evidence: 'DOM: ng-app / ng-controller / ng-scope', source: 'dom', confidence: 0.85});
    // Modern Angular — require ng-version attribute on a specific element
    var ngVerAttr = document.querySelector('[ng-version]');
    if (ngVerAttr) {
        var tag = ngVerAttr.tagName.toLowerCase();
        var ver = ngVerAttr.getAttribute('ng-version');
        d.push({name: 'Angular', version: ver, category: 'js-framework',
                 evidence: 'DOM: ' + tag + ' ng-version=' + ver, source: 'dom', confidence: 0.9});
    } else {
        try {
            var ghost = document.querySelector('[class*=""_nghost-""], [class*=""_ngcontent-""]');
            if (ghost && !document.querySelector('[ng-app], [data-ng-app]')) {
                d.push({name: 'Angular', category: 'js-framework',
                         evidence: 'DOM: ' + ghost.tagName.toLowerCase() + ' class*=' + (ghost.className || '').substring(0,40),
                         source: 'dom', confidence: 0.75});
            }
        } catch(e){}
    }
    // Vue
    if (document.querySelector('[data-v-], [v-cloak], #__nuxt'))
        d.push({name: 'Vue.js', category: 'js-framework', evidence: 'DOM: data-v- / v-cloak / __nuxt', source: 'dom', confidence: 0.85});
    // Svelte
    if (document.querySelector('[class*=""svelte-""]'))
        d.push({name: 'Svelte', category: 'js-framework', evidence: 'DOM: svelte- class', source: 'dom', confidence: 0.8});
    // Blazor
    if (document.querySelector('[_bl_], #blazor-error-ui, script[src*=""_framework""]'))
        d.push({name: 'Blazor', category: 'framework', evidence: 'DOM: _bl_ / blazor-error-ui', source: 'dom', confidence: 0.9});
    // WordPress
    if (document.querySelector('link[href*=""wp-content""], link[href*=""wp-includes""]'))
        d.push({name: 'WordPress', category: 'cms', evidence: 'DOM: wp-content / wp-includes link', source: 'dom', confidence: 0.9});
    // Tailwind
    if (document.querySelector('[class*=""tw-""], [class*=""flex ""], [class*=""grid ""]') &&
        document.querySelector('style')?.textContent?.includes('--tw-'))
        d.push({name: 'Tailwind CSS', category: 'js-library', evidence: 'DOM: tw- CSS variables', source: 'dom', confidence: 0.7});

    // --- Stylesheets ---
    var links = document.querySelectorAll('link[rel=""stylesheet""][href]');
    for (var lnk of links) {
        var href = lnk.href;
        if (/bootstrap/i.test(href)) {
            var bv = (href.match(/bootstrap[\/\-.](\d+\.\d+[\d.]*)/i) || [])[1];
            d.push({name: 'Bootstrap', version: bv || null, category: 'js-library',
                     evidence: 'stylesheet: ' + href.substring(0, 80), source: 'stylesheet', confidence: 0.85});
        }
        if (/font-awesome|fontawesome/i.test(href))
            d.push({name: 'Font Awesome', category: 'js-library', evidence: 'stylesheet', source: 'stylesheet', confidence: 0.85});
        if (/material/i.test(href) && /google/i.test(href))
            d.push({name: 'Material Design', category: 'js-library', evidence: 'stylesheet', source: 'stylesheet', confidence: 0.7});
    }

    return JSON.stringify(d);
})()";
    }

    private static List<TechStackDetection> ParseDomDetections(string json)
    {
        if (string.IsNullOrEmpty(json) || json == "null") return [];

        try
        {
            var arr = JsonSerializer.Deserialize<JsonElement>(json);
            if (arr.ValueKind != JsonValueKind.Array) return [];

            var results = new List<TechStackDetection>();
            foreach (var el in arr.EnumerateArray())
            {
                results.Add(new TechStackDetection
                {
                    Name = el.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                    Version = el.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null,
                    Category = el.TryGetProperty("category", out var c) ? c.GetString() ?? "" : "",
                    Evidence = el.TryGetProperty("evidence", out var ev) ? ev.GetString() ?? "" : "",
                    Source = el.TryGetProperty("source", out var s) ? s.GetString() ?? "" : "",
                    Confidence = el.TryGetProperty("confidence", out var conf) && conf.ValueKind == JsonValueKind.Number ? conf.GetDouble() : 0.5
                });
            }
            return results;
        }
        catch
        {
            return [];
        }
    }

    #endregion

    #region Fingerprint Rules

    private record HeaderRule(string Header, string? Pattern, string Name, string Category, double Confidence, string? VersionPattern = null);
    private record CookieRule(string Pattern, string Name, string Category, double Confidence);

    private static readonly HeaderRule[] HeaderRules =
    [
        // Servers
        new("server", @"^nginx", "Nginx", "server", 0.95, @"nginx/(\d+\.\d+[\d.]*)"),
        new("server", @"^apache", "Apache", "server", 0.95, @"Apache/(\d+\.\d+[\d.]*)"),
        new("server", @"^Microsoft-IIS", "IIS", "server", 0.95, @"Microsoft-IIS/(\d+\.\d+)"),
        new("server", @"^LiteSpeed", "LiteSpeed", "server", 0.9, @"LiteSpeed"),
        new("server", @"^Kestrel", "Kestrel", "server", 0.9),
        new("server", @"^Caddy", "Caddy", "server", 0.9),
        new("server", @"^gunicorn", "Gunicorn", "server", 0.9, @"gunicorn/(\d+\.\d+[\d.]*)"),
        new("server", @"^openresty", "OpenResty", "server", 0.9, @"openresty/(\d+\.\d+[\d.]*)"),
        new("server", @"^envoy", "Envoy", "server", 0.9),
        new("server", @"^Cowboy", "Cowboy (Erlang)", "server", 0.9),
        new("server", @"^Jetty", "Jetty", "server", 0.9, @"Jetty\((\d+\.\d+[\d.]*)\)"),
        new("server", @"^Werkzeug", "Werkzeug (Python)", "server", 0.9, @"Werkzeug/(\d+\.\d+[\d.]*)"),
        new("server", @"^uvicorn", "Uvicorn", "server", 0.9),
        new("server", @"^Puma", "Puma (Ruby)", "server", 0.9, @"Puma/(\d+\.\d+[\d.]*)"),
        new("server", @"^thin", "Thin (Ruby)", "server", 0.9),

        // Frameworks & languages
        new("x-powered-by", @"^ASP\.NET", "ASP.NET", "framework", 0.95),
        new("x-powered-by", @"^PHP", "PHP", "language", 0.95, @"PHP/(\d+\.\d+[\d.]*)"),
        new("x-powered-by", @"^Express", "Express.js", "framework", 0.95),
        new("x-powered-by", @"^Next\.js", "Next.js", "js-framework", 0.95),
        new("x-powered-by", @"^Servlet", "Java Servlet", "framework", 0.9),
        new("x-powered-by", @"^JSF", "JavaServer Faces", "framework", 0.9),
        new("x-powered-by", @"^Phusion", "Phusion Passenger", "server", 0.9),
        new("x-powered-by", @"^PleskLin", "Plesk", "server", 0.8),
        new("x-aspnet-version", null, "ASP.NET", "framework", 0.95, @"(\d+\.\d+[\d.]*)"),
        new("x-aspnetmvc-version", null, "ASP.NET MVC", "framework", 0.95, @"(\d+\.\d+[\d.]*)"),

        // CDN / WAF
        new("server", @"^cloudflare", "Cloudflare", "cdn", 0.95),
        new("cf-ray", null, "Cloudflare", "cdn", 0.95),
        new("cf-cache-status", null, "Cloudflare", "cdn", 0.9),
        new("x-amz-cf-id", null, "Amazon CloudFront", "cdn", 0.95),
        new("x-amz-cf-pop", null, "Amazon CloudFront", "cdn", 0.9),
        new("x-vercel-id", null, "Vercel", "cdn", 0.95),
        new("x-vercel-cache", null, "Vercel", "cdn", 0.9),
        new("x-netlify-request-id", null, "Netlify", "cdn", 0.95),
        new("x-nf-request-id", null, "Netlify", "cdn", 0.9),
        new("x-fastly-request-id", null, "Fastly", "cdn", 0.95),
        new("x-served-by", @"cache-", "Fastly", "cdn", 0.8),
        new("x-cache", @"cloudfront", "Amazon CloudFront", "cdn", 0.8),
        new("x-azure-ref", null, "Azure CDN", "cdn", 0.9),
        new("server", @"^AkamaiGHost", "Akamai", "cdn", 0.95),
        new("x-akamai-transformed", null, "Akamai", "cdn", 0.9),

        // WAF-specific
        new("x-sucuri-id", null, "Sucuri WAF", "waf", 0.95),
        new("x-sucuri-cache", null, "Sucuri WAF", "waf", 0.9),
        new("server", @"Sucuri", "Sucuri WAF", "waf", 0.95),
        new("server", @"AkamaiGHost", "Akamai WAF", "waf", 0.8),
        new("x-cdn", @"Incapsula", "Imperva/Incapsula WAF", "waf", 0.95),
        new("x-iinfo", null, "Imperva/Incapsula WAF", "waf", 0.85),
        new("server", @"^Barracuda", "Barracuda WAF", "waf", 0.9),

        // Misc headers
        new("x-drupal-cache", null, "Drupal", "cms", 0.95),
        new("x-generator", @"Drupal", "Drupal", "cms", 0.95),
        new("x-generator", @"WordPress", "WordPress", "cms", 0.95),
        new("x-shopify-stage", null, "Shopify", "cms", 0.95),
        new("x-powered-cms", null, "CMS", "cms", 0.7),
        new("x-turbo-charged-by", @"LiteSpeed", "LiteSpeed Cache", "cache", 0.8),
        new("x-litespeed-cache", null, "LiteSpeed Cache", "cache", 0.8),
        new("x-varnish", null, "Varnish", "cache", 0.9),
        new("via", @"varnish", "Varnish", "cache", 0.8),
        new("x-rack-cache", null, "Ruby on Rails", "framework", 0.7),
        new("x-runtime", null, "Ruby on Rails", "framework", 0.6),
        new("x-request-id", null, "Ruby on Rails", "framework", 0.3),
        new("x-django-request-id", null, "Django", "framework", 0.9),
    ];

    private static readonly CookieRule[] CookieRules =
    [
        new(@"\bJSESSIONID\b", "Java", "language", 0.9),
        // Cookie-only PHPSESSID is suggestive, not definitive (apps can set arbitrary cookie names).
        new(@"\bPHPSESSID\b", "PHP", "language", 0.55),
        new(@"\bASP\.NET_SessionId\b", "ASP.NET", "framework", 0.95),
        new(@"\b\.AspNetCore\.", "ASP.NET Core", "framework", 0.95),
        new(@"\b__RequestVerificationToken\b", "ASP.NET MVC", "framework", 0.85),
        new(@"\bcsrftoken\b", "Django", "framework", 0.8),
        new(@"\bdjango_language\b", "Django", "framework", 0.9),
        new(@"\b_rails_session\b", "Ruby on Rails", "framework", 0.9),
        new(@"\b_session_id\b.*rack", "Ruby/Rack", "framework", 0.7),
        new(@"\bLARAVEL_SESSION\b", "Laravel", "framework", 0.95),
        new(@"\bXSRF-TOKEN\b", "Angular/Laravel", "framework", 0.5),
        new(@"\b_ga\b", "Google Analytics", "analytics", 0.9),
        new(@"\b_gid\b", "Google Analytics", "analytics", 0.85),
        new(@"\b__cf_bm\b", "Cloudflare Bot Management", "waf", 0.9),
        new(@"\bcf_clearance\b", "Cloudflare WAF", "waf", 0.85),
        new(@"\bvisid_incap_\b", "Imperva/Incapsula WAF", "waf", 0.9),
        new(@"\bincap_ses_\b", "Imperva/Incapsula WAF", "waf", 0.9),
        new(@"\b__cfduid\b", "Cloudflare", "cdn", 0.85),
        new(@"\bwp-settings\b", "WordPress", "cms", 0.9),
        new(@"\bwp_logged_in\b", "WordPress", "cms", 0.9),
        new(@"\bShopify\b", "Shopify", "cms", 0.9),
        new(@"\b_shopify\b", "Shopify", "cms", 0.9),
        new(@"\bconnect\.sid\b", "Express.js", "framework", 0.7),
        new(@"\bci_session\b", "CodeIgniter", "framework", 0.9),
        new(@"\bcakephp\b", "CakePHP", "framework", 0.9),
        new(@"\bplay_session\b", "Play Framework", "framework", 0.9),
    ];

    #endregion

    #region Helpers
    /// <summary>
    /// Cookie-only language inferences (e.g. PHPSESSID → PHP) are weak when a stronger
    /// non-matching server/framework signal is present (Werkzeug, Kestrel, Express, …).
    /// </summary>
    private static void SuppressConflictingLanguageInferences(List<TechStackDetection> detections)
    {
        static bool IsPythonStack(TechStackDetection d) =>
            d.Name.Contains("Werkzeug", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Gunicorn", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Uvicorn", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Django", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Flask", StringComparison.OrdinalIgnoreCase)
            || (d.Category.Equals("language", StringComparison.OrdinalIgnoreCase)
                && d.Name.Equals("Python", StringComparison.OrdinalIgnoreCase));

        static bool IsNonPhpServer(TechStackDetection d) =>
            IsPythonStack(d)
            || d.Name.Contains("Kestrel", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Express", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("Next.js", StringComparison.OrdinalIgnoreCase)
            || d.Name.Contains("ASP.NET", StringComparison.OrdinalIgnoreCase);

        if (!detections.Any(IsNonPhpServer)) return;

        detections.RemoveAll(d =>
            d.Name.Equals("PHP", StringComparison.OrdinalIgnoreCase)
            && d.Source.Equals("cookie", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSameHost(string? url, string? pageHost)
    {
        if (string.IsNullOrEmpty(pageHost)) return true;
        if (string.IsNullOrEmpty(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        return string.Equals(uri.Host, pageHost, StringComparison.OrdinalIgnoreCase);
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    #endregion
}
