using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.XssAudit;

/// <summary>
/// Audits the current page's DOM for XSS-prone patterns:
/// inline event handlers, javascript: URLs, dangerous sinks,
/// cross-domain scripts, data: URIs, and external form actions.
///
/// Inspired by OWASP ZAP passive scan rules and DOM XSS testing guidance.
/// Pure client-side JavaScript injection — no external dependencies needed.
/// </summary>
public class XssChecker
{
    private readonly WebView2 _webView;

    public XssChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run the DOM XSS audit on the current page.
    /// </summary>
    public async Task<XssResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var json = await WebViewUiScript.RunAsync(_webView, BuildScannerScript(), cancellationToken,
            operationLabel: "DOM XSS audit");
        if (string.IsNullOrEmpty(json))
            throw new InvalidOperationException("XSS audit returned no data — page may be unavailable.");

        return ParseResults(json);
    }

    #region Scanner JavaScript

    private static string BuildScannerScript()
    {
        return """
            (function() {
                try {
                    var findings = [];
                    var pageOrigin = location.origin;

                    function selectorOf(el) {
                        if (el.id) return el.tagName.toLowerCase() + '#' + el.id;
                        var path = el.tagName.toLowerCase();
                        if (el.className && typeof el.className === 'string') {
                            var cls = el.className.trim().split(/\s+/).slice(0, 2).join('.');
                            if (cls) path += '.' + cls;
                        }
                        if (el.parentElement && el.parentElement !== document.body) {
                            var parent = el.parentElement.tagName.toLowerCase();
                            if (el.parentElement.id) parent += '#' + el.parentElement.id;
                            path = parent + ' > ' + path;
                        }
                        return path;
                    }

                    var handlerAttrs = [
                        'onclick','ondblclick','onmousedown','onmouseup','onmouseover','onmouseout','onmousemove',
                        'onkeydown','onkeyup','onkeypress','onfocus','onblur','onchange','onsubmit','onreset',
                        'onerror','onload','onunload','onresize','onscroll','oninput','oncontextmenu',
                        'ontouchstart','ontouchend','ontouchmove','onanimationend','ondrag','ondrop',
                        'onpointerdown','onpointerup'
                    ];
                    var allElements = document.querySelectorAll('*');
                    var handlerCount = 0;
                    for (var i = 0; i < allElements.length && handlerCount < 50; i++) {
                        var el = allElements[i];
                        for (var j = 0; j < handlerAttrs.length; j++) {
                            if (el.hasAttribute(handlerAttrs[j])) {
                                var handlerName = handlerAttrs[j];
                                var handlerVal = (el.getAttribute(handlerName) || '').trim();
                                // Benign stylesheet media-switch pattern used by many sites/CDNs:
                                // <link ... onload="this.media='all'"> — not an XSS sink.
                                if (handlerName === 'onload' && el.tagName === 'LINK'
                                    && /^this\.media\s*=\s*['"]all['"]\s*;?$/i.test(handlerVal)) {
                                    continue;
                                }
                                if (/window\.__x\d+/i.test(handlerVal)) continue;
                                var staticDevHandler = /^[\w$]+(?:\.[\w$]+)*\(\s*[\w$.,\s'"]*\s*\)\s*;?$/;
                                var urlSourceRe = /(?:location\.search|location\.hash|document\.referrer|window\.name|URLSearchParams\s*\(\s*location\.search\s*\))/;
                                var locAssignRe = /(?:location\s*=|location\.href\s*=|location\.assign\s*\(|location\.replace\s*\()/;
                                if (urlSourceRe.test(handlerVal) && locAssignRe.test(handlerVal)) {
                                    handlerCount++;
                                    if (handlerCount <= 20) {
                                        var evFull = handlerName + '="' + handlerVal + '"';
                                        var evSnip = evFull.length > 200 ? evFull.substring(0, 200) : evFull;
                                        var cut = evSnip.lastIndexOf(' ');
                                        if (cut > 120) evSnip = evSnip.substring(0, cut);
                                        findings.push({
                                            category: 'dom-open-redirect',
                                            severity: 'high',
                                            description: 'Inline handler assigns location from URL-derived input (open redirect candidate)',
                                            location: selectorOf(el),
                                            evidence: evSnip,
                                            recommendation: 'Validate redirect targets against an allowlist. Confirm with trace-input / click the control with monitorSinks enabled.'
                                        });
                                    }
                                    break;
                                }
                                handlerCount++;
                                if (handlerCount <= 20) {
                                    var isStaticDev = staticDevHandler.test(handlerVal);
                                    findings.push({
                                        category: 'inline-handler',
                                        severity: isStaticDev ? 'info' : 'medium',
                                        description: isStaticDev
                                            ? 'Static inline handler (developer code, not reflected user data): ' + handlerName
                                            : 'Inline event handler attribute: ' + handlerName,
                                        location: selectorOf(el),
                                        evidence: handlerName + '="' + handlerVal.substring(0, 80) + '"',
                                        recommendation: isStaticDev
                                            ? 'Hygiene: prefer addEventListener. A future script-src without unsafe-inline will block these handlers.'
                                            : 'Use addEventListener() instead of inline event handlers to improve CSP compatibility and reduce XSS surface.'
                                    });
                                }
                                break;
                            }
                        }
                    }
                    if (handlerCount > 20) {
                        findings.push({
                            category: 'inline-handler',
                            severity: 'medium',
                            description: 'Additional ' + (handlerCount - 20) + ' inline event handler(s) found (truncated)',
                            location: 'multiple elements',
                            evidence: handlerCount + ' total inline handlers',
                            recommendation: 'Use addEventListener() instead of inline event handlers.'
                        });
                    }

                    var dangerousUrlAttrs = ['href', 'src', 'action', 'formaction'];
                    var staticJsUrl = /^javascript:\s*void\s*\(\s*(?:0|null|undefined)\s*\)\s*;?\s*$/i;
                    var jsUrlElements = document.querySelectorAll('[href], [src], [action], [formaction]');
                    var jsUrlCount = 0;
                    for (var i = 0; i < jsUrlElements.length && jsUrlCount < 20; i++) {
                        var el = jsUrlElements[i];
                        for (var j = 0; j < dangerousUrlAttrs.length; j++) {
                            var rawVal = (el.getAttribute(dangerousUrlAttrs[j]) || '').trim();
                            var val = rawVal.toLowerCase();
                            if (!val.startsWith('javascript:') || val === 'javascript:;') continue;
                            if (staticJsUrl.test(val)) {
                                jsUrlCount++;
                                findings.push({
                                    category: 'javascript-url',
                                    severity: 'info',
                                    description: 'Static javascript:void placeholder in ' + dangerousUrlAttrs[j] + ' (developer markup — not attacker-controlled)',
                                    location: selectorOf(el),
                                    evidence: dangerousUrlAttrs[j] + '="' + rawVal.substring(0, 80) + '"',
                                    recommendation: 'Hygiene: prefer href="#" with preventDefault or button type="button". Not exploitable unless this URL is built from request/DOM data at runtime.'
                                });
                                continue;
                            }
                            if (val !== 'javascript:void(0)' && val !== 'javascript:void(0);') {
                                jsUrlCount++;
                                findings.push({
                                    category: 'javascript-url',
                                    severity: 'high',
                                    description: 'javascript: URL in ' + dangerousUrlAttrs[j] + ' attribute',
                                    location: selectorOf(el),
                                    evidence: dangerousUrlAttrs[j] + '="' + rawVal.substring(0, 80) + '"',
                                    recommendation: 'Replace javascript: URLs with proper event handlers or navigation. These bypass CSP and are an XSS vector when attacker-controlled.'
                                });
                            }
                        }
                    }

                    var dataElements = document.querySelectorAll('iframe[src], object[data], embed[src]');
                    for (var i = 0; i < dataElements.length; i++) {
                        var el = dataElements[i];
                        var attrName = el.tagName === 'OBJECT' ? 'data' : 'src';
                        var val = (el.getAttribute(attrName) || '').trim().toLowerCase();
                        if (val.startsWith('data:') && (val.includes('text/html') || val.includes('application/xhtml') || val.includes('image/svg+xml'))) {
                            findings.push({
                                category: 'data-uri-execution',
                                severity: 'high',
                                description: 'data: URI with executable content type in ' + el.tagName.toLowerCase(),
                                location: selectorOf(el),
                                evidence: attrName + '="' + val.substring(0, 80) + '"',
                                recommendation: 'Avoid data: URIs with text/html or SVG content types as they can execute arbitrary scripts.'
                            });
                        }
                    }

                    var scripts = document.querySelectorAll('script[src]');
                    var externalScripts = [];
                    for (var i = 0; i < scripts.length; i++) {
                        var src = scripts[i].src;
                        try {
                            var scriptUrl = new URL(src);
                            if (scriptUrl.origin !== pageOrigin) {
                                var hasIntegrity = scripts[i].hasAttribute('integrity');
                                externalScripts.push({
                                    src: src,
                                    origin: scriptUrl.origin,
                                    hasIntegrity: hasIntegrity,
                                    el: scripts[i]
                                });
                                if (!hasIntegrity) {
                                    findings.push({
                                        category: 'cross-domain-script',
                                        severity: 'low',
                                        description: 'External script from ' + scriptUrl.origin + ' without Subresource Integrity (SRI)',
                                        location: selectorOf(scripts[i]),
                                        evidence: 'src="' + src.substring(0, 100) + '"',
                                        recommendation: 'Add integrity and crossorigin attributes to external scripts to prevent supply-chain attacks.'
                                    });
                                }
                            }
                        } catch(e) {}
                    }
                    if (externalScripts.length > 0) {
                        var origins = [];
                        for (var i = 0; i < externalScripts.length; i++) {
                            if (origins.indexOf(externalScripts[i].origin) === -1) origins.push(externalScripts[i].origin);
                        }
                        var withoutSri = externalScripts.filter(function(s) { return !s.hasIntegrity; }).length;
                        findings.push({
                            category: 'cross-domain-script-summary',
                            severity: 'info',
                            description: externalScripts.length + ' external script(s) from ' + origins.length + ' domain(s). ' + withoutSri + ' without SRI.',
                            location: 'page',
                            evidence: origins.join(', '),
                            recommendation: 'Review external script sources. Use SRI hashes for all external scripts.'
                        });
                    }

                    var inlineScripts = document.querySelectorAll('script:not([src])');
                    var inlineCount = 0;
                    for (var i = 0; i < inlineScripts.length; i++) {
                        var content = (inlineScripts[i].textContent || '').trim();
                        if (content.length > 0 && inlineScripts[i].type !== 'application/json' && inlineScripts[i].type !== 'application/ld+json' && inlineScripts[i].type !== 'text/template') {
                            inlineCount++;
                        }
                    }
                    if (inlineCount > 0) {
                        findings.push({
                            category: 'inline-script',
                            severity: 'info',
                            description: inlineCount + ' inline <script> block(s) found. Inline scripts require unsafe-inline in CSP.',
                            location: 'page',
                            evidence: inlineCount + ' inline scripts',
                            recommendation: 'Move inline scripts to external files or use CSP nonces/hashes for strict CSP policies.'
                        });
                    }

                    var dangerousSinks = ['eval(', 'eval (', 'document.write(', 'document.write (', 'document.writeln(', 'document.writeln (',
                                         '.innerHTML =', '.innerHTML=', '.outerHTML =', '.outerHTML=',
                                         'setTimeout(', 'setInterval('];
                    var sinkFindings = {};
                    for (var i = 0; i < inlineScripts.length; i++) {
                        var content = inlineScripts[i].textContent || '';
                        for (var j = 0; j < dangerousSinks.length; j++) {
                            if (content.indexOf(dangerousSinks[j]) !== -1) {
                                var sink = dangerousSinks[j].replace(/[( =]/g, '').trim();
                                if (!sinkFindings[sink]) sinkFindings[sink] = 0;
                                sinkFindings[sink]++;
                            }
                        }
                    }
                    for (var sink in sinkFindings) {
                        var sev = (sink === 'eval' || sink === 'document.write' || sink === 'document.writeln') ? 'medium' : 'low';
                        findings.push({
                            category: 'dangerous-sink',
                            severity: sev,
                            description: sink + '() used ' + sinkFindings[sink] + ' time(s) in inline scripts',
                            location: 'inline scripts',
                            evidence: sink,
                            recommendation: sink === 'eval' ? 'Avoid eval(). Use JSON.parse() or Function constructors if dynamic code execution is necessary.' :
                                sink === 'document.write' || sink === 'document.writeln' ? 'Avoid document.write(). Use DOM manipulation methods instead.' :
                                sink === 'innerHTML' || sink === 'outerHTML' ? 'Use textContent instead of innerHTML when inserting untrusted data, or sanitize input first.' :
                                'Ensure string arguments to ' + sink + '() do not contain user-controlled data.'
                        });
                    }

                    var sourcePatterns = [
                        { name: 'location.href', re: /(?:document\.)?location\.href/gi },
                        { name: 'location.search', re: /(?:document\.)?location\.search/gi },
                        { name: 'location.hash', re: /(?:document\.)?location\.hash/gi },
                        { name: 'location.pathname', re: /(?:document\.)?location\.pathname/gi },
                        { name: 'document.URL', re: /document\.(?:URL|documentURI)/gi },
                        { name: 'document.referrer', re: /document\.referrer/gi },
                        { name: 'URLSearchParams', re: /URLSearchParams/gi },
                        { name: 'window.name', re: /window\.name/gi }
                    ];
                    var sinkPatterns = [
                        { name: 'document.write', re: /document\.write(?:ln)?\s*\(/gi },
                        { name: 'innerHTML', re: /\.innerHTML\s*=/gi },
                        { name: 'outerHTML', re: /\.outerHTML\s*=/gi },
                        { name: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/gi },
                        { name: 'eval', re: /\beval\s*\(/gi },
                        { name: 'Function', re: /\bnew\s+Function\s*\(/gi },
                        { name: 'setTimeout(string)', re: /setTimeout\s*\(\s*['"]/gi },
                        { name: 'setInterval(string)', re: /setInterval\s*\(\s*['"]/gi }
                    ];
                    var flowSeen = {};
                    var maxFlowFindings = 15;
                    for (var si = 0; si < inlineScripts.length && Object.keys(flowSeen).length < maxFlowFindings; si++) {
                        var scriptContent = inlineScripts[si].textContent || '';
                        if (scriptContent.length < 8) continue;
                        for (var sp = 0; sp < sourcePatterns.length; sp++) {
                            var srcPat = sourcePatterns[sp];
                            srcPat.re.lastIndex = 0;
                            var srcMatch;
                            while ((srcMatch = srcPat.re.exec(scriptContent)) !== null) {
                                for (var sk = 0; sk < sinkPatterns.length; sk++) {
                                    var sinkPat = sinkPatterns[sk];
                                    sinkPat.re.lastIndex = 0;
                                    var sinkMatch;
                                    while ((sinkMatch = sinkPat.re.exec(scriptContent)) !== null) {
                                        var dist = Math.abs(sinkMatch.index - srcMatch.index);
                                        if (dist > 400) continue;
                                        var key = srcPat.name + '->' + sinkPat.name;
                                        if (flowSeen[key]) continue;
                                        flowSeen[key] = true;
                                        var start = Math.max(0, Math.min(srcMatch.index, sinkMatch.index) - 20);
                                        var end = Math.min(scriptContent.length, Math.max(srcMatch.index, sinkMatch.index) + 80);
                                        var snippet = scriptContent.substring(start, end).replace(/\s+/g, ' ').trim();
                                        var hasDecode = /decodeURI(?:Component)?|unescape/i.test(scriptContent);
                                        // Proximity-only heuristic — keep medium/low; active tools confirm HIGH.
                                        var mediumConfidence = dist < 160 && (
                                            sinkPat.name === 'document.write' || sinkPat.name === 'innerHTML' ||
                                            sinkPat.name === 'eval' || hasDecode);
                                        var usesUrlSearchParams = /URLSearchParams/i.test(scriptContent);
                                        var decodeNote = hasDecode
                                            ? ' Script uses decodeURI/decodeURIComponent — confirm decoding occurs before the sink (trace-input with queryEncode/fragmentEncode: none).'
                                            : usesUrlSearchParams
                                                ? ' URLSearchParams.get percent-decodes query values — encoding alone may not neutralize; verify allowlisting at the sink.'
                                                : ' No decodeURI/decodeURIComponent in this script — browser URL-encoding may neutralize the payload at the sink unless decoding occurs elsewhere; verify the full source→sink path.';
                                        findings.push({
                                            category: 'dom-xss-flow',
                                            severity: mediumConfidence ? 'medium' : 'low',
                                            confidence: mediumConfidence ? 'medium' : 'low',
                                            source: srcPat.name,
                                            sink: sinkPat.name,
                                            description: 'URL/DOM source may flow into dangerous sink without sanitization (heuristic proximity — not confirmed taint)' +
                                                (hasDecode ? ' (URL decoding present in script)' : ' (no URL decoding detected in script)'),
                                            location: 'inline script #' + (si + 1),
                                            evidence: snippet.substring(0, 160),
                                            recommendation: 'Sanitize or encode ' + srcPat.name + ' before passing to ' + sinkPat.name +
                                                '. Prefer textContent over innerHTML. Confirm with browser_trace_input / xss-scan before treating as high severity.' +
                                                decodeNote
                                        });
                                    }
                                }
                            }
                        }
                    }

                    var forms = document.querySelectorAll('form[action]');
                    for (var i = 0; i < forms.length; i++) {
                        var action = forms[i].action;
                        try {
                            var actionUrl = new URL(action);
                            if (actionUrl.origin !== pageOrigin) {
                                findings.push({
                                    category: 'external-form-action',
                                    severity: 'medium',
                                    description: 'Form submits to external domain: ' + actionUrl.origin,
                                    location: selectorOf(forms[i]),
                                    evidence: 'action="' + action.substring(0, 100) + '"',
                                    recommendation: 'Verify this external form action is intentional. External form submissions can leak user data.'
                                });
                            }
                        } catch(e) {}
                    }

                    var baseTags = document.querySelectorAll('base[href]');
                    if (baseTags.length > 0) {
                        for (var i = 0; i < baseTags.length; i++) {
                            var baseHref = baseTags[i].getAttribute('href');
                            try {
                                var baseUrl = new URL(baseHref, location.href);
                                if (baseUrl.origin !== pageOrigin) {
                                    findings.push({
                                        category: 'base-tag-hijack',
                                        severity: 'high',
                                        description: 'External <base> tag could redirect all relative URLs',
                                        location: 'head > base',
                                        evidence: 'href="' + baseHref + '"',
                                        recommendation: 'Remove external base tags or ensure the href points to the same origin.'
                                    });
                                }
                            } catch(e) {}
                        }
                    }

                    return JSON.stringify({
                        url: location.href,
                        timestamp: new Date().toISOString(),
                        findings: findings
                    });
                } catch(e) {
                    return JSON.stringify({ error: e.message || String(e) });
                }
            })()
            """;
    }

    #endregion

    #region Result Parsing

    private static XssResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"XSS audit error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";

        var findings = new List<XssFinding>();
        if (root.TryGetProperty("findings", out var findingsArray))
        {
            foreach (var f in findingsArray.EnumerateArray())
            {
                findings.Add(new XssFinding
                {
                    Category = f.TryGetProperty("category", out var cat) ? cat.GetString() ?? "" : "",
                    Severity = ParseSeverity(
                        f.TryGetProperty("severity", out var sev) ? sev.GetString() : null),
                    Description = f.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                    Location = f.TryGetProperty("location", out var loc) ? loc.GetString() ?? "" : "",
                    Evidence = f.TryGetProperty("evidence", out var ev) ? ev.GetString() : null,
                    Recommendation = f.TryGetProperty("recommendation", out var rec) ? rec.GetString() ?? "" : "",
                    Confidence = f.TryGetProperty("confidence", out var conf) ? conf.GetString() : null,
                    Source = f.TryGetProperty("source", out var src) ? src.GetString() : null,
                    Sink = f.TryGetProperty("sink", out var snk) ? snk.GetString() : null
                });
            }
        }

        return new XssResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Findings = findings
        };
    }

    private static XssSeverity ParseSeverity(string? severity)
    {
        return severity?.ToLowerInvariant() switch
        {
            "high" => XssSeverity.High,
            "medium" => XssSeverity.Medium,
            "low" => XssSeverity.Low,
            "info" => XssSeverity.Info,
            _ => XssSeverity.Info
        };
    }

    #endregion

}
