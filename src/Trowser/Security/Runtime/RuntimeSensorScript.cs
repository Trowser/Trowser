namespace Trowser.Security.Runtime;

/// <summary>
/// Shared in-page runtime sensor: dangerous sinks, source reads, and message listeners.
/// Install via document-created script or ExecuteJs. Events push via
/// <c>chrome.webview.postMessage({type:'__trowser_rt',...})</c> and also append to
/// <c>window.__trowser_sink_log</c> for the legacy poll path used by trace-input.
/// </summary>
internal static class RuntimeSensorScript
{
    /// <summary>Idempotent install script. Returns 'INSTALLED', 'UPGRADED', or 'ALREADY_INSTALLED'.</summary>
    internal static string Build(RuntimeSensorProfile profile = RuntimeSensorProfile.Active, bool enableGadgetRadar = false)
    {
        var wantCodeExec = profile == RuntimeSensorProfile.Active ? "true" : "false";
        var wantGadgetRadar = enableGadgetRadar || profile == RuntimeSensorProfile.Ambient;
        var gadgetRadarBlock = wantGadgetRadar ? GadgetRadarScript.InstallMissingGlobalBody : "";
        return $$"""
        (function(wantCodeExecHooks) {
            if (window.__trowser_rt_installed) {
                if (wantCodeExecHooks && window.__trowser_rt_install_code_exec)
                    window.__trowser_rt_install_code_exec();
                return (window.__trowser_rt_code_exec || !wantCodeExecHooks) ? 'ALREADY_INSTALLED' : 'UPGRADED';
            }
            window.__trowser_rt_installed = true;
            window.__trowser_sink_log = window.__trowser_sink_log || [];
            var sinkLog = window.__trowser_sink_log;
            var maxSinkLog = 200;
            var maxBatch = 40;
            var batch = [];
            var flushTimer = null;
            var frameName = '';
            try { frameName = window.name || ''; } catch(e) {}
            var frameOrigin = '';
            try { frameOrigin = location.origin || ''; } catch(e) {}

            function trimStack(stack) {
                if (!stack) return '';
                return String(stack).split('\n').slice(2, 12).join('\n');
            }

            function pageStackFrom(full) {
                if (!full) return '';
                var sensor = /trowser-runtime-sensor|captureSink|captureSource|captureListener|pushHost|__trowser_rt/i;
                return String(full).split('\n').filter(function(line) {
                    return line && !sensor.test(line);
                }).slice(0, 10).join('\n');
            }

            function pushHost(kind, name, data, stack, extra) {
                var evt = {
                    type: '__trowser_rt',
                    kind: kind,
                    name: name,
                    data: typeof data === 'string' ? data.substring(0, 500) : String(data).substring(0, 500),
                    stack: stack || '',
                    frameName: frameName,
                    frameOrigin: frameOrigin,
                    documentUrl: (function(){ try { return String(location.href).substring(0, 300); } catch(e){ return ''; } })(),
                    extra: extra || {},
                    time: Date.now()
                };
                batch.push(evt);
                if (batch.length >= maxBatch) flush();
                else if (!flushTimer) flushTimer = setTimeout(flush, 50);
            }

            function flush() {
                flushTimer = null;
                if (!batch.length) return;
                var events = batch;
                batch = [];
                try {
                    if (window.chrome && chrome.webview && chrome.webview.postMessage) {
                        chrome.webview.postMessage({ type: '__trowser_rt', events: events });
                    }
                } catch(e) {}
            }

            var lastSource = { name: '', data: '', at: 0 };
            var sourceRing = [];
            var maxSourceRing = 40;
            var canaryRe = /trowser[_-]?canary|__trowser_exec|trowserxss/i;

            function noteSource(name, data) {
                var s = String(data || '').substring(0, 200);
                lastSource = { name: name, data: s, at: Date.now() };
                if (s.length >= 6) {
                    sourceRing.push({ name: name, data: s, at: Date.now() });
                    if (sourceRing.length > maxSourceRing) sourceRing.shift();
                }
            }

            function findMatchedSources(snippet) {
                var matched = [];
                if (!snippet) return matched;
                var low = String(snippet);
                for (var i = sourceRing.length - 1; i >= 0 && matched.length < 5; i--) {
                    var src = sourceRing[i];
                    if (src.data.length >= 6 && low.indexOf(src.data) >= 0) {
                        matched.push(src.name + ':' + src.data.substring(0, 80));
                    }
                }
                if (canaryRe.test(low)) matched.push('canary');
                return matched;
            }

            function classifyConsequence(sink, snippet) {
                if (/__trowser_exec|trowser_exec_proof/i.test(snippet || '')) return 'exec';
                if (/^(location\.|window\.open)/.test(sink)) return 'nav-hijack';
                if (/^(fetch|xhr\.open)/.test(sink)) return 'request-forgery';
                if (/javascript:/i.test(snippet || '') || /<script/i.test(snippet || '')) return 'executable-markup';
                return 'inert';
            }

            function captureSink(sink, data, extra) {
                var stack = '';
                try { stack = trimStack(new Error().stack); } catch(e) {}
                var snippet = typeof data === 'string' ? data.substring(0, 300) : String(data).substring(0, 300);
                extra = extra || {};
                if (lastSource.name && (Date.now() - lastSource.at) < 8000) {
                    extra.lastSource = lastSource.name;
                    extra.lastSourceData = lastSource.data;
                }
                var matched = findMatchedSources(snippet);
                if (matched.length) {
                    extra.matchedSources = matched.join('|');
                    extra.confidence = matched.indexOf('canary') >= 0 ? 'canary' :
                        (matched.length ? 'value-match' : 'temporal');
                } else if (extra.lastSource) {
                    extra.confidence = 'temporal';
                }
                extra.consequence = classifyConsequence(sink, snippet);
                if (sinkLog.length < maxSinkLog) {
                    var shortStack = '';
                    try { shortStack = pageStackFrom(new Error().stack).split('\n').slice(0, 4).join(' <- '); } catch(e){}
                    sinkLog.push({ sink: sink, data: snippet, stack: shortStack, pageStack: pageStackFrom(stack), time: Date.now(),
                        lastSource: extra.lastSource || null, matchedSources: matched,
                        consequence: extra.consequence, confidence: extra.confidence || null });
                }
                pushHost('sink', sink, snippet, pageStackFrom(stack) || stack, extra);
            }

            function captureSource(name, data, extra) {
                noteSource(name, data);
                var stack = '';
                try { stack = trimStack(new Error().stack); } catch(e) {}
                pushHost('source', name, data, stack, extra);
            }

            function captureListener(name, handlerSrc, extra) {
                var stack = '';
                try { stack = trimStack(new Error().stack); } catch(e) {}
                pushHost('listener', name, handlerSrc, stack, extra);
            }

            function installCodeExecHooks() {
                if (window.__trowser_rt_code_exec) return;
                window.__trowser_rt_code_exec = true;
                var origEval = window.eval;
                window.eval = function(code) { captureSink('eval', code); return origEval.apply(this, arguments); };
                var origFunction = window.Function;
                window.Function = function() {
                    var args = Array.from(arguments);
                    captureSink('Function', args.join(', '));
                    return origFunction.apply(this, arguments);
                };
                window.Function.prototype = origFunction.prototype;
            }
            window.__trowser_rt_install_code_exec = installCodeExecHooks;

            // --- sinks (DOM / network; safe for ambient browsing) ---
            function hookDocumentWrite(doc, label) {
                if (!doc || doc.__trowser_rt_docwrite) return;
                doc.__trowser_rt_docwrite = true;
                var origWrite = doc.write.bind(doc);
                var origWriteln = doc.writeln.bind(doc);
                doc.write = function(html) {
                    captureSink(label + '.write', html);
                    flush();
                    return origWrite.apply(doc, arguments);
                };
                doc.writeln = function(html) {
                    captureSink(label + '.writeln', html);
                    flush();
                    return origWriteln.apply(doc, arguments);
                };
            }
            hookDocumentWrite(document, 'document');
            try {
                if (typeof Document !== 'undefined' && Document.prototype) {
                    var dpWrite = Document.prototype.write;
                    var dpWriteln = Document.prototype.writeln;
                    if (dpWrite && !Document.prototype.__trowser_rt_proto_write) {
                        Document.prototype.__trowser_rt_proto_write = true;
                        Document.prototype.write = function(html) {
                            captureSink('Document.prototype.write', html);
                            flush();
                            return dpWrite.apply(this, arguments);
                        };
                        Document.prototype.writeln = function(html) {
                            captureSink('Document.prototype.writeln', html);
                            flush();
                            return dpWriteln.apply(this, arguments);
                        };
                    }
                }
            } catch(e) {}

            var elProto = Element.prototype;
            var origInnerHTMLDesc = Object.getOwnPropertyDescriptor(elProto, 'innerHTML');
            if (origInnerHTMLDesc && origInnerHTMLDesc.set) {
                Object.defineProperty(elProto, 'innerHTML', {
                    set: function(val) { captureSink('innerHTML', val); return origInnerHTMLDesc.set.call(this, val); },
                    get: origInnerHTMLDesc.get,
                    configurable: true
                });
            }
            var origOuterHTMLDesc = Object.getOwnPropertyDescriptor(elProto, 'outerHTML');
            if (origOuterHTMLDesc && origOuterHTMLDesc.set) {
                Object.defineProperty(elProto, 'outerHTML', {
                    set: function(val) { captureSink('outerHTML', val); return origOuterHTMLDesc.set.call(this, val); },
                    get: origOuterHTMLDesc.get,
                    configurable: true
                });
            }
            var origInsertAdjacentHTML = elProto.insertAdjacentHTML;
            if (origInsertAdjacentHTML) {
                elProto.insertAdjacentHTML = function(pos, html) {
                    captureSink('insertAdjacentHTML', html);
                    return origInsertAdjacentHTML.call(this, pos, html);
                };
            }

            var origSetTimeout = window.setTimeout;
            window.setTimeout = function(fn, delay) {
                if (typeof fn === 'string') captureSink('setTimeout(string)', fn);
                return origSetTimeout.apply(this, arguments);
            };
            var origSetInterval = window.setInterval;
            window.setInterval = function(fn, delay) {
                if (typeof fn === 'string') captureSink('setInterval(string)', fn);
                return origSetInterval.apply(this, arguments);
            };

            var dangerousAttrs = { href:1, src:1, srcdoc:1, formaction:1, action:1, data:1, poster:1 };
            var origSetAttr = elProto.setAttribute;
            elProto.setAttribute = function(name, value) {
                var n = String(name || '').toLowerCase();
                if (n.indexOf('on') === 0 || dangerousAttrs[n]) {
                    captureSink('setAttribute', String(value), { attr: n });
                }
                return origSetAttr.apply(this, arguments);
            };

            try {
                var iframeProto = HTMLIFrameElement.prototype;
                var srcdocDesc = Object.getOwnPropertyDescriptor(iframeProto, 'srcdoc');
                if (srcdocDesc && srcdocDesc.set) {
                    Object.defineProperty(iframeProto, 'srcdoc', {
                        set: function(val) { captureSink('iframe.srcdoc', val); return srcdocDesc.set.call(this, val); },
                        get: srcdocDesc.get,
                        configurable: true
                    });
                }
                var iframeSrcDesc = Object.getOwnPropertyDescriptor(iframeProto, 'src');
                if (iframeSrcDesc && iframeSrcDesc.set) {
                    Object.defineProperty(iframeProto, 'src', {
                        set: function(val) { captureSink('iframe.src', val); return iframeSrcDesc.set.call(this, val); },
                        get: iframeSrcDesc.get,
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                var scriptProto = HTMLScriptElement.prototype;
                var scriptSrcDesc = Object.getOwnPropertyDescriptor(scriptProto, 'src');
                if (scriptSrcDesc && scriptSrcDesc.set) {
                    Object.defineProperty(scriptProto, 'src', {
                        set: function(val) { captureSink('script.src', val); return scriptSrcDesc.set.call(this, val); },
                        get: scriptSrcDesc.get,
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                var loc = window.location;
                var origAssign = loc.assign.bind(loc);
                var origReplace = loc.replace.bind(loc);
                function captureNavSink(sink, url) {
                    captureSink(sink, url);
                    flush();
                }
                loc.assign = function(url) { captureNavSink('location.assign', url); return origAssign(url); };
                loc.replace = function(url) { captureNavSink('location.replace', url); return origReplace(url); };
                var locProto = Location.prototype;
                var hrefDesc = Object.getOwnPropertyDescriptor(locProto, 'href');
                if (hrefDesc && hrefDesc.set) {
                    Object.defineProperty(locProto, 'href', {
                        set: function(val) { captureNavSink('location.href', val); return hrefDesc.set.call(this, val); },
                        get: hrefDesc.get,
                        configurable: true
                    });
                }
            } catch(e) {}

            var origOpen = window.open;
            window.open = function(url) {
                captureSink('window.open', url);
                flush();
                return origOpen.apply(this, arguments);
            };

            var origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function(input, init) {
                    var url = (typeof input === 'string') ? input : (input && input.url) || '';
                    captureSink('fetch', url);
                    return origFetch.apply(this, arguments);
                };
            }

            try {
                var xhrOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url) {
                    captureSink('xhr.open', String(url), { method: String(method || '') });
                    return xhrOpen.apply(this, arguments);
                };
            } catch(e) {}

            try {
                if (typeof DOMParser !== 'undefined') {
                    var origParse = DOMParser.prototype.parseFromString;
                    DOMParser.prototype.parseFromString = function(str, type) {
                        captureSink('DOMParser.parseFromString', str, { type: String(type || '') });
                        return origParse.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                if (typeof Range !== 'undefined' && Range.prototype.createContextualFragment) {
                    var origFrag = Range.prototype.createContextualFragment;
                    Range.prototype.createContextualFragment = function(html) {
                        captureSink('createContextualFragment', html);
                        return origFrag.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                if (window.trustedTypes && trustedTypes.createPolicy) {
                    var origCreatePolicy = trustedTypes.createPolicy.bind(trustedTypes);
                    trustedTypes.createPolicy = function(name, rules) {
                        captureSink('trustedTypes.createPolicy', name);
                        return origCreatePolicy(name, rules);
                    };
                }
            } catch(e) {}

            function hookJQuery() {
                try {
                    var $ = window.jQuery || window.$;
                    if (!$ || !$.fn || $.fn.__trowser_rt) return;
                    $.fn.__trowser_rt = true;
                    ['html', 'append', 'prepend', 'after', 'before'].forEach(function(m) {
                        if (typeof $.fn[m] !== 'function') return;
                        var orig = $.fn[m];
                        $.fn[m] = function() {
                            if (arguments.length && typeof arguments[0] === 'string')
                                captureSink('jquery.' + m, arguments[0]);
                            return orig.apply(this, arguments);
                        };
                    });
                } catch(e) {}
            }
            hookJQuery();
            setTimeout(hookJQuery, 0);
            setTimeout(hookJQuery, 500);

            // --- extended sinks: script creation, URL props, attrs, SVG/MathML, frameworks ---
            try {
                var scriptTextDesc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'text');
                if (scriptTextDesc && scriptTextDesc.set) {
                    Object.defineProperty(HTMLScriptElement.prototype, 'text', {
                        set: function(val) { captureSink('script.text', val); return scriptTextDesc.set.call(this, val); },
                        get: scriptTextDesc.get, configurable: true
                    });
                }
                ['textContent', 'innerText'].forEach(function(prop) {
                    var desc = Object.getOwnPropertyDescriptor(Node.prototype, prop)
                        || Object.getOwnPropertyDescriptor(HTMLElement.prototype, prop);
                    if (!desc || !desc.set) return;
                    Object.defineProperty(HTMLScriptElement.prototype, prop, {
                        set: function(val) {
                            if (this && this.tagName === 'SCRIPT') captureSink('script.' + prop, val);
                            return desc.set.call(this, val);
                        },
                        get: desc.get, configurable: true
                    });
                });
            } catch(e) {}

            try {
                function hookAppend(proto, method) {
                    if (!proto || typeof proto[method] !== 'function') return;
                    var orig = proto[method];
                    proto[method] = function() {
                        for (var i = 0; i < arguments.length; i++) {
                            var n = arguments[i];
                            try {
                                if (n && n.tagName === 'SCRIPT')
                                    captureSink('script.append', n.src || n.text || n.textContent || '');
                            } catch(e2) {}
                        }
                        return orig.apply(this, arguments);
                    };
                }
                hookAppend(Node.prototype, 'appendChild');
                hookAppend(Node.prototype, 'insertBefore');
                hookAppend(Element.prototype, 'append');
                hookAppend(Element.prototype, 'prepend');
            } catch(e) {}

            try {
                function hookUrlProp(ctor, prop, sinkName) {
                    if (!ctor || !ctor.prototype) return;
                    var desc = Object.getOwnPropertyDescriptor(ctor.prototype, prop);
                    if (!desc || !desc.set) return;
                    Object.defineProperty(ctor.prototype, prop, {
                        set: function(val) { captureSink(sinkName || (ctor.name + '.' + prop), val); return desc.set.call(this, val); },
                        get: desc.get, configurable: true
                    });
                }
                hookUrlProp(HTMLAnchorElement, 'href', 'a.href');
                hookUrlProp(HTMLAreaElement, 'href', 'area.href');
                hookUrlProp(HTMLFormElement, 'action', 'form.action');
                hookUrlProp(HTMLButtonElement, 'formAction', 'button.formAction');
                hookUrlProp(HTMLInputElement, 'formAction', 'input.formAction');
                hookUrlProp(HTMLObjectElement, 'data', 'object.data');
                hookUrlProp(HTMLEmbedElement, 'src', 'embed.src');
                hookUrlProp(HTMLBaseElement, 'href', 'base.href');
                hookUrlProp(HTMLLinkElement, 'href', 'link.href');
            } catch(e) {}

            try {
                var origSetAttrNS = Element.prototype.setAttributeNS;
                if (origSetAttrNS) {
                    Element.prototype.setAttributeNS = function(ns, name, value) {
                        var n = String(name || '').toLowerCase();
                        if (n.indexOf('on') === 0 || n === 'href' || n.indexOf('href') >= 0 || dangerousAttrs[n])
                            captureSink('setAttributeNS', String(value), { attr: n, ns: String(ns || '') });
                        return origSetAttrNS.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                var attrDesc = Object.getOwnPropertyDescriptor(Attr.prototype, 'value');
                if (attrDesc && attrDesc.set) {
                    Object.defineProperty(Attr.prototype, 'value', {
                        set: function(val) {
                            var n = '';
                            try { n = String(this.name || '').toLowerCase(); } catch(e2) {}
                            if (n.indexOf('on') === 0 || dangerousAttrs[n] || n === 'href')
                                captureSink('Attr.value', val, { attr: n });
                            return attrDesc.set.call(this, val);
                        },
                        get: attrDesc.get, configurable: true
                    });
                }
            } catch(e) {}

            try {
                if (typeof document.createElementNS === 'function') {
                    var origCreateNS = document.createElementNS.bind(document);
                    document.createElementNS = function(ns, name) {
                        var el = origCreateNS(ns, name);
                        var nsStr = String(ns || '');
                        if (nsStr.indexOf('svg') >= 0 || nsStr.indexOf('MathML') >= 0)
                            captureSink('createElementNS', String(name), { ns: nsStr });
                        return el;
                    };
                }
            } catch(e) {}

            try {
                if (typeof SVGAnimatedString !== 'undefined') {
                    var baseDesc = Object.getOwnPropertyDescriptor(SVGAnimatedString.prototype, 'baseVal');
                    if (baseDesc && baseDesc.set) {
                        Object.defineProperty(SVGAnimatedString.prototype, 'baseVal', {
                            set: function(val) { captureSink('svg.href.baseVal', val); return baseDesc.set.call(this, val); },
                            get: baseDesc.get, configurable: true
                        });
                    }
                }
            } catch(e) {}

            // Framework attribution from stack + jQuery extras + DOMPurify
            var _origCaptureSink = captureSink;
            captureSink = function(sink, data, extra) {
                extra = extra || {};
                try {
                    var st = new Error().stack || '';
                    if (st.indexOf('react-dom') >= 0 || st.indexOf('react.development') >= 0)
                        extra.framework = 'react';
                    else if (st.indexOf('angular') >= 0 || st.indexOf('bypassSecurityTrust') >= 0)
                        extra.framework = 'angular';
                    else if (st.indexOf('vue') >= 0 || st.indexOf('v-html') >= 0)
                        extra.framework = 'vue';
                } catch(e) {}
                return _origCaptureSink(sink, data, extra);
            };

            try {
                var $ = window.jQuery || window.$;
                if ($ && $.fn && !$.fn.__trowser_rt_extra) {
                    $.fn.__trowser_rt_extra = true;
                    ['attr', 'replaceWith', 'wrap', 'wrapInner', 'wrapAll'].forEach(function(m) {
                        if (typeof $.fn[m] !== 'function') return;
                        var orig = $.fn[m];
                        $.fn[m] = function() {
                            if (arguments.length && typeof arguments[0] === 'string')
                                captureSink('jquery.' + m, arguments[0]);
                            return orig.apply(this, arguments);
                        };
                    });
                    if (typeof $ === 'function') {
                        var origJq = $;
                        // Cannot easily wrap $() globally without breaking; skip.
                    }
                }
            } catch(e) {}

            try {
                function hookDomPurify() {
                    var dp = window.DOMPurify;
                    if (!dp || dp.__trowser_rt) return;
                    dp.__trowser_rt = true;
                    var origSan = dp.sanitize.bind(dp);
                    dp.sanitize = function(dirty, cfg) {
                        captureSink('DOMPurify.sanitize', dirty, { sanitizer: 'true' });
                        return origSan(dirty, cfg);
                    };
                }
                hookDomPurify();
                setTimeout(hookDomPurify, 500);
            } catch(e) {}


            // --- extended sinks: shadow root, Function.constructor, setHTMLUnsafe ---
            try {
                var srProto = ShadowRoot.prototype;
                if (srProto && !srProto.__trowser_rt_shadow) {
                    srProto.__trowser_rt_shadow = true;
                    var srInner = Object.getOwnPropertyDescriptor(srProto, 'innerHTML');
                    if (srInner && srInner.set) {
                        Object.defineProperty(srProto, 'innerHTML', {
                            set: function(val) { captureSink('shadowRoot.innerHTML', val); return srInner.set.call(this, val); },
                            get: srInner.get, configurable: true
                        });
                    }
                }
                var origAttach = Element.prototype.attachShadow;
                if (origAttach && !Element.prototype.__trowser_rt_attach) {
                    Element.prototype.__trowser_rt_attach = true;
                    Element.prototype.attachShadow = function(init) {
                        var root = origAttach.call(this, init);
                        try {
                            if (root && !root.__trowser_rt_hooked) {
                                root.__trowser_rt_hooked = true;
                                var idh = Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML');
                                if (idh && idh.set) {
                                    Object.defineProperty(root, 'innerHTML', {
                                        set: function(val) { captureSink('shadowRoot.innerHTML', val); return idh.set.call(this, val); },
                                        get: idh.get, configurable: true
                                    });
                                }
                            }
                        } catch(e2) {}
                        return root;
                    };
                }
            } catch(e) {}

            try {
                if (!Function.prototype.__trowser_rt_ctor) {
                    Function.prototype.__trowser_rt_ctor = true;
                    var origCtor = Function.prototype.constructor;
                    Function.prototype.constructor = function() {
                        var args = Array.from(arguments);
                        captureSink('Function.constructor', args.join(', '));
                        return origCtor.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                if (Element.prototype.setHTMLUnsafe && !Element.prototype.__trowser_rt_setHTMLUnsafe) {
                    Element.prototype.__trowser_rt_setHTMLUnsafe = true;
                    var origSetHtmlUnsafe = Element.prototype.setHTMLUnsafe;
                    Element.prototype.setHTMLUnsafe = function(html) {
                        captureSink('setHTMLUnsafe', html);
                        return origSetHtmlUnsafe.call(this, html);
                    };
                }
                if (typeof Document !== 'undefined' && Document.parseHTMLUnsafe && !Document.__trowser_rt_parseHTMLUnsafe) {
                    Document.__trowser_rt_parseHTMLUnsafe = true;
                    var origParseUnsafe = Document.parseHTMLUnsafe;
                    Document.parseHTMLUnsafe = function(html) {
                        captureSink('Document.parseHTMLUnsafe', html);
                        return origParseUnsafe(html);
                    };
                }
            } catch(e) {}


            // --- source reads ---
            try {
                var storageProto = Storage.prototype;
                var origGetItem = storageProto.getItem;
                storageProto.getItem = function(key) {
                    var v = origGetItem.call(this, key);
                    var which = (this === localStorage) ? 'localStorage' : (this === sessionStorage) ? 'sessionStorage' : 'Storage';
                    captureSource(which + '.getItem', String(key) + '=' + String(v == null ? '' : v).substring(0, 200));
                    return v;
                };
                var origSetItem = storageProto.setItem;
                storageProto.setItem = function(key, value) {
                    var which = (this === localStorage) ? 'localStorage' : (this === sessionStorage) ? 'sessionStorage' : 'Storage';
                    captureSource(which + '.setItem', String(key).substring(0, 80));
                    return origSetItem.apply(this, arguments);
                };
            } catch(e) {}

            try {
                var cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie')
                    || Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
                if (cookieDesc && cookieDesc.get) {
                    Object.defineProperty(document, 'cookie', {
                        get: function() {
                            var v = cookieDesc.get.call(document);
                            captureSource('document.cookie', v);
                            return v;
                        },
                        set: cookieDesc.set ? function(v) { return cookieDesc.set.call(document, v); } : undefined,
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                var nameDesc = Object.getOwnPropertyDescriptor(Window.prototype, 'name')
                    || Object.getOwnPropertyDescriptor(window, 'name');
                if (nameDesc && nameDesc.get) {
                    Object.defineProperty(window, 'name', {
                        get: function() {
                            var v = nameDesc.get.call(window);
                            captureSource('window.name', v);
                            return v;
                        },
                        set: nameDesc.set ? function(v) {
                            try {
                                var s = v == null ? '' : String(v).substring(0, 300);
                                pushHost('outbound-window-name', 'window.name', s, pageStackFrom(new Error().stack), {});
                            } catch(e0) {}
                            return nameDesc.set.call(window, v);
                        } : undefined,
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                if (!Window.prototype.__trowser_rt_postMessage) {
                    Window.prototype.__trowser_rt_postMessage = true;
                    var origPm = Window.prototype.postMessage;
                    Window.prototype.postMessage = function(message, targetOrigin, transfer) {
                        try {
                            var preview = '';
                            try { preview = typeof message === 'string' ? message.substring(0, 300) : JSON.stringify(message).substring(0, 300); }
                            catch(e1) { preview = String(message).substring(0, 300); }
                            var to = targetOrigin == null ? '' : String(targetOrigin);
                            var wild = (to === '*');
                            if (preview.indexOf('__trowser_rt') < 0 && preview.indexOf('__trowser_async') < 0) {
                                pushHost('outbound-postmessage', 'window.postMessage', preview, pageStackFrom(new Error().stack), {
                                    targetOrigin: to,
                                    wildcard: wild ? 'true' : 'false'
                                });
                            }
                        } catch(e2) {}
                        return origPm.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                var refDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'referrer');
                if (refDesc && refDesc.get) {
                    Object.defineProperty(document, 'referrer', {
                        get: function() {
                            var v = refDesc.get.call(document);
                            captureSource('document.referrer', v);
                            return v;
                        },
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                var histStateDesc = Object.getOwnPropertyDescriptor(History.prototype, 'state');
                if (histStateDesc && histStateDesc.get) {
                    Object.defineProperty(history, 'state', {
                        get: function() {
                            var v = histStateDesc.get.call(history);
                            var s = '';
                            try { s = v == null ? '' : JSON.stringify(v).substring(0, 200); }
                            catch(e) { s = '[unserializable]'; }
                            captureSource('history.state', s);
                            return v;
                        },
                        configurable: true
                    });
                }
            } catch(e) {}

            try {
                function wrapIdbRequest(req, label, keyHint) {
                    if (!req || typeof req !== 'object') return req;
                    try {
                        req.addEventListener('success', function() {
                            var v = '';
                            try {
                                v = req.result == null ? '' :
                                    (typeof req.result === 'string' ? req.result : JSON.stringify(req.result));
                            } catch(e2) { v = '[unserializable]'; }
                            captureSource('indexedDB.get', String(keyHint || label) + '=' + String(v).substring(0, 200), { method: label });
                        });
                    } catch(e3) {}
                    return req;
                }
                if (typeof IDBObjectStore !== 'undefined') {
                    ['get', 'getAll', 'getKey', 'getAllKeys'].forEach(function(m) {
                        if (typeof IDBObjectStore.prototype[m] !== 'function') return;
                        var orig = IDBObjectStore.prototype[m];
                        IDBObjectStore.prototype[m] = function() {
                            var keyHint = arguments.length ? String(arguments[0]).substring(0, 80) : m;
                            return wrapIdbRequest(orig.apply(this, arguments), 'IDBObjectStore.' + m, keyHint);
                        };
                    });
                }
                if (typeof IDBIndex !== 'undefined') {
                    ['get', 'getAll', 'getKey', 'getAllKeys'].forEach(function(m) {
                        if (typeof IDBIndex.prototype[m] !== 'function') return;
                        var orig = IDBIndex.prototype[m];
                        IDBIndex.prototype[m] = function() {
                            var keyHint = arguments.length ? String(arguments[0]).substring(0, 80) : m;
                            return wrapIdbRequest(orig.apply(this, arguments), 'IDBIndex.' + m, keyHint);
                        };
                    });
                }
            } catch(e) {}

            // --- listeners ---
            var watchTypes = { message: 1, hashchange: 1, storage: 1 };
            var origAdd = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, listener, options) {
                if (watchTypes[type] && typeof listener === 'function') {
                    var src = '';
                    try { src = Function.prototype.toString.call(listener).substring(0, 800); } catch(e) {}
                    var target = 'other';
                    try {
                        if (this === window) target = 'window';
                        else if (this === document) target = 'document';
                        else if (typeof WebSocket !== 'undefined' && this instanceof WebSocket) target = 'websocket';
                    } catch(e2) {}
                    captureListener(type, src, { target: target });
                }
                return origAdd.call(this, type, listener, options);
            };

            try {
                var onmsgDesc = Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
                if (onmsgDesc && onmsgDesc.set) {
                    Object.defineProperty(window, 'onmessage', {
                        get: onmsgDesc.get,
                        set: function(fn) {
                            if (typeof fn === 'function') {
                                var src = '';
                                try { src = Function.prototype.toString.call(fn).substring(0, 800); } catch(e) {}
                                captureListener('message', src, { target: 'window.onmessage' });
                            }
                            return onmsgDesc.set.call(window, fn);
                        },
                        configurable: true
                    });
                }
            } catch(e) {}

            // Observe delivered messages (for messageDelivered oracle / postMessage fuzz)
            origAdd.call(window, 'message', function(ev) {
                var origin = String(ev.origin || '');
                if (origin !== 'https://evil.trowser.test') {
                    try { noteSource('postMessage', JSON.stringify(ev.data).substring(0, 200)); }
                    catch(e2) { noteSource('postMessage', String(ev.data).substring(0, 200)); }
                }
                try {
                    pushHost('message', 'message', JSON.stringify(ev.data).substring(0, 500), '', {
                        origin: origin,
                        isTrusted: ev.isTrusted ? 'true' : 'false',
                        sensor: 'true'
                    });
                } catch(e) {
                    pushHost('message', 'message', String(ev.data).substring(0, 500), '', {
                        origin: origin,
                        isTrusted: ev.isTrusted ? 'true' : 'false',
                        sensor: 'true'
                    });
                }
            }, true);

            // --- DOM mutation stage (dangerous nodes near sinks) ---
            try {
                if (typeof MutationObserver !== 'undefined' && !window.__trowser_rt_mo) {
                    window.__trowser_rt_mo = true;
                    var mo = new MutationObserver(function(muts) {
                        for (var i = 0; i < muts.length; i++) {
                            var m = muts[i];
                            if (m.type === 'childList') {
                                for (var j = 0; j < m.addedNodes.length; j++) {
                                    var n = m.addedNodes[j];
                                    if (!n || n.nodeType !== 1) continue;
                                    var tag = (n.tagName || '').toLowerCase();
                                    var html = '';
                                    try { html = n.outerHTML || ''; } catch(e2) {}
                                    var dangerous = tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed'
                                        || /on\w+\s*=/i.test(html) || /javascript:/i.test(html) || /srcdoc=/i.test(html)
                                        || canaryRe.test(html);
                                    if (dangerous) {
                                        pushHost('mutation', tag || 'node', html.substring(0, 400), '', {
                                            type: 'childList', consequence: canaryRe.test(html) ? 'exec-candidate' : 'dangerous-dom'
                                        });
                                    }
                                }
                            } else if (m.type === 'attributes') {
                                var an = String(m.attributeName || '').toLowerCase();
                                var av = '';
                                try { av = m.target.getAttribute(m.attributeName) || ''; } catch(e3) {}
                                if (an.indexOf('on') === 0 || an === 'srcdoc' || an === 'href' || an === 'src'
                                    || /javascript:/i.test(av) || canaryRe.test(av)) {
                                    pushHost('mutation', 'attr:' + an, av.substring(0, 300), '', {
                                        type: 'attributes', consequence: /javascript:/i.test(av) ? 'executable-markup' : 'dangerous-dom'
                                    });
                                }
                            }
                        }
                    });
                    mo.observe(document.documentElement || document, { childList: true, subtree: true, attributes: true });
                }
            } catch(e) {}

            // --- consequence oracles ---
            try {
                window.__trowser_exec = function(id) {
                    pushHost('oracle', 'exec', String(id || '1'), '', { consequence: 'exec', confidence: 'canary' });
                    window.__trowser_exec_proof = String(id || '1');
                    return true;
                };
            } catch(e) {}

            try {
                document.addEventListener('securitypolicyviolation', function(ev) {
                    pushHost('oracle', 'blocked-csp', String(ev.blockedURI || ev.violatedDirective || ''), '', {
                        consequence: 'blocked-csp',
                        directive: String(ev.violatedDirective || ''),
                        effectiveDirective: String(ev.effectiveDirective || '')
                    });
                }, true);
            } catch(e) {}

            try {
                if (window.trustedTypes) {
                    // TT violations surface as TypeError on sinks; also listen if available
                    document.addEventListener('securitypolicyviolation', function(){}, true);
                }
            } catch(e) {}

            try {
                if (typeof JSON !== 'undefined' && JSON.parse && !JSON.__trowser_rt_parse) {
                    JSON.__trowser_rt_parse = true;
                    var origJsonParse = JSON.parse;
                    JSON.parse = function(text, reviver) {
                        captureSource('JSON.parse', typeof text === 'string' ? text : String(text));
                        return origJsonParse.apply(this, arguments);
                    };
                }
            } catch(e) {}

            try {
                if (typeof AsyncFunction !== 'undefined' && !window.__trowser_rt_async_fn) {
                    window.__trowser_rt_async_fn = true;
                    var OrigAsync = AsyncFunction;
                    window.AsyncFunction = function() {
                        var args = Array.from(arguments);
                        captureSink('AsyncFunction', args.join(', '));
                        return OrigAsync.apply(this, arguments);
                    };
                    window.AsyncFunction.prototype = OrigAsync.prototype;
                }
            } catch(e) {}

            try {
                function hookJqParse() {
                    var $ = window.jQuery || window.$;
                    if (!$ || $.__trowser_rt_parse) return;
                    $.__trowser_rt_parse = true;
                    if (typeof $.parseHTML === 'function') {
                        var origParseHtml = $.parseHTML;
                        $.parseHTML = function(data) {
                            if (typeof data === 'string') captureSink('jquery.parseHTML', data);
                            return origParseHtml.apply(this, arguments);
                        };
                    }
                    if (typeof $.globalEval === 'function') {
                        var origGlobalEval = $.globalEval;
                        $.globalEval = function(code) {
                            captureSink('jquery.globalEval', code);
                            return origGlobalEval.apply(this, arguments);
                        };
                    }
                }
                hookJqParse();
                setTimeout(hookJqParse, 500);
            } catch(e) {}

            {{gadgetRadarBlock}}

            try {
                window.__trowser_rt_noteInboundMessage = function(data) {
                    noteSource('websocket-message', data);
                    pushHost('source', 'websocket-message', data, '', {});
                };
            } catch(e) {}

            try {
                window.__trowser_rt_bridge = {
                    pushHost: pushHost,
                    pageStackFrom: pageStackFrom,
                    trimStack: trimStack
                };
            } catch(e) {}

            if (wantCodeExecHooks) installCodeExecHooks();
            return 'INSTALLED';
        })({{wantCodeExec}})
        //# sourceURL=trowser-runtime-sensor.js
        """;
    }

    /// <summary>Sink names the sensor instruments (for inventory / coverage).</summary>
    internal static readonly string[] InstrumentedSinks =
    [
        "eval", "Function", "document.write", "document.writeln",
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "setTimeout(string)", "setInterval(string)",
        "setAttribute", "setAttributeNS", "Attr.value",
        "iframe.srcdoc", "iframe.src", "script.src", "script.text", "script.append",
        "a.href", "area.href", "form.action", "object.data", "embed.src", "base.href", "link.href",
        "location.assign", "location.replace", "location.href", "window.open",
        "fetch", "xhr.open", "DOMParser.parseFromString", "createContextualFragment",
        "trustedTypes.createPolicy", "createElementNS", "svg.href.baseVal",
        "shadowRoot.innerHTML", "Function.constructor", "setHTMLUnsafe", "Document.parseHTMLUnsafe",
        "jquery.html", "jquery.append", "jquery.attr", "jquery.replaceWith",
        "jquery.parseHTML", "jquery.globalEval",
        "Document.prototype.write", "Document.prototype.writeln",
        "AsyncFunction", "JSON.parse",
        "DOMPurify.sanitize"
    ];

    internal static readonly string[] InstrumentedSources =
    [
        "localStorage.getItem", "sessionStorage.getItem", "document.cookie",
        "window.name", "document.referrer", "history.state", "indexedDB.get",
        "JSON.parse", "window.postMessage(outbound)"
    ];
}
