using System.Text.Json;

namespace Trowser.Security.Runtime;

/// <summary>
/// In-page gadget radar hooks (missing-global reads + optional Object.prototype getter traps).
/// Must run inside the runtime sensor IIFE where <c>pushHost</c> and <c>pageStackFrom</c> exist,
/// or after the sensor via <see cref="BuildStandaloneInstall"/> which bridges through
/// <c>window.__trowser_rt_bridge</c>.
/// </summary>
internal static class GadgetRadarScript
{
    /// <summary>
    /// Non-perturbing missing-name radar.
    /// WebView2/Chromium keeps <c>EventTarget.prototype</c> immutable, so a proxy cannot sit on the
    /// <c>window</c> lookup chain. Live traps cover <c>document.&lt;name&gt;</c> (Document.prototype is mutable).
    /// <c>window.&lt;name&gt;</c> reads are recovered by scanning same-document script source.
    /// </summary>
    internal const string InstallMissingGlobalBody = """
            function installMissingGlobalRadar() {
                try { delete Object.prototype.__trowser_gadget_proxy; } catch(e) {}
                if (window.__trowser_gadget_radar_global) return 'already';
                window.__trowser_gadget_radar_global = true;
                var deny = {
                    module:1, define:1, exports:1, process:1, global:1, require:1,
                    webpackJsonp:1, __webpack_require__:1, __REACT_DEVTOOLS_GLOBAL_HOOK__:1,
                    chrome:1, webkit:1, moz:1, ms:1, opr:1, location:1, document:1, window:1
                };
                var docBudget = 200;
                var used = 0;
                var siteHits = Object.create(null);
                function denyKey(k) {
                    if (!k || k.length < 2 || k.length > 80) return true;
                    if (/^[0-9]/.test(k)) return true;
                    if (deny[k]) return true;
                    if (k.indexOf('__') === 0) return true;
                    return false;
                }
                function logRead(receiverLabel, key, stackFull, how, prop) {
                    if (denyKey(key) || used >= docBudget) return;
                    var id = receiverLabel + '.' + key + (prop ? '.' + prop : '');
                    var bucket = siteHits[id] || (siteHits[id] = { n: 0, stacks: 0 });
                    bucket.n++;
                    if (bucket.stacks >= 3) return;
                    bucket.stacks++;
                    used++;
                    var stack = pageStackFrom(stackFull) || stackFull || '';
                    var extra = { receiver: receiverLabel, key: key, undefined: 'true', how: how || 'trap' };
                    if (prop) extra.prop = prop;
                    pushHost('gadget-read', id, how || '', stack, extra);
                }
                function installDocumentProxy() {
                    var docProto = Document.prototype;
                    var orig = Object.getPrototypeOf(docProto);
                    if (!orig) return 'no-proto';
                    var proxy = new Proxy(orig, {
                        get: function(target, prop, receiver) {
                            var value = Reflect.get(target, prop, receiver);
                            if (typeof prop === 'string' && receiver === document && value === undefined) {
                                try {
                                    var stackFull = '';
                                    try { stackFull = new Error().stack; } catch(e) {}
                                    logRead('document', prop, stackFull, 'trap');
                                } catch(e) {}
                            }
                            return value;
                        },
                        has: function(target, prop) { return Reflect.has(target, prop); }
                    });
                    Object.setPrototypeOf(docProto, proxy);
                    window.__trowser_gadget_doc_restore = function() {
                        try { Object.setPrototypeOf(docProto, orig); } catch(e) {}
                    };
                    return 'document-proxy';
                }
                function scanScriptSources() {
                    var re = /\b(window|self|globalThis|document)\s*\.\s*([A-Za-z_$][\w$]{0,63})/g;
                    var re2 = /\b(window|self|globalThis)\s*\.\s*([A-Za-z_$][\w$]{0,63})\s*\.\s*([A-Za-z_$][\w$]{0,63})/g;
                    var stack = 'at page (' + location.href + ':1:1)';
                    var nodes = document.scripts || [];
                    for (var i = 0; i < nodes.length; i++) {
                        var text = nodes[i].textContent || '';
                        if (!text) continue;
                        re2.lastIndex = 0;
                        var m;
                        while ((m = re2.exec(text))) {
                            logRead('window', m[2], stack, 'script-scan', m[3]);
                        }
                        re.lastIndex = 0;
                        while ((m = re.exec(text))) {
                            var recv = m[1] === 'document' ? 'document' : 'window';
                            logRead(recv, m[2], stack, 'script-scan');
                        }
                    }
                }
                var mode = 'script-scan';
                try { mode = installDocumentProxy(); } catch(e) { mode = 'script-scan-only'; }
                function runScan() { try { scanScriptSources(); } catch(e) {} }
                if (document.readyState === 'loading')
                    document.addEventListener('DOMContentLoaded', runScan);
                else
                    runScan();
                window.__trowser_gadget_radar_restore = function() {
                    if (window.__trowser_gadget_doc_restore) window.__trowser_gadget_doc_restore();
                    window.__trowser_gadget_radar_global = false;
                };
                return mode;
            }
            window.__trowser_rt_install_gadget_radar = installMissingGlobalRadar;
            installMissingGlobalRadar();
        """;

    /// <summary>
    /// Install the missing-global radar outside the sensor IIFE, using <c>__trowser_rt_bridge</c>.
    /// Register as a document-created script after the sensor so the next navigation scans script text
    /// once the document has been parsed.
    /// </summary>
    internal static string BuildStandaloneInstall() =>
        """
        (function(){
            function pushHost(kind, name, data, stack, extra) {
                var b = window.__trowser_rt_bridge;
                if (b && typeof b.pushHost === 'function')
                    b.pushHost(kind, name, data, stack, extra);
            }
            function pageStackFrom(full) {
                var b = window.__trowser_rt_bridge;
                if (b && typeof b.pageStackFrom === 'function')
                    return b.pageStackFrom(full) || full || '';
                return full || '';
            }
        """
        + InstallMissingGlobalBody
        + "\n})();\n";

    internal static string BuildProtoTrapsInstall(IReadOnlyList<string> keys)
    {
        var trimmed = keys
            .Where(k => !string.IsNullOrWhiteSpace(k) && k.Length is >= 2 and <= 64)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(24)
            .ToList();
        var keysJson = JsonSerializer.Serialize(trimmed);
        return $$"""
            (function(){
                var keys = {{keysJson}};
                window.__trowser_proto_trap_keys = window.__trowser_proto_trap_keys || [];
                function bridgePush(kind, name, data, stack, extra) {
                    if (typeof pushHost === 'function') {
                        pushHost(kind, name, data, stack, extra);
                        return;
                    }
                    var b = window.__trowser_rt_bridge;
                    if (b && typeof b.pushHost === 'function')
                        b.pushHost(kind, name, data, stack, extra);
                }
                function pageStack(full) {
                    if (typeof pageStackFrom === 'function') return pageStackFrom(full) || full;
                    var b = window.__trowser_rt_bridge;
                    if (b && typeof b.pageStackFrom === 'function') return b.pageStackFrom(full) || full;
                    return full || '';
                }
                keys.forEach(function(k) {
                    if (window.__trowser_proto_trap_keys.indexOf(k) >= 0) return;
                    try {
                        Object.defineProperty(Object.prototype, k, {
                            configurable: true,
                            enumerable: false,
                            get: function() {
                                var st = '';
                                try { st = new Error().stack; } catch(e) {}
                                bridgePush('proto-read', k, '', pageStack(st), { key: k, perturbing: 'true' });
                                return undefined;
                            }
                        });
                        window.__trowser_proto_trap_keys.push(k);
                    } catch(e) {}
                });
                return JSON.stringify({ installed: window.__trowser_proto_trap_keys.length, keys: window.__trowser_proto_trap_keys });
            })()
            """;
    }

    internal static string BuildProtoTrapsUninstall() =>
        """
        (function(){
            var keys = window.__trowser_proto_trap_keys || [];
            keys.forEach(function(k) {
                try { delete Object.prototype[k]; } catch(e) {}
            });
            window.__trowser_proto_trap_keys = [];
            try { delete Object.prototype.__trowser_gadget_proxy; } catch(e) {}
            if (window.__trowser_gadget_radar_restore) {
                try { window.__trowser_gadget_radar_restore(); } catch(e) {}
            }
            return 'ok';
        })()
        """;

    /// <summary>Expose pushHost for proto-trap install after sensor load.</summary>
    internal static string BuildBridgeExpose() =>
        """
        (function(){
            if (window.__trowser_rt_bridge) return 'ok';
            return 'no-sensor';
        })()
        """;
}
