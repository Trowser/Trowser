using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Client-side prototype pollution via URL/hash/postMessage canaries, plus a small gadget table.
/// Separate from server-side <see cref="PrototypePollutionScanProbe"/>.
/// </summary>
public sealed class ClientPrototypePollutionScanner
{
    private readonly AutomationContext _ctx;

    public ClientPrototypePollutionScanner(AutomationContext context) => _ctx = context;

    private const string CanaryKey = "trowserPp";
    private const string CanaryValue = "trowser_pp_canary";

    public async Task<ClientPpScanResult> RunAsync(
        string? baseUrl = null,
        bool tryGadgets = true,
        IReadOnlyList<string>? priorityPropertyNames = null)
    {
        var sw = Stopwatch.StartNew();
        await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);

        baseUrl ??= await _ctx.GetCurrentUrl();
        var restoreUrl = await ProbeNavigationRestore.CaptureBaselineUrlAsync(_ctx);
        var findings = new List<UnifiedSecurityFinding>();
        var probes = new List<ClientPpProbeResult>();

        var vectors = new (string Name, string Url)[]
        {
            ("query-proto-bracket", AppendQuery(baseUrl, $"__proto__[{CanaryKey}]={CanaryValue}")),
            ("query-proto-dot", AppendQuery(baseUrl, $"__proto__.{CanaryKey}={CanaryValue}")),
            ("query-constructor", AppendQuery(baseUrl, $"constructor[prototype][{CanaryKey}]={CanaryValue}")),
            ("hash-proto", AppendHash(baseUrl, $"__proto__[{CanaryKey}]={CanaryValue}")),
        };

        foreach (var (name, url) in vectors)
        {
            try
            {
                await NavigateCleanAsync(baseUrl);
                if (await ObjectPrototypeAlreadyPollutedAsync())
                {
                    probes.Add(new ClientPpProbeResult
                    {
                        Vector = name,
                        Url = url,
                        Polluted = false,
                        Error = "canary-already-present-before-vector"
                    });
                    continue;
                }

                await _ctx.Navigate(url);
                await Task.Delay(400);
                var polluted = await CheckPollutionAsync();
                probes.Add(new ClientPpProbeResult { Vector = name, Url = url, Polluted = polluted });
                if (polluted)
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "client-prototype-pollution",
                        title: $"Client-side prototype pollution via {name}",
                        severity: "high",
                        confidence: SecurityConfidence.Confirmed,
                        endpoint: url,
                        evidence: $"({{}}).{CanaryKey} === '{CanaryValue}'",
                        proofHint: "Escalate with application script gadgets (js-audit), not scanner-only sinks",
                        nextActions:
                        [
                            SecurityNextActions.TraceInputMonitorSinks,
                            "POST /api/security/js-audit on loaded scripts"
                        ],
                        id: Guid.NewGuid().ToString("N")));
                    break; // one confirmed pollution is enough to escalate
                }
            }
            catch (Exception ex)
            {
                probes.Add(new ClientPpProbeResult { Vector = name, Url = url, Error = ex.Message });
            }
        }

        // postMessage vector — fresh document so prior URL pollution does not inherit
        try
        {
            await NavigateCleanAsync(baseUrl);
            await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);
            if (await ObjectPrototypeAlreadyPollutedAsync())
            {
                probes.Add(new ClientPpProbeResult
                {
                    Vector = "postMessage",
                    Error = "canary-already-present-before-vector"
                });
            }
            else
            {
            await _ctx.ExecuteJs(
                $@"(function(){{
                    window.dispatchEvent(new MessageEvent('message', {{
                        data: {{ __proto__: {{ {CanaryKey}: '{CanaryValue}' }} }},
                        origin: 'https://evil.trowser.test'
                    }}));
                    return 'ok';
                }})()");
            await Task.Delay(300);
            // Also try JSON-parse style merge if page listens
            var pmPayload = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                [CanaryKey] = CanaryValue,
                ["__proto__"] = new Dictionary<string, string> { [CanaryKey] = CanaryValue }
            });
            await _ctx.ExecuteJs(
                $@"(function(){{
                    window.dispatchEvent(new MessageEvent('message', {{
                        data: {pmPayload},
                        origin: 'https://evil.trowser.test'
                    }}));
                    return 'ok';
                }})()");
            await Task.Delay(300);
            var polluted = await CheckPollutionAsync();
            probes.Add(new ClientPpProbeResult { Vector = "postMessage", Polluted = polluted });
            if (polluted && findings.Count == 0)
            {
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "client-prototype-pollution",
                    title: "Client-side prototype pollution via postMessage",
                    severity: "high",
                    confidence: SecurityConfidence.Confirmed,
                    evidence: $"({{}}).{CanaryKey} === '{CanaryValue}'",
                    nextActions: [SecurityNextActions.PostMessageAudit],
                    id: Guid.NewGuid().ToString("N")));
            }
            }
        }
        catch (Exception ex)
        {
            probes.Add(new ClientPpProbeResult { Vector = "postMessage", Error = ex.Message });
        }

        await TryFormJsonMergeVectorsAsync(baseUrl, probes, findings);

        var gadgetHits = new List<ClientPpGadgetHit>();
        if (tryGadgets)
        {
            var appHits = await TryApplicationScriptGadgetsAsync(baseUrl, priorityPropertyNames);
            gadgetHits.AddRange(appHits);
            foreach (var g in appHits.Where(g => g.SinkReached && !g.Synthetic))
            {
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "client-prototype-pollution",
                    title: $"Application PP gadget ({g.Gadget}) via {g.PropertyName}",
                    severity: "critical",
                    confidence: SecurityConfidence.Confirmed,
                    endpoint: g.ScriptUrl,
                    evidence: g.Evidence,
                    proofHint: "Gadget chain confirmed in same-origin script bundle (js-audit style static match + runtime sink)",
                    nextActions:
                    [
                        SecurityNextActions.ClientPrototypePollution,
                        "POST /api/security/js-audit on loaded scripts"
                    ],
                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["synthetic"] = false,
                        ["gadget"] = g.Gadget,
                        ["property"] = g.PropertyName,
                        ["scriptUrl"] = g.ScriptUrl
                    },
                    id: Guid.NewGuid().ToString("N")));
            }
        }

        var pollutionConfirmed = probes.Any(p => p.Polluted);
        if (tryGadgets && pollutionConfirmed)
        {
            var runtimeKeys = CollectProtoReadPropertyNames();
            if (runtimeKeys.Count > 0)
            {
                var guided = await TryApplicationScriptGadgetsAsync(baseUrl, runtimeKeys);
                gadgetHits.AddRange(guided);
                foreach (var g in guided.Where(g => g.SinkReached && !g.Synthetic))
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "client-prototype-pollution",
                        title: $"Application PP gadget ({g.Gadget}) via {g.PropertyName}",
                        severity: "critical",
                        confidence: SecurityConfidence.Confirmed,
                        endpoint: g.ScriptUrl,
                        evidence: g.Evidence,
                        proofHint: "Property read from polluted object in application code",
                        nextActions:
                        [
                            SecurityNextActions.TraceInputMonitorSinks,
                            "POST /api/security/js-audit on loaded scripts"
                        ],
                        extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["synthetic"] = false,
                            ["gadget"] = g.Gadget,
                            ["property"] = g.PropertyName,
                            ["scriptUrl"] = g.ScriptUrl
                        },
                        id: Guid.NewGuid().ToString("N")));
                }
            }

            var syntheticHits = await TryGadgetsAsync();
            gadgetHits.AddRange(syntheticHits);
            foreach (var g in syntheticHits.Where(g => g.SinkReached))
            {
                var extra = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["synthetic"] = true,
                    ["gadget"] = g.Gadget
                };
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "client-prototype-pollution",
                    title: $"Scanner synthetic gadget ({g.Gadget}) — canary readable, not an app gadget",
                    severity: "info",
                    confidence: SecurityConfidence.Tentative,
                    evidence: g.Evidence,
                    proofHint: "Synthetic probe only — confirm real gadgets in same-origin script bundles via js-audit",
                    tier: SecurityFindingTier.Informational,
                    nextActions: ["POST /api/security/js-audit on loaded scripts"],
                    extra: extra,
                    id: Guid.NewGuid().ToString("N")));
            }
        }

        await CleanupCanaryAsync();

        await ProbeNavigationRestore.TryRestoreAsync(_ctx, restoreUrl);

        sw.Stop();
        return new ClientPpScanResult
        {
            ElapsedMs = sw.ElapsedMilliseconds,
            DocumentUrl = baseUrl ?? "",
            Probes = probes,
            GadgetHits = gadgetHits,
            Findings = findings,
            Coverage = new ClientScanCoverage
            {
                Instrumented = RuntimeSensorScript.InstrumentedSinks.ToList(),
                Untested = [],
                ZeroResultReason = findings.Count == 0
                    ? "no-object-prototype-pollution-detected"
                    : null
            },
            NextActions = findings.Count > 0
                ? findings.SelectMany(f => f.NextActions).Distinct().Take(8).ToList()
                : [SecurityNextActions.ClientSurface, "If the app merges URL/JSON into objects, re-test after auth"]
        };
    }

    private async Task TryFormJsonMergeVectorsAsync(
        string? baseUrl,
        List<ClientPpProbeResult> probes,
        List<UnifiedSecurityFinding> findings)
    {
        if (findings.Count > 0 || string.IsNullOrWhiteSpace(baseUrl))
            return;

        var payloads = new[]
        {
            ($"{{\"__proto__\":{{\"{CanaryKey}\":\"{CanaryValue}\"}}}}", "form-json-proto"),
            ($"{{\"constructor\":{{\"prototype\":{{\"{CanaryKey}\":\"{CanaryValue}\"}}}}}}", "form-json-constructor")
        };

        foreach (var (jsonPayload, vectorName) in payloads)
        {
            try
            {
                await NavigateCleanAsync(baseUrl);
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);
                if (await ObjectPrototypeAlreadyPollutedAsync())
                {
                    probes.Add(new ClientPpProbeResult
                    {
                        Vector = vectorName,
                        Error = "canary-already-present-before-vector"
                    });
                    continue;
                }

                var discoveryJson = await _ctx.ExecuteJs("""
                    (function(){
                        function pickSubmit(root, el){
                            var scope = root || document;
                            var btn = scope.querySelector('button[type="submit"], input[type="submit"]');
                            if (!btn && el) {
                                var sib = el.parentElement;
                                for (var i = 0; i < 4 && sib; i++) {
                                    btn = sib.querySelector('button, input[type="submit"]');
                                    if (btn) break;
                                    sib = sib.parentElement;
                                }
                            }
                            if (!btn) btn = document.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
                            if (btn && btn.id) return '#' + CSS.escape(btn.id);
                            if (btn) return 'button';
                            return null;
                        }
                        function selectorFor(el, idx){
                            if (el.id) return '#' + CSS.escape(el.id);
                            if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name.replace(/"/g,'\\"') + '"]';
                            var tag = el.tagName.toLowerCase();
                            var all = document.querySelectorAll(tag);
                            for (var j = 0; j < all.length; j++) if (all[j] === el) return tag + ':nth-of-type(' + (j+1) + ')';
                            return tag + '[data-trowser-idx="' + idx + '"]';
                        }
                        var out = [];
                        document.querySelectorAll('textarea, input[type="text"], input:not([type])').forEach(function(el, idx){
                            var sel = selectorFor(el, idx);
                            var form = el.form || el.closest('form');
                            var submit = pickSubmit(form, el);
                            if (!submit) return;
                            out.push({ target: sel, submit: submit, tag: el.tagName });
                            if (out.length >= 6) return;
                        });
                        return JSON.stringify(out);
                    })()
                    """);
                using var doc = JsonDocument.Parse(Unquote(discoveryJson));
                if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() == 0)
                {
                    probes.Add(new ClientPpProbeResult { Vector = vectorName, Error = "no-form-json-fields" });
                    continue;
                }

                foreach (var field in doc.RootElement.EnumerateArray())
                {
                    if (findings.Count > 0) break;
                    var target = field.TryGetProperty("target", out var t) ? t.GetString() : null;
                    var submit = field.TryGetProperty("submit", out var s) ? s.GetString() : null;
                    if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(submit))
                        continue;

                    await NavigateCleanAsync(baseUrl);
                    await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);
                    if (await ObjectPrototypeAlreadyPollutedAsync())
                        continue;

                    await _ctx.ExecuteJs(
                        $"(function(){{ var el = document.querySelector({JsonSerializer.Serialize(target)}); if (!el) return 'missing'; el.focus(); el.value = {JsonSerializer.Serialize(jsonPayload)}; el.dispatchEvent(new Event('input', {{ bubbles: true }})); return 'ok'; }})()");
                    if (submit == "button")
                    {
                        await _ctx.ExecuteJs(
                            "(function(){ var b = document.querySelector('button[type=\"submit\"], input[type=\"submit\"], button:not([type])'); if (b) b.click(); return 'ok'; })()");
                    }
                    else
                    {
                        try { await _ctx.Click(submit); }
                        catch { continue; }
                    }

                    await Task.Delay(500);
                    var polluted = await CheckPollutionAsync();
                    probes.Add(new ClientPpProbeResult
                    {
                        Vector = vectorName,
                        Url = baseUrl,
                        Polluted = polluted,
                        Error = polluted ? null : $"target={target}"
                    });
                    if (polluted)
                    {
                        findings.Add(UnifiedSecurityFinding.Create(
                            category: "client-prototype-pollution",
                            title: $"Client-side prototype pollution via {vectorName}",
                            severity: "high",
                            confidence: SecurityConfidence.Confirmed,
                            endpoint: baseUrl,
                            evidence: $"({{}}).{CanaryKey} === '{CanaryValue}' after JSON form merge",
                            proofHint: "Settings/import JSON merged into objects without __proto__ filtering",
                            nextActions:
                            [
                                SecurityNextActions.ClientPrototypePollution,
                                SecurityNextActions.TraceInputMonitorSinks
                            ],
                            id: Guid.NewGuid().ToString("N")));
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                probes.Add(new ClientPpProbeResult { Vector = vectorName, Error = ex.Message });
            }
        }
    }

    private async Task NavigateCleanAsync(string? baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return;
        var clean = baseUrl.Contains('#') ? baseUrl[..baseUrl.IndexOf('#')] : baseUrl;
        var q = clean.IndexOf('?');
        if (q >= 0) clean = clean[..q];
        await _ctx.Navigate(clean);
        await Task.Delay(350);
        await CleanupCanaryAsync();
    }

    private async Task<bool> ObjectPrototypeAlreadyPollutedAsync()
    {
        var json = await _ctx.ExecuteJs(
            $@"(function(){{
                try {{
                    return JSON.stringify({{
                        polluted: Object.prototype[{JsonSerializer.Serialize(CanaryKey)}] === {JsonSerializer.Serialize(CanaryValue)}
                    }});
                }} catch(e) {{ return JSON.stringify({{ polluted:false }}); }}
            }})()");
        try
        {
            using var doc = JsonDocument.Parse(Unquote(json));
            return doc.RootElement.TryGetProperty("polluted", out var p) && p.ValueKind == JsonValueKind.True;
        }
        catch { return false; }
    }

    private async Task<bool> CheckPollutionAsync()
    {
        var json = await _ctx.ExecuteJs(
            $@"(function(){{
                try {{
                    var o = {{}};
                    return JSON.stringify({{
                        polluted: o[{JsonSerializer.Serialize(CanaryKey)}] === {JsonSerializer.Serialize(CanaryValue)}
                            || Object.prototype[{JsonSerializer.Serialize(CanaryKey)}] === {JsonSerializer.Serialize(CanaryValue)}
                    }});
                }} catch(e) {{ return JSON.stringify({{ polluted:false, error:String(e) }}); }}
            }})()");
        try
        {
            using var doc = JsonDocument.Parse(Unquote(json));
            return doc.RootElement.TryGetProperty("polluted", out var p) && p.ValueKind == JsonValueKind.True;
        }
        catch { return false; }
    }

    private async Task<List<ClientPpGadgetHit>> TryApplicationScriptGadgetsAsync(
        string? baseUrl,
        IReadOnlyList<string>? priorityPropertyNames = null)
    {
        var hits = new List<ClientPpGadgetHit>();
        baseUrl ??= await _ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(baseUrl)) return hits;

        List<string> scriptUrls;
        try
        {
            scriptUrls = await ScriptDiscovery.CollectScriptUrlsAsync(_ctx, sameOriginOnly: true, max: 24);
        }
        catch
        {
            return hits;
        }

        var candidates = new List<ClientPpScriptGadgetAnalyzer.Candidate>();
        foreach (var scriptUrl in scriptUrls)
        {
            string text;
            try
            {
                var fetch = await SecurityProbeHttp.FetchAsync(
                    _ctx, scriptUrl, "GET", headers: null, body: null,
                    timeoutMs: 20_000, includeBrowserCookies: true);
                if (fetch.Status is < 200 or >= 300 || string.IsNullOrEmpty(fetch.Body))
                    continue;
                text = fetch.Body;
            }
            catch { continue; }

            candidates.AddRange(ClientPpScriptGadgetAnalyzer.FindCandidates(scriptUrl, text));
        }

        if (priorityPropertyNames is { Count: > 0 })
        {
            foreach (var prop in priorityPropertyNames.Where(p => p.Length >= 2).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (candidates.Any(c => c.PropertyName.Equals(prop, StringComparison.OrdinalIgnoreCase)))
                    continue;
                candidates.Add(new ClientPpScriptGadgetAnalyzer.Candidate
                {
                    ScriptUrl = scriptUrls.FirstOrDefault() ?? baseUrl,
                    PropertyName = prop,
                    Sink = "radar-priority",
                    Snippet = "(execution-guided proto-read key)"
                });
            }
        }

        foreach (var c in candidates
                     .GroupBy(x => x.PropertyName, StringComparer.OrdinalIgnoreCase)
                     .Select(g => g.First())
                     .Take(5))
        {
            var canary = $"https://{RedirectAnalysis.DefaultProbeHost}/trowser-pp-{Guid.NewGuid():N}.js";
            try
            {
                await NavigateCleanAsync(baseUrl);
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);
                var vectorUrl = AppendQuery(baseUrl, $"__proto__[{c.PropertyName}]={Uri.EscapeDataString(canary)}");
                await ClearSinkLogAsync();
                await _ctx.Navigate(vectorUrl);
                await Task.Delay(700);

                var sinkJson = await _ctx.ExecuteJs(
                    "(function(){ var log=window.__trowser_sink_log||[]; return JSON.stringify(log.slice(0,20)); })()");
                var logText = Unquote(sinkJson);
                var scriptHint = Path.GetFileName(new Uri(c.ScriptUrl).AbsolutePath);
                var reached = logText.Contains(canary, StringComparison.Ordinal)
                              && (logText.Contains(scriptHint, StringComparison.OrdinalIgnoreCase)
                                  || logText.Contains(c.ScriptUrl, StringComparison.OrdinalIgnoreCase));

                hits.Add(new ClientPpGadgetHit
                {
                    Gadget = c.Sink,
                    PropertyName = c.PropertyName,
                    ScriptUrl = c.ScriptUrl,
                    Synthetic = !reached,
                    SinkReached = reached,
                    Evidence = reached
                        ? $"{c.Sink} reached with canary; script={scriptHint}; snippet={Truncate(c.Snippet, 80)}"
                        : Truncate(logText, 200)
                });
            }
            catch (Exception ex)
            {
                hits.Add(new ClientPpGadgetHit
                {
                    Gadget = c.Sink,
                    PropertyName = c.PropertyName,
                    ScriptUrl = c.ScriptUrl,
                    Error = ex.Message
                });
            }
        }

        return hits;
    }

    private async Task<List<ClientPpGadgetHit>> TryGadgetsAsync()
    {
        var hits = new List<ClientPpGadgetHit>();
        // After confirmed pollution, exercise common DOM paths that read from {} — do not set prototype sink properties ourselves.
        var keyJs = JsonSerializer.Serialize(CanaryKey);
        var valJs = JsonSerializer.Serialize(CanaryValue);
        var gadgets = new (string Name, string Script)[]
        {
            ("empty-object-to-innerHTML", $@"(function(){{
                var c = ({{}})[{keyJs}];
                if (!c) return 'no-canary';
                var d = document.createElement('div');
                d.innerHTML = String(c);
                return 'ok';
            }})()"),
            ("empty-object-to-script-src", $@"(function(){{
                var c = ({{}})[{keyJs}];
                if (!c) return 'no-canary';
                var s = document.createElement('script');
                s.src = String(c);
                return 'ok';
            }})()")
        };

        foreach (var (name, script) in gadgets)
        {
            try
            {
                await ClearSinkLogAsync();
                var mark = _ctx.ActiveTab.RuntimeEvents.Mark();
                await _ctx.ExecuteJs(script);
                await Task.Delay(200);
                var sinkJson = await _ctx.ExecuteJs(
                    "(function(){ var log=window.__trowser_sink_log||[]; return JSON.stringify(log.slice(0,10)); })()");
                var logText = Unquote(sinkJson);
                var reached = logText.Contains(CanaryValue, StringComparison.Ordinal)
                              || _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(mark)
                                  .Any(e => e.Kind == "sink"
                                            && e.Data != null
                                            && e.Data.Contains(CanaryValue, StringComparison.Ordinal));
                hits.Add(new ClientPpGadgetHit
                {
                    Gadget = name,
                    SinkReached = reached,
                    Evidence = Truncate(logText, 300)
                });
            }
            catch (Exception ex)
            {
                hits.Add(new ClientPpGadgetHit { Gadget = name, Error = ex.Message });
            }
        }

        return hits;
    }

    private async Task CleanupCanaryAsync()
    {
        try
        {
            await _ctx.ExecuteJs(
                $@"(function(){{
                    try {{ delete Object.prototype[{JsonSerializer.Serialize(CanaryKey)}]; }} catch(e){{}}
                    try {{ delete Object.prototype.src; }} catch(e){{}}
                    try {{ delete Object.prototype.innerHTML; }} catch(e){{}}
                    return 'ok';
                }})()");
        }
        catch { }
    }

    private async Task ClearSinkLogAsync()
    {
        try { await _ctx.ExecuteJs("if(window.__trowser_sink_log) window.__trowser_sink_log.length=0;"); }
        catch { }
    }

    private List<string> CollectProtoReadPropertyNames()
    {
        var keys = new List<string>();
        foreach (var evt in _ctx.ActiveTab.RuntimeEvents.All())
        {
            if (!evt.Kind.Equals("proto-read", StringComparison.OrdinalIgnoreCase))
                continue;
            var data = evt.Data ?? "";
            var eq = data.IndexOf('=');
            var key = (eq >= 0 ? data[..eq] : data).Trim().Trim('"', '\'');
            if (key.Length >= 2 && !keys.Contains(key, StringComparer.OrdinalIgnoreCase))
                keys.Add(key);
        }

        return keys;
    }

    private static string AppendQuery(string baseUrl, string query)
    {
        var sep = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var hashIdx = baseUrl.IndexOf('#');
        if (hashIdx >= 0)
            return baseUrl[..hashIdx] + sep + query + baseUrl[hashIdx..];
        return baseUrl + sep + query;
    }

    private static string AppendHash(string baseUrl, string fragment)
    {
        var bare = baseUrl.Contains('#', StringComparison.Ordinal)
            ? baseUrl[..baseUrl.IndexOf('#')]
            : baseUrl;
        return bare + "#" + fragment;
    }

    private static string Unquote(string? json)
    {
        if (string.IsNullOrEmpty(json)) return "{}";
        var s = json.Trim();
        if (s.Length >= 2 && s[0] == '"')
        {
            try { return JsonSerializer.Deserialize<string>(s) ?? "{}"; }
            catch { return "{}"; }
        }
        return s;
    }

    private static string? Truncate(string? s, int max) =>
        s == null ? null : s.Length <= max ? s : s[..max];
}

public sealed class ClientPpScanResult
{
    public long ElapsedMs { get; init; }
    public string DocumentUrl { get; init; } = "";
    public List<ClientPpProbeResult> Probes { get; init; } = [];
    public List<ClientPpGadgetHit> GadgetHits { get; init; } = [];
    public List<UnifiedSecurityFinding> Findings { get; init; } = [];
    public ClientScanCoverage Coverage { get; init; } = new();
    public List<string> NextActions { get; init; } = [];

    public object ToApiResponse() => new
    {
        message = Findings.Count > 0
            ? $"Client prototype pollution: {Findings.Count} finding(s)"
            : "Client prototype pollution: no pollution detected",
        elapsedMs = ElapsedMs,
        documentUrl = DocumentUrl,
        probes = Probes,
        gadgetHits = GadgetHits,
        findings = Findings.Select(SecurityScanResult.ToApiFinding).ToList(),
        nextActions = NextActions,
        coverage = Coverage.ToApiObject()
    };
}

public sealed class ClientPpProbeResult
{
    public string Vector { get; init; } = "";
    public string? Url { get; init; }
    public bool Polluted { get; init; }
    public string? Error { get; init; }
}

public sealed class ClientPpGadgetHit
{
    public string Gadget { get; init; } = "";
    public string? PropertyName { get; init; }
    public string? ScriptUrl { get; init; }
    public bool Synthetic { get; init; } = true;
    public bool SinkReached { get; init; }
    public string? Evidence { get; init; }
    public string? Error { get; init; }
}
