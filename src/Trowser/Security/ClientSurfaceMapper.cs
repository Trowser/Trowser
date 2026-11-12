using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Automation;
using Trowser.Security.DomFlow;
using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Browser-native attack-surface map: sources, sinks, listeners, DOM facts, SW/cache,
/// plus ranked nextActions so the LLM always has a to-do list.
/// </summary>
public sealed class ClientSurfaceMapper
{
    private readonly AutomationContext _ctx;

    public ClientSurfaceMapper(AutomationContext context) => _ctx = context;

    public async Task<ClientSurfaceResult> MapAsync(
        bool installSensor = true,
        int waitMs = 400,
        bool reloadForSensor = true,
        bool reset = false,
        bool scopeToCurrentDocument = true)
    {
        var sw = Stopwatch.StartNew();
        var pageUrl = UrlPayloadInjector.StripToolQueryParams(await SafeUrl());
        var documentScopeKey = DocumentScopeKey(pageUrl);
        var newDocument = !string.IsNullOrEmpty(_ctx.ActiveTab.LastClientSurfaceScopeKey)
                          && !string.Equals(_ctx.ActiveTab.LastClientSurfaceScopeKey, documentScopeKey,
                              StringComparison.OrdinalIgnoreCase);
        if (reset || newDocument)
            _ctx.ActiveTab.RuntimeEvents.Clear();

        _ctx.ActiveTab.LastClientSurfaceScopeKey = documentScopeKey;
        var useExistingRuntimeBuffer = !installSensor && !reset;
        long observationMark = useExistingRuntimeBuffer
            ? 0
            : _ctx.ActiveTab.RuntimeEvents.Mark();
        var loadObserved = true;
        if (installSensor)
        {
            var docScriptId = await RuntimeSensorInstaller.InstallDocumentCreatedAsync(_ctx);
            if (docScriptId == null)
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);

            if (reloadForSensor)
            {
                var current = await _ctx.GetCurrentUrl();
                if (!string.IsNullOrWhiteSpace(current))
                {
                    loadObserved = false;
                    observationMark = _ctx.ActiveTab.RuntimeEvents.Mark();
                    await _ctx.Navigate(UrlPayloadInjector.EnsureFullNavigation(current));
                    var idleTimeout = Math.Clamp(waitMs * 5, 4_000, 25_000);
                    try { await _ctx.WaitForIdle(300, idleTimeout); }
                    catch { await Task.Delay(Math.Clamp(waitMs, 400, 5_000)); }
                    await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx);
                }
            }
            else if (docScriptId == null)
            {
                await RuntimeSensorInstaller.EnsureAmbientAsync(_ctx);
                if (_ctx.ActiveTab.RuntimeEvents.All().Count == 0)
                    loadObserved = false;
            }
        }

        // One-shot DOM / SW collector (does not require prior browsing with the sensor).
        var domJson = await _ctx.ExecuteJs("""
            (function(){
                function safe(fn, fallback){ try { return fn(); } catch(e){ return fallback; } }
                var blanks = [];
                document.querySelectorAll('a[target="_blank"]').forEach(function(a){
                    var rel = (a.getAttribute('rel')||'').toLowerCase();
                    if (rel.indexOf('noopener') < 0 && rel.indexOf('noreferrer') < 0) {
                        blanks.push({
                            href: (a.href||'').substring(0,200),
                            text: (a.textContent||'').trim().substring(0,80),
                            navigationKind: 'anchor-target-blank',
                            missingExplicitRel: true,
                            effectiveOpenerPolicy: 'implicit-noopener'
                        });
                    }
                });
                var domFrameworkHints = [];
                try {
                    var ngEl = document.querySelector('[ng-version]');
                    if (ngEl && ngEl.getAttribute('ng-version'))
                        domFrameworkHints.push('ng-version=' + ngEl.getAttribute('ng-version'));
                } catch(e){}
                var iframes = [];
                document.querySelectorAll('iframe').forEach(function(f, i){
                    var same = false;
                    try { same = !!f.contentDocument; } catch(e){ same = false; }
                    iframes.push({ src: (f.src||'').substring(0,300), sameOrigin: same, name: f.name||('frame'+i) });
                });
                var idCounts = {};
                document.querySelectorAll('[id]').forEach(function(el){
                    if (el.id) idCounts[el.id] = (idCounts[el.id] || 0) + 1;
                });
                var clobber = [];
                document.querySelectorAll('[id]').forEach(function(el){
                    var id = el.id;
                    if (!id || id.length < 2) return;
                    if ((idCounts[id] || 0) > 1) {
                        clobber.push({ id: id, tag: el.tagName, reason: 'duplicate-id' });
                        return;
                    }
                    try {
                        var forms = document.getElementsByTagName('form');
                        for (var fi = 0; fi < forms.length; fi++) {
                            var f = forms[fi];
                            if (f[id] === el || (el.name && f[el.name] === el)) {
                                clobber.push({ id: id, tag: el.tagName, reason: 'form-named-access' });
                                break;
                            }
                        }
                    } catch(e){}
                });
                var globals = [];
                ['_NEXT_DATA_','__NEXT_DATA__','__NUXT__','__INITIAL_STATE__','ng','angular','React','Vue','jQuery','__REACT_DEVTOOLS_GLOBAL_HOOK__'].forEach(function(g){
                    try { if (typeof window[g] !== 'undefined') globals.push(g); } catch(e){}
                });
                try { if (window.__NEXT_DATA__) globals.push('__NEXT_DATA__'); } catch(e){}
                var inlineDocWrite = false;
                var guardedGlobals = [];
                var inlineScripts = [];
                var scriptBudget = 80000;
                document.querySelectorAll('script:not([src])').forEach(function(s){
                    var t = s.textContent || '';
                    if (t.indexOf('document.write') >= 0) inlineDocWrite = true;
                    var re = /typeof\\s+(?:window\\.)?([a-zA-Z_$][\\w$]*)\\s*===?\\s*['"]undefined['"]/g;
                    var m;
                    while ((m = re.exec(t)) !== null) {
                        if (m[1] && guardedGlobals.indexOf(m[1]) < 0) guardedGlobals.push(m[1]);
                    }
                    if (scriptBudget > 0 && t) {
                        var slice = t.length > 24000 ? t.substring(0, 24000) : t;
                        if (slice.length > scriptBudget) slice = slice.substring(0, scriptBudget);
                        scriptBudget -= slice.length;
                        inlineScripts.push(slice);
                    }
                });
                var formFields = [];
                document.querySelectorAll('input[name], textarea[name]').forEach(function(el){
                    var n = el.getAttribute('name');
                    if (n && formFields.indexOf(n) < 0) formFields.push(n);
                });
                var storageKeys = [];
                function collectKeys(store, prefix) {
                    try {
                        for (var i = 0; i < store.length && storageKeys.length < 60; i++) {
                            var k = store.key(i);
                            if (k) storageKeys.push(prefix + k.substring(0, 80));
                        }
                    } catch(e) {}
                }
                collectKeys(localStorage, 'local:');
                collectKeys(sessionStorage, 'session:');
                return JSON.stringify({
                    tabnabbing: blanks.slice(0,40),
                    domFrameworkHints: domFrameworkHints,
                    iframes: iframes.slice(0,40),
                    clobberCandidates: clobber.slice(0,40),
                    frameworkGlobals: Array.from(new Set(globals)),
                    inlineDocumentWrite: inlineDocWrite,
                    guardedGlobals: guardedGlobals.slice(0, 24),
                    formFieldNames: formFields.slice(0, 40),
                    storageKeys: storageKeys,
                    inlineScripts: inlineScripts,
                    location: location.href,
                    origin: location.origin
                });
            })()
            """);

        var swJson = await _ctx.ExecuteJs("""
            (async function(){
                var regs = [];
                try {
                    if (navigator.serviceWorker) {
                        var list = await navigator.serviceWorker.getRegistrations();
                        for (var i=0;i<list.length;i++){
                            var r = list[i];
                            var worker = r.active || r.installing || r.waiting;
                            regs.push({
                                scope: r.scope,
                                active: !!(r.active),
                                waiting: !!(r.waiting),
                                scriptUrl: worker && worker.scriptURL ? String(worker.scriptURL).substring(0, 300) : ''
                            });
                        }
                    }
                } catch(e){}
                var controllerScriptUrl = '';
                try {
                    if (navigator.serviceWorker && navigator.serviceWorker.controller)
                        controllerScriptUrl = String(navigator.serviceWorker.controller.scriptURL || '').substring(0, 300);
                } catch(e){}
                var caches = [];
                try {
                    if (self.caches && caches.keys) {
                        var keys = await caches.keys();
                        caches = keys.slice(0,40);
                    }
                } catch(e){}
                var idb = [];
                try {
                    if (indexedDB.databases) {
                        var dbs = await indexedDB.databases();
                        for (var d = 0; d < dbs.length && d < 20; d++) {
                            if (dbs[d] && dbs[d].name) idb.push(String(dbs[d].name).substring(0, 80));
                        }
                    }
                } catch(e){}
                return JSON.stringify({ serviceWorkers: regs, cacheNames: caches, indexedDb: idb, controllerScriptUrl: controllerScriptUrl });
            })()
            """);

        await Task.Delay(Math.Clamp(waitMs, 0, 5_000));

        var events = useExistingRuntimeBuffer
            ? _ctx.ActiveTab.RuntimeEvents.All().ToList()
            : scopeToCurrentDocument
                ? _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(observationMark).ToList()
                : _ctx.ActiveTab.RuntimeEvents.All().ToList();
        var sinks = events.Where(e => e.Kind == "sink")
            .Where(e => !RuntimeInstrumentationFilter.IsToolArtifactSink(e.Name, e.Stack, e.Data))
            .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ClientSurfaceSink
            {
                Name = g.Key,
                Count = g.Count(),
                SampleStack = g.Select(x => x.Stack).FirstOrDefault(s => !string.IsNullOrEmpty(s)),
                SampleData = g.Select(x => x.Data).FirstOrDefault(d => !string.IsNullOrEmpty(d)),
                ToolArtifact = false
            }).OrderByDescending(s => s.Count).ToList();

        var sources = events.Where(e => e.Kind == "source")
            .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ClientSurfaceSource { Name = g.Key, Count = g.Count() })
            .OrderByDescending(s => s.Count).ToList();

        var listenerEvents = events.Where(e => e.Kind == "listener")
            .Where(e => !RuntimeInstrumentationFilter.IsHostOrSensorListener(e.Stack, e.Data))
            .ToList();
        var webSocketEvents = listenerEvents.Where(IsWebSocketListener).ToList();
        var listeners = listenerEvents.Where(e => !IsWebSocketListener(e))
            .GroupBy(e => (e.Data ?? "") + "\n" + (e.DocumentUrl ?? ""), StringComparer.Ordinal)
            .Select(g =>
            {
                var first = g.First();
                var grade = PostMessageAuditor.GradeOriginCheck(first.Data);
                return new ClientSurfaceListener
                {
                    Type = first.Name,
                    OriginCheck = grade,
                    HandlerPreview = Truncate(first.Data, 240),
                    Stack = Truncate(first.Stack, 400),
                    FrameOrigin = first.FrameOrigin,
                    DocumentUrl = first.DocumentUrl
                };
            })
            .ToList();

        ClientSurfaceDomFacts? dom = null;
        try
        {
            using var doc = JsonDocument.Parse(Unquote(domJson));
            var root = doc.RootElement;
            var iframes = ReadIframes(root)
                .Where(i => !RuntimeInstrumentationFilter.IsClickjackProbeIframe(i.Src))
                .ToList();
            dom = new ClientSurfaceDomFacts
            {
                TabnabbingLinks = ReadTabnabbing(root),
                Iframes = iframes,
                ClobberCandidates = ReadClobber(root),
                FrameworkGlobals = root.TryGetProperty("frameworkGlobals", out var fg) && fg.ValueKind == JsonValueKind.Array
                    ? fg.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).Distinct().ToList()
                    : [],
                InlineDocumentWrite = root.TryGetProperty("inlineDocumentWrite", out var idw)
                                      && idw.ValueKind == JsonValueKind.True,
                FormFieldNames = root.TryGetProperty("formFieldNames", out var ff) && ff.ValueKind == JsonValueKind.Array
                    ? ff.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                    : [],
                StorageKeys = root.TryGetProperty("storageKeys", out var sk) && sk.ValueKind == JsonValueKind.Array
                    ? sk.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                    : [],
                InlineScripts = root.TryGetProperty("inlineScripts", out var scripts) && scripts.ValueKind == JsonValueKind.Array
                    ? scripts.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                    : [],
                GuardedGlobals = root.TryGetProperty("guardedGlobals", out var gg) && gg.ValueKind == JsonValueKind.Array
                    ? gg.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).Distinct().ToList()
                    : [],
                DomFrameworkHints = root.TryGetProperty("domFrameworkHints", out var dfh) && dfh.ValueKind == JsonValueKind.Array
                    ? dfh.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).Distinct().ToList()
                    : []
            };
        }
        catch { dom = new ClientSurfaceDomFacts(); }

        ClientSurfaceServiceWorkers? swInfo = null;
        try
        {
            using var doc = JsonDocument.Parse(Unquote(swJson));
            var root = doc.RootElement;
            swInfo = new ClientSurfaceServiceWorkers
            {
                Registrations = root.TryGetProperty("serviceWorkers", out var regs) && regs.ValueKind == JsonValueKind.Array
                    ? regs.EnumerateArray().Select(r => new ClientSurfaceSwReg
                    {
                        Scope = r.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "",
                        ScriptUrl = r.TryGetProperty("scriptUrl", out var su) ? su.GetString() ?? "" : "",
                        Active = r.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True
                    }).ToList()
                    : [],
                CacheNames = root.TryGetProperty("cacheNames", out var cn) && cn.ValueKind == JsonValueKind.Array
                    ? cn.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                    : [],
                IndexedDbNames = root.TryGetProperty("indexedDb", out var idb) && idb.ValueKind == JsonValueKind.Array
                    ? idb.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                    : [],
                ControllerScriptUrl = root.TryGetProperty("controllerScriptUrl", out var ctrl)
                    ? ctrl.GetString() ?? ""
                    : ""
            };
        }
        catch { swInfo = new ClientSurfaceServiceWorkers(); }

        var filteredEvents = events
            .Where(e => e.Kind != "sink"
                        || !RuntimeInstrumentationFilter.IsToolArtifactSink(e.Name, e.Stack, e.Data))
            .ToList();
        pageUrl = UrlPayloadInjector.StripToolQueryParams(await SafeUrl());
        listeners = listeners.Where(l => ListenerStillOnDocument(l.DocumentUrl, pageUrl)).ToList();
        var sameOriginIframeCount = dom?.Iframes.Count(i => i.SameOrigin) ?? 0;
        var (externalScriptEntries, externalScriptBodiesScanned) = CountExternalScriptCoverage(pageUrl);
        var scriptFacts = ClientScriptTextScanner.Scan(
            (dom?.InlineScripts ?? []).Concat(SameOriginScriptBodies(pageUrl)));
        var runtimeSeen = sources.Count + sinks.Count + listeners.Count > 0
                          || filteredEvents.Any(e => e.Kind is "gadget-read" or "proto-read");
        var coverageSurfaces = new ClientSurfaceCoverageSurfaces
        {
            RuntimeObserved = runtimeSeen,
            InlineScriptScanned = dom?.InlineScripts.Count > 0,
            ExternalScriptEntriesInLog = externalScriptEntries,
            ExternalScriptBodiesScanned = externalScriptBodiesScanned,
            DocumentHeadersFromNetwork = PageHasDocumentResponse(pageUrl),
            DomFrameworkHints = dom?.DomFrameworkHints ?? []
        };
        var hasPageLocalXsLead = scriptFacts.UsesWebSocket
                                 || webSocketEvents.Count > 0
                                 || (swInfo?.Registrations.Count ?? 0) > 0
                                 || scriptFacts.RegistersServiceWorker;
        var cells = BuildCells(filteredEvents, sources, sinks, listeners);
        var domFlows = DomFlowGraph.BuildChains(filteredEvents);
        var plan = ClientSurfaceRiskPlanner.Build(new ClientSurfaceRiskEvidence
        {
            RuntimeSeen = runtimeSeen,
            ScriptSurfaceIncomplete = coverageSurfaces.ScriptSurfaceIncomplete,
            DomFrameworkHints = dom?.DomFrameworkHints ?? [],
            Sources = sources.Select(s => s.Name).ToList(),
            Sinks = sinks.Select(s => s.Name).ToList(),
            Listeners = listeners.Select(l => (l.Type, l.OriginCheck)).ToList(),
            Cells = cells.Select(c => (c.Source, c.Sink, c.Status)).ToList(),
            Flows = domFlows.Select(f => (f.Source, f.Sink, f.Consequence, f.Tier)).ToList(),
            TabnabbingHygieneCount = dom?.TabnabbingLinks.Count ?? 0,
            ClobberIds = dom?.ClobberCandidates.Select(c => c.Id).Where(id => id.Length > 0).ToList() ?? [],
            FrameworkGlobals = dom?.FrameworkGlobals ?? [],
            InlineDocumentWrite = dom?.InlineDocumentWrite ?? false,
            FormFieldNames = dom?.FormFieldNames ?? [],
            StorageKeys = dom?.StorageKeys ?? [],
            StorageKeysTouched = StorageKeysTouchedSince(filteredEvents),
            ServiceWorkerScopes = swInfo?.Registrations.Select(r => r.Scope).Where(s => s.Length > 0).ToList() ?? [],
            ServiceWorkerScriptUrls = swInfo?.Registrations.Select(r => r.ScriptUrl).Where(s => s.Length > 0).Distinct().ToList() ?? [],
            ControllingWorkerScriptUrl = string.IsNullOrWhiteSpace(swInfo?.ControllerScriptUrl) ? null : swInfo!.ControllerScriptUrl,
            ServiceWorkerRegisteredByDocument = scriptFacts.RegistersServiceWorker,
            IndexedDbNames = swInfo?.IndexedDbNames ?? [],
            GadgetReadCount = filteredEvents.Count(e => e.Kind.Equals("gadget-read", StringComparison.OrdinalIgnoreCase)),
            ProtoReadCount = filteredEvents.Count(e => e.Kind.Equals("proto-read", StringComparison.OrdinalIgnoreCase)),
            WebSocketListeners = webSocketEvents.Count,
            WebSocketEvaluates = webSocketEvents.Any(e =>
                (e.Data ?? "").Contains("eval", StringComparison.OrdinalIgnoreCase)
                || (e.Data ?? "").Contains("Function", StringComparison.Ordinal)),
            Script = scriptFacts,
            LoadObserved = loadObserved,
            SameOriginIframeCount = sameOriginIframeCount,
            HasPageLocalXsLead = hasPageLocalXsLead,
            Network = ClientSurfaceNetworkSignals.From(_ctx.Network.PageEntries, pageUrl)
        });

        var shadowCount = _ctx.SecurityShadow?.GetFindings()?.Count ?? 0;

        sw.Stop();
        return new ClientSurfaceResult
        {
            ElapsedMs = sw.ElapsedMilliseconds,
            Url = pageUrl,
            LoadObserved = loadObserved,
            SensorInstalled = _ctx.ActiveTab.RuntimeEvents.Installed,
            Sources = sources,
            Sinks = sinks,
            Listeners = listeners,
            Dom = dom ?? new ClientSurfaceDomFacts(),
            ServiceWorkers = swInfo ?? new ClientSurfaceServiceWorkers(),
            Cells = cells,
            DomFlows = domFlows,
            Script = scriptFacts,
            Risks = plan.Risks,
            NextActions = plan.NextActions,
            ShadowFindingCount = shadowCount,
            WhisperClueCount = _ctx.RedTeamWhisper?.LastClues?.Count ?? 0,
            Coverage = new ClientScanCoverage
            {
                Instrumented = RuntimeSensorScript.InstrumentedSinks.ToList(),
                SourcesSeen = sources.Select(s => s.Name).ToList(),
                SinksSeen = sinks.Select(s => s.Name).ToList(),
                ListenersSeen = listeners.Select(l => l.Type).Distinct().ToList(),
                Untested = cells.Where(c => c.Status == "untested")
                    .Select(c => $"{c.Source}->{c.Sink} ({c.Status})").Take(30).ToList(),
                ZeroResultReason = sinks.Count == 0 && listeners.Count == 0
                    ? "no-runtime-events-browse-more-or-enable-shadow-runtime"
                    : null,
                Surfaces = coverageSurfaces
            }
        };
    }

    private async Task<string> SafeUrl()
    {
        try { return await _ctx.GetCurrentUrl(); }
        catch { return _ctx.ActiveTab.Url; }
    }

    internal static string DocumentScopeKey(string? pageUrl)
    {
        pageUrl = UrlPayloadInjector.StripToolQueryParams(pageUrl);
        if (string.IsNullOrWhiteSpace(pageUrl)
            || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
            return pageUrl ?? "";

        return uri.GetLeftPart(UriPartial.Authority)
               + NormalizePath(uri)
               + uri.Fragment;
    }

    private static List<ClientSurfaceCell> BuildCells(
        IReadOnlyList<RuntimeEvent> events,
        List<ClientSurfaceSource> sources,
        List<ClientSurfaceSink> sinks,
        List<ClientSurfaceListener> listeners)
    {
        var cells = new List<ClientSurfaceCell>();
        var sourceNames = sources.Select(s => s.Name).ToList();
        if (listeners.Any(l => l.Type == "message" && l.OriginCheck != "instrumentation"))
            sourceNames.Add("postMessage");
        sourceNames = sourceNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (sourceNames.Count == 0)
            sourceNames.AddRange(["url", "postMessage", "storage"]);

        var sinkNames = sinks.Select(s => s.Name).ToList();
        if (sinkNames.Count == 0)
            sinkNames.AddRange(["innerHTML", "eval", "location.assign"]);

        foreach (var src in sourceNames.Take(12))
        foreach (var sink in sinkNames.Take(12))
        {
            cells.Add(new ClientSurfaceCell
            {
                Source = src,
                Sink = sink,
                Status = RuntimeEventCorrelation.ClassifyCell(src, sink, events)
            });
        }
        return cells;
    }

    private static List<ClientSurfaceTabnabbing> ReadTabnabbing(JsonElement root)
    {
        if (!root.TryGetProperty("tabnabbing", out var arr) || arr.ValueKind != JsonValueKind.Array) return [];
        return arr.EnumerateArray().Select(x => new ClientSurfaceTabnabbing
        {
            Href = x.TryGetProperty("href", out var h) ? h.GetString() ?? "" : "",
            Text = x.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "",
            NavigationKind = x.TryGetProperty("navigationKind", out var nk) ? nk.GetString() ?? "" : "",
            MissingExplicitRel = x.TryGetProperty("missingExplicitRel", out var mer)
                                 && mer.ValueKind == JsonValueKind.True,
            EffectiveOpenerPolicy = x.TryGetProperty("effectiveOpenerPolicy", out var eop) ? eop.GetString() ?? "" : ""
        }).ToList();
    }

    private static List<ClientSurfaceIframe> ReadIframes(JsonElement root)
    {
        if (!root.TryGetProperty("iframes", out var arr) || arr.ValueKind != JsonValueKind.Array) return [];
        return arr.EnumerateArray().Select(x => new ClientSurfaceIframe
        {
            Src = x.TryGetProperty("src", out var s) ? s.GetString() ?? "" : "",
            SameOrigin = x.TryGetProperty("sameOrigin", out var so) && so.ValueKind == JsonValueKind.True,
            Name = x.TryGetProperty("name", out var n) ? n.GetString() ?? "" : ""
        }).ToList();
    }

    private static List<ClientSurfaceClobber> ReadClobber(JsonElement root)
    {
        if (!root.TryGetProperty("clobberCandidates", out var arr) || arr.ValueKind != JsonValueKind.Array) return [];
        return arr.EnumerateArray().Select(x => new ClientSurfaceClobber
        {
            Id = x.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "",
            Tag = x.TryGetProperty("tag", out var t) ? t.GetString() ?? "" : ""
        }).ToList();
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

    private static bool IsWebSocketListener(RuntimeEvent evt)
    {
        if (!evt.Name.Equals("message", StringComparison.OrdinalIgnoreCase))
            return false;
        return evt.Extra.TryGetValue("target", out var target)
               && target != null
               && target.Equals("websocket", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Drop listeners tagged with a document that is no longer the current one (path and hash).</summary>
    internal static bool ListenerStillOnDocument(string? capturedOnUrl, string? pageUrl)
    {
        if (string.IsNullOrWhiteSpace(capturedOnUrl))
            return false;
        if (string.IsNullOrWhiteSpace(pageUrl))
            return true;
        if (!Uri.TryCreate(capturedOnUrl, UriKind.Absolute, out var captured))
            return true;
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var current))
            return true;
        return string.Equals(captured.GetLeftPart(UriPartial.Authority), current.GetLeftPart(UriPartial.Authority),
                   StringComparison.OrdinalIgnoreCase)
               && string.Equals(NormalizePath(captured), NormalizePath(current), StringComparison.OrdinalIgnoreCase)
               && string.Equals(captured.Fragment, current.Fragment, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (path.Length > 1 && path.EndsWith('/'))
            path = path[..^1];
        return path.Length == 0 ? "/" : path;
    }

    private List<string> SameOriginScriptBodies(string? pageUrl)
    {
        var host = "";
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var page))
            host = page.Host;
        var bodies = new List<string>();
        foreach (var entry in _ctx.Network.Entries)
        {
            if (entry.IsTrowserGenerated || string.IsNullOrEmpty(entry.ResponseBody)) continue;
            if (!entry.ResourceType.Equals("Script", StringComparison.OrdinalIgnoreCase)
                && !entry.ContentType.Contains("javascript", StringComparison.OrdinalIgnoreCase))
                continue;
            if (host.Length > 0 && Uri.TryCreate(entry.Url, UriKind.Absolute, out var u) && !u.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (IsVendorScript(entry.Url)) continue;
            var body = entry.ResponseBody.Length > 48_000 ? entry.ResponseBody[..48_000] : entry.ResponseBody;
            bodies.Add(body);
            if (bodies.Count >= 6) break;
        }
        return bodies;
    }

    private bool PageHasDocumentResponse(string? pageUrl)
    {
        var host = "";
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var page))
            host = page.Host;
        return _ctx.Network.PageEntries.Any(e =>
            e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase)
            && (host.Length == 0
                || (Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                    && u.Host.Equals(host, StringComparison.OrdinalIgnoreCase))));
    }

    private (int EntriesInLog, int BodiesScanned) CountExternalScriptCoverage(string? pageUrl)
    {
        var host = "";
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var page))
            host = page.Host;
        var entries = 0;
        var scanned = 0;
        foreach (var entry in _ctx.Network.Entries)
        {
            if (entry.IsTrowserGenerated) continue;
            if (!entry.ResourceType.Equals("Script", StringComparison.OrdinalIgnoreCase)
                && !entry.ContentType.Contains("javascript", StringComparison.OrdinalIgnoreCase))
                continue;
            if (host.Length > 0 && Uri.TryCreate(entry.Url, UriKind.Absolute, out var u)
                && !u.Host.Equals(host, StringComparison.OrdinalIgnoreCase))
                continue;
            entries++;
            if (!string.IsNullOrEmpty(entry.ResponseBody) && !IsVendorScript(entry.Url))
                scanned++;
            if (scanned >= 6) break;
        }
        return (entries, Math.Min(scanned, 6));
    }

    private static bool IsVendorScript(string url)
    {
        var path = url.ToLowerInvariant();
        return path.Contains("react") || path.Contains("vue") || path.Contains("jquery")
               || path.Contains("angular") || path.Contains("polyfill") || path.Contains("vendor")
               || path.Contains("node_modules");
    }

    private static List<string> StorageKeysTouchedSince(IReadOnlyList<RuntimeEvent> events)
    {
        var keys = new List<string>();
        foreach (var evt in events)
        {
            if (!evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase)) continue;
            string? prefix = null;
            if (evt.Name.StartsWith("localStorage.", StringComparison.OrdinalIgnoreCase))
                prefix = "local:";
            else if (evt.Name.StartsWith("sessionStorage.", StringComparison.OrdinalIgnoreCase))
                prefix = "session:";
            if (prefix == null) continue;
            if (!evt.Name.Contains("getItem", StringComparison.OrdinalIgnoreCase)
                && !evt.Name.Contains("setItem", StringComparison.OrdinalIgnoreCase))
                continue;
            var data = evt.Data ?? "";
            var eq = data.IndexOf('=');
            var key = (eq >= 0 ? data[..eq] : data).Trim();
            if (key.Length == 0) continue;
            var labeled = prefix + key;
            if (!keys.Contains(labeled, StringComparer.OrdinalIgnoreCase))
                keys.Add(labeled);
        }
        return keys;
    }
}

public sealed class ClientSurfaceResult
{
    public long ElapsedMs { get; init; }
    public string Url { get; init; } = "";
    public bool SensorInstalled { get; init; }
    /// <summary>False when the sensor was installed after this document loaded (reload recommended).</summary>
    public bool LoadObserved { get; init; } = true;
    public List<ClientSurfaceSource> Sources { get; init; } = [];
    public List<ClientSurfaceSink> Sinks { get; init; } = [];
    public List<ClientSurfaceListener> Listeners { get; init; } = [];
    public ClientSurfaceDomFacts Dom { get; init; } = new();
    public ClientSurfaceServiceWorkers ServiceWorkers { get; init; } = new();
    public List<ClientSurfaceCell> Cells { get; init; } = [];
    public List<DomFlowGraph.DomFlowChain> DomFlows { get; init; } = [];
    /// <summary>Static script hints (sinks and location params that did not have to run).</summary>
    public ClientScriptTextFacts Script { get; init; } = new();
    /// <summary>Triage clues. Status is dismiss, lead, pursue, or manual. Not confirmed findings.</summary>
    public List<ClientSurfaceRisk> Risks { get; init; } = [];
    public List<string> NextActions { get; init; } = [];
    public int ShadowFindingCount { get; init; }
    public int WhisperClueCount { get; init; }
    public ClientScanCoverage Coverage { get; init; } = new();

    public object ToApiResponse() => new
    {
        message = "Client-side attack surface mapped",
        elapsedMs = ElapsedMs,
        url = Url,
        sensorInstalled = SensorInstalled,
        loadObserved = LoadObserved,
        sources = Sources,
        sinks = Sinks,
        listeners = Listeners,
        dom = Dom,
        serviceWorkers = ServiceWorkers,
        cells = Cells,
        domFlows = DomFlows,
        scriptSignals = Script,
        risks = Risks,
        riskSummary = new
        {
            pursue = Risks.Count(r => r.Status == ClientSurfaceRiskPlanner.Pursue),
            lead = Risks.Count(r => r.Status == ClientSurfaceRiskPlanner.Lead),
            manual = Risks.Count(r => r.Status == ClientSurfaceRiskPlanner.Manual),
            notObserved = Risks.Count(r => r.Status == ClientSurfaceRiskPlanner.NotObserved),
            dismiss = Risks.Count(r => r.Status == ClientSurfaceRiskPlanner.Dismiss)
        },
        nextActions = NextActions,
        shadowFindingCount = ShadowFindingCount,
        whisperClueCount = WhisperClueCount,
        coverage = Coverage.ToApiObject()
    };
}

public sealed class ClientSurfaceSource
{
    public string Name { get; init; } = "";
    public int Count { get; init; }
}

public sealed class ClientSurfaceSink
{
    public string Name { get; init; } = "";
    public int Count { get; init; }
    public string? SampleStack { get; init; }
    public string? SampleData { get; init; }
    public bool ToolArtifact { get; init; }
}

public sealed class ClientSurfaceListener
{
    public string Type { get; init; } = "";
    public string OriginCheck { get; init; } = "unknown";
    public string? HandlerPreview { get; init; }
    public string? Stack { get; init; }
    public string? FrameOrigin { get; init; }
    /// <summary>Document URL that registered the listener. Empty when the sensor did not tag it.</summary>
    public string? DocumentUrl { get; init; }
}

public sealed class ClientSurfaceCell
{
    public string Source { get; init; } = "";
    public string Sink { get; init; } = "";
    public string Status { get; init; } = "untested";
}

public sealed class ClientSurfaceDomFacts
{
    public List<ClientSurfaceTabnabbing> TabnabbingLinks { get; init; } = [];
    public List<ClientSurfaceIframe> Iframes { get; init; } = [];
    public List<ClientSurfaceClobber> ClobberCandidates { get; init; } = [];
    public List<string> FrameworkGlobals { get; init; } = [];
    public List<string> DomFrameworkHints { get; init; } = [];
    public bool InlineDocumentWrite { get; init; }
    public List<string> FormFieldNames { get; init; } = [];
    /// <summary>Names from <c>typeof window.X === "undefined"</c> initialization guards in inline scripts.</summary>
    public List<string> GuardedGlobals { get; init; } = [];
    /// <summary>localStorage/sessionStorage key names only (local: / session: prefix). Values are not read.</summary>
    public List<string> StorageKeys { get; init; } = [];
    /// <summary>Inline script source, capped. Feeds the checklist; omitted from the API payload.</summary>
    [JsonIgnore]
    public List<string> InlineScripts { get; init; } = [];
}

public sealed class ClientSurfaceTabnabbing
{
    public string Href { get; init; } = "";
    public string Text { get; init; } = "";
    public string NavigationKind { get; init; } = "";
    public bool MissingExplicitRel { get; init; }
    public string EffectiveOpenerPolicy { get; init; } = "";
}

public sealed class ClientSurfaceIframe
{
    public string Src { get; init; } = "";
    public bool SameOrigin { get; init; }
    public string Name { get; init; } = "";
}

public sealed class ClientSurfaceClobber
{
    public string Id { get; init; } = "";
    public string Tag { get; init; } = "";
}

public sealed class ClientSurfaceServiceWorkers
{
    public List<ClientSurfaceSwReg> Registrations { get; init; } = [];
    public List<string> CacheNames { get; init; } = [];
    public List<string> IndexedDbNames { get; init; } = [];
    /// <summary>scriptURL of the worker currently controlling this document, if any.</summary>
    public string ControllerScriptUrl { get; init; } = "";
}

public sealed class ClientSurfaceSwReg
{
    public string Scope { get; init; } = "";
    public string ScriptUrl { get; init; } = "";
    public bool Active { get; init; }
}
