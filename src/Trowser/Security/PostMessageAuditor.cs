using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Enumerate message listeners, grade origin checks, screen with synthetic MessageEvents,
/// and confirm with mocked attacker-origin technique probes at safetyMode active.
/// </summary>
public sealed class PostMessageAuditor
{
    private readonly AutomationContext _ctx;
    private string? _activeAttackerOrigin;

    public PostMessageAuditor(AutomationContext context) => _ctx = context;

    private static string? ResolveAttackerOrigin(
        PostMessageAuditOptions options,
        IReadOnlyList<PostMessageListenerInfo> listeners)
    {
        if (!string.IsNullOrWhiteSpace(options.AttackerOrigin))
            return options.AttackerOrigin.Trim();

        foreach (var l in listeners)
        {
            var src = l.HandlerFullSource ?? l.HandlerPreview ?? "";
            if (src.Contains("trusted-app.example", StringComparison.OrdinalIgnoreCase))
                return "https://trusted-app.example.evil.trowser.test";
        }

        return null;
    }

    public Task<PostMessageAuditResult> RunAsync(
        string safetyMode = "safe",
        bool fuzz = true,
        int maxPayloads = 8) =>
        RunAsync(new PostMessageAuditOptions
        {
            SafetyMode = safetyMode,
            Fuzz = fuzz,
            MaxPayloads = maxPayloads
        });

    public async Task<PostMessageAuditResult> RunAsync(PostMessageAuditOptions options)
    {
        var sw = Stopwatch.StartNew();
        var runId = Guid.NewGuid().ToString("N")[..10];
        var safetyMode = options.SafetyMode ?? "safe";
        var depth = SecurityScanDepth.Normalize(options.Depth);
        var isActive = safetyMode is "active" or "aggressive";

        if (options.Reset)
            _ctx.ActiveTab.RuntimeEvents.Clear();

        await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx, RuntimeSensorProfile.Active);
        _ = _ctx.ActiveTab.RuntimeEvents.Mark();
        await EnsureIframesLoadedForAuditAsync();

        var victimOrigin = await TryGetPageOriginAsync();
        var posture = await BuildPostureAsync(victimOrigin);
        List<PostMessageListenerInfo> listeners;
        string? frameEnumNote = null;
        string? restoreUrl = null;
        try
        {
            listeners = await CollectListenersAsync();
            if (options.DescendIframes && listeners.Count == 0)
            {
                restoreUrl = await _ctx.GetCurrentUrl();
                listeners = await CollectListenersViaIframeDescentAsync(restoreUrl);
                if (listeners.Count > 0)
                    frameEnumNote = "iframe-descent";
            }
        }
        catch (Exception ex) when (ex.Message.Contains("Frame5", StringComparison.OrdinalIgnoreCase)
                                   || ex.Message.Contains("ICoreWebView2Frame", StringComparison.OrdinalIgnoreCase))
        {
            listeners = CollectListenersFromRuntimeLogOnly();
            frameEnumNote = "failed-webview-version";
        }

        var pageUrl = UrlPayloadInjector.StripToolQueryParams(await _ctx.GetCurrentUrl());
        var staleDropped = MarkAndFilterStaleListeners(listeners, await TryGetPageOriginAsync(), pageUrl, dropFromList: !options.IncludeHistory);
        listeners = ApplyListenerFilter(listeners, options.ListenerFilter);
        listeners = EnrichListenerGrades(listeners);

        if (listeners.Any(l => l.Via == "inline-script"))
        {
            listeners.RemoveAll(l => l.Via == "runtime-event-log"
                                     && (l.HandlerFullSource ?? l.HandlerPreview ?? "").Length < 120);
        }

        var techniques = new List<PostMessageTechniqueResult>();
        var findings = new List<UnifiedSecurityFinding>();
        var fuzzHits = new List<PostMessageFuzzHit>();
        var budgetExhausted = false;
        var sessionLostDuringScan = false;
        string? sessionLostReason = null;
        var popupTabsOpened = 0;
        var orphanPopupTabsClosed = 0;

        if (options.SuggestOnly)
        {
            sw.Stop();
            return BuildResult(_ctx, sw, runId, depth, listeners, fuzzHits, findings, techniques, posture,
                budgetExhausted, suggestOnly: true, frameEnumeration: frameEnumNote, staleListenersDropped: staleDropped);
        }

        foreach (var l in listeners.Where(l => !l.Stale && l.OriginCheck is "none" or "weak"))
        {
            var handler = l.HandlerFullSource ?? l.HandlerPreview ?? "";
            var ck = l.CheckKind ?? PostMessageOriginGrader.Analyze(handler).CheckKind;
            if (ck == "data-gate-only")
                continue;
            if (!string.IsNullOrEmpty(PostMessagePayloadInference.InferMessageSchema(handler).TypeLiteral))
                continue;
            findings.Add(BuildHygieneFinding(l, pageUrl));
        }

        if (options.IncludeOutbound)
        {
            var oauthSession = PostMessageOAuthShape.SessionHasOAuthTraffic(_ctx);
            findings.AddRange(PostMessageOutboundAnalyzer.Analyze(_ctx, victimOrigin, oauthSession));
        }

        if (options.Fuzz && listeners.Count > 0)
            await RunSyntheticFuzzAsync(listeners, options, runId, findings, fuzzHits);

        if (isActive && listeners.Count > 0)
        {
            _activeAttackerOrigin = ResolveAttackerOrigin(options, listeners);
            var victimTab = _ctx.ActiveTab;
            var victimHost = Uri.TryCreate(victimTab.Url, UriKind.Absolute, out var victimUri)
                ? victimUri.Host
                : "";
            var tabScope = SecurityScanTabScope.Begin(_ctx);
            try
            {
                var topologies = ResolveTopologies(options, depth, posture);
                foreach (var topology in topologies)
                {
                    if (options.MaxSeconds > 0 && sw.Elapsed.TotalSeconds >= options.MaxSeconds)
                    {
                        budgetExhausted = true;
                        break;
                    }

                    foreach (var listener in listeners.Where(l => ShouldRunActiveForDepth(l, depth)))
                    {
                        if (options.MaxSeconds > 0 && sw.Elapsed.TotalSeconds >= options.MaxSeconds)
                        {
                            budgetExhausted = true;
                            break;
                        }

                        var canary = $"__trowser_pm_{runId}__";
                        var canaryHtml = $"<img src=x data-trowser-canary=\"{canary}\">";
                        var handlerForPayloads = listener.HandlerFullSource ?? listener.HandlerPreview;
                        var payloads = PostMessagePayloadInference.BuildPayloadsForListener(
                            handlerForPayloads, canaryHtml, options.MaxPayloadsPerListener);

                        foreach (var payload in payloads)
                        {
                            var tech = await RunActiveTopologyAsync(
                                topology, runId, payload, canary, listener, posture, fuzzHits, victimTab);
                            techniques.Add(tech);
                            if (tech.Verdict == "sink-reached" && tech.Confidence == SecurityConfidence.Confirmed)
                            {
                                findings.Add(UnifiedSecurityFinding.Create(
                                    category: "postmessage",
                                    title: "Attacker-origin postMessage reached a dangerous sink",
                                    severity: "critical",
                                    confidence: SecurityConfidence.Confirmed,
                                    tier: SecurityFindingTier.Exploitable,
                                    payload: Truncate(payload, 120),
                                    evidence: tech.Detail,
                                    proofHint: "Trusted cross-origin delivery; confirm origin check on handler",
                                    nextActions: [SecurityNextActions.VerifyWorkflow],
                                    extra: new Dictionary<string, object?>
                                    {
                                        ["isTrusted"] = true,
                                        ["activeProof"] = true,
                                        ["topology"] = topology,
                                        ["listenerId"] = listener.ListenerId
                                    }));
                            }

                            await tabScope.CloseProbePopupsAsync(victimHost, runId);
                        }
                    }
                }

                if (!string.IsNullOrEmpty(victimHost)
                    && !await tabScope.IsHomeSessionIntactAsync(victimHost, "unknown"))
                {
                    sessionLostDuringScan = true;
                    sessionLostReason = "home-tab-session-not-intact";
                }

                PostMessageActiveReconciliation.Apply(findings, techniques);
                PostMessageActiveReconciliation.EnrichFindingEvidence(findings, techniques);
            }
            finally
            {
                var stats = await tabScope.FinishAsync(victimHost, runId);
                popupTabsOpened = stats.Opened;
                orphanPopupTabsClosed = stats.Closed;
            }
        }

        if (!string.IsNullOrWhiteSpace(restoreUrl))
        {
            try
            {
                await _ctx.Navigate(restoreUrl);
                await _ctx.WaitForIdle(250, 8000);
            }
            catch { /* best-effort restore after iframe descent */ }
        }

        sw.Stop();
        return BuildResult(_ctx, sw, runId, depth, listeners, fuzzHits, findings, techniques, posture,
            budgetExhausted, suggestOnly: false, sessionLostDuringScan, sessionLostReason, popupTabsOpened,
            orphanPopupTabsClosed, frameEnumNote, staleListenersDropped: staleDropped);
    }

    public static string GradeOriginCheck(string? handlerSource) =>
        PostMessageOriginGrader.GradeOriginCheck(handlerSource);

    private static bool ShouldActiveProbe(PostMessageListenerInfo l) =>
        l.OriginCheck is "none" or "weak" or "unknown"
        || (l.OriginCheck == "strict"
            && l.CheckKind is not ("literal-origin-compare" or "message-source-ref"));

    private static bool ShouldRunActiveForDepth(PostMessageListenerInfo l, string depth)
    {
        var checkKind = l.CheckKind
                        ?? PostMessageOriginGrader.Analyze(l.HandlerFullSource ?? l.HandlerPreview).CheckKind;
        if (checkKind == "data-gate-only")
            return false;
        if (!ShouldActiveProbe(l))
            return false;
        if (string.Equals(depth, SecurityScanDepth.Deep, StringComparison.OrdinalIgnoreCase))
            return true;
        var grade = PostMessageOriginGrader.Analyze(l.HandlerFullSource ?? l.HandlerPreview);
        return PostMessageOriginGrader.ShouldRunSyntheticScreen(grade);
    }

    private static List<PostMessageListenerInfo> EnrichListenerGrades(List<PostMessageListenerInfo> listeners)
    {
        foreach (var l in listeners)
        {
            var grade = PostMessageOriginGrader.Analyze(l.HandlerFullSource ?? l.HandlerPreview);
            l.OriginCheck = grade.Grade;
            l.CheckKind = grade.CheckKind;
            l.OriginLiterals = grade.Literals;
            l.ListenerId = $"pm-{HashCode.Combine(l.Via, l.HandlerPreview ?? "").ToString("x8")}";
            l.InferredSchema = PostMessagePayloadInference.InferMessageSchema(l.HandlerFullSource ?? l.HandlerPreview);
        }

        return listeners;
    }

    private List<PostMessageListenerInfo> CollectListenersFromRuntimeLogOnly()
    {
        var listeners = new List<PostMessageListenerInfo>();
        foreach (var evt in _ctx.ActiveTab.RuntimeEvents.OfKind("listener")
                     .Where(e => e.Name.Equals("message", StringComparison.OrdinalIgnoreCase)))
        {
            if (RuntimeInstrumentationFilter.IsHostOrSensorListener(evt.Stack, evt.Data))
                continue;
            if (IsWebSocketMessageListener(evt))
                continue;
            listeners.Add(new PostMessageListenerInfo
            {
                Via = "runtime-event-log",
                HandlerFullSource = evt.Data,
                HandlerPreview = Truncate(evt.Data, 400),
                Stack = Truncate(evt.Stack, 500),
                FrameOrigin = evt.FrameOrigin,
                CapturedOnUrl = evt.DocumentUrl
            });
        }

        return listeners;
    }

    private static int MarkAndFilterStaleListeners(
        List<PostMessageListenerInfo> listeners,
        string? pageOrigin,
        string? pageUrl,
        bool dropFromList)
    {
        if (listeners.Count == 0 || string.IsNullOrEmpty(pageOrigin))
            return 0;

        var staleCount = 0;
        for (var i = listeners.Count - 1; i >= 0; i--)
        {
            var l = listeners[i];
            var belongs = ListenerBelongsToCurrentDocument(l, pageOrigin, pageUrl);
            l.Stale = !belongs;
            if (belongs) continue;
            staleCount++;
            if (dropFromList)
                listeners.RemoveAt(i);
        }

        return staleCount;
    }

    private static bool ListenerBelongsToCurrentDocument(
        PostMessageListenerInfo l,
        string pageOrigin,
        string? pageUrl)
    {
        return DocumentMatches(l.CapturedOnUrl, string.IsNullOrEmpty(pageUrl) ? pageOrigin : pageUrl);
    }

    private static bool IsWebSocketMessageListener(Runtime.RuntimeEvent evt) =>
        evt.Extra.TryGetValue("target", out var target)
        && target != null
        && target.Equals("websocket", StringComparison.OrdinalIgnoreCase);

    private static bool DocumentMatches(string? capturedOnUrl, string? pageUrl)
    {
        if (string.IsNullOrEmpty(capturedOnUrl) || string.IsNullOrEmpty(pageUrl))
            return false;
        if (!Uri.TryCreate(capturedOnUrl, UriKind.Absolute, out var cap)
            || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var cur))
            return false;
        return string.Equals(cap.GetLeftPart(UriPartial.Authority), cur.GetLeftPart(UriPartial.Authority),
                   StringComparison.OrdinalIgnoreCase)
               && string.Equals(NormalizePath(cap), NormalizePath(cur), StringComparison.OrdinalIgnoreCase)
               && string.Equals(cap.Fragment, cur.Fragment, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (path.Length > 1 && path.EndsWith('/'))
            path = path[..^1];
        return path;
    }

    private static async Task EnsureIframesLoadedForAuditAsync(AutomationContext ctx)
    {
        try
        {
            await ctx.ExecuteJsAsync("""
                (function(){
                  return new Promise(function(resolve){
                    var pending = 0, done = false;
                    function finish(){ if (!done){ done = true; resolve('ok'); } }
                    document.querySelectorAll('iframe[src]').forEach(function(f){
                      try { if (f.contentDocument && f.contentDocument.readyState === 'complete') return; } catch(e) {}
                      pending++;
                      f.addEventListener('load', function(){ pending--; if (pending <= 0) finish(); }, { once: true });
                    });
                    if (pending === 0) finish();
                    setTimeout(finish, 5000);
                  });
                })()
                """);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
    }

    private async Task EnsureIframesLoadedForAuditAsync() =>
        await EnsureIframesLoadedForAuditAsync(_ctx);

    private async Task<List<string>> GetIframeSrcUrlsAsync()
    {
        var json = await _ctx.ExecuteJs("""
            (function(){
              var out = [];
              document.querySelectorAll('iframe[src]').forEach(function(f){
                try {
                  var u = new URL(f.src, location.href).href;
                  if (u && out.indexOf(u) < 0) out.push(u);
                } catch(e){}
              });
              return JSON.stringify(out.slice(0, 12));
            })()
            """);
        try
        {
            using var doc = JsonDocument.Parse(Unquote(json));
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                return [];
            return doc.RootElement.EnumerateArray()
                .Select(e => e.GetString())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Cast<string>()
                .ToList();
        }
        catch { return []; }
    }

    private async Task<List<PostMessageListenerInfo>> CollectListenersViaIframeDescentAsync(string? parentUrl)
    {
        var merged = new List<PostMessageListenerInfo>();
        var iframeUrls = await GetIframeSrcUrlsAsync();
        if (iframeUrls.Count == 0)
            return merged;

        foreach (var src in iframeUrls)
        {
            try
            {
                await _ctx.Navigate(UrlPayloadInjector.EnsureFullNavigation(src));
                await _ctx.WaitForIdle(300, 12_000);
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_ctx, RuntimeSensorProfile.Active);
                await EnsureIframesLoadedForAuditAsync();
                var found = await CollectListenersAsync();
                foreach (var l in found)
                {
                    l.Via = string.IsNullOrEmpty(l.Via) ? "iframe-descent" : $"iframe-descent:{l.Via}";
                    merged.Add(l);
                }

                if (merged.Count > 0)
                    break;
            }
            catch { /* try next iframe */ }
        }

        return merged
            .GroupBy(l => l.HandlerPreview ?? "", StringComparer.Ordinal)
            .Select(g => g.First())
            .ToList();
    }

    private async Task<List<PostMessageListenerInfo>> CollectListenersAsync()
    {
        var capturedOnUrl = await _ctx.GetCurrentUrl();
        var liveJson = await _ctx.ExecuteJs("""
            (function(){
                var handlers = [];
                if (typeof window.onmessage === 'function') {
                    try { handlers.push({ type:'message', source: Function.prototype.toString.call(window.onmessage), via:'onmessage' }); }
                    catch(e){ handlers.push({ type:'message', source:'', via:'onmessage' }); }
                }
                document.querySelectorAll('script:not([src])').forEach(function(s){
                    var t = s.textContent || '';
                    if (t.indexOf('addEventListener') < 0) return;
                    if (t.indexOf("'message'") < 0 && t.indexOf('"message"') < 0) return;
                    handlers.push({ type:'message', source: t, via:'inline-script' });
                });
                return JSON.stringify({ handlers: handlers, origin: location.origin });
            })()
            """);

        var listeners = new List<PostMessageListenerInfo>();

        foreach (var evt in _ctx.ActiveTab.RuntimeEvents.OfKind("listener")
                     .Where(e => e.Name.Equals("message", StringComparison.OrdinalIgnoreCase)))
        {
            if (RuntimeInstrumentationFilter.IsHostOrSensorListener(evt.Stack, evt.Data))
                continue;
            if (IsWebSocketMessageListener(evt))
                continue;
            listeners.Add(new PostMessageListenerInfo
            {
                Via = "runtime-event-log",
                HandlerFullSource = evt.Data,
                HandlerPreview = Truncate(evt.Data, 400),
                Stack = Truncate(evt.Stack, 500),
                FrameOrigin = evt.FrameOrigin,
                CapturedOnUrl = string.IsNullOrWhiteSpace(evt.DocumentUrl) ? null : evt.DocumentUrl
            });
        }

        IReadOnlyList<Runtime.RuntimeCdpMessageListeners.CdpListener> cdpListeners;
        try
        {
            cdpListeners = await Runtime.RuntimeCdpMessageListeners.TryEnumerateAllAsync(_ctx);
        }
        catch (Exception ex) when (ex.Message.Contains("Frame5", StringComparison.OrdinalIgnoreCase)
                                   || ex.Message.Contains("ICoreWebView2Frame", StringComparison.OrdinalIgnoreCase))
        {
            cdpListeners = Array.Empty<Runtime.RuntimeCdpMessageListeners.CdpListener>();
        }

        foreach (var cdp in cdpListeners)
        {
            if (RuntimeInstrumentationFilter.IsHostOrSensorListener(null, cdp.HandlerSource))
                continue;
            listeners.Add(new PostMessageListenerInfo
            {
                Via = cdp.Via,
                HandlerFullSource = cdp.HandlerSource,
                HandlerPreview = Truncate(cdp.HandlerSource, 400),
                FrameOrigin = cdp.FrameOrigin,
                CapturedOnUrl = capturedOnUrl
            });
        }

        try
        {
            using var doc = JsonDocument.Parse(Unquote(liveJson));
            if (doc.RootElement.TryGetProperty("handlers", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var h in arr.EnumerateArray())
                {
                    var src = h.TryGetProperty("source", out var s) ? s.GetString() : null;
                    listeners.Add(new PostMessageListenerInfo
                    {
                        Via = h.TryGetProperty("via", out var v) ? v.GetString() ?? "onmessage" : "onmessage",
                        HandlerFullSource = src,
                        HandlerPreview = Truncate(src, 400),
                        CapturedOnUrl = capturedOnUrl,
                        FrameOrigin = doc.RootElement.TryGetProperty("origin", out var o) ? o.GetString() : null
                    });
                }
            }
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        listeners = listeners
            .Where(l => !RuntimeInstrumentationFilter.IsHostOrSensorListener(null, l.HandlerPreview))
            .GroupBy(l => l.HandlerPreview ?? "", StringComparer.Ordinal)
            .Select(g => g
                .OrderByDescending(l => (l.HandlerFullSource ?? l.HandlerPreview ?? "").Length)
                .FirstOrDefault(l => DocumentMatches(l.CapturedOnUrl, capturedOnUrl))
                ?? g.OrderByDescending(l => (l.HandlerFullSource ?? l.HandlerPreview ?? "").Length).First())
            .ToList();
        return listeners;
    }

    private async Task RunSyntheticFuzzAsync(
        List<PostMessageListenerInfo> listeners,
        PostMessageAuditOptions options,
        string runId,
        List<UnifiedSecurityFinding> findings,
        List<PostMessageFuzzHit> fuzzHits)
    {
        var victimOrigin = await TryGetPageOriginAsync();
        var payloads = BuildPayloads(listeners, options.MaxPayloads);
        var canary = $"__trowser_pm_scr_{runId[..6]}__";

        foreach (var listener in listeners)
        {
            var grade = PostMessageOriginGrader.Analyze(listener.HandlerFullSource ?? listener.HandlerPreview);
            if (!PostMessageOriginGrader.ShouldRunSyntheticScreen(grade))
                continue;

            var origins = PostMessageOriginGrader.ScreeningOrigins(grade, victimOrigin).ToList();
            if (origins.Count == 0)
                continue;

            var screenPayload = PostMessagePayloadInference.BuildPayloadsForListener(
                listener.HandlerPreview, canary, 1).FirstOrDefault() ?? canary;

            var controlOrigin = origins[0];
            var controlHit = await SyntheticScreenHitAsync(screenPayload, canary, controlOrigin);

            var bypassHit = false;
            string? bypassOrigin = null;
            foreach (var origin in origins.Skip(1))
            {
                if (await SyntheticScreenHitAsync(screenPayload, canary, origin))
                {
                    bypassHit = true;
                    bypassOrigin = origin;
                    break;
                }
            }

            if (bypassHit && !controlHit)
            {
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "postmessage",
                    title: "Synthetic postMessage screening: bypass origin differential (confirm with active proof)",
                    severity: "medium",
                    confidence: SecurityConfidence.Tentative,
                    tier: SecurityFindingTier.Hygiene,
                    payload: Truncate(screenPayload, 120),
                    evidence: $"bypass origin={bypassOrigin}; control={controlOrigin} had no sink",
                    proofHint: "isTrusted=false — run safetyMode active child-iframe proof",
                    extra: new Dictionary<string, object?>
                    {
                        ["isTrusted"] = false,
                        ["screening"] = true,
                        ["differential"] = "bypass-only"
                    }));
            }
            else if (controlHit && !bypassHit)
            {
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "postmessage",
                    title: "Synthetic postMessage screening: control origin reached sink (static grade uncertain)",
                    severity: "low",
                    confidence: SecurityConfidence.Tentative,
                    tier: SecurityFindingTier.Hygiene,
                    payload: Truncate(screenPayload, 120),
                    evidence: $"control origin={controlOrigin}; sinks observed with spoofable origin",
                    proofHint: "Treat static none/weak as uncertain; use active proof",
                    extra: new Dictionary<string, object?>
                    {
                        ["isTrusted"] = false,
                        ["screening"] = true,
                        ["differential"] = "control-only"
                    }));
            }
        }

        foreach (var payload in payloads)
        {
            await ClearSinkLogAsync();
            var before = _ctx.ActiveTab.RuntimeEvents.Mark();
            await DispatchSyntheticMessageAsync(payload);
            await Task.Delay(250);

            var sinkHits = await CollectPayloadSinkHitsAsync(payload);
            var delivered = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(before)
                .Any(e => e.Kind == "message" && !e.IsSensorInternalMessage);

            if (sinkHits.Count > 0 || delivered)
            {
                fuzzHits.Add(new PostMessageFuzzHit
                {
                    Payload = Truncate(payload, 200) ?? "",
                    Delivered = delivered,
                    IsTrusted = false,
                    SinkHits = sinkHits
                });
            }
        }
    }

    private async Task<PostMessageTechniqueResult> RunActiveTopologyAsync(
        string topology,
        string runId,
        string payload,
        string canary,
        PostMessageListenerInfo listener,
        PostMessagePosture posture,
        List<PostMessageFuzzHit> fuzzHits,
        BrowserTab victimTab)
    {
        var result = new PostMessageTechniqueResult
        {
            TechniqueId = topology,
            Topology = topology,
            ListenerId = listener.ListenerId,
            PayloadPreview = Truncate(payload, 120),
            Canary = canary,
            Verdict = "blocked",
            Tier = SecurityFindingTier.Hygiene,
            Confidence = SecurityConfidence.Tentative,
            ConfirmationStatus = "none"
        };

        if (topology == "framed-target" && posture.FramingLikelyBlocked)
        {
            result.Mitigated = true;
            result.MitigationReason = "XFO / frame-ancestors likely block cross-origin embed";
            result.Verdict = "blocked";
            return result;
        }

        var injectedChildIframe = false;
        try
        {
            var probeUrl = PostMessageProbeBuilder.ProbePageUrl(runId, topology, _activeAttackerOrigin);
            var victimPageUrl = await _ctx.GetCurrentUrl() ?? victimTab.Url;
            var html = topology switch
            {
                "popup-to-opener" => PostMessageProbeBuilder.BuildPopupToOpenerHtml(payload),
                "framed-target" => PostMessageProbeBuilder.BuildFramedTargetHtml(victimPageUrl, payload),
                "opener-to-popup" => PostMessageProbeBuilder.BuildOpenerToPopupHtml(victimPageUrl, payload),
                _ => PostMessageProbeBuilder.BuildChildIframeHtml(payload)
            };
            victimTab.MockResponse(probeUrl, 200, html,
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

            var activeMark = victimTab.RuntimeEvents.Mark();
            string? restoreUrl = null;
            BrowserTab? popupTab = null;
            long popupMark = 0;
            var tabIdsBefore = _ctx.Tabs.Select(t => t.Id).ToHashSet();

            if (topology == "child-frame-target")
            {
                EnsureActiveTab(victimTab);
                var iframeCount = await CountCrossOriginIframesAsync();
                if (iframeCount == 0)
                {
                    result.Verdict = "blocked";
                    result.Detail = "no-cross-origin-iframes-on-page";
                    return result;
                }

                await DispatchToChildFramesAsync(payload);
                await Task.Delay(900);
            }
            else if (topology == "popup-to-opener")
            {
                EnsureActiveTab(victimTab);
                await _ctx.ExecuteJs(
                    $"(function(){{ window.open({JsonSerializer.Serialize(probeUrl)}, '_blank'); return 'opened'; }})()");
                await Task.Delay(1500);
                popupTab = _ctx.Tabs.FirstOrDefault(t => !tabIdsBefore.Contains(t.Id));
                if (popupTab != null)
                    popupMark = popupTab.RuntimeEvents.Mark();
            }
            else if (topology == "opener-to-popup")
            {
                restoreUrl = victimPageUrl;
                EnsureActiveTab(victimTab);
                await _ctx.Navigate(probeUrl);
                await _ctx.WaitForIdle(400, 10_000);
                await Task.Delay(2800);
                for (var wait = 0; wait < 20; wait++)
                {
                    popupTab = _ctx.Tabs.FirstOrDefault(t => !tabIdsBefore.Contains(t.Id));
                    if (popupTab != null)
                    {
                        popupMark = popupTab.RuntimeEvents.Mark();
                        break;
                    }

                    await Task.Delay(250);
                }

                await Task.Delay(3200);
            }
            else if (topology == "framed-target")
            {
                restoreUrl = victimPageUrl;
                await _ctx.Navigate(probeUrl);
                await _ctx.WaitForIdle(400, 8000);
                await Task.Delay(800);
            }
            else
            {
                EnsureActiveTab(victimTab);
                injectedChildIframe = true;
                await _ctx.ExecuteJs(
                    $@"(function(){{
                        var f=document.createElement('iframe');
                        f.style.display='none';
                        f.setAttribute('data-trowser-pm-probe','1');
                        f.src={JsonSerializer.Serialize(probeUrl)};
                        document.documentElement.appendChild(f);
                        return 'attacker-frame';
                    }})()");
                await Task.Delay(1200);
            }

            var slice = victimTab.RuntimeEvents.SliceSinceMark(activeMark).ToList();
            if (popupTab != null && popupMark > 0)
                slice.AddRange(popupTab.RuntimeEvents.SliceSinceMark(popupMark));
            var activeSinks = slice
                .Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)
                            && IsDangerousPostMessageSink(e.Name)
                            && !RuntimeInstrumentationFilter.IsBrowserChromeErrorPageSample(e.Data)
                            && (e.Data ?? "").Contains(canary, StringComparison.Ordinal))
                .ToList();
            var trustedDelivered = slice.Any(IsActiveProbeTrustedDelivery);

            if (!trustedDelivered && activeSinks.Count == 0)
            {
                result.Verdict = "blocked";
                result.Detail = "No trusted delivery or canary sink";
                return result;
            }

            result.Verdict = trustedDelivered ? "message-delivered" : "delivered-untrusted";
            if (activeSinks.Count > 0 && trustedDelivered)
            {
                result.Verdict = "sink-reached";
                result.Tier = SecurityFindingTier.Exploitable;
                result.Confidence = SecurityConfidence.Confirmed;
                result.ConfirmationStatus = "confirmed";
                result.Detail = string.Join("; ", activeSinks.Select(s => s.Name).Distinct());
                result.PocHtml = PostMessageProbeBuilder.WatermarkPocHtml(topology, payload);
            }
            else if (trustedDelivered)
            {
                result.ConfirmationStatus = "delivered-shape-mismatch";
                result.Detail = "MessageEvent was trusted-delivered to a listener but payload shape did not reach a dangerous sink (wrong type/code field or inert eval).";
            }

            fuzzHits.Add(new PostMessageFuzzHit
            {
                Payload = $"active:{topology}:{Truncate(payload, 80)}",
                Delivered = trustedDelivered,
                IsTrusted = trustedDelivered,
                SinkHits = activeSinks.Select(e => new PostMessageSinkHit
                {
                    Sink = e.Name,
                    Snippet = Truncate(e.Data, 200)
                }).ToList()
            });

            if (popupTab != null && _ctx.Tabs.Any(t => ReferenceEquals(t, popupTab)))
            {
                var idx = _ctx.Tabs.ToList().FindIndex(t => ReferenceEquals(t, popupTab));
                if (idx >= 0 && _ctx.Tabs.Count > 1)
                {
                    if (ReferenceEquals(_ctx.ActiveTab, popupTab))
                        EnsureActiveTab(victimTab);
                    await _ctx.CloseTab(idx);
                }
            }

            if (!string.IsNullOrEmpty(restoreUrl)
                && restoreUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                try { await _ctx.Navigate(restoreUrl); await _ctx.WaitForIdle(300, 6000); }
                catch { /* best-effort restore */ }
            }
        }
        catch (Exception ex)
        {
            result.Verdict = "blocked";
            result.Detail = ex.Message;
        }
        finally
        {
            if (injectedChildIframe)
            {
                try
                {
                    EnsureActiveTab(victimTab);
                    await RemoveInjectedProbeIframesAsync();
                }
                catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
            }
        }

        return result;
    }

    private async Task RemoveInjectedProbeIframesAsync()
    {
        await _ctx.ExecuteJs("""
            (function(){
              document.querySelectorAll('iframe[data-trowser-pm-probe="1"], iframe[src*="evil.trowser.test/pm/"]').forEach(function(f){
                f.remove();
              });
              return 'removed';
            })()
            """);
    }

    private async Task<int> CountCrossOriginIframesAsync()
    {
        var json = await _ctx.ExecuteJs("""
            (function(){
              var n = 0;
              document.querySelectorAll('iframe').forEach(function(f){
                try { if (f.contentWindow) n++; } catch(e) { n++; }
              });
              return String(n);
            })()
            """);
        return int.TryParse(json.Trim('"'), out var n) ? n : 0;
    }

    private async Task DispatchToChildFramesAsync(string payload)
    {
        await _ctx.ExecuteJs(
            $@"(function(){{
                var raw = {JsonSerializer.Serialize(payload)};
                var data;
                try {{ data = JSON.parse(raw); }} catch(e) {{ data = raw; }}
                document.querySelectorAll('iframe').forEach(function(f){{
                    try {{ f.contentWindow.postMessage(data, '*'); }} catch(e2) {{}}
                }});
                return 'posted';
            }})()");
    }

    private void EnsureActiveTab(BrowserTab victimTab)
    {
        if (ReferenceEquals(_ctx.ActiveTab, victimTab)) return;
        for (var i = 0; i < _ctx.Tabs.Count; i++)
        {
            if (ReferenceEquals(_ctx.Tabs[i], victimTab))
            {
                _ctx.SwitchTab(i);
                return;
            }
        }
    }

    private async Task ClosePostMessageProbeTabsAsync(BrowserTab victimTab)
    {
        for (var i = _ctx.Tabs.Count - 1; i >= 0; i--)
        {
            var tab = _ctx.Tabs[i];
            if (ReferenceEquals(tab, victimTab) || _ctx.Tabs.Count <= 1)
                continue;
            if (tab.Url.Contains("evil.trowser.test/pm/", StringComparison.OrdinalIgnoreCase))
            {
                if (ReferenceEquals(_ctx.ActiveTab, tab))
                    EnsureActiveTab(victimTab);
                await _ctx.CloseTab(i);
            }
        }
    }

    private static UnifiedSecurityFinding BuildHygieneFinding(PostMessageListenerInfo l, string? currentPageUrl)
    {
        var handler = l.HandlerFullSource ?? l.HandlerPreview ?? "";
        var dangerous = HandlerUsesDangerousSink(handler);
        var checkKind = l.CheckKind ?? PostMessageOriginGrader.Analyze(handler).CheckKind;
        var schemaOrDataGateOnly = checkKind is "data-gate-only";
        var noOriginGate = l.OriginCheck is "none" && !schemaOrDataGateOnly
                           || l.CheckKind is "origin-referenced-not-validated";
        var severity = schemaOrDataGateOnly && dangerous ? "high"
            : dangerous && noOriginGate ? "critical"
            : l.OriginCheck == "none" ? "high"
            : "medium";
        var tier = dangerous && noOriginGate && !schemaOrDataGateOnly
            ? SecurityFindingTier.Exploitable
            : SecurityFindingTier.Hygiene;
        var capturedOn = UrlPayloadInjector.StripToolQueryParams(l.CapturedOnUrl ?? "");

        return UnifiedSecurityFinding.Create(
            category: "postmessage",
            title: l.OriginCheck == "none"
                ? "postMessage listener without origin check"
                : "postMessage listener with weak origin check",
            severity: severity,
            confidence: dangerous && noOriginGate ? SecurityConfidence.Likely : SecurityConfidence.Likely,
            tier: tier,
            endpoint: string.IsNullOrEmpty(capturedOn) ? currentPageUrl : capturedOn,
            evidence: l.HandlerPreview,
            proofHint: dangerous
                ? "Handler reaches eval/Function or HTML sinks without origin validation — run safetyMode active postMessage audit"
                : "Run active child-iframe proof or trace-input post-message",
            nextActions: [SecurityNextActions.PostMessageAudit, SecurityNextActions.TraceInputMonitorSinks],
            id: l.ListenerId ?? $"pm-{HashCode.Combine(l.Via, l.HandlerPreview ?? "").ToString("x8")}",
            extra: new Dictionary<string, object?>
            {
                ["originCheck"] = l.OriginCheck,
                ["checkKind"] = l.CheckKind,
                ["via"] = l.Via,
                ["dangerousSink"] = dangerous,
                ["capturedOnUrl"] = capturedOn
            });
    }

    private static bool HandlerUsesDangerousSink(string handler) =>
        !string.IsNullOrWhiteSpace(handler)
        && (Regex.IsMatch(handler, @"\beval\s*\(", RegexOptions.IgnoreCase)
            || handler.Contains("new Function", StringComparison.OrdinalIgnoreCase)
            || handler.Contains(".innerHTML", StringComparison.OrdinalIgnoreCase)
            || handler.Contains("document.write", StringComparison.OrdinalIgnoreCase));

    private static PostMessageAuditResult BuildResult(
        AutomationContext ctx,
        Stopwatch sw,
        string runId,
        string depth,
        List<PostMessageListenerInfo> listeners,
        List<PostMessageFuzzHit> fuzzHits,
        List<UnifiedSecurityFinding> findings,
        List<PostMessageTechniqueResult> techniques,
        PostMessagePosture posture,
        bool budgetExhausted,
        bool suggestOnly = false,
        bool sessionLostDuringScan = false,
        string? sessionLostReason = null,
        int popupTabsOpened = 0,
        int orphanPopupTabsClosed = 0,
        string? frameEnumeration = null,
        int staleListenersDropped = 0)
    {
        var coverage = new ClientScanCoverage
        {
            Instrumented = RuntimeSensorScript.InstrumentedSinks.ToList(),
            ListenersSeen = listeners.Select(l => l.Via).Distinct().ToList(),
            SinksSeen = fuzzHits.SelectMany(h => h.SinkHits.Select(s => s.Sink)).Distinct().ToList(),
            Untested = listeners.Where(l => l.OriginCheck == "unknown").Select(l => "listener:" + l.Via).ToList(),
            FrameEnumeration = frameEnumeration,
            ZeroResultReason = listeners.Count == 0
                ? "no-message-listeners-observed — browse flows that register postMessage handlers, or enable Shadow runtime"
                : findings.Count == 0 ? "listeners-audited-no-sink-reach" : null
        };
        coverage.Untested.Add("BroadcastChannel / MessagePort (not instrumented in v1)");

        var next = findings.Count > 0
            ? findings.SelectMany(f => f.NextActions).Distinct().Take(10).ToList()
            : new List<string> { SecurityNextActions.ClientSurface, "Browse SPA chat/auth flows then re-run postmessage audit" };
        if (suggestOnly && listeners.Any(l => l.OriginCheck is "none" or "weak"))
            next.Insert(0, "browser_postmessage_audit with safetyMode active and depth deep");
        next.AddRange(PostMessageFederationHints.NextActionsFromSession(ctx, listeners));

        return new PostMessageAuditResult
        {
            RunId = runId,
            CatalogMode = depth,
            BudgetExhausted = budgetExhausted,
            SessionLostDuringScan = sessionLostDuringScan,
            SessionLostReason = sessionLostReason,
            PopupTabsOpened = popupTabsOpened,
            OrphanPopupTabsClosed = orphanPopupTabsClosed,
            ElapsedMs = sw.ElapsedMilliseconds,
            Listeners = listeners,
            FuzzHits = fuzzHits,
            Findings = findings,
            Techniques = techniques,
            Posture = posture,
            Coverage = coverage,
            NextActions = next,
            StaleListenersDropped = staleListenersDropped
        };
    }

    private static List<string> ResolveTopologies(PostMessageAuditOptions options, string depth, PostMessagePosture posture)
    {
        if (options.Topologies is { Count: > 0 })
            return options.Topologies.ToList();

        var list = new List<string> { "child-iframe" };
        if (depth == SecurityScanDepth.Deep)
        {
            list.Add("popup-to-opener");
            if (!posture.FramingLikelyBlocked)
                list.Add("framed-target");
            else
                list.Add("child-frame-target");
        }

        if (string.Equals(options.SafetyMode, "aggressive", StringComparison.OrdinalIgnoreCase))
            list.Add("opener-to-popup");

        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Framing headers live on the document response. Later same-origin scripts share the URL prefix and must not replace it.
    /// </summary>
    public static NetworkEntry? SelectDocumentForFraming(IEnumerable<NetworkEntry> entries, string pageUrl)
    {
        if (string.IsNullOrWhiteSpace(pageUrl))
            return null;
        var page = pageUrl.Split('#')[0];
        return entries.LastOrDefault(e =>
            e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase)
            && (e.Url.Equals(pageUrl, StringComparison.OrdinalIgnoreCase)
                || e.Url.Split('#')[0].Equals(page, StringComparison.OrdinalIgnoreCase)));
    }

    private async Task<PostMessagePosture> BuildPostureAsync(string? victimOrigin)
    {
        var posture = new PostMessagePosture();
        var entry = SelectDocumentForFraming(_ctx.Network.Entries, _ctx.ActiveTab.Url);

        if (entry?.ResponseHeaders != null)
        {
            var headers = entry.ResponseHeaders;
            if (headers.TryGetValue("X-Frame-Options", out var xfo) || headers.TryGetValue("x-frame-options", out xfo))
                posture.XFrameOptions = xfo;
            if (headers.TryGetValue("Referrer-Policy", out var rp) || headers.TryGetValue("referrer-policy", out rp))
                posture.ReferrerPolicy = rp;
            if (headers.TryGetValue("Content-Security-Policy", out var csp) || headers.TryGetValue("content-security-policy", out csp))
            {
                var m = Regex.Match(csp, @"(?i)frame-ancestors\s+([^;]+)");
                if (m.Success) posture.FrameAncestors = m.Groups[1].Value.Trim();
            }
        }

        var fp = ClickjackTester.AnalyzeFrameProtection(
            entry?.ResponseHeaders ?? new Dictionary<string, string>());
        posture.FramingLikelyBlocked = !fp.MissingProtection
            && (fp.XFrameOptions is "DENY" or "SAMEORIGIN" || fp.HasCspFrameAncestors);
        posture.RecommendedTopologies = ["child-iframe"];
        if (await HasTabnabbingRiskAsync())
            posture.RecommendedTopologies.Add("popup-to-opener");
        return posture;
    }

    private async Task<bool> HasTabnabbingRiskAsync()
    {
        try
        {
            var json = await _ctx.ExecuteJs("""
                (function(){
                  var n = 0;
                  document.querySelectorAll('a[target="_blank"]').forEach(function(a){
                    var r = (a.getAttribute('rel')||'').toLowerCase();
                    if (r.indexOf('noopener') < 0 && r.indexOf('noreferrer') < 0) n++;
                  });
                  return String(n);
                })()
                """);
            return int.TryParse(json.Trim('"'), out var n) && n > 0;
        }
        catch
        {
            return false;
        }
    }

    private static List<PostMessageListenerInfo> ApplyListenerFilter(
        List<PostMessageListenerInfo> listeners, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return listeners;
        return listeners.Where(l =>
            (l.ListenerId?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)
            || (l.HandlerPreview?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false)).ToList();
    }

    private async Task<string?> TryGetPageOriginAsync()
    {
        try
        {
            var json = await _ctx.ExecuteJs("JSON.stringify(location.origin)");
            return JsonSerializer.Deserialize<string>(json.Trim('"'));
        }
        catch { return null; }
    }

    private static List<string> BuildPayloads(List<PostMessageListenerInfo> listeners, int max)
    {
        var handlerSources = listeners
            .Select(l => l.HandlerPreview)
            .Where(s => !string.IsNullOrEmpty(s))
            .Cast<string>()
            .ToList();
        var shaped = PostMessagePayloadInference.ShapeForDispatch("<img src=x onerror=alert(1)>", handlerSources);

        var payloads = new List<string>
        {
            shaped,
            "{\"type\":\"trowser\",\"html\":\"<img src=x onerror=alert(1)>\"}",
            "<img src=x onerror=alert(1)>"
        };

        foreach (var l in listeners)
        {
            if (string.IsNullOrEmpty(l.HandlerPreview)) continue;
            payloads.AddRange(PostMessagePayloadInference.BuildPayloadsForListener(
                l.HandlerPreview, "<img src=x onerror=1>", 2));
        }

        return payloads.Distinct().Take(Math.Clamp(max, 1, 20)).ToList();
    }

    /// <summary>
    /// Trusted cross-origin delivery for active mocks: app-originated message events, or the sensor's
    /// capture-phase log when origin is the mocked attacker page (sensor-tagged events are otherwise excluded).
    /// </summary>
    private static bool IsActiveProbeTrustedDelivery(RuntimeEvent e)
    {
        if (!e.Kind.Equals("message", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!e.Extra.TryGetValue("isTrusted", out var t) || t != "true")
            return false;
        if (!e.IsSensorInternalMessage)
            return true;
        return e.Extra.TryGetValue("origin", out var o)
               && string.Equals(o, PostMessageProbeBuilder.AttackerOrigin, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDangerousPostMessageSink(string sink) =>
        sink is "innerHTML" or "outerHTML" or "insertAdjacentHTML"
            or "eval" or "Function" or "document.write" or "document.writeln"
            or "setAttribute" or "iframe.srcdoc" or "script.src"
            or "location.assign" or "location.replace" or "location.href"
            or "createContextualFragment" or "jquery.html" or "jquery.append";

    private async Task<bool> SyntheticScreenHitAsync(string screenPayload, string canary, string origin)
    {
        await ClearSinkLogAsync();
        var before = _ctx.ActiveTab.RuntimeEvents.Mark();
        await DispatchSyntheticMessageAsync(screenPayload, origin);
        await Task.Delay(200);
        var sinkHits = await CollectCanarySinkHitsAsync(canary);
        var delivered = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(before)
            .Any(e => e.Kind == "message" && !e.IsSensorInternalMessage);
        return sinkHits.Count > 0 && delivered;
    }

    private async Task DispatchSyntheticMessageAsync(string payload, string? origin = null)
    {
        origin ??= PostMessageProbeBuilder.AttackerOrigin;
        await _ctx.ExecuteJs(
            $@"(function(){{
                var origin = {JsonSerializer.Serialize(origin)};
                var raw = {JsonSerializer.Serialize(payload)};
                try {{
                    var parsed = JSON.parse(raw);
                    if (parsed !== null && typeof parsed === 'object')
                        window.dispatchEvent(new MessageEvent('message', {{ data: parsed, origin: origin, source: window }}));
                }} catch(e) {{}}
                window.dispatchEvent(new MessageEvent('message', {{ data: raw, origin: origin, source: window }}));
                return 'ok';
            }})()");
    }

    private async Task ClearSinkLogAsync()
    {
        try { await _ctx.ExecuteJs("if(window.__trowser_sink_log) window.__trowser_sink_log.length=0;"); }
        catch { }
    }

    private async Task<List<PostMessageSinkHit>> CollectCanarySinkHitsAsync(string canary)
    {
        var json = await _ctx.ExecuteJs(
            $@"(function(){{
                var log = window.__trowser_sink_log || [];
                var marker = {JsonSerializer.Serialize(canary)};
                var hits = [];
                for (var i=0;i<log.length;i++){{
                    if (log[i].data && String(log[i].data).indexOf(marker)>=0)
                        hits.push({{sink:log[i].sink, snippet:String(log[i].data).substring(0,200)}});
                }}
                return JSON.stringify(hits);
            }})()");
        return ParseSinkHits(json);
    }

    private async Task<List<PostMessageSinkHit>> CollectPayloadSinkHitsAsync(string payload)
    {
        var marker = payload.Length > 24 ? payload[..24] : payload;
        var json = await _ctx.ExecuteJs(
            $@"(function(){{
                var log = window.__trowser_sink_log || [];
                var marker = {JsonSerializer.Serialize(marker)};
                var hits = [];
                for (var i=0;i<log.length;i++){{
                    if (log[i].data && String(log[i].data).indexOf(marker)>=0)
                        hits.push({{sink:log[i].sink, snippet:String(log[i].data).substring(0,200)}});
                }}
                return JSON.stringify(hits);
            }})()");
        return ParseSinkHits(json);
    }

    private static List<PostMessageSinkHit> ParseSinkHits(string? json)
    {
        try
        {
            using var doc = JsonDocument.Parse(Unquote(json));
            return doc.RootElement.EnumerateArray().Select(x => new PostMessageSinkHit
            {
                Sink = x.TryGetProperty("sink", out var s) ? s.GetString() ?? "" : "",
                Snippet = x.TryGetProperty("snippet", out var sn) ? sn.GetString() : null
            }).ToList();
        }
        catch { return []; }
    }

    private static string Unquote(string? json)
    {
        if (string.IsNullOrEmpty(json)) return "[]";
        var s = json.Trim();
        if (s.Length >= 2 && s[0] == '"')
        {
            try { return JsonSerializer.Deserialize<string>(s) ?? "[]"; }
            catch { return "[]"; }
        }
        return s;
    }

    private static string? Truncate(string? s, int max) =>
        s == null ? null : s.Length <= max ? s : s[..max];
}

public sealed class PostMessageAuditResult
{
    public string RunId { get; init; } = "";
    public string CatalogMode { get; init; } = SecurityScanDepth.Quick;
    public bool BudgetExhausted { get; init; }
    public bool SessionLostDuringScan { get; init; }
    public string? SessionLostReason { get; init; }
    public int PopupTabsOpened { get; init; }
    public int OrphanPopupTabsClosed { get; init; }
    public long ElapsedMs { get; init; }
    public List<PostMessageListenerInfo> Listeners { get; init; } = [];
    public List<PostMessageFuzzHit> FuzzHits { get; init; } = [];
    public List<PostMessageTechniqueResult> Techniques { get; init; } = [];
    public PostMessagePosture? Posture { get; init; }
    public List<UnifiedSecurityFinding> Findings { get; init; } = [];
    public ClientScanCoverage Coverage { get; init; } = new();
    public List<string> NextActions { get; init; } = [];
    /// <summary>Listeners from prior pages dropped when includeHistory is false.</summary>
    public int StaleListenersDropped { get; init; }

    public object ToApiResponse() => new
    {
        message = Findings.Count > 0
            ? $"postMessage audit: {Findings.Count} finding(s), {Listeners.Count} listener(s)"
            : $"postMessage audit: {Listeners.Count} listener(s), no confirmed sink reach",
        runId = RunId,
        catalogMode = CatalogMode,
        budgetExhausted = BudgetExhausted,
        sessionLostDuringScan = SessionLostDuringScan ? (bool?)true : null,
        sessionLostReason = SessionLostReason,
        popupTabsOpened = PopupTabsOpened,
        orphanPopupTabsClosed = OrphanPopupTabsClosed,
        elapsedMs = ElapsedMs,
        staleListenersDropped = StaleListenersDropped > 0 ? (int?)StaleListenersDropped : null,
        listeners = Listeners,
        fuzzHits = FuzzHits,
        techniques = Techniques,
        posture = Posture,
        findings = Findings.Select(SecurityScanResult.ToApiFinding).ToList(),
        nextActions = NextActions,
        coverage = Coverage.ToApiObject()
    };
}

public sealed class PostMessageListenerInfo
{
    public string ListenerId { get; set; } = "";
    public string Via { get; set; } = "";
    public string OriginCheck { get; set; } = "unknown";
    public string? CheckKind { get; set; }
    public List<string> OriginLiterals { get; set; } = [];
    public string? HandlerPreview { get; init; }
    public string? HandlerFullSource { get; init; }
    public string? Stack { get; init; }
    public string? FrameOrigin { get; init; }
    public string? CapturedOnUrl { get; set; }
    public bool Stale { get; set; }
    public PostMessageInferredSchema? InferredSchema { get; set; }
}

public sealed class PostMessageFuzzHit
{
    public string Payload { get; init; } = "";
    public bool Delivered { get; init; }
    public bool IsTrusted { get; init; }
    public List<PostMessageSinkHit> SinkHits { get; init; } = [];
}

public sealed class PostMessageSinkHit
{
    public string Sink { get; init; } = "";
    public string? Snippet { get; init; }
}
