using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.Runtime;
using Trowser.Security.WebSocket;

namespace Trowser.Security.DomFlow;

/// <summary>
/// Builds attacker-input → JS → DOM mutation → sink → consequence chains from the runtime sensor.
/// </summary>
public sealed class DomFlowGraph
{
    private readonly AutomationContext _ctx;

    public DomFlowGraph(AutomationContext ctx) => _ctx = ctx;

    public sealed class DomFlowChain
    {
        public string Source { get; init; } = "";
        public string? Value { get; init; }
        public string Sink { get; init; } = "";
        public string? SinkData { get; init; }
        public string? Stack { get; init; }
        public string? FrameOrigin { get; init; }
        public string? Mutation { get; init; }
        public string Consequence { get; init; } = "inert";
        public string Confidence { get; init; } = "temporal";
        public string? Framework { get; init; }
        public string Tier { get; init; } = "hygiene";
        public DateTime Timestamp { get; init; }
    }

    public sealed class DomFlowResult
    {
        public string Mode { get; init; } = "observe";
        public string Url { get; init; } = "";
        public bool SensorInstalled { get; init; }
        public int EventCount { get; init; }
        public List<DomFlowChain> Chains { get; init; } = new();
        public List<string> NextActions { get; init; } = new();
        public List<string> CoverageHints { get; init; } = new();
        public Dictionary<string, int> ConsequenceCounts { get; init; } = new();
        public Dictionary<string, int> TierCounts { get; init; } = new();
        public string Summary { get; init; } = "";
        public int ExploitableChainCount { get; init; }
    }

    public async Task<DomFlowResult> ObserveAsync(int waitMs = 400, bool waitForSpa = true)
    {
        if (!_ctx.ActiveTab.RuntimeEvents.Installed)
        {
            try
            {
                await _ctx.InstallRuntimeSensorAsync();
            }
            catch
            {
                /* best effort */
            }
        }

        var mark = _ctx.ActiveTab.RuntimeEvents.Mark();

        if (waitForSpa)
            await WaitForSpaSettleAsync(waitMs);
        else if (waitMs > 0)
            await Task.Delay(waitMs);

        var url = await _ctx.GetCurrentUrl();
        var events = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(mark);
        var pageOrigin = Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.GetLeftPart(UriPartial.Authority) : null;
        var chains = BuildChains(events, probeMode: false, pageOrigin);
        var tt = await TrustedTypesPosture.FromDocumentHeadersAsync(_ctx);
        return Finalize("observe", url, events.Count, chains, tt);
    }

    /// <summary>Clears accumulated runtime sensor events without wiping cookies, storage, or network.</summary>
    public void ResetSensorBuffer() => _ctx.ActiveTab.RuntimeEvents.Clear();

    public async Task<DomFlowResult> ProbeAsync(
        IReadOnlyList<string>? sources = null,
        string? canary = null,
        bool restoreUrl = true,
        CancellationToken ct = default)
    {
        await SecurityScanHygiene.PrepareActiveScanAsync(_ctx);

        canary ??= $"trowser_canary_{Guid.NewGuid():N}"[..24];
        var execPayload = $"<img src=x onerror=\"window.__trowser_exec('{canary}')\">";
        var attrBreakoutPayload =
            $"\"><img src=x onerror=\"window.__trowser_exec('{canary}')\">";
        var url = await _ctx.GetCurrentUrl();
        var restoreTarget = url;
        var wanted = sources?.Count > 0
            ? sources
            : new[] { "url-query", "url-hash", "storage", "window-name", "post-message", "websocket-message" };

        await _ctx.PrepareRuntimeSensorForNavigationAsync();
        var mark = _ctx.ActiveTab.RuntimeEvents.Mark();
        IReadOnlyList<string>? discoveredParams = null;
        try
        {
            var discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(_ctx);
            discoveredParams = discovery.QueryParams
                .Concat(discovery.HashParams)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            /* best-effort param discovery */
        }

        try
        {
        foreach (var source in wanted)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                switch (source.ToLowerInvariant())
                {
                    case "url-query":
                    case "query":
                    {
                        foreach (var payload in new[] { execPayload, attrBreakoutPayload })
                        {
                            foreach (var probeUrl in DomFlowSpaProbe.BuildQueryProbeUrls(url, payload, discoveredParams))
                            {
                                await _ctx.ForceNavigateAsync(probeUrl, terminateScripts: true);
                                await WaitForSpaSettleAsync(400);
                            }
                        }
                        break;
                    }
                    case "url-hash":
                    case "hash":
                    {
                        if (DomFlowSpaProbe.IsHashRouterUrl(url))
                        {
                            foreach (var payload in new[] { execPayload, attrBreakoutPayload })
                            {
                                foreach (var probeUrl in DomFlowSpaProbe.BuildQueryProbeUrls(url, payload, discoveredParams))
                                {
                                    await _ctx.ForceNavigateAsync(probeUrl, terminateScripts: true);
                                    await WaitForSpaSettleAsync(400);
                                }
                            }
                        }
                        else
                        {
                            foreach (var payload in new[] { execPayload, attrBreakoutPayload })
                            {
                                await _ctx.Navigate(
                                    DomFlowSpaProbe.BuildRawHashPayloadUrl(url, Uri.EscapeDataString(payload)));
                                await WaitForSpaSettleAsync(400);
                            }
                        }
                        break;
                    }
                    case "websocket-message":
                    case "websocket":
                    {
                        await ProbeWebSocketMessageAsync(execPayload, ct);
                        break;
                    }
                    case "storage":
                    case "localstorage":
                    {
                        await _ctx.SetStorageItem("local", "trowser_probe", execPayload);
                        // Reload so app code (not Trowser) reads storage into sinks — never inject innerHTML here (self-calibration FP).
                        await _ctx.Navigate(url.Split('#')[0]);
                        await WaitForSpaSettleAsync(600);
                        break;
                    }
                    case "window-name":
                    {
                        await _ctx.ExecuteJs($"window.name = {JsonSerializer.Serialize(execPayload)};");
                        var baseForName = url.Split('#')[0];
                        await _ctx.Navigate(baseForName);
                        await WaitForSpaSettleAsync(600);
                        break;
                    }
                    case "post-message":
                    case "postmessage":
                    {
                        await _ctx.InstallRuntimeSensorAsync();
                        await _ctx.ExecuteJs(
                            $"window.dispatchEvent(new MessageEvent('message',{{data:{JsonSerializer.Serialize(execPayload)},origin:'https://evil.trowser.test'}}));");
                        await Task.Delay(300, ct);
                        break;
                    }
                    case "indexeddb":
                    {
                        await _ctx.ExecuteJsAsync($@"
(async function(){{
  var name='trowser_probe_db';
  await new Promise(function(res){{ var d=indexedDB.deleteDatabase(name); d.onsuccess=d.onerror=d.onblocked=function(){{res();}}; }});
  var db=await new Promise(function(res,rej){{
    var r=indexedDB.open(name,1);
    r.onupgradeneeded=function(){{ r.result.createObjectStore('s'); }};
    r.onsuccess=function(){{ res(r.result); }};
    r.onerror=function(){{ rej(r.error); }};
  }});
  await new Promise(function(res,rej){{
    var tx=db.transaction('s','readwrite');
    tx.objectStore('s').put({JsonSerializer.Serialize(execPayload)}, 'k');
    tx.oncomplete=function(){{res();}}; tx.onerror=function(){{rej(tx.error);}};
  }});
                  db.close();
                  return 'OK';
                }})()");
                        var baseForIdb = url.Split('#')[0];
                        await _ctx.Navigate(baseForIdb);
                        await WaitForSpaSettleAsync(600);
                        break;
                    }
                }
            }
            catch
            {
                /* continue other sources */
            }
        }

        await Task.Delay(500, ct);
        var events = _ctx.ActiveTab.RuntimeEvents.SliceSinceMark(mark);
        var all = events.Count > 0 ? events : _ctx.ActiveTab.RuntimeEvents.All();
        var finalUrl = await _ctx.GetCurrentUrl();
        var pageOrigin = Uri.TryCreate(finalUrl, UriKind.Absolute, out var pu)
            ? pu.GetLeftPart(UriPartial.Authority)
            : null;
        var chains = BuildChains(all, probeMode: true, pageOrigin);
        await SecurityScanHygiene.TryClearBlockingDialogAsync(_ctx);

        var tt = await TrustedTypesPosture.FromDocumentHeadersAsync(_ctx);
        return Finalize("probe", finalUrl, all.Count, chains, tt);
        }
        finally
        {
            if (restoreUrl && !string.IsNullOrWhiteSpace(restoreTarget))
            {
                try
                {
                    await _ctx.DeleteStorageItem("local", "trowser_probe");
                }
                catch { /* best effort */ }

                try
                {
                    var now = await _ctx.GetCurrentUrl();
                    if (!string.Equals(now, restoreTarget, StringComparison.OrdinalIgnoreCase))
                    {
                        await _ctx.Navigate(restoreTarget);
                        await WaitForSpaSettleAsync(300);
                    }
                }
                catch { /* best effort */ }
            }
        }
    }

    private async Task ProbeWebSocketMessageAsync(string payload, CancellationToken ct)
    {
        await WebSocketJsBridge.EnsureHookAsync(_ctx);
        try
        {
            await _ctx.InstallRuntimeSensorAsync();
        }
        catch
        {
            /* best effort */
        }

        var connections = _ctx.ActiveTab.WebSocket.GetConnections()
            .Where(c => c.State is "open" or "connecting")
            .Take(2)
            .ToList();
        if (connections.Count == 0)
            return;

        foreach (var conn in connections)
        {
            ct.ThrowIfCancellationRequested();
            await WebSocketJsBridge.SendAsync(_ctx, conn.ConnectionId, payload);
            await WebSocketJsBridge.SendAsync(_ctx, conn.ConnectionId,
                JsonSerializer.Serialize(new { type = "message", data = payload, payload }));
            await Task.Delay(450, ct);
        }
    }

    private async Task WaitForSpaSettleAsync(int waitMs)
    {
        var quiet = Math.Clamp(waitMs, 300, 2000);
        try
        {
            await _ctx.WaitForIdle(quiet, Math.Max(waitMs + 6000, 10_000));
        }
        catch { /* optional */ }

        try
        {
            await _ctx.ExecuteJsAsync(
                """
                (async function(){
                  for (var i = 0; i < 40; i++) {
                    if (document.querySelector('app-root, router-outlet, [ng-version], #root'))
                      return 'ready';
                    await new Promise(function(r){ setTimeout(r, 200); });
                  }
                  return 'timeout';
                })()
                """);
        }
        catch { /* optional */ }
    }

    internal static List<DomFlowChain> BuildChains(
        IReadOnlyList<RuntimeEvent> events,
        bool probeMode = false,
        string? pageOrigin = null)
    {
        var chains = new List<DomFlowChain>();
        var mutations = events.Where(e => e.Kind.Equals("mutation", StringComparison.OrdinalIgnoreCase)).ToList();
        var oracles = events.Where(e => e.Kind.Equals("oracle", StringComparison.OrdinalIgnoreCase)).ToList();

        foreach (var sink in events.Where(e => e.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase)))
        {
            var confidence = sink.Extra.TryGetValue("confidence", out var conf) && !string.IsNullOrEmpty(conf)
                ? conf! : "temporal";
            var consequence = sink.Extra.TryGetValue("consequence", out var cons) && !string.IsNullOrEmpty(cons)
                ? cons! : "inert";
            var source = sink.Extra.TryGetValue("lastSource", out var ls) ? ls ?? "" : "";
            var value = sink.Extra.TryGetValue("lastSourceData", out var lsd) ? lsd : null;
            if (sink.Extra.TryGetValue("matchedSources", out var ms) && !string.IsNullOrEmpty(ms))
            {
                var first = ms.Split('|')[0];
                var colon = first.IndexOf(':');
                if (colon > 0)
                {
                    source = first[..colon];
                    value = first[(colon + 1)..];
                }
                else if (first == "canary")
                {
                    confidence = "canary";
                    source = string.IsNullOrEmpty(source) ? "canary" : source;
                }
            }

            // Upgrade consequence from nearby oracle
            foreach (var o in oracles)
            {
                if (Math.Abs((o.Timestamp - sink.Timestamp).TotalMilliseconds) < 5000
                    && o.Name.Equals("exec", StringComparison.OrdinalIgnoreCase))
                {
                    consequence = "exec";
                    confidence = "canary";
                }
                if (o.Name.Equals("blocked-csp", StringComparison.OrdinalIgnoreCase)
                    && Math.Abs((o.Timestamp - sink.Timestamp).TotalMilliseconds) < 5000)
                    consequence = "blocked-csp";
            }

            string? mutation = null;
            foreach (var m in mutations)
            {
                if (m.Timestamp >= sink.Timestamp
                    && (m.Timestamp - sink.Timestamp).TotalMilliseconds < 2000)
                {
                    mutation = $"{m.Name}:{(m.Data ?? "").Truncate(120)}";
                    break;
                }
            }

            // Skip pure sanitizer noise unless matched
            if (sink.Name.Equals("DOMPurify.sanitize", StringComparison.OrdinalIgnoreCase)
                && confidence == "temporal" && string.IsNullOrEmpty(source))
                continue;

            if (probeMode && IsProbeInjectionArtifact(source, value, sink.Data, sink.Stack, consequence))
            {
                consequence = "inert";
                confidence = "temporal";
            }

            var chain = RefineChain(new DomFlowChain
            {
                Source = string.IsNullOrEmpty(source) ? "(unknown)" : source,
                Value = value,
                Sink = sink.Name,
                SinkData = sink.Data,
                Stack = sink.Stack,
                FrameOrigin = sink.FrameOrigin,
                Mutation = mutation,
                Consequence = consequence,
                Confidence = confidence,
                Framework = sink.Extra.TryGetValue("framework", out var fw) ? fw : null,
                Timestamp = sink.Timestamp,
                Tier = ClassifyTier(source, confidence, consequence, sink.Name, sink.Data, value, sink.Stack,
                    sink.FrameOrigin, probeMode, pageOrigin)
            }, pageOrigin);
            chains.Add(chain);
        }

        // Dedup by source+sink+consequence
        return chains
            .GroupBy(c => $"{c.Source}|{c.Sink}|{c.Consequence}|{(c.SinkData ?? "").Truncate(40)}")
            .Select(g => g.OrderByDescending(Priority).First())
            .OrderByDescending(Priority)
            .ThenByDescending(c => c.Timestamp)
            .Take(100)
            .ToList();
    }

    internal static string ClassifyTier(
        string? source,
        string confidence,
        string consequence,
        string? sinkName,
        string? sinkData,
        string? value = null,
        string? stack = null,
        string? frameOrigin = null,
        bool probeMode = false,
        string? pageOrigin = null)
    {
        if (IsProbeInjectionArtifact(source, value, sinkData, stack, consequence)
            || IsProbeMarkerTier(source, sinkData, value))
            return "probe-artifact";

        if (IsThirdPartyWidgetFrame(frameOrigin, pageOrigin))
            return "noise";

        if (IsSessionCookieToSameOriginApi(source, sinkName, sinkData, pageOrigin))
            return "hygiene";

        if (IsInertUrlAttributeWrite(sinkName, sinkData))
            return "hygiene";

        if (probeMode && consequence == "exec" && !StackIncludesPageScript(stack))
            return "probe-artifact";

        if (!IsAttackerReachableSource(source))
        {
            if (consequence == "exec" || confidence is "canary" or "value-match")
                return "hygiene";
            return source?.Contains("cookie", StringComparison.OrdinalIgnoreCase) == true ? "noise" : "hygiene";
        }

        if (consequence == "open-redirect" && IsAttackerReachableSource(source))
            return "exploitable";

        if (confidence is "canary" or "value-match" || consequence == "exec")
            return "exploitable";
        if (confidence == "temporal" && consequence == "inert"
            && (source?.Contains("cookie", StringComparison.OrdinalIgnoreCase) == true
                || source?.Contains("history.state", StringComparison.OrdinalIgnoreCase) == true))
            return "noise";
        return "hygiene";
    }

    private static DomFlowChain RefineChain(DomFlowChain chain, string? pageOrigin)
    {
        var consequence = chain.Consequence;
        if (IsInertUrlAttributeWrite(chain.Sink, chain.SinkData) && consequence == "exec")
            consequence = "inert";

        if (IsSessionCookieToSameOriginApi(chain.Source, chain.Sink, chain.SinkData, pageOrigin)
            && consequence is "exec" or "executable-markup" or "request-forgery")
            consequence = "inert";

        if (IsThirdPartyWidgetFrame(chain.FrameOrigin, pageOrigin))
        {
            return new DomFlowChain
            {
                Source = chain.Source,
                Value = chain.Value,
                Sink = chain.Sink,
                SinkData = chain.SinkData,
                Stack = chain.Stack,
                FrameOrigin = chain.FrameOrigin,
                Mutation = chain.Mutation,
                Consequence = "inert",
                Confidence = "temporal",
                Framework = chain.Framework,
                Timestamp = chain.Timestamp,
                Tier = "noise"
            };
        }

        if (IsNavigationSink(chain.Sink)
            && IsAttackerReachableSource(chain.Source)
            && LooksLikeOffOriginNavigation(chain.SinkData, pageOrigin))
            consequence = "open-redirect";

        if (IsStyleInjectionSink(chain.Sink, chain.SinkData)
            && IsAttackerReachableSource(chain.Source)
            && consequence is "inert" or "executable-markup")
            consequence = "css-injection";

        if (IsMarkupSinkName(chain.Sink)
            && IsAttackerReachableSource(chain.Source)
            && LooksLikeDanglingMarkup(chain.Value ?? chain.SinkData)
            && consequence is "inert" or "executable-markup")
            consequence = "dangling-markup";

        var tier = chain.Tier;
        if (consequence != chain.Consequence)
            tier = ClassifyTier(chain.Source, chain.Confidence, consequence, chain.Sink, chain.SinkData,
                chain.Value, chain.Stack, chain.FrameOrigin, probeMode: false, pageOrigin);

        if (consequence == chain.Consequence && tier == chain.Tier)
            return chain;

        return new DomFlowChain
        {
            Source = chain.Source,
            Value = chain.Value,
            Sink = chain.Sink,
            SinkData = chain.SinkData,
            Stack = chain.Stack,
            FrameOrigin = chain.FrameOrigin,
            Mutation = chain.Mutation,
            Consequence = consequence,
            Confidence = chain.Confidence,
            Framework = chain.Framework,
            Timestamp = chain.Timestamp,
            Tier = tier
        };
    }

    internal static bool IsAttackerReachableSource(string? source)
    {
        if (string.IsNullOrWhiteSpace(source) || source is "(unknown)" or "canary")
            return false;
        var s = source.ToLowerInvariant();
        if (s.Contains("document.cookie", StringComparison.Ordinal))
            return false;
        if (s.Contains("json.parse", StringComparison.Ordinal) && s.Contains("referrer", StringComparison.Ordinal))
            return false;
        return s.Contains("url", StringComparison.Ordinal)
               || s.Contains("location.", StringComparison.Ordinal)
               || s.Contains("hash", StringComparison.Ordinal)
               || s.Contains("search", StringComparison.Ordinal)
               || s.Contains("postmessage", StringComparison.Ordinal)
               || s.Contains("storage", StringComparison.Ordinal)
               || s.Contains("window.name", StringComparison.Ordinal)
               || s.Contains("referrer", StringComparison.Ordinal)
               || s.StartsWith("input", StringComparison.Ordinal);
    }

    private static bool IsNavigationSink(string? sinkName) =>
        sinkName is "location.assign" or "location.replace" or "location.href" or "window.open";

    private static bool LooksLikeOffOriginNavigation(string? sinkData, string? pageOrigin)
    {
        if (string.IsNullOrWhiteSpace(sinkData))
            return false;
        var data = sinkData.Trim();
        if (data.StartsWith("//", StringComparison.Ordinal))
            return true;
        if (Uri.TryCreate(data, UriKind.Absolute, out var uri)
            && (uri.Scheme is "http" or "https"))
        {
            if (string.IsNullOrEmpty(pageOrigin))
                return true;
            if (Uri.TryCreate(pageOrigin, UriKind.Absolute, out var page))
                return !string.Equals(uri.Host, page.Host, StringComparison.OrdinalIgnoreCase);
            return true;
        }

        return false;
    }

    internal static bool IsInertUrlAttributeWrite(string? sinkName, string? sinkData)
    {
        if (!string.Equals(sinkName, "setAttribute", StringComparison.OrdinalIgnoreCase)
            && sinkName is not ("a.href" or "link.href"))
            return false;
        if (string.IsNullOrEmpty(sinkData))
            return sinkName is "a.href" or "link.href";
        var d = sinkData.ToLowerInvariant();
        return d.Contains("href", StringComparison.Ordinal)
               || d.Contains("src=", StringComparison.Ordinal)
               || d.Contains("action", StringComparison.Ordinal);
    }

    internal static bool IsSessionCookieToSameOriginApi(
        string? source,
        string? sinkName,
        string? sinkData,
        string? pageOrigin)
    {
        if (source?.Contains("cookie", StringComparison.OrdinalIgnoreCase) != true)
            return false;
        if (sinkName is not "fetch" and not "xhr.open")
            return false;
        if (string.IsNullOrEmpty(sinkData) || string.IsNullOrEmpty(pageOrigin))
            return true;
        return sinkData.Contains(pageOrigin, StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsThirdPartyWidgetFrame(string? frameOrigin, string? pageOrigin)
    {
        if (string.IsNullOrWhiteSpace(frameOrigin) || string.IsNullOrWhiteSpace(pageOrigin))
            return false;
        if (frameOrigin.StartsWith(pageOrigin, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!Uri.TryCreate(frameOrigin, UriKind.Absolute, out var fo))
            return false;
        var host = fo.Host.ToLowerInvariant();
        return host.Contains("google.", StringComparison.Ordinal)
               || host.Contains("gstatic.", StringComparison.Ordinal)
               || host.Contains("facebook.", StringComparison.Ordinal)
               || host.Contains("doubleclick.", StringComparison.Ordinal)
               || host.Contains("youtube.", StringComparison.Ordinal);
    }

    private static bool IsProbeMarkerTier(string? source, string? sinkData, string? value)
    {
        if (string.Equals(source, "canary", StringComparison.OrdinalIgnoreCase))
            return true;
        if (ContainsProbeMarker(sinkData) || ContainsProbeMarker(value))
            return true;
        if (source?.Contains("trowser_probe", StringComparison.OrdinalIgnoreCase) == true)
            return true;
        return false;
    }

    private static bool ContainsProbeMarker(string? text) =>
        !string.IsNullOrEmpty(text)
        && (text.Contains("trowser_canary", StringComparison.OrdinalIgnoreCase)
            || text.Contains("trowser_probe", StringComparison.OrdinalIgnoreCase)
            || text.Contains("trowser_q=", StringComparison.OrdinalIgnoreCase));

    /// <summary>Probe-mode sinks from Trowser-injected scripts (anonymous stack, canary payload).</summary>
    internal static bool IsProbeInjectionArtifact(
        string? source,
        string? value,
        string? sinkData,
        string? stack,
        string consequence)
    {
        if (ContainsProbeMarker(sinkData) || ContainsProbeMarker(value))
            return true;
        if (consequence != "exec" && consequence != "executable-markup")
            return false;
        if (!StackIsAnonymousOnly(stack))
            return false;
        return true;
    }

    internal static bool StackIsAnonymousOnly(string? stack)
    {
        if (string.IsNullOrWhiteSpace(stack))
            return false;
        var lines = stack.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
            return false;
        foreach (var line in lines)
        {
            if (line.Contains("://", StringComparison.Ordinal))
                return false;
        }
        return lines.Any(l => l.Contains("<anonymous>", StringComparison.OrdinalIgnoreCase)
                              || l.Contains("eval at", StringComparison.OrdinalIgnoreCase));
    }

    internal static bool StackIncludesPageScript(string? stack) =>
        !string.IsNullOrWhiteSpace(stack) && stack.Contains("://", StringComparison.Ordinal);

    private static int Priority(DomFlowChain c) =>
        (c.Tier == "exploitable" ? 200 : c.Tier == "probe-artifact" ? 80 : c.Tier == "hygiene" ? 20 : 5)
        + (c.Consequence == "exec" ? 100 : 0)
        + (c.Confidence == "canary" ? 50 : c.Confidence == "value-match" ? 30 : 10)
        + (c.Consequence is "nav-hijack" or "request-forgery" or "executable-markup" or "dangling-markup" or "css-injection" ? 20 : 0);

    private static bool IsMarkupSinkName(string? sink) =>
        sink is "innerHTML" or "outerHTML" or "insertAdjacentHTML" or "shadowRoot.innerHTML"
            or "document.write" or "document.writeln";

    private static bool IsStyleInjectionSink(string? sink, string? sinkData)
    {
        if (sink is "link.href" or "setAttribute" or "setAttributeNS")
        {
            var d = (sinkData ?? "").ToLowerInvariant();
            return d.Contains("stylesheet", StringComparison.Ordinal)
                   || d.Contains("rel=stylesheet", StringComparison.Ordinal);
        }

        return sink?.Contains("style", StringComparison.OrdinalIgnoreCase) == true
               && sink.Contains("css", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeDanglingMarkup(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 4000)
            return false;
        var t = text.Trim();
        if (!t.Contains('<', StringComparison.Ordinal))
            return false;
        var lastOpen = t.LastIndexOf('<');
        var lastClose = t.LastIndexOf('>');
        return lastOpen > lastClose;
    }

    private DomFlowResult Finalize(
        string mode,
        string url,
        int eventCount,
        List<DomFlowChain> chains,
        TrustedTypesPosture? trustedTypes = null)
    {
        var counts = chains.GroupBy(c => c.Consequence)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var tierCounts = chains.GroupBy(c => c.Tier)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var exploitable = chains.Count(c => c.Tier == "exploitable" && IsAttackerReachableSource(c.Source));

        var next = new List<string>();
        var hints = new List<string>();
        if (chains.Any(c => c.Consequence == "exec" && c.Tier == "exploitable"))
            next.Add("Confirmed executable DOM XSS — verify CSP and sanitizer bypass; capture with repro/verify.");
        if (mode == "probe" && chains.Any(c => c.Tier == "probe-artifact"))
            hints.Add("probe-artifact: some chains are from Trowser probe injection — require a page-origin script URL in stack before filing exec.");
        if (chains.Any(c => c.Consequence is "nav-hijack" or "executable-markup"))
            next.Add("Run POST /api/security/trace-input with monitorSinks:true on the matching source.");
        if (chains.Any(c => c.Source.Contains("postMessage", StringComparison.OrdinalIgnoreCase)))
            next.Add("Run POST /api/security/postmessage to grade origin checks.");
        if (mode == "observe" && exploitable == 0)
            next.Add("Browse the app with Shadow runtime enabled, or use mode:\"probe\" with safetyMode:\"active\".");
        if (mode == "probe")
            next.Add("Probe may leave canaries in the URL — POST /api/clear-session or re-navigate to a clean route.");
        if (mode == "observe" && exploitable == 0 && eventCount < 5)
            hints.Add("coverageGap: runtime sensor saw few events — wait for SPA route (hash router) or run mode:\"probe\".");
        if (mode == "observe" && exploitable == 0 && chains.Count > 0)
            hints.Add("coverageGap: temporal/hygiene flows only — confirm with POST /api/security/xss-scan (includeDom) or mode:\"probe\".");
        if (mode == "observe")
            hints.Add("observe uses events since the start of this call only; POST dom-flows with reset:true clears the sensor buffer without clear-all.");

        if (chains.Any(c => c.Consequence == "dangling-markup" && c.Tier == "exploitable"))
            next.Add("Dangling markup chain — confirm parser truncation with a controlled canary; not provable from HTTP status alone.");
        if (chains.Any(c => c.Consequence == "css-injection" && c.Tier == "exploitable"))
            next.Add("CSS injection lead — pair with POST /api/security/xs-leaks when stylesheet load/error oracles apply.");

        if (trustedTypes is { RequireTrustedTypesForScript: true }
            && chains.Any(c => c.Tier == "exploitable"
                               && c.Consequence is "exec" or "executable-markup"
                               && IsAttackerReachableSource(c.Source)))
        {
            hints.Add(
                "trustedTypes: CSP require-trusted-types-for 'script' is set — exploitable legacy sinks may still indicate policy gaps or trustedTypes.createPolicy bypass; verify in browser.");
        }

        var exec = counts.GetValueOrDefault("exec");
        var summary = chains.Count == 0
            ? "No source→sink flows observed."
            : $"{chains.Count} flow(s); exploitable={exploitable} (attacker-reachable sources only), exec={exec} (sink-capable consequence label — not execution proof), value-match={chains.Count(c => c.Confidence == "value-match")}, canary={chains.Count(c => c.Confidence == "canary")}.";

        return new DomFlowResult
        {
            Mode = mode,
            Url = url,
            SensorInstalled = _ctx.ActiveTab.RuntimeEvents.Installed,
            EventCount = eventCount,
            Chains = chains,
            NextActions = next,
            CoverageHints = hints,
            ConsequenceCounts = counts,
            TierCounts = tierCounts,
            ExploitableChainCount = exploitable,
            Summary = summary
        };
    }
}

file static class DomFlowStringExt
{
    public static string Truncate(this string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
