using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security.Runtime;

/// <summary>
/// Start/stop/read the gadget radar on the active tab.
/// </summary>
public sealed class GadgetRadarService
{
    private readonly AutomationContext _ctx;

    public GadgetRadarService(AutomationContext context) => _ctx = context;

    public sealed class RadarReadResult
    {
        public string Url { get; init; } = "";
        public bool SensorInstalled { get; init; }
        public bool PerturbingActive { get; init; }
        public int EventCount { get; init; }
        public List<GadgetRadarHit> Hits { get; init; } = [];
        public List<string> ProtoReadKeys { get; init; } = [];
        public List<string> NextActions { get; init; } = [];
        public string Summary { get; init; } = "";

        public object ToApiResponse() => new
        {
            url = Url,
            sensorInstalled = SensorInstalled,
            perturbingActive = PerturbingActive,
            eventCount = EventCount,
            hits = Hits,
            protoReadKeys = ProtoReadKeys,
            nextActions = NextActions,
            summary = Summary
        };
    }

    public sealed class GadgetRadarHit
    {
        public string Name { get; init; } = "";
        public string? Key { get; init; }
        public string? Receiver { get; init; }
        public int Count { get; init; } = 1;
        public bool FirstPartyStack { get; init; }
        public string? SampleStack { get; init; }
        public int Rank { get; init; }
        /// <summary>Second identifier in <c>window.name.prop</c>, when the read is dotted.</summary>
        public string? Prop { get; init; }
        /// <summary><see cref="GadgetChains.GadgetRadarLeads.DiscoveryTrap"/> or script-scan.</summary>
        public string Discovery { get; init; } = GadgetChains.GadgetRadarLeads.DiscoveryTrap;
        public bool ClobberProbeCandidate { get; init; }
    }

    public async Task StartAsync(bool perturbing = false, IReadOnlyList<string>? protoKeys = null)
    {
        await RuntimeSensorInstaller.EnsureAmbientAsync(_ctx);
        var tab = _ctx.ActiveTab;
        if (string.IsNullOrEmpty(tab.RuntimeEvents.GadgetRadarScriptId))
        {
            try
            {
                var id = await _ctx.AddDocumentCreatedScriptAsync(GadgetRadarScript.BuildStandaloneInstall());
                if (!string.IsNullOrEmpty(id))
                    tab.RuntimeEvents.GadgetRadarScriptId = id;
            }
            catch { /* next navigation still depends on the live install below */ }
        }

        try { await _ctx.ExecuteJs(GadgetRadarScript.BuildStandaloneInstall()); }
        catch { /* current document is best-effort; the document-created script covers the next load */ }

        if (perturbing)
        {
            var keys = protoKeys?.Count > 0
                ? protoKeys
                : GadgetRadarAggregator.DefaultProtoTrapKeys;
            await _ctx.ExecuteJs(GadgetRadarScript.BuildProtoTrapsInstall(keys));
        }
    }

    public async Task StopAsync()
    {
        try { await _ctx.ExecuteJs(GadgetRadarScript.BuildProtoTrapsUninstall()); }
        catch { /* best-effort */ }

        var id = _ctx.ActiveTab.RuntimeEvents.GadgetRadarScriptId;
        if (!string.IsNullOrEmpty(id))
        {
            await RuntimeSensorInstaller.RemoveDocumentCreatedAsync(_ctx, id);
            if (_ctx.ActiveTab.RuntimeEvents.GadgetRadarScriptId == id)
                _ctx.ActiveTab.RuntimeEvents.GadgetRadarScriptId = null;
        }
    }

    public async Task<RadarReadResult> ReadAsync(string? pageOrigin = null)
    {
        pageOrigin ??= await SafeOriginAsync();
        var scriptOrigins = await CollectScriptOriginsAsync(pageOrigin);
        var events = _ctx.ActiveTab.RuntimeEvents.All()
            .Where(e => e.Kind is "gadget-read" or "proto-read")
            .Where(e => !RuntimeInstrumentationFilter.IsGadgetRadarArtifact(e.Stack, e.Data))
            .ToList();

        var hits = GadgetRadarAggregator.RankHits(events, pageOrigin, scriptOrigins);
        var protoKeys = events
            .Where(e => e.Kind == "proto-read")
            .Select(e => e.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var next = new List<string>();
        if (hits.Any(h => h.FirstPartyStack))
            next.Add(SecurityNextActions.GadgetChains);
        if (hits.Count == 0)
            next.Add("Browse key flows with Shadow audit runtime enabled, or POST /api/security/gadget-radar action:start");

        return new RadarReadResult
        {
            Url = await SafeUrlAsync(),
            SensorInstalled = _ctx.ActiveTab.RuntimeEvents.Installed,
            PerturbingActive = protoKeys.Count > 0,
            EventCount = events.Count,
            Hits = hits,
            ProtoReadKeys = protoKeys,
            NextActions = next,
            Summary = hits.Count == 0
                ? "No gadget-read events in the runtime buffer."
                : $"{hits.Count} ranked global/proto read candidate(s); first-party stacks={hits.Count(h => h.FirstPartyStack)}."
        };
    }

    private async Task<string?> SafeOriginAsync()
    {
        try
        {
            var url = await _ctx.GetCurrentUrl();
            if (Uri.TryCreate(url, UriKind.Absolute, out var u))
                return u.GetLeftPart(UriPartial.Authority);
        }
        catch { /* ignore */ }
        return null;
    }

    private async Task<string> SafeUrlAsync()
    {
        try { return await _ctx.GetCurrentUrl(); }
        catch { return _ctx.ActiveTab.Url; }
    }

    private async Task<IReadOnlyCollection<string>> CollectScriptOriginsAsync(string? pageOrigin)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(pageOrigin))
            set.Add(pageOrigin);

        foreach (var e in _ctx.ActiveTab.Network.Entries)
        {
            if (e.Url.Contains(".js", StringComparison.OrdinalIgnoreCase)
                && Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
                set.Add(u.GetLeftPart(UriPartial.Authority));
        }

        try
        {
            var json = await _ctx.ExecuteJs(
                """
                (function(){
                  var o = [];
                  document.querySelectorAll('script[src]').forEach(function(s){
                    try { o.push(new URL(s.src, location.href).origin); } catch(e){}
                  });
                  return JSON.stringify(o);
                })()
                """);
            using var doc = JsonDocument.Parse(Unquote(json));
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var s = el.GetString();
                if (!string.IsNullOrEmpty(s)) set.Add(s);
            }
        }
        catch { /* ignore */ }

        return set;
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
}
