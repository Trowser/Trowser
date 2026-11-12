using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.DomFlow;
using Trowser.Security.Orchestration;
using Trowser.Security.Runtime;

namespace Trowser.Security.GadgetChains;

public sealed class GadgetChainScanner
{
    private readonly AutomationContext _ctx;

    public GadgetChainScanner(AutomationContext context) => _ctx = context;

    public sealed class GadgetChainOptions
    {
        public IReadOnlyList<string>? Probes { get; init; }
        public int MaxSeconds { get; init; }
        public bool IncludeRadar { get; init; } = true;
        public IReadOnlyList<string>? TargetGlobals { get; init; }
        public bool PerturbingRadar { get; init; }
    }

    public sealed class GadgetChainResult
    {
        public long ElapsedMs { get; set; }
        public string Url { get; set; } = "";
        public GadgetChainPlanner.Plan? Plan { get; set; }
        public List<GadgetRadarService.GadgetRadarHit> RadarHits { get; set; } = [];
        public List<UnifiedSecurityFinding> Findings { get; set; } = [];
        public List<ChainableFinding> ChainFindings { get; set; } = [];
        public List<string> Warnings { get; set; } = [];
        public List<string> NextActions { get; set; } = [];
        public bool BudgetExhausted { get; set; }
        public ChainEngine.ChainAnalysisResult? ChainAnalysis { get; set; }
        public ClientPpScanResult? ClientPp { get; set; }
        public DomFlowGraph.DomFlowResult? DomFlowProbe { get; set; }
        public List<ClobberProbeOutcome> ClobberProbes { get; set; } = [];
        public List<GadgetChainLead> Leads { get; set; } = [];
        public string Summary { get; set; } = "";

        public object ToApiResponse(bool includeHygiene = true)
        {
            var findings = includeHygiene
                ? Findings
                : Findings.Where(f => f.Tier != SecurityFindingTier.Hygiene).ToList();
            return new
            {
                message = Summary,
                elapsedMs = ElapsedMs,
                url = Url,
                findings = findings.Select(SecurityScanResult.ToApiFinding).ToList(),
                plan = Plan == null ? null : new
                {
                    selected = Plan.SelectedProbes,
                    skipped = Plan.SkippedProbes,
                    targetGlobalNames = Plan.TargetGlobalNames,
                    clobberProbeNames = Plan.ClobberProbeNames,
                    notes = Plan.Notes
                },
                radarHits = RadarHits,
                leads = Leads,
                clobberProbes = ClobberProbes,
                clientPp = ClientPp?.ToApiResponse(),
                domFlowProbe = DomFlowProbe == null ? null : new
                {
                    mode = DomFlowProbe.Mode,
                    summary = DomFlowProbe.Summary,
                    exploitableChainCount = DomFlowProbe.ExploitableChainCount,
                    chains = DomFlowProbe.Chains.Take(20)
                },
                budgetExhausted = BudgetExhausted ? (bool?)true : null,
                nextActions = NextActions,
                warnings = Warnings.Count > 0 ? Warnings : null,
                chainAnalysis = ChainAnalysis == null
                    ? null
                    : ChainEngine.ChainAnalysisService.BuildAnalyzePayload(ChainAnalysis)
            };
        }
    }

    public sealed class ClobberProbeOutcome
    {
        public string GlobalName { get; init; } = "";
        public string? Param { get; init; }
        public bool Confirmed { get; init; }
        public string? Evidence { get; init; }
        public string? Stack { get; init; }
    }

    public async Task<GadgetChainResult> RunAsync(GadgetChainOptions options, SafetyMode mode)
    {
        var sw = Stopwatch.StartNew();
        var active = mode >= SafetyMode.Active;
        var url = await SafeUrlAsync();
        var pageOrigin = Uri.TryCreate(url, UriKind.Absolute, out var u)
            ? u.GetLeftPart(UriPartial.Authority)
            : null;

        var radar = new GadgetRadarService(_ctx);
        if (options.IncludeRadar)
            await radar.StartAsync(options.PerturbingRadar && active);

        ClientSurfaceResult? surface = null;
        try
        {
            surface = await new ClientSurfaceMapper(_ctx).MapAsync(installSensor: true, waitMs: 300, reloadForSensor: false);
        }
        catch
        {
            /* best-effort */
        }

        var radarRead = await radar.ReadAsync(pageOrigin);

        var plan = GadgetChainPlanner.Build(radarRead.Hits, surface, active, options.Probes);
        if (options.TargetGlobals is { Count: > 0 })
        {
            plan.ClobberProbeNames = GadgetRadarLeads.SelectClobberProbeNames(radarRead.Hits, options.TargetGlobals);
            plan.TargetGlobalNames = options.TargetGlobals
                .Where(g => g.Length >= 2)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();
            if (active && plan.ClobberProbeNames.Count > 0 && !plan.SelectedProbes.Contains("clobber"))
                plan.SelectedProbes.Add("clobber");
        }

        var clobberProbeNames = plan.ClobberProbeNames;

        var result = new GadgetChainResult
        {
            Url = url,
            Plan = plan,
            RadarHits = radarRead.Hits,
            Warnings = plan.Notes.ToList(),
            Leads = radarRead.Hits
                .Where(h => h.FirstPartyStack)
                .Select(GadgetRadarLeads.ToRadarLead)
                .ToList()
        };

        var deadline = options.MaxSeconds > 0 ? sw.Elapsed + TimeSpan.FromSeconds(options.MaxSeconds) : (TimeSpan?)null;

        if (surface is { LoadObserved: false } && radarRead.Hits.Count == 0)
        {
            result.Warnings.Add(
                "Document load was not observed with the runtime sensor — inline scripts may read globals before traps attach. " +
                "Reflected-clobber fetch probes and POST /api/security/dom-flows mode=probe complement gadget-chains.");
        }

        if (active && plan.SelectedProbes.Contains("clobber") && clobberProbeNames.Count > 0)
        {
            DomRuntimeInjectionDiscovery.DiscoveryResult? discovery = null;
            try
            {
                discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(_ctx);
            }
            catch
            {
                /* best-effort */
            }

            var paramNames = ClobberParamDiscovery.Collect(surface, discovery);

            foreach (var name in clobberProbeNames.Take(4))
            {
                if (deadline.HasValue && sw.Elapsed > deadline.Value)
                {
                    result.BudgetExhausted = true;
                    break;
                }

                var prop = radarRead.Hits
                    .Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                    .Select(h => h.Prop)
                    .FirstOrDefault(p => !string.IsNullOrWhiteSpace(p));

                ReflectedDomClobberProbe.Outcome? fetchHit = null;
                foreach (var param in paramNames.Take(6))
                {
                    fetchHit = await ReflectedDomClobberProbe.TryFetchReflectionAsync(
                        _ctx, url, name, param, propertyName: prop);
                    if (fetchHit != null)
                        break;
                }

                if (fetchHit != null)
                {
                    result.ClobberProbes.Add(new ClobberProbeOutcome
                    {
                        GlobalName = fetchHit.GlobalName,
                        Param = fetchHit.Param,
                        Confirmed = true,
                        Evidence = fetchHit.Evidence
                    });
                    var fetchId = Guid.NewGuid().ToString("N");
                    result.Findings.Add(UnifiedSecurityFinding.Create(
                        category: "dom-clobbering",
                        title: $"Reflected DOM clobbering gadget: global '{name}' via HTML injection",
                        severity: "high",
                        confidence: SecurityConfidence.Likely,
                        endpoint: url,
                        param: fetchHit.Param,
                        evidence: fetchHit.Evidence,
                        proofHint: "Response HTML reflects clobber markup — confirm with live navigation if read happens before sensor install.",
                        nextActions: [SecurityNextActions.TraceInputMonitorSinks],
                        id: fetchId));
                    continue;
                }

                ClobberProbeOutcome? outcome = null;
                foreach (var param in paramNames.Take(6))
                {
                    outcome = await RunClobberProbeAsync(url, name, prop, param);
                    if (outcome.Confirmed)
                        break;
                }

                result.ClobberProbes.Add(outcome ?? new ClobberProbeOutcome
                {
                    GlobalName = name,
                    Param = paramNames.FirstOrDefault(),
                    Confirmed = false,
                    Evidence = "no param produced clobber confirmation"
                });
                outcome = result.ClobberProbes[^1];
                if (outcome.Confirmed)
                {
                    var id = Guid.NewGuid().ToString("N");
                    result.Findings.Add(UnifiedSecurityFinding.Create(
                        category: "dom-clobbering",
                        title: $"DOM clobbering gadget: global '{name}' resolves to injected element",
                        severity: "high",
                        confidence: SecurityConfidence.Confirmed,
                        endpoint: url,
                        evidence: outcome.Evidence,
                        proofHint: "App code read a missing global that attacker HTML can define via id/name.",
                        nextActions: [SecurityNextActions.GadgetChains, SecurityNextActions.TraceInputMonitorSinks],
                        id: id));
                    result.ChainFindings.Add(new ChainableFinding
                    {
                        Id = id,
                        Category = "dom-clobbering",
                        Severity = "high",
                        Title = $"DOM clobber on '{name}'",
                        Endpoint = url,
                        Detail = outcome.Evidence
                    });
                }
            }
        }

        if (active && plan.SelectedProbes.Contains("client-pp") && !(deadline.HasValue && sw.Elapsed > deadline.Value))
        {
            var ppKeys = radarRead.ProtoReadKeys.Concat(
                    radarRead.Hits.Where(h => h.Name.StartsWith("proto", StringComparison.OrdinalIgnoreCase)).Select(h => h.Key ?? ""))
                .Where(k => k.Length >= 2)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();
            var pp = new ClientPrototypePollutionScanner(_ctx);
            var ppResult = await pp.RunAsync(url, tryGadgets: true, priorityPropertyNames: ppKeys);
            result.ClientPp = ppResult;
            foreach (var f in ppResult.Findings)
            {
                if (f.Confidence == SecurityConfidence.Confirmed
                    && f.Tier == SecurityFindingTier.Exploitable)
                {
                    result.Findings.Add(f);
                    result.ChainFindings.Add(new ChainableFinding
                    {
                        Id = f.Id,
                        Category = f.Category,
                        Severity = f.Severity,
                        Title = f.Title,
                        Endpoint = f.Endpoint,
                        Detail = f.Evidence
                    });
                    continue;
                }

                if (f.Tier == SecurityFindingTier.Informational)
                    continue;

                result.Leads.Add(new GadgetChainLead
                {
                    Kind = "client-pp",
                    Name = f.Title,
                    Detail = f.Evidence,
                    SuggestedAction = "Run client prototype pollution scan with tryGadgets and review script gadgets."
                });
            }
        }

        if (active && plan.SelectedProbes.Contains("dom-flow-probe") && !(deadline.HasValue && sw.Elapsed > deadline.Value))
        {
            var graph = new DomFlowGraph(_ctx);
            var domProbe = await graph.ProbeAsync(
                sources: ["url-query", "url-hash", "storage", "window-name", "post-message", "websocket-message"],
                restoreUrl: true);
            result.DomFlowProbe = domProbe;
            foreach (var chain in domProbe.Chains)
            {
                if (GadgetRadarLeads.ShouldEmitDomFlowFinding(chain))
                {
                    var id = $"domflow-{Guid.NewGuid():N}";
                    result.Findings.Add(UnifiedSecurityFinding.Create(
                        category: "client-gadget-chain",
                        title: $"DOM flow {chain.Source} → {chain.Sink} ({chain.Consequence})",
                        severity: chain.Consequence == "exec" ? "high" : "medium",
                        confidence: chain.Confidence == "canary" ? SecurityConfidence.Confirmed : SecurityConfidence.Likely,
                        endpoint: url,
                        evidence: $"{chain.Source} → {chain.Sink}; tier={chain.Tier}; confidence={chain.Confidence}",
                        tier: SecurityFindingTier.Exploitable,
                        nextActions: [SecurityNextActions.TraceInputMonitorSinks],
                        id: id));
                    continue;
                }

                if (GadgetRadarLeads.IsDomFlowLead(chain))
                    result.Leads.Add(GadgetRadarLeads.ToDomFlowLead(chain));
            }
        }

        if (options.PerturbingRadar && active)
            await radar.StopAsync();

        sw.Stop();
        ChainEngine.ChainAnalysisResult? chainAnalysis = null;
        try
        {
            chainAnalysis = GadgetChainIntegrator.Analyze(_ctx, result);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        return new GadgetChainResult
        {
            ElapsedMs = sw.ElapsedMilliseconds,
            Url = result.Url,
            Plan = result.Plan,
            RadarHits = result.RadarHits,
            Findings = result.Findings,
            ChainFindings = result.ChainFindings,
            Warnings = result.Warnings,
            NextActions = BuildNextActions(result),
            BudgetExhausted = result.BudgetExhausted,
            ClientPp = result.ClientPp,
            DomFlowProbe = result.DomFlowProbe,
            ClobberProbes = result.ClobberProbes,
            ChainAnalysis = chainAnalysis,
            Summary = result.Findings.Count == 0 && result.Leads.Count == 0
                ? "Gadget chain scan: no confirmed chains; browse key flows then re-run gadget-radar."
                : $"Gadget chain scan: {result.Findings.Count} confirmed finding(s), {result.Leads.Count} lead(s) for follow-up.",
            Leads = result.Leads
        };
    }

    private static List<string> BuildNextActions(GadgetChainResult result)
    {
        var list = new List<string>();
        if (result.Leads.Any(l => l.Kind == "dom-flow"))
            list.Add(SecurityNextActions.TraceInputMonitorSinks);
        if (result.Leads.Any(l => l.Kind == "gadget-read"))
            list.Add(SecurityNextActions.GadgetRadarRead);
        if (result.Findings.Count == 0 && result.Leads.Count == 0)
            list.Add(SecurityNextActions.GadgetRadarRead);
        if (result.DomFlowProbe?.ExploitableChainCount > 0)
            list.Add(SecurityNextActions.TraceInputMonitorSinks);
        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
    }

    private async Task<ClobberProbeOutcome> RunClobberProbeAsync(
        string baseUrl, string globalName, string? propertyName = null, string? queryParam = null)
    {
        if (!IsSafeClobberName(globalName))
        {
            return new ClobberProbeOutcome
            {
                GlobalName = globalName,
                Confirmed = false,
                Evidence = "unsafe-or-reserved-global-name"
            };
        }

        var param = queryParam;
        if (string.IsNullOrWhiteSpace(param))
        {
            try
            {
                var discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(_ctx);
                param = ClobberParamDiscovery.Collect(null, discovery).FirstOrDefault() ?? "q";
            }
            catch
            {
                param = "q";
            }
        }

        var safeId = globalName.Replace('"', '_');
        var safeProp = string.IsNullOrWhiteSpace(propertyName) ? null : propertyName.Replace('"', '_');
        var canary = "trowser-clobber-value";
        var payload = safeProp == null
            ? $"<a id=\"{safeId}\" data-trowser-clobber=\"1\"></a>"
            : $"<form id=\"{safeId}\"><input name=\"{safeProp}\" value=\"{canary}\"></form>";
        var probeUrl = AppendQuery(baseUrl, $"{param}={Uri.EscapeDataString(payload)}");

        try
        {
            await _ctx.PrepareRuntimeSensorForNavigationAsync();
            await _ctx.Navigate(probeUrl);
            await Task.Delay(500);

            var checkJs = $$"""
                (function(){
                  try {
                    var n = {{JsonSerializer.Serialize(globalName)}};
                    var prop = {{JsonSerializer.Serialize(safeProp)}};
                    var canary = {{JsonSerializer.Serialize(canary)}};
                    var el = window[n];
                    var ok = false;
                    if (prop) {
                      var child = el && el[prop];
                      ok = !!(child && (child.value === canary
                        || (child.getAttribute && child.getAttribute('value') === canary)));
                    } else {
                      ok = !!(el && el.nodeType === 1 && el.getAttribute && el.getAttribute('data-trowser-clobber') === '1');
                    }
                    return JSON.stringify({ ok: !!ok, tag: el && el.tagName ? el.tagName : null });
                  } catch(e) { return JSON.stringify({ ok:false, error: String(e) }); }
                })()
                """;
            var json = await _ctx.ExecuteJs(checkJs);
            using var doc = JsonDocument.Parse(Unquote(json));
            var ok = doc.RootElement.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            return new ClobberProbeOutcome
            {
                GlobalName = globalName,
                Param = param,
                Confirmed = ok,
                Evidence = ok
                    ? $"window['{globalName}'] is clobberable via HTML injection in query param '{param}'"
                    : "injection did not clobber global read"
            };
        }
        catch (Exception ex)
        {
            return new ClobberProbeOutcome
            {
                GlobalName = globalName,
                Param = param,
                Confirmed = false,
                Evidence = ex.Message
            };
        }
        finally
        {
            try
            {
                var clean = baseUrl.Contains('#') ? baseUrl[..baseUrl.IndexOf('#')] : baseUrl;
                var q = clean.IndexOf('?');
                if (q >= 0) clean = clean[..q];
                await _ctx.Navigate(clean);
            }
            catch { /* restore */ }
        }
    }

    private static bool IsSafeClobberName(string name)
    {
        if (name.Length is < 2 or > 64)
            return false;
        if (!char.IsLetter(name[0]) && name[0] != '_')
            return false;
        return name.All(c => char.IsLetterOrDigit(c) || c == '_' || c == '-');
    }

    private async Task<string> SafeUrlAsync()
    {
        try { return await _ctx.GetCurrentUrl(); }
        catch { return _ctx.ActiveTab.Url; }
    }

    private static string AppendQuery(string baseUrl, string query)
    {
        var sep = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var hashIdx = baseUrl.IndexOf('#');
        if (hashIdx >= 0)
            return baseUrl[..hashIdx] + sep + query + baseUrl[hashIdx..];
        return baseUrl + sep + query;
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
}
