using System.Net;
using Trowser.Security;
using Trowser.Security.DomFlow;
using Trowser.Security.Orchestration;
using Trowser.Security.GadgetChains;
using Trowser.Security.Runtime;
using Trowser.Security.XsLeaks;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    private Task HandlePostSecurityServiceWorkerAudit(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityServiceWorkerAuditAsync);

    internal async Task<object> BuildSecurityServiceWorkerAuditAsync(JsonBody body)
    {
        var mode = SafetyGate.Resolve(body);
        if (mode < SafetyMode.Safe)
            throw new ApiCommandException(403,
                "Service worker audit requires safetyMode 'safe' or higher " +
                $"(current: '{mode.ToLabel()}').");

        var fetchScripts = body.GetBool("fetchScripts", true);
        var maxScriptBytes = Math.Clamp(body.GetInt("maxScriptBytes", 256_000), 4096, 512_000);
        var auditor = new ServiceWorkerAuditor(_context);
        var result = await auditor.RunAsync(fetchScripts, maxScriptBytes);
        return auditor.ToApiResponse(result);
    }

    private Task HandlePostSecurityClientSurface(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityClientSurfaceAsync);

    internal async Task<object> BuildSecurityClientSurfaceAsync(JsonBody body)
    {
        var installSensor = body.GetBool("installSensor", true);
        var waitMs = body.HasProperty("waitMs") ? body.GetInt("waitMs") : 400;
        var reloadForSensor = body.GetBool("reloadForSensor", true);
        var reset = body.GetBool("reset", false);
        var scopeToDocument = body.GetBool("scopeToCurrentDocument", true);
        var mapper = new ClientSurfaceMapper(_context);
        var result = await mapper.MapAsync(installSensor, waitMs, reloadForSensor, reset, scopeToDocument);
        return result.ToApiResponse();
    }

    private Task HandlePostSecurityPostMessage(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityPostMessageAsync);

    internal async Task<object> BuildSecurityPostMessageAsync(JsonBody body)
    {
        // Synthetic MessageEvent fuzz is allowed at safe; active adds mocked attacker-origin proof.
        var mode = SafetyGate.Resolve(body);
        if (mode < SafetyMode.Safe)
            throw new ApiCommandException(403,
                "postMessage audit requires safetyMode 'safe' or higher " +
                $"(current: '{mode.ToLabel()}').");

        var topologies = body.GetStringArray("topologies");

        var options = new PostMessageAuditOptions
        {
            SafetyMode = mode.ToLabel(),
            Fuzz = body.GetBool("fuzz", true),
            MaxPayloads = Math.Clamp(body.GetInt("maxPayloads", 8), 1, 20),
            MaxPayloadsPerListener = Math.Clamp(body.GetInt("maxPayloadsPerListener", 2), 1, 4),
            Depth = body.GetString("depth") ?? SecurityScanDepth.Quick,
            SuggestOnly = body.GetBool("suggestOnly"),
            IncludeOutbound = body.GetBool("includeOutbound", true),
            MaxSeconds = body.GetInt("maxSeconds", 0),
            ListenerFilter = body.GetString("listenerFilter"),
            Topologies = topologies is { Count: > 0 } ? topologies : null,
            IncludeHistory = body.GetBool("includeHistory"),
            Reset = body.GetBool("reset"),
            AttackerOrigin = body.GetString("attackerOrigin"),
            DescendIframes = !body.HasProperty("descendIframes") || body.GetBool("descendIframes", true)
        };

        var auditor = new PostMessageAuditor(_context);
        var result = await auditor.RunAsync(options);
        return result.ToApiResponse();
    }

    private Task HandlePostSecurityClientPrototypePollution(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityClientPrototypePollutionAsync);

    internal async Task<object> BuildSecurityClientPrototypePollutionAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "Client prototype pollution navigates and mutates Object.prototype");
        if (gateError != null)
            throw new ApiCommandException(403, gateError.Value);

        var baseUrl = body.GetString("baseUrl") ?? body.GetString("url");
        var tryGadgets = body.GetBool("tryGadgets", true);
        var scanner = new ClientPrototypePollutionScanner(_context);
        var result = await scanner.RunAsync(baseUrl, tryGadgets);
        return result.ToApiResponse();
    }

    private Task HandlePostSecurityDomXssAudit(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityDomXssAuditAsync);

    internal async Task<object> BuildSecurityDomXssAuditAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "DOM XSS audit navigates with injection payloads and runtime sink monitoring");
        if (gateError != null)
            throw new ApiCommandException(403, gateError.Value);

        var mode = SafetyGate.Resolve(body);
        var confirmExecution = body.HasProperty("confirmExecution")
            ? body.GetBool("confirmExecution")
            : mode >= SafetyMode.Aggressive;

        var budgetObj = body.HasProperty("budget") ? new JsonBody(body.GetObject("budget")) : null;
        var maxSecondsOverride = budgetObj?.GetInt("maxSeconds", 0) ?? body.GetInt("maxSeconds", 0);

        var depthPlan = DomXssAuditRunner.PlanScanDepth(body.GetString("depth"));
        if (depthPlan.ConfirmExecutionUnlessExplicit && !body.HasProperty("confirmExecution"))
            confirmExecution = true;

        var options = DomXssAuditRunner.ResolveOptions(
            depthPlan,
            confirmExecution,
            maxSecondsOverride,
            runClientSurface: body.HasProperty("runClientSurface") ? body.GetBool("runClientSurface") : null,
            runPassiveXss: body.HasProperty("runPassiveXss") ? body.GetBool("runPassiveXss") : null,
            runDomFlowProbe: body.HasProperty("runDomFlowProbe") ? body.GetBool("runDomFlowProbe") : null,
            runTraceInput: body.HasProperty("runTraceInput") ? body.GetBool("runTraceInput") : null,
            probeAllUrlParams: body.HasProperty("probeAllUrlParams") ? body.GetBool("probeAllUrlParams") : null,
            probeUrlHash: body.HasProperty("probeUrlHash") ? body.GetBool("probeUrlHash") : null,
            runScriptGatedTraces: body.HasProperty("runScriptGatedTraces") ? body.GetBool("runScriptGatedTraces") : null,
            fireEvents: body.HasProperty("fireEvents") ? body.GetBool("fireEvents") : null,
            timeoutMs: body.HasProperty("timeoutMs") ? body.GetInt("timeoutMs") : null);

        var result = await new DomXssAuditRunner(_context).RunAsync(options, _context.OperationCancellation);
        return result.ToApiResponse();
    }

    private Task HandlePostSecurityDomFlows(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityDomFlowsAsync);

    internal async Task<object> BuildSecurityDomFlowsAsync(JsonBody body)
    {
        var mode = (body.GetString("mode") ?? "observe").Trim().ToLowerInvariant();
        var waitMs = body.HasProperty("waitMs") ? body.GetInt("waitMs") : 400;
        var waitForSpa = body.GetBool("waitForSpa", true);
        var minTier = (body.GetString("minTier") ?? "hygiene").Trim().ToLowerInvariant();
        var restoreUrl = body.GetBool("restoreUrl", true);
        var graph = new DomFlowGraph(_context);
        if (body.GetBool("reset"))
            graph.ResetSensorBuffer();

        DomFlowGraph.DomFlowResult result;
        if (mode is "probe" or "active")
        {
            var gateError = SafetyGate.RequireActive(body,
                "DOM flow probe plants canaries in attacker-controlled sources");
            if (gateError != null)
                throw new ApiCommandException(403, gateError.Value);

            var sources = body.GetStringList("sources");
            var canary = body.GetString("canary");
            result = await graph.ProbeAsync(sources, canary, restoreUrl);
        }
        else
            result = await graph.ObserveAsync(waitMs, waitForSpa);

        var chains = FilterDomFlowChains(result.Chains, minTier);
        var tt = await TrustedTypesPosture.FromDocumentHeadersAsync(_context);
        return new
        {
            mode = result.Mode,
            url = result.Url,
            trustedTypes = tt.ToApiObject(),
            sensorInstalled = result.SensorInstalled,
            eventCount = result.EventCount,
            chainCount = chains.Count,
            exploitableChainCount = result.ExploitableChainCount,
            consequenceCounts = result.ConsequenceCounts,
            tierCounts = result.TierCounts,
            summary = result.Summary,
            coverageHints = result.CoverageHints,
            nextActions = result.NextActions,
            chains
        };
    }

    private static List<DomFlowGraph.DomFlowChain> FilterDomFlowChains(
        IReadOnlyList<DomFlowGraph.DomFlowChain> chains,
        string minTier)
    {
        var minRank = minTier switch
        {
            "exploitable" => 3,
            "probe-artifact" => 2,
            "hygiene" => 1,
            "noise" => 0,
            _ => 1
        };
        static int Rank(string tier) => tier switch
        {
            "exploitable" => 3,
            "probe-artifact" => 2,
            "hygiene" => 1,
            _ => 0
        };
        return chains.Where(c => Rank(c.Tier) >= minRank).ToList();
    }

    private Task HandlePostSecurityGadgetChains(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityGadgetChainsAsync);

    internal async Task<object> BuildSecurityGadgetChainsAsync(JsonBody body)
    {
        var gateError = SafetyGate.RequireActive(body,
            "Gadget chain scan runs active clobber, client-PP, and dom-flow probes");
        if (gateError != null)
            throw new ApiCommandException(403, gateError.Value);

        var mode = SafetyGate.Resolve(body);
        var budgetObj = body.HasProperty("budget") ? new JsonBody(body.GetObject("budget")) : null;
        var options = new GadgetChainScanner.GadgetChainOptions
        {
            Probes = body.GetStringList("probes"),
            MaxSeconds = budgetObj?.GetInt("maxSeconds", 0) ?? body.GetInt("maxSeconds", 0),
            IncludeRadar = !body.HasProperty("includeRadar") || body.GetBool("includeRadar"),
            TargetGlobals = body.GetStringList("targetGlobals"),
            PerturbingRadar = body.GetBool("perturbingRadar")
        };
        var scanner = new GadgetChainScanner(_context);
        var result = await scanner.RunAsync(options, mode);
        return result.ToApiResponse(body.GetBool("includeHygiene", true));
    }

    private Task HandlePostSecurityGadgetRadar(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityGadgetRadarAsync);

    internal async Task<object> BuildSecurityGadgetRadarAsync(JsonBody body)
    {
        var action = (body.GetString("action") ?? "read").Trim().ToLowerInvariant();
        var radar = new GadgetRadarService(_context);
        switch (action)
        {
            case "start":
            {
                if (body.GetBool("perturbing"))
                {
                    var gateError = SafetyGate.RequireActive(body,
                        "Perturbing gadget radar installs Object.prototype getter traps");
                    if (gateError != null)
                        throw new ApiCommandException(403, gateError.Value);
                }

                await radar.StartAsync(body.GetBool("perturbing"), body.GetStringList("protoKeys"));
                return new { message = "Gadget radar started", perturbing = body.GetBool("perturbing") };
            }
            case "stop":
                await radar.StopAsync();
                return new { message = "Gadget radar stopped (proto traps removed)" };
            default:
                return (await radar.ReadAsync()).ToApiResponse();
        }
    }

    private Task HandlePostSecurityXssiScan(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityXssiScanAsync);

    internal async Task<object> BuildSecurityXssiScanAsync(JsonBody body)
    {
        var mode = SafetyGate.Resolve(body);
        if (mode < SafetyMode.Safe)
            throw new ApiCommandException(403,
                "XSSI scan requires safetyMode 'safe' or higher " +
                $"(current: '{mode.ToLabel()}').");

        var options = new XssiScanProbe.XssiOptions
        {
            Urls = body.GetStringArray("urls"),
            MaxUrls = body.GetInt("maxUrls", 12),
            TimeoutMs = body.GetInt("timeoutMs", 12_000),
            IncludeNetworkLog = body.GetBool("includeNetworkLog", true)
        };
        var result = await _context.RunXssiScanAsync(options);
        return result.ToApiResponse();
    }

    private Task HandlePostSecurityXsLeaks(HttpListenerRequest request, HttpListenerResponse response) =>
        RespondAsync(request, response, BuildSecurityXsLeaksAsync);

    internal async Task<object> BuildSecurityXsLeaksAsync(JsonBody body)
    {
        var mode = SafetyGate.Resolve(body);
        if (mode < SafetyMode.Safe)
            throw new ApiCommandException(403,
                "XS-Leaks scan requires safetyMode 'safe' or higher " +
                $"(current: '{mode.ToLabel()}').");

        var states = XsLeakScanner.ParseStatesFromJson(body.GetRawJson("states"));
        var hypothesis = XsLeakScanner.ParseHypothesisFromJson(body.GetRawJson("hypothesis"));
        var autoStates = body.HasProperty("autoStates")
            ? body.GetBool("autoStates")
            : hypothesis == null && states.Count < 2;
        if (states.Count < 2
            && !autoStates
            && !XsLeakHypothesis.CanExpandFromHypothesis(hypothesis))
        {
            throw new ApiCommandException(400,
                "XS-Leaks requires at least two states: [{label,url,identity?}, ...], a hypothesis with urlTemplate plus hitValues and missValues, " +
                "or omit states to auto-derive from session (autoStates defaults true when states are omitted).");
        }

        var attackerSite = body.GetString("attackerSite")?.Trim();
        if (string.IsNullOrEmpty(attackerSite))
            attackerSite = "cross-site";

        var budgetObj = body.HasProperty("budget") ? new JsonBody(body.GetObject("budget")) : null;
        var options = new XsLeakScanner.XsLeakOptions
        {
            States = states,
            Hypothesis = hypothesis,
            SuggestOnly = body.GetBool("suggestOnly"),
            Techniques = body.GetStringList("techniques"),
            Trials = body.HasProperty("trials") ? body.GetInt("trials") : 0,
            SkipWarmup = body.GetBool("skipWarmup") == true,
            AutoStates = autoStates,
            AttackerSite = attackerSite,
            IncludePosture = !body.HasProperty("includePosture") || body.GetBool("includePosture"),
            PostureInteractionProbes = body.HasProperty("postureInteractionProbes")
                ? body.GetBool("postureInteractionProbes")
                : null,
            FullCatalog = body.GetBool("fullCatalog") == true,
            MaxSeconds = budgetObj?.GetInt("maxSeconds", 0) ?? body.GetInt("maxSeconds", 0),
            ObserveMode = body.GetBool("observeMode") == true,
            IdentifyAuthCookie = body.GetBool("identifyAuthCookie") == true
        };
        var scanner = new XsLeakScanner(_context, _identityStore);
        try
        {
            var result = await scanner.RunAsync(options, mode);
            return result.ToApiResponse();
        }
        catch (InvalidOperationException ex)
        {
            throw new ApiCommandException(400, ex.Message);
        }
    }
}
