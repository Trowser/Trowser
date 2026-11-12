using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;

namespace Trowser.Security.XsLeaks;

public sealed class XsLeakScanner
{
    private readonly AutomationContext _ctx;
    private readonly IdentityStore _identities;
    private string _attackerOrigin = AttackerPageBuilder.AttackerOrigin;
    private int _probeTimeoutMs = 4000;
    private SecurityScanTabScope? _activeScanTabs;
    private string? _activeScanVictimHost;
    private string? _activeScanRunId;

    public XsLeakScanner(AutomationContext ctx, IdentityStore? identities = null)
    {
        _ctx = ctx;
        _identities = identities ?? ctx.OrchestrateIdentityStore ?? new IdentityStore();
    }

    public sealed class StateSpec
    {
        public string Label { get; init; } = "";
        public string Url { get; init; } = "";
        /// <summary>Captured identity name, or <c>anonymous</c> to clear cookies/storage before trials.</summary>
        public string? Identity { get; init; }
        /// <summary>Optional navigation on the home tab after identity apply (e.g. warm session).</summary>
        public string? SetupUrl { get; init; }
        /// <summary>hit | miss | control — steers evaluation and tiering.</summary>
        public string? Role { get; init; }
        /// <summary>GET (default) or POST for server validation and form-post probes.</summary>
        public string Method { get; init; } = "GET";
        public string? Body { get; init; }
        public string? ContentType { get; init; }
        /// <summary>application/x-www-form-urlencoded fields for POST (also used by form-post-frame probe).</summary>
        public Dictionary<string, string>? Form { get; init; }
    }

    public sealed class XsLeakOptions
    {
        public List<StateSpec> States { get; init; } = new();
        public XsLeakHypothesis.HypothesisSpec? Hypothesis { get; init; }
        /// <summary>Return candidate hypotheses without running probes.</summary>
        public bool SuggestOnly { get; init; }
        public List<string>? Techniques { get; init; }
        public int Trials { get; init; }
        /// <summary>When true, skip warm-up trials (default: one warm-up round per state).</summary>
        public bool SkipWarmup { get; init; }
        /// <summary>Derive states from identities, search traffic, or protected URLs (used when states has fewer than two entries).</summary>
        public bool AutoStates { get; init; }
        /// <summary>cross-site (default, evil.trowser.test) or same-site (mock sibling under victim host).</summary>
        public string AttackerSite { get; init; } = "cross-site";
        /// <summary>When false, skips posture analyzer (faster scan).</summary>
        public bool IncludePosture { get; init; } = true;
        /// <summary>When null (default), interaction probes run in active mode only. Set false to skip COOP/Fetch-Metadata live probes.</summary>
        public bool? PostureInteractionProbes { get; init; }
        /// <summary>Run the full technique catalog (default is a fast representative subset).</summary>
        public bool FullCatalog { get; init; }
        /// <summary>Wall-clock budget in seconds; partial results when exhausted (0 = no limit).</summary>
        public int MaxSeconds { get; init; }
        /// <summary>Run observation vectors per state (see details.observe).</summary>
        public bool ObserveMode { get; init; }
        /// <summary>Active only: leave-one-out auth cookie identification (session restored after).</summary>
        public bool IdentifyAuthCookie { get; init; }
    }

    public sealed class StatePairResult
    {
        public string StateA { get; init; } = "";
        public string StateB { get; init; } = "";
        public string Verdict { get; init; } = "indistinguishable";
        public string? Detail { get; init; }
        public double? EffectSize { get; init; }
    }

    public sealed class TechniqueResult
    {
        public string Technique { get; init; } = "";
        public string Category { get; init; } = "";
        /// <summary>Worst-case verdict across state pairs (before tier downgrade).</summary>
        public string Verdict { get; init; } = "indistinguishable";
        public string Tier { get; init; } = SecurityFindingTier.Exploitable;
        public bool Mitigated { get; init; }
        public string? MitigationReason { get; init; }
        public int Trials { get; init; }
        public Dictionary<string, List<string?>> ValuesByState { get; init; } = new();
        public Dictionary<string, List<double>> TimingByState { get; init; } = new();
        public List<StatePairResult> Pairs { get; init; } = new();
        public double? EffectSize { get; init; }
        public List<string> MitigatedBy { get; init; } = new();
        public string? Detail { get; init; }
        public string? PocHtml { get; init; }
        /// <summary>When set (e.g. low), the technique was skipped or results are structurally uninformative.</summary>
        public string? Applicability { get; init; }
        /// <summary>confirmed | candidate-* | screening | none</summary>
        public string ConfirmationStatus { get; init; } = "none";
    }

    public sealed class XsLeakResult
    {
        public string CookieMode { get; set; } = "unknown";
        public string RunId { get; set; } = "";
        public List<StateSpec> States { get; set; } = new();
        public List<TechniqueResult> Techniques { get; set; } = new();
        public List<UnifiedSecurityFinding> Findings { get; set; } = new();
        public List<ChainableFinding> ChainFindings { get; set; } = new();
        public XsLeakPostureAnalyzer.PostureResult? Posture { get; set; }
        public string? StateGenerationStrategy { get; set; }
        public string? StateGenerationDetail { get; set; }
        public List<string> AuthModelNotes { get; set; } = new();
        public XsLeakBrowserModel BrowserModel { get; set; } = XsLeakBrowserModel.Current();
        public int DistinguishableCount => Techniques.Count(t =>
            t.Verdict == "distinguishable" && t.Tier == SecurityFindingTier.Exploitable);
        public int ProbableCount => Techniques.Count(t =>
            t.Verdict == "probable" && t.Tier == SecurityFindingTier.Exploitable);
        public int HygieneCount => Techniques.Count(t =>
            (t.Verdict is "distinguishable" or "probable") && t.Tier == SecurityFindingTier.Hygiene);
        public int InformationalCount => Techniques.Count(t =>
            (t.Verdict is "distinguishable" or "probable") && t.Tier == SecurityFindingTier.Informational);
        public string Summary { get; set; } = "";
        public List<string> NextActions { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
        public bool SameUrlStates { get; set; }
        public bool BudgetExhausted { get; set; }
        public string? CatalogMode { get; set; }
        public ChainEngine.ChainAnalysisResult? ChainAnalysis { get; set; }
        public XsLeakStateValidator.ValidationResult? StateValidation { get; set; }
        public XsLeakTechniquePlanner.PlanResult? Plan { get; set; }
        public XsLeakSessionProfile? SessionProfile { get; set; }
        public object? CredentialDelivery { get; set; }
        public List<XsLeakHypothesis.Suggestion>? SuggestedHypotheses { get; set; }
        public XsLeakHypothesis.HypothesisSpec? HypothesisApplied { get; set; }
        public bool HypothesisExpanded { get; set; }
        public bool HypothesisRequested { get; set; }
        public bool SessionLostDuringScan { get; set; }
        public int PopupTabsOpened { get; set; }
        public int OrphanPopupTabsClosed { get; set; }
        public XsLeakObserveMode.ObserveResult? Observe { get; set; }
        public long ElapsedMs { get; set; }
        public int CandidatesProbed { get; set; }
        public int PayloadsSent { get; set; }

        public object ToApiResponse(bool includeHygiene = true)
        {
            var scan = new SecurityScanResult
            {
                Message = Summary,
                ElapsedMs = (int)Math.Min(ElapsedMs, int.MaxValue),
                CandidatesProbed = CandidatesProbed,
                PayloadsSent = PayloadsSent,
                Findings = Findings,
                Details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["cookieMode"] = CookieMode,
                    ["runId"] = RunId,
                    ["states"] = States.Select(s => new
                    {
                        s.Label,
                        s.Url,
                        s.Identity,
                        s.SetupUrl,
                        s.Role,
                        method = s.Method,
                        form = s.Form
                    }).ToList(),
                    ["hypothesis"] = XsLeakHypothesis.ToApiObject(
                        HypothesisApplied, HypothesisExpanded, HypothesisRequested),
                    ["stateValidation"] = StateValidation?.ToApiObject() ?? EmptyValidation(),
                    ["hypothesisValidation"] = StateValidation?.ToApiObject() ?? EmptyValidation(),
                    ["plan"] = Plan?.ToApiObject() ?? EmptyPlan(),
                    ["sessionProfile"] = SessionProfile?.ToApiObject() ?? EmptySessionProfile(CookieMode),
                    ["credentialDelivery"] = CredentialDelivery ?? EmptyCredentialDelivery(),
                    ["suggestedHypotheses"] = (SuggestedHypotheses ?? []).Select(s => new
                    {
                        s.Strategy,
                        s.Detail,
                        hypothesis = s.Hypothesis,
                        states = s.States.Select(st => new
                        {
                            st.Label,
                            st.Url,
                            st.Role,
                            st.Identity,
                            method = st.Method,
                            form = st.Form
                        })
                    }).ToList(),
                    ["techniques"] = Techniques.Select(t => new
                    {
                        t.Technique,
                        t.Category,
                        t.Verdict,
                        t.Tier,
                        t.Mitigated,
                        t.MitigationReason,
                        t.Trials,
                        t.ValuesByState,
                        t.TimingByState,
                        pairs = t.Pairs,
                        t.EffectSize,
                        t.MitigatedBy,
                        t.Detail,
                        t.Applicability,
                        confirmationStatus = t.ConfirmationStatus,
                        pocHtml = t.PocHtml != null ? "(see finding extra.pocHtml)" : null
                    }).ToList(),
                    ["observe"] = Observe == null
                        ? null
                        : new
                        {
                            Observe.Summary,
                            vectorsByState = Observe.VectorsByState,
                            diffFeatures = Observe.DiffFeatures
                        },
                    ["distinguishable"] = DistinguishableCount,
                    ["probable"] = ProbableCount,
                    ["hygieneMitigated"] = HygieneCount,
                    ["posture"] = Posture?.ToApiObject(),
                    ["browserModel"] = BrowserModel.ToApiObject(),
                    ["stateGeneration"] = StateGenerationStrategy == null ? null : new
                    {
                        strategy = StateGenerationStrategy,
                        detail = StateGenerationDetail
                    },
                    ["authModelNotes"] = AuthModelNotes.Count > 0 ? AuthModelNotes : null,
                    ["warnings"] = Warnings.Count > 0 ? Warnings : null,
                    ["sameUrlStates"] = SameUrlStates ? true : null,
                    ["sessionLostDuringScan"] = SessionLostDuringScan ? true : null,
                    ["popupTabsOpened"] = PopupTabsOpened,
                    ["orphanPopupTabsClosed"] = OrphanPopupTabsClosed,
                    ["budgetExhausted"] = BudgetExhausted ? true : null,
                    ["catalogMode"] = CatalogMode,
                    ["chainFindings"] = ChainFindings.Select(c => new
                    {
                        c.Id,
                        c.Category,
                        c.Severity,
                        c.Title,
                        c.Endpoint,
                        c.Detail,
                        c.Remediation
                    }).ToList(),
                    ["corsChainedCount"] = ChainFindings.Count(c =>
                        c.Category.Equals("xs-leaks+cors", StringComparison.OrdinalIgnoreCase)),
                    ["chainAnalysis"] = ChainAnalysis == null
                        ? null
                        : ChainEngine.ChainAnalysisService.BuildAnalyzePayload(ChainAnalysis)
                }
            };
            return scan.ToApiResponse(includeHygiene: includeHygiene);
        }

        private static object EmptyValidation() => new
        {
            credentialedDiff = "none",
            anonymousDiff = "none",
            latencyGap = false,
            detail = "not-run",
            probeTimeoutMs = 4000,
            states = Array.Empty<object>()
        };

        private static object EmptyPlan() => new
        {
            selected = Array.Empty<object>(),
            skipped = Array.Empty<object>(),
            note = "not-run"
        };

        private static object EmptySessionProfile(string cookieMode) => new
        {
            cookieMode,
            authMechanism = "unknown",
            authCookies = Array.Empty<object>(),
            note = "not-run"
        };

        private static object EmptyCredentialDelivery() => new
        {
            subresource = "unknown",
            topLevel = "not-run",
            note = "not-run"
        };
    }

    public async Task<XsLeakResult> RunAsync(XsLeakOptions options, SafetyMode mode)
    {
        if (options.SuggestOnly)
        {
            var suggestions = await XsLeakHypothesis.SuggestAsync(_ctx, _identities);
            return new XsLeakResult
            {
                RunId = Guid.NewGuid().ToString("N")[..12],
                Summary = suggestions.Count == 0
                    ? "No XS-Leak hypothesis candidates — browse authenticated APIs or capture identities."
                    : $"{suggestions.Count} candidate hypothesis(es). Re-run without suggestOnly to execute.",
                SuggestedHypotheses = suggestions,
                CookieMode = "unknown"
            };
        }

        var resolved = await XsLeakHypothesisResolver.ResolveAsync(_ctx, _identities, options);
        var states = resolved.States;
        var genStrategy = resolved.StateGenerationStrategy;
        var genDetail = resolved.StateGenerationDetail;

        if (states.Count < 2)
        {
            var msg = resolved.HypothesisRequested
                ? "XS-Leaks hypothesis could not be expanded into two states — fix urlTemplate/hitValues/missValues or pass explicit states[]."
                : "XS-Leaks could not derive two states — browse the app (authenticated APIs, search) or pass explicit states[].";
            throw new InvalidOperationException(msg);
        }

        XsLeakScanSafety.EnsureStatesAllowed(states);

        _attackerOrigin = AttackerPageBuilder.ResolveAttackerOrigin(options.AttackerSite, states[0].Url);
        var hypothesisRequested = resolved.HypothesisRequested;
        var hypothesisMode = hypothesisRequested
                             || resolved.HypothesisExpanded
                             || !string.IsNullOrWhiteSpace(options.Hypothesis?.Secret);
        var maxSeconds = options.MaxSeconds > 0 ? options.MaxSeconds : (hypothesisMode ? 60 : 0);

        var victimHost = Uri.TryCreate(states[0].Url, UriKind.Absolute, out var victimUri)
            ? victimUri.Host
            : "";

        string? sessionCheckpoint = null;
        var tabScope = SecurityScanTabScope.Begin(_ctx);
        var homeTabIdx = tabScope.HomeTabIndex;
        _activeScanTabs = tabScope;
        _activeScanVictimHost = victimHost;
        try
        {
            sessionCheckpoint = await _ctx.BrowserSessionCaptureAsync(
                BrowserSessionScopeKind.Site, states[0].Url);
        }
        catch
        {
            /* snapshot best-effort */
        }

        var active = mode >= SafetyMode.Active;
        var sessionProfile = await XsLeakSessionProfile.BuildAsync(
            _ctx, _identities, states, victimHost, options.IdentifyAuthCookie && active);
        var validation = await new XsLeakStateValidator().ValidateAsync(_ctx, _identities, states, homeTabIdx);
        _probeTimeoutMs = validation.ProbeTimeoutMs;

        if (sessionCheckpoint != null)
        {
            try
            {
                await _ctx.BrowserSessionRestoreAsync(sessionCheckpoint);
            }
            catch
            {
                /* restore before trials */
            }
        }

        var authNotes = BuildAuthModelNotes(states);
        authNotes.AddRange(sessionProfile.Notes);
        var postureInteractions = options.PostureInteractionProbes ?? (active && !hypothesisMode);

        var explicitTechniques = options.Techniques is { Count: > 0 };
        if (hypothesisMode && validation.ShouldShortCircuitHypothesis && !explicitTechniques)
        {
            return await FinishRunAsync(new XsLeakResult
            {
                CookieMode = sessionProfile.CookieMode,
                RunId = Guid.NewGuid().ToString("N")[..12],
                States = states,
                StateGenerationStrategy = genStrategy,
                StateGenerationDetail = genDetail,
                AuthModelNotes = authNotes,
                BrowserModel = XsLeakBrowserModel.ForRun(_attackerOrigin, options.AttackerSite),
                StateValidation = validation,
                SessionProfile = sessionProfile,
                HypothesisApplied = resolved.Hypothesis,
                HypothesisExpanded = resolved.HypothesisExpanded,
                HypothesisRequested = hypothesisRequested,
                Summary = "Hypothesis invalid — states do not differ server-side (no content or latency gap).",
                Warnings =
                [
                    "Server-side validation found no measurable difference between states.",
                    ..resolved.Warnings
                ]
            }, sessionCheckpoint, tabScope, victimHost);
        }

        XsLeakCredentialObservation.DeliveryResult delivery = new();
        var credProbeTabIdx = -1;
        try
        {
            var credPageUrl = AttackerPageBuilder.PageUrl("cred-probe", _attackerOrigin);
            credProbeTabIdx = await _ctx.NewTab(credPageUrl, owner: "agent");
            CopyNetworkRules(homeTabIdx, credProbeTabIdx);
            _ctx.Tabs[credProbeTabIdx].MockResponse(credPageUrl, 200,
                "<!DOCTYPE html><html><head><title>xsleak cred probe</title></head><body></body></html>",
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
            delivery = await XsLeakCredentialObservation.ObserveAsync(
                _ctx, credProbeTabIdx, _attackerOrigin, states[0].Url, sessionProfile.AuthCookies,
                sessionProfile.CookieMode, active);
        }
        catch
        {
            /* observation best-effort */
        }
        finally
        {
            if (credProbeTabIdx >= 0 && _ctx.Tabs.Count > 1)
            {
                try { await _ctx.CloseTab(credProbeTabIdx); } catch { /* ignore */ }
            }
            _ctx.SwitchTab(homeTabIdx);
        }

        var plan = XsLeakTechniquePlanner.Build(
            active,
            hypothesisMode,
            maxSeconds,
            options.AttackerSite,
            validation,
            sessionProfile,
            delivery,
            options.Techniques,
            options.FullCatalog);

        List<XsLeakTechniques.TechniqueDef> techniques;
        if (options.Techniques is { Count: > 0 } || options.FullCatalog)
            techniques = XsLeakTechniques.ForMode(active, options.Techniques, options.FullCatalog).ToList();
        else if (plan.SelectedTechniques.Count > 0)
            techniques = plan.SelectedTechniques.ToList();
        else if (plan.NothingEligible)
        {
            var early = new XsLeakResult
            {
                CookieMode = sessionProfile.CookieMode,
                RunId = Guid.NewGuid().ToString("N")[..12],
                States = states,
                StateGenerationStrategy = genStrategy,
                StateGenerationDetail = genDetail,
                AuthModelNotes = authNotes,
                BrowserModel = XsLeakBrowserModel.ForRun(_attackerOrigin, options.AttackerSite),
                StateValidation = validation,
                Plan = plan,
                SessionProfile = sessionProfile,
                CredentialDelivery = new XsLeakCredentialObservation().ToApiObject(delivery),
                HypothesisApplied = resolved.Hypothesis,
                HypothesisExpanded = resolved.HypothesisExpanded,
                HypothesisRequested = hypothesisRequested,
                Summary =
                    "Not tested: no eligible XS-Leak techniques for this session and attacker mode (see details.plan).",
                Warnings = [..resolved.Warnings, ..plan.Warnings]
            };
            XsLeakSessionProfile.AppendSameSiteExploitabilityNotes(
                sessionProfile, delivery, options.AttackerSite, early.Warnings, early.NextActions);
            return await FinishRunAsync(early, sessionCheckpoint, tabScope, victimHost);
        }
        else
            techniques = XsLeakTechniques.ForMode(active, null, fullCatalog: false).ToList();

        var sameUrlStates = AllStatesShareSameRequestTarget(states);
        var catalogMode = options.FullCatalog ? "full" : (options.Techniques is { Count: > 0 } ? "explicit" : "planned");

        var runId = Guid.NewGuid().ToString("N")[..12];
        _activeScanRunId = runId;
        var sw = Stopwatch.StartNew();

        var result = new XsLeakResult
        {
            CookieMode = sessionProfile.CookieMode,
            RunId = runId,
            States = states,
            StateGenerationStrategy = genStrategy,
            StateGenerationDetail = genDetail,
            AuthModelNotes = authNotes,
            BrowserModel = XsLeakBrowserModel.ForRun(_attackerOrigin, options.AttackerSite),
            SameUrlStates = sameUrlStates,
            CatalogMode = catalogMode,
            StateValidation = validation,
            Plan = plan,
            SessionProfile = sessionProfile,
            CredentialDelivery = new XsLeakCredentialObservation().ToApiObject(delivery),
            HypothesisApplied = resolved.Hypothesis,
            HypothesisExpanded = resolved.HypothesisExpanded,
            HypothesisRequested = hypothesisRequested
        };
        if (authNotes.Count > 0)
            result.NextActions.AddRange(authNotes.Take(2));

        result.Warnings.AddRange(resolved.Warnings);
        result.Warnings.AddRange(plan.Warnings);
        XsLeakSessionProfile.AppendSameSiteExploitabilityNotes(
            sessionProfile, delivery, options.AttackerSite, result.Warnings, result.NextActions);
        if (!options.FullCatalog && options.Techniques is not { Count: > 0 })
        {
            result.Warnings.Add(
                plan.SelectedTechniques.Count > 0
                    ? "Technique set chosen by session-aware planner (see details.plan)."
                    : "Default quick XS-Leaks technique subset. Pass fullCatalog:true or explicit techniques[] for the full catalog.");
        }

        if (sameUrlStates)
        {
            var keepTiming = validation.LatencyGap;
            if (keepTiming)
            {
                result.Warnings.Add(
                    "States share the same request target, but server samples show a latency gap of the same body. Timing techniques stay enabled.");
            }
            else
            {
                result.Warnings.Add(
                    "All victim states share the same request target (URL, method, and body) — timing/cache side channels are disabled (WAN jitter is not XS-Leak evidence).");
            }

            if (string.Equals(genStrategy, "identity-pair", StringComparison.OrdinalIgnoreCase))
            {
                result.Warnings.Add(
                    "Auto identity-pair did not produce distinct URLs — capture a session with cookies on this host, or pass explicit states with different endpoints.");
            }

            if (!keepTiming)
                techniques = techniques.Where(t => !t.IsTiming).ToList();

            if (!StatesHaveDistinctSessionIdentities(states) && !validation.LatencyGap && !explicitTechniques)
            {
                var validationHint = validation.CredentialedDiff != "none" || validation.LatencyGap
                    ? $" Server validation reports credentialedDiff={validation.CredentialedDiff}, latencyGap={validation.LatencyGap} — read details.stateValidation before trusting this summary."
                    : "";
                result.Summary =
                    "No distinguishable victim states — identical request target without distinct captured session identities." + validationHint;
                result.Warnings.Add(
                    "Short-circuited: for same-URL GET oracles use distinct query URLs; for POST JSON search use different body (or role: hit/miss) on the same API URL — not the SPA shell route.");
                result.Warnings.Add(
                    "Top-level message can undersell details.stateValidation when sameUrlStates is true — always inspect credentialedDiff before concluding there is no server-side difference.");
                result.NextActions.Add("POST /api/identity/capture after logging in, then re-run with autoStates or explicit states.");
                result.NextActions.Add(
                    "For SPAs, prefer JSON API endpoints from the network log (e.g. POST /api/search) over client route URLs like /userprofile.");
                AppendDangerousEndpointHints(states, result);
                return await FinishRunAsync(result, sessionCheckpoint, tabScope, victimHost);
            }
        }
        else if (AllStatesShareSameUrlPath(states) && !validation.LatencyGap && !explicitTechniques)
        {
            result.Warnings.Add(
                "States share the same URL path but differ by method or body — POST/form oracles (e.g. form-post-frame) apply; timing techniques are still omitted.");
            techniques = techniques.Where(t => !t.IsTiming).ToList();
        }

        if (states.Any(s =>
                string.Equals(s.Method, "POST", StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrWhiteSpace(s.Body)
                || s.Form is { Count: > 0 }))
        {
            var formProbe = XsLeakTechniques.Catalog.First(t => t.Id == "form-post-frame");
            if (!techniques.Any(t => t.Id == formProbe.Id))
                techniques.Add(formProbe);
        }

        var baselineCookieMode = sessionProfile.CookieMode;
        if (XsLeakScanSafety.StatesRiskSessionTermination(validation.States, states))
        {
            techniques = techniques
                .Where(t => !XsLeakScanSafety.TopLevelNavigationTechniques.Contains(t.Id))
                .ToList();
            result.Warnings.Add(
                "Skipped popup/window XS-Leak techniques — a state URL or credentialed fetch final URL looks like logout/session termination.");
        }

        if (sessionProfile.AuthCookies.Count > 1)
        {
            result.NextActions.Add(
                "Multiple auth cookie candidates — run POST /api/security/auth-control-identifier (active) on the victim API to confirm which cookie gates access.");
        }

        AppendDangerousEndpointHints(states, result);

        if (options.ObserveMode)
        {
            try
            {
                var probeTabIdx = await _ctx.NewTab(
                    AttackerPageBuilder.PageUrl("observe", _attackerOrigin), owner: "agent");
                CopyNetworkRules(homeTabIdx, probeTabIdx);
                result.Observe = await XsLeakObserveMode.RunAsync(
                    _ctx, homeTabIdx, probeTabIdx, _attackerOrigin, runId, states, ApplyStateAsync);
                if (probeTabIdx >= 0 && _ctx.Tabs.Count > 1)
                {
                    try { await _ctx.CloseTab(probeTabIdx); } catch { /* ignore */ }
                }
                _ctx.SwitchTab(homeTabIdx);
            }
            catch
            {
                result.Warnings.Add("Observe mode failed (best-effort).");
            }
        }

        var stateResourceProfiles = validation.States
            .Select(s => XsLeakResourceApplicability.FromContentType(s.ContentType))
            .ToList();

        foreach (var tech in techniques)
        {
            if (maxSeconds > 0 && sw.Elapsed.TotalSeconds >= maxSeconds)
            {
                result.BudgetExhausted = true;
                result.Warnings.Add(
                    $"Scan stopped after budget.maxSeconds={maxSeconds} — partial technique results returned.");
                break;
            }

            var applicabilityNote = XsLeakResourceApplicability.LowApplicabilityReason(tech.Id, stateResourceProfiles);
            if (applicabilityNote != null)
            {
                result.Techniques.Add(new TechniqueResult
                {
                    Technique = tech.Id,
                    Category = tech.Category,
                    Verdict = "indistinguishable",
                    Trials = 0,
                    Detail = applicabilityNote,
                    Applicability = applicabilityNote.StartsWith("low", StringComparison.OrdinalIgnoreCase)
                        ? "low"
                        : applicabilityNote
                });
                continue;
            }

            var baseTrials = options.Trials > 0 ? options.Trials : tech.DefaultTrials;
            if (!active && tech.IsTiming)
                baseTrials = Math.Min(baseTrials, 3);

            var screeningStates = hypothesisMode
                ? XsLeakConfirmation.ScreeningStates(states)
                : states;
            var screeningTrials = hypothesisMode
                ? Math.Min(baseTrials, XsLeakConfirmation.ScreeningTrials)
                : baseTrials;

            var valuesByState = states.ToDictionary(
                s => s.Label,
                _ => new List<string?>(),
                StringComparer.OrdinalIgnoreCase);
            var timingByState = states.ToDictionary(
                s => s.Label,
                _ => new List<double>(),
                StringComparer.OrdinalIgnoreCase);
            var statusByState = states.ToDictionary(
                s => s.Label,
                _ => new List<int?>(),
                StringComparer.OrdinalIgnoreCase);
            var allMitigations = new List<string>();
            var evalStates = states.ToList();
            StateSpec? controlState = null;
            var ranConfirmation = false;
            var sessionHealthy = true;

            await RunTrialBatchAsync(
                screeningStates, screeningTrials, warmup: !options.SkipWarmup, tech, runId, homeTabIdx,
                sw, maxSeconds, valuesByState, timingByState, statusByState, allMitigations, result);

            if (result.BudgetExhausted)
                break;

            var screeningPairs = EvaluatePairs(evalStates, tech, valuesByState, timingByState, statusByState);
            var screeningWorst = SelectWorstHitMissPair(screeningPairs, states);

            if (hypothesisMode && screeningWorst.Verdict is "distinguishable" or "probable")
            {
                var hitState = screeningStates.FirstOrDefault(s =>
                                  string.Equals(s.Role, "hit", StringComparison.OrdinalIgnoreCase))
                              ?? screeningStates[0];
                var missState = screeningStates.FirstOrDefault(s =>
                                    string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase))
                                ?? screeningStates[^1];
                var baseline = validation.States.FirstOrDefault(s =>
                    string.Equals(s.Label, hitState.Label, StringComparison.OrdinalIgnoreCase));
                if (baseline != null)
                {
                    var (ok, msg) = await new XsLeakStateValidator().VerifyHitSessionStableAsync(
                        _ctx, _identities, hitState, homeTabIdx, baseline);
                    sessionHealthy = ok;
                    if (!ok && msg != null)
                        result.Warnings.Add(msg);
                }

                if (sessionHealthy)
                {
                    controlState = XsLeakConfirmation.TryBuildControlState(states, resolved.Hypothesis);
                    if (controlState != null)
                    {
                        evalStates.Add(controlState);
                        EnsureMeasurementKeys(controlState, valuesByState, timingByState, statusByState);
                    }

                    var confirmStates = new List<StateSpec> { hitState, missState };
                    if (controlState != null)
                        confirmStates.Add(controlState);
                    await RunTrialBatchAsync(
                        confirmStates, XsLeakConfirmation.ConfirmTrials, warmup: false, tech, runId, homeTabIdx,
                        sw, maxSeconds, valuesByState, timingByState, statusByState, allMitigations, result);
                    ranConfirmation = true;
                }
            }

            if (result.BudgetExhausted)
                break;

            var pairs = EvaluatePairs(evalStates, tech, valuesByState, timingByState, statusByState);
            var worst = SelectWorstHitMissPair(pairs, states);
            var mitigatedBy = allMitigations.Distinct(StringComparer.OrdinalIgnoreCase).Take(16).ToList();
            var parsed = XsLeakMitigations.Parse(mitigatedBy);
            string? mitReason = null;
            var mitigated = worst.Verdict is "distinguishable" or "probable"
                            && XsLeakMitigations.IsLikelyMitigated(
                                tech.Id, tech.Category, parsed, valuesByState, out mitReason);

            var tier = mitigated ? SecurityFindingTier.Hygiene : SecurityFindingTier.Exploitable;
            if (IsExistenceOnlyStates(states, genStrategy) && worst.Verdict is "distinguishable" or "probable")
            {
                tier = SecurityFindingTier.Informational;
                mitReason ??= "States differ only by public resource existence (404 vs hit), not a secret-dependent oracle.";
            }

            var diffKind = validation.AnonymousDiff != "none" ? validation.AnonymousDiff : validation.CredentialedDiff;
            var explainable = !hypothesisMode
                              || XsLeakStateValidator.ExplainsDifferential(diffKind, tech.Category, tech.Id)
                              || (tech.IsTiming && validation.LatencyGap);
            var missLabel = states.FirstOrDefault(s =>
                string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase))?.Label;
            var controlFailed = controlState != null
                                && missLabel != null
                                && XsLeakConfirmation.ControlInvalidatesSecret(
                                    tech, valuesByState, missLabel, controlState.Label);
            if (controlFailed)
                mitReason = (mitReason ?? "") + " Control miss value separated from primary miss — oracle may track URL shape, not secret.";

            var confirmVerdict = ranConfirmation ? worst.Verdict : null;
            var confirmationStatus = XsLeakConfirmation.ResolveConfirmationStatus(
                hypothesisMode,
                screeningWorst.Verdict,
                confirmVerdict,
                controlFailed,
                explainable,
                mitigated,
                sessionHealthy,
                ranConfirmation);

            if (hypothesisMode && confirmationStatus.StartsWith("candidate", StringComparison.OrdinalIgnoreCase))
                tier = SecurityFindingTier.Informational;
            if (hypothesisMode && tech.IsTiming
                && validation.CredentialedDiff == "none"
                && validation.AnonymousDiff == "none"
                && validation.LatencyGap)
                tier = SecurityFindingTier.Informational;

            string? poc = null;
            if (worst.Verdict is "distinguishable" or "probable"
                && XsLeakConfirmation.ShouldEmitFinding(confirmationStatus))
                poc = BuildWatermarkedPoc(runId, tech.Id, states, worst.Verdict);

            var techniqueResult = new TechniqueResult
            {
                Technique = tech.Id,
                Category = tech.Category,
                Verdict = worst.Verdict,
                Tier = tier,
                Mitigated = mitigated,
                MitigationReason = mitReason,
                Trials = screeningTrials + (ranConfirmation ? XsLeakConfirmation.ConfirmTrials : 0),
                ValuesByState = valuesByState,
                TimingByState = timingByState,
                Pairs = pairs,
                EffectSize = pairs.Where(p => p.EffectSize.HasValue).Select(p => p.EffectSize).Max(),
                MitigatedBy = mitigatedBy,
                Detail = worst.Detail ?? "No stable differential across trials.",
                PocHtml = poc,
                ConfirmationStatus = confirmationStatus
            };
            result.Techniques.Add(techniqueResult);

            if (active && !await IsSessionIntactAsync(victimHost, baselineCookieMode))
            {
                result.SessionLostDuringScan = true;
                result.Warnings.Add(
                    "Session disrupted during scan (logout URL, IdP/SSO step-up on the home tab, or auth cookies cleared) — results after this point are unreliable.");
                result.Summary =
                    "Scan stopped — session disrupted during active XS-Leak probing. Re-authenticate and re-run; avoid fullCatalog active popups on endpoints that redirect to logout or IdP.";
                break;
            }

            var emitFinding = worst.Verdict is "distinguishable" or "probable"
                              && XsLeakConfirmation.ShouldEmitFinding(confirmationStatus)
                              && explainable
                              && !controlFailed;

            if (emitFinding)
            {
                var findingId = $"xsleak-{runId}-{tech.Id}";
                var confidence = worst.Verdict == "distinguishable"
                    ? SecurityConfidence.Confirmed
                    : SecurityConfidence.Likely;
                var severity = tier == SecurityFindingTier.Exploitable
                    ? (worst.Verdict == "distinguishable" ? "medium" : "low")
                    : "info";

                var evidence = worst.Detail + (mitigatedBy.Count > 0
                    ? " mitigatedBy=" + string.Join(",", mitigatedBy)
                    : "");
                if (mitReason != null)
                    evidence += " mitigationNote=" + mitReason;

                result.Findings.Add(UnifiedSecurityFinding.Create(
                    category: "xs-leaks",
                    title: $"XS-Leak {tech.Id}: {worst.Verdict}" + (mitigated ? " (isolation likely blocks exploit)" : ""),
                    severity: severity,
                    confidence: confidence,
                    endpoint: states[0].Url,
                    method: "GET",
                    param: tech.Id,
                    evidence: evidence,
                    proofHint: poc != null ? "Standalone PoC HTML in extra.pocHtml (local session evidence only)." : null,
                    tier: tier,
                    nextActions: mitigated
                        ? ["Re-test from a cross-site attacker origin after deploying COOP/CORP/frame-ancestors."]
                        :
                        [
                            "Confirm with manual attacker page; tighten COOP/CORP/SameSite on victim responses.",
                            "If ACAO reflects Origin with credentials, chain with POST /api/security/cors on the same host."
                        ],
                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["technique"] = tech.Id,
                        ["pairs"] = pairs,
                        ["pocHtml"] = poc,
                        ["runId"] = runId
                    },
                    id: findingId));

                result.ChainFindings.Add(new ChainableFinding
                {
                    Id = findingId,
                    Source = "xs-leaks",
                    Category = "xs-leaks",
                    Severity = severity,
                    Title = $"XS-Leak {tech.Id}: {worst.Verdict}",
                    Endpoint = states[0].Url,
                    Detail = evidence,
                    Remediation =
                        "Set Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, frame-ancestors / X-Frame-Options, " +
                        "and SameSite cookies so cross-site pages cannot distinguish authenticated vs unauthenticated responses.",
                    Reference = "https://xsleaks.dev/",
                    Tags = mitigated ? ["mitigated", tech.Category] : [tech.Category]
                });

                if (poc != null)
                {
                    try
                    {
                        XsLeakVpxArtifacts.RegisterPocHtml(_ctx, findingId, tech.Id, runId, poc);
                    }
                    catch
                    {
                        /* VPX artifact feed is best-effort */
                    }
                }
            }
        }

        sw.Stop();
        result.ElapsedMs = sw.ElapsedMilliseconds;
        result.CandidatesProbed = result.Techniques.Count;
        result.PayloadsSent = result.Techniques.Sum(t => t.Trials);
        result.Summary =
            $"{result.DistinguishableCount} exploitable distinguishable, {result.ProbableCount} exploitable probable, " +
            $"{result.HygieneCount} hygiene (headers likely block), {result.InformationalCount} informational, " +
            $"{result.Techniques.Count(t => t.Verdict == "indistinguishable")} indistinguishable " +
            $"(cookieMode={result.CookieMode}, {sw.ElapsedMilliseconds}ms).";

        if (result.DistinguishableCount > 0)
            result.NextActions.Add("Review exploitable differentials; use extra.pocHtml only on localhost/lab hosts.");
        if (result.ProbableCount > 0)
            result.NextActions.Add("Re-run timing techniques with higher trials under safetyMode:active.");
        if (result.DistinguishableCount == 0 && result.ProbableCount == 0
            && result.HygieneCount == 0 && result.InformationalCount == 0)
            result.NextActions.Add("No XS-Leak differential observed — try identity pairs or search hit/miss URLs.");

        if (options.IncludePosture)
        {
            try
            {
                var postureUrl = states[0].Url;
                var probeTags = result.Techniques
                    .SelectMany(t => t.MitigatedBy)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                result.Posture = await new XsLeakPostureAnalyzer(_ctx)
                    .AnalyzeAsync(postureUrl, result.CookieMode, probeTags);
                if (postureInteractions)
                {
                    await XsLeakPostureInteractionProbes.EnrichAsync(
                        _ctx, result.Posture, postureUrl, _attackerOrigin, mode);
                }

                if (result.Posture.Recommendations.Count > 0)
                    result.NextActions.AddRange(result.Posture.Recommendations.Take(3));
            }
            catch
            {
                /* posture is best-effort */
            }
        }

        try
        {
            XsLeakCorsCorrelator.Apply(_ctx, result, states);
        }
        catch
        {
            /* CORS correlation is best-effort */
        }

        try
        {
            XsLeakPostureCorrelator.Apply(result);
        }
        catch
        {
            /* posture correlation is best-effort */
        }

        try
        {
            if (result.Findings.Count > 0
                && (!sameUrlStates || result.DistinguishableCount > 0 || result.ProbableCount > 0))
                result.ChainAnalysis = XsLeakChainIntegrator.Analyze(_ctx, result);
        }
        catch
        {
            /* chain discovery is best-effort */
        }

        return await FinishRunAsync(result, sessionCheckpoint, tabScope, victimHost);
    }

    private async Task<XsLeakResult> FinishRunAsync(
        XsLeakResult result,
        string? sessionCheckpoint,
        SecurityScanTabScope? tabScope = null,
        string? victimHost = null)
    {
        try
        {
            if (tabScope != null)
            {
                var (opened, closed) = await tabScope.FinishAsync(victimHost, result.RunId);
                result.PopupTabsOpened = opened;
                result.OrphanPopupTabsClosed = closed;
            }
        }
        finally
        {
            _activeScanTabs = null;
            _activeScanVictimHost = null;
            _activeScanRunId = null;
        }

        if (sessionCheckpoint != null)
        {
            try
            {
                await _ctx.BrowserSessionRestoreAsync(sessionCheckpoint);
            }
            catch
            {
                /* best-effort restore */
            }
            finally
            {
                _ctx.BrowserSessionDiscardCheckpoint(sessionCheckpoint);
            }
        }

        return result;
    }

    internal static string NormalizeStateRequestKey(StateSpec s)
    {
        var url = NormalizeStateUrl(s);
        var method = string.IsNullOrWhiteSpace(s.Method) ? "GET" : s.Method.Trim().ToUpperInvariant();
        if (s.Form is { Count: > 0 })
        {
            var formKey = string.Join("&",
                s.Form.OrderBy(kv => kv.Key, StringComparer.Ordinal)
                    .Select(kv => $"{kv.Key}={kv.Value}"));
            return $"{method}|{url}|form:{formKey}";
        }

        if (!string.IsNullOrWhiteSpace(s.Body))
            return $"{method}|{url}|body:{s.Body.Trim()}";

        return $"{method}|{url}";
    }

    internal static bool AllStatesShareSameRequestTarget(IReadOnlyList<StateSpec> states)
    {
        if (states.Count < 2) return false;
        return states.Select(NormalizeStateRequestKey).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1;
    }

    internal static bool AllStatesShareSameUrlPath(IReadOnlyList<StateSpec> states)
    {
        if (states.Count < 2) return false;
        return states.Select(NormalizeStateUrl).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1;
    }

    [Obsolete("Use AllStatesShareSameRequestTarget")]
    internal static bool AllStatesShareSameUrl(IReadOnlyList<StateSpec> states) =>
        AllStatesShareSameRequestTarget(states);

    internal static bool StatesHaveDistinctSessionIdentities(IReadOnlyList<StateSpec> states)
    {
        if (states.Count < 2)
            return false;
        var identities = states
            .Select(s => string.IsNullOrWhiteSpace(s.Identity) ? "anonymous" : s.Identity.Trim())
            .Select(i => i.Equals("anonymous", StringComparison.OrdinalIgnoreCase) ? "anonymous" : i.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (identities.Count < 2)
            return false;
        return identities.Any(i => i != "anonymous");
    }

    private static void AppendDangerousEndpointHints(IReadOnlyList<StateSpec> states, XsLeakResult result)
    {
        foreach (var s in states)
        {
            var u = (s.Url ?? "").ToLowerInvariant();
            if (!u.Contains("spawn", StringComparison.Ordinal)
                && !u.Contains("command=", StringComparison.Ordinal)
                && !u.Contains("runcommand", StringComparison.Ordinal)
                && !u.Contains("/exec", StringComparison.Ordinal))
                continue;

            result.AuthModelNotes.Add($"Auto-selected state URL resembles a command/API execution route: {s.Url}");
            if (!result.NextActions.Any(n => n.Contains("command", StringComparison.OrdinalIgnoreCase)))
            {
                result.NextActions.Add(
                    "State URL looks like command execution — validate with injection/workflow scans; XS-Leaks needs distinct auth states on safer JSON routes.");
            }

            break;
        }
    }

    private static string NormalizeStateUrl(StateSpec s)
    {
        var url = !string.IsNullOrWhiteSpace(s.SetupUrl) ? s.SetupUrl : s.Url;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Trim();
        return uri.GetLeftPart(UriPartial.Path) + uri.Query;
    }

    private static string StatusBucket(IReadOnlyList<int?> codes)
    {
        var known = codes.Where(c => c is > 0).Select(c => c!.Value).ToList();
        if (known.Count == 0) return "unknown";
        var code = known.GroupBy(c => c).OrderByDescending(g => g.Count()).First().Key;
        return code switch
        {
            >= 200 and < 300 => "2xx",
            >= 300 and < 400 => "3xx",
            >= 400 and < 500 => "4xx",
            >= 500 => "5xx",
            _ => "other"
        };
    }

    internal static bool IsExistenceOnlyStates(IReadOnlyList<StateSpec> states, string? generationStrategy = null)
    {
        if (string.Equals(generationStrategy, "protected-vs-synthetic-miss", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(generationStrategy, "search-hit-miss", StringComparison.OrdinalIgnoreCase)
            || string.Equals(generationStrategy, "identity-pair", StringComparison.OrdinalIgnoreCase))
            return false;

        if (states.Count != 2) return false;
        if (states.Any(s => s.Url.Contains("xsleak-miss", StringComparison.OrdinalIgnoreCase)
                            || s.Url.Contains("xsleak-probe-miss", StringComparison.OrdinalIgnoreCase)
                            || s.Url.Contains("trowser-xsleak-miss", StringComparison.OrdinalIgnoreCase)))
            return true;

        var labels = states.Select(s => s.Label).ToList();
        if (labels.Any(l => l.Equals("miss", StringComparison.OrdinalIgnoreCase)
                            || l.Equals("synthetic-miss", StringComparison.OrdinalIgnoreCase)
                            || l.Contains("404", StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private static int VerdictRank(string verdict) => verdict switch
    {
        "distinguishable" => 3,
        "probable" => 2,
        _ => 1
    };

    private static IEnumerable<(StateSpec A, StateSpec B)> EnumerateEvaluationPairs(IReadOnlyList<StateSpec> states)
    {
        var hits = states.Where(s => string.Equals(s.Role, "hit", StringComparison.OrdinalIgnoreCase)).ToList();
        var misses = states.Where(s => string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase)).ToList();
        if (hits.Count > 0 && misses.Count > 0)
        {
            foreach (var h in hits)
            foreach (var m in misses)
                yield return (h, m);
            yield break;
        }

        for (var i = 0; i < states.Count; i++)
        for (var j = i + 1; j < states.Count; j++)
            yield return (states[i], states[j]);
    }

    private static StatePairResult SelectWorstHitMissPair(
        IReadOnlyList<StatePairResult> pairs,
        IReadOnlyList<StateSpec> states)
    {
        if (pairs.Count == 0)
        {
            return new StatePairResult
            {
                Verdict = "indistinguishable",
                Detail = "No state pairs evaluated."
            };
        }

        var hits = states.Where(s => string.Equals(s.Role, "hit", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Label).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var misses = states.Where(s => string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Label).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var filtered = pairs;
        if (hits.Count > 0 && misses.Count > 0)
        {
            filtered = pairs.Where(p =>
                    (hits.Contains(p.StateA) && misses.Contains(p.StateB))
                    || (hits.Contains(p.StateB) && misses.Contains(p.StateA)))
                .ToList();
            if (filtered.Count == 0)
                filtered = pairs;
        }

        return filtered.OrderByDescending(p => VerdictRank(p.Verdict)).First();
    }

    private static void EnsureMeasurementKeys(
        StateSpec state,
        Dictionary<string, List<string?>> valuesByState,
        Dictionary<string, List<double>> timingByState,
        Dictionary<string, List<int?>> statusByState)
    {
        if (!valuesByState.ContainsKey(state.Label))
            valuesByState[state.Label] = [];
        if (!timingByState.ContainsKey(state.Label))
            timingByState[state.Label] = [];
        if (!statusByState.ContainsKey(state.Label))
            statusByState[state.Label] = [];
    }

    private async Task RunTrialBatchAsync(
        IReadOnlyList<StateSpec> trialStates,
        int trials,
        bool warmup,
        XsLeakTechniques.TechniqueDef tech,
        string runId,
        int homeTabIdx,
        Stopwatch sw,
        int maxSeconds,
        Dictionary<string, List<string?>> valuesByState,
        Dictionary<string, List<double>> timingByState,
        Dictionary<string, List<int?>> statusByState,
        List<string> allMitigations,
        XsLeakResult result)
    {
        var schedule = BuildTrialSchedule(trialStates, trials, warmup);
        var probeTabIdx = -1;
        var popupPerTrial = tech.Id == "popup-closed";
        int ResolveHomeTabIdx() => _activeScanTabs?.HomeTabIndex ?? homeTabIdx;

        try
        {
            if (!popupPerTrial)
            {
                probeTabIdx = await _ctx.NewTab(
                    AttackerPageBuilder.PageUrl($"session-{runId}", _attackerOrigin), owner: "agent");
                CopyNetworkRules(ResolveHomeTabIdx(), probeTabIdx);
            }

            foreach (var slot in schedule)
            {
                if (maxSeconds > 0 && sw.Elapsed.TotalSeconds >= maxSeconds)
                {
                    result.BudgetExhausted = true;
                    break;
                }

                _ctx.SwitchTab(ResolveHomeTabIdx());
                await ApplyStateAsync(slot.State);

                if (popupPerTrial)
                {
                    probeTabIdx = await _ctx.NewTab(
                        AttackerPageBuilder.PageUrl($"session-{runId}", _attackerOrigin), owner: "agent");
                    CopyNetworkRules(ResolveHomeTabIdx(), probeTabIdx);
                }
                else
                    _ctx.SwitchTab(probeTabIdx);

                var networkMark = _ctx.ActiveTab.Network.Count;
                var observation = await RunOneTrialOnActiveTabAsync(
                    runId, slot.State, tech.Id, slot.TrialIndex, networkMark);

                if (popupPerTrial && _ctx.Tabs.Count > 1)
                {
                    try { await _ctx.CloseTab(probeTabIdx); } catch { /* ignore */ }
                    probeTabIdx = -1;
                }

                if (slot.IsWarmup) continue;

                EnsureMeasurementKeys(slot.State, valuesByState, timingByState, statusByState);
                valuesByState[slot.State.Label].Add(observation.Value);
                timingByState[slot.State.Label].Add(observation.Ms);
                statusByState[slot.State.Label].Add(observation.GroundTruth.StatusCode);
                allMitigations.AddRange(observation.GroundTruth.Mitigations);
            }
        }
        finally
        {
            if (probeTabIdx >= 0 && _ctx.Tabs.Count > 1)
            {
                try { await _ctx.CloseTab(probeTabIdx); } catch { /* ignore */ }
            }
            if (_activeScanTabs != null)
            {
                try
                {
                    await _activeScanTabs.CloseProbePopupsAsync(_activeScanVictimHost, _activeScanRunId);
                }
                catch { /* ignore */ }
            }
            try
            {
                var homeIdx = ResolveHomeTabIdx();
                if (homeIdx >= 0 && homeIdx < _ctx.Tabs.Count)
                    _ctx.SwitchTab(homeIdx);
            }
            catch { /* ignore */ }
        }
    }

    private static List<StatePairResult> EvaluatePairs(
        IReadOnlyList<StateSpec> states,
        XsLeakTechniques.TechniqueDef tech,
        Dictionary<string, List<string?>> valuesByState,
        Dictionary<string, List<double>> timingByState,
        Dictionary<string, List<int?>> statusByState)
    {
        var pairs = new List<StatePairResult>();
        foreach (var (sa, sb) in EnumerateEvaluationPairs(states))
        {
                var la = sa.Label;
                var lb = sb.Label;
                var a = valuesByState[la];
                var b = valuesByState[lb];
                var timingA = timingByState[la];
                var timingB = timingByState[lb];

                string verdict;
                double? effect = null;
                string? detail;

                if (tech.IsTiming)
                {
                    var numA = XsLeakStats.ParseNumericObservations(a);
                    var numB = XsLeakStats.ParseNumericObservations(b);
                    var samplesA = numA.Count >= 3 ? numA : timingA;
                    var samplesB = numB.Count >= 3 ? numB : timingB;
                    var (sig, meanA, meanB, eff, pVal) = XsLeakStats.CompareTiming(samplesA, samplesB);
                    effect = eff;
                    verdict = sig ? "probable" : "indistinguishable";
                    var pSuffix = pVal.HasValue ? $", p≈{pVal.Value:F3}" : "";
                    detail = sig
                        ? $"Timing mean {meanA:F0}ms vs {meanB:F0}ms (effect={eff:F2}{pSuffix})"
                        : $"Timing not stable (mean {meanA:F0}ms vs {meanB:F0}ms, effect={eff:F2}{pSuffix})";
                }
                else if (tech.Id == "status-bucket-oracle")
                {
                    if (XsLeakStats.DeterministicDistinct(a, b))
                    {
                        verdict = "distinguishable";
                        detail =
                            $"Cross-site observable {string.Join(",", a.Distinct())} vs {string.Join(",", b.Distinct())}";
                    }
                    else
                    {
                        var bucketA = StatusBucket(statusByState[la]);
                        var bucketB = StatusBucket(statusByState[lb]);
                        if (bucketA != "unknown" && bucketB != "unknown" && bucketA != bucketB)
                        {
                            verdict = "indistinguishable";
                            detail =
                                $"Probe traffic saw HTTP {bucketA} vs {bucketB}, but cross-site observables matched " +
                                $"({string.Join(",", a.Distinct().Concat(b.Distinct()).Distinct())}) — not an exploitable side channel.";
                        }
                        else if (a.Distinct().Count() == 1 && b.Distinct().Count() == 1
                                 && string.Equals(a[0], b[0], StringComparison.OrdinalIgnoreCase))
                        {
                            verdict = "indistinguishable";
                            detail =
                                $"Identical cross-site opaque observables ({a[0]}) — server status may differ but this browser does not leak it cross-origin.";
                        }
                        else
                        {
                            verdict = "indistinguishable";
                            detail = "No stable status-bucket differential across trials.";
                        }
                    }
                }
                else if (XsLeakStats.DeterministicDistinct(a, b))
                {
                    verdict = "distinguishable";
                    detail = $"State '{la}' values {{{string.Join(",", a.Distinct())}}} vs '{lb}' {{{string.Join(",", b.Distinct())}}}";
                }
                else
                {
                    verdict = "indistinguishable";
                    detail = "No stable differential across trials.";
                }

                if (tech.Id == "iframe-load"
                    && verdict is "distinguishable" or "probable"
                    && UniformIframeLoadOracle(a, b))
                {
                    verdict = "indistinguishable";
                    detail = "iframe onload fired for all trials; HTTP status differences are not reflected in this oracle.";
                }

                pairs.Add(new StatePairResult
                {
                    StateA = la,
                    StateB = lb,
                    Verdict = verdict,
                    Detail = detail,
                    EffectSize = effect
                });
        }
        return pairs;
    }

    private static bool UniformIframeLoadOracle(IReadOnlyList<string?> a, IReadOnlyList<string?> b)
    {
        bool AllLoad(IReadOnlyList<string?> xs) =>
            xs.Count > 0 && xs.All(v => string.Equals(v, "load", StringComparison.OrdinalIgnoreCase));
        return AllLoad(a) && AllLoad(b);
    }

    private List<string> BuildAuthModelNotes(IReadOnlyList<StateSpec> states)
    {
        var notes = new List<string>();
        var usesIdentity = states.Any(s =>
            !string.IsNullOrWhiteSpace(s.Identity)
            && !string.Equals(s.Identity, "anonymous", StringComparison.OrdinalIgnoreCase));
        if (!usesIdentity) return notes;

        var jwtLike = false;
        var cookieSession = false;
        foreach (var s in states)
        {
            if (string.IsNullOrWhiteSpace(s.Identity)
                || string.Equals(s.Identity, "anonymous", StringComparison.OrdinalIgnoreCase))
                continue;
            var snap = _identities.Load(s.Identity!.Trim());
            if (snap == null) continue;
            if (snap.Metadata.CookieCount > 0
                && snap.Metadata.LocalStorageCount == 0
                && string.Equals(snap.Metadata.InferredMechanism, "session-cookie",
                    StringComparison.OrdinalIgnoreCase))
                cookieSession = true;
            if (snap.Metadata.LocalStorageCount > 0
                && snap.LocalStorage.Keys.Any(k =>
                    k.Contains("token", StringComparison.OrdinalIgnoreCase)
                    || k.Contains("jwt", StringComparison.OrdinalIgnoreCase)))
                jwtLike = true;
        }

        if (jwtLike && !cookieSession)
        {
            notes.Add(
                "Auth appears JWT/localStorage-only: cross-site img/script/iframe probes do not send Authorization. " +
                "Use cookie session identities, same-site attacker mode, or explicit HTML navigations with setupUrl on the victim origin.");
        }

        foreach (var s in states)
        {
            if (string.IsNullOrWhiteSpace(s.Identity)
                || string.Equals(s.Identity, "anonymous", StringComparison.OrdinalIgnoreCase))
                continue;
            var snap = _identities.Load(s.Identity!.Trim());
            if (snap?.Metadata.Domain == null) continue;
            if (!Uri.TryCreate(s.Url, UriKind.Absolute, out var victim)) continue;
            if (!XsLeakStateGenerator.IdentityHostMatches(victim.Host, snap.Metadata.Domain))
            {
                notes.Add(
                    $"Identity '{s.Identity}' was captured on '{snap.Metadata.Domain}' but state URL host is '{victim.Host}' — identity may not apply to this victim.");
            }
        }

        return notes.Distinct(StringComparer.Ordinal).ToList();
    }

    private sealed record TrialSlot(StateSpec State, int TrialIndex, bool IsWarmup);

    private static List<TrialSlot> BuildTrialSchedule(IReadOnlyList<StateSpec> states, int trials, bool warmup)
    {
        var list = new List<TrialSlot>();
        if (warmup)
        {
            foreach (var s in states)
                list.Add(new TrialSlot(s, -1, true));
        }

        for (var t = 0; t < trials; t++)
        {
            var order = states.OrderBy(_ => Random.Shared.Next()).ToList();
            foreach (var s in order)
                list.Add(new TrialSlot(s, t, false));
        }
        return list;
    }

    private void CopyNetworkRules(int sourceTabIdx, int destTabIdx)
    {
        if (sourceTabIdx < 0 || destTabIdx < 0
            || sourceTabIdx >= _ctx.Tabs.Count || destTabIdx >= _ctx.Tabs.Count)
            return;
        _ctx.Tabs[destTabIdx].CopyNetworkRulesFrom(_ctx.Tabs[sourceTabIdx]);
    }

    private Task ApplyStateAsync(StateSpec state) =>
        XsLeakStateValidator.ApplyStateAsync(_ctx, _identities, state);

    private async Task<bool> IsSessionIntactAsync(string victimHost, string baselineCookieMode)
    {
        if (_activeScanTabs != null)
            return await _activeScanTabs.IsHomeSessionIntactAsync(victimHost, baselineCookieMode);

        try
        {
            var currentUrl = await _ctx.GetCurrentUrl();
            if (SecurityUrlPolicy.IsSessionDisruptionUrl(currentUrl, victimHost))
                return false;
        }
        catch
        {
            /* ignore */
        }

        return await SecurityScanSessionGuard.IsHomeSessionIntactAsync(
            _ctx, _ctx.ActiveTab?.Id ?? 0, victimHost, baselineCookieMode);
    }

    private async Task<(string? Value, double Ms, XsLeakTrialGroundTruth GroundTruth)> RunOneTrialOnActiveTabAsync(
        string runId, StateSpec state, string technique, int trialIndex, int networkMark)
    {
        var pageUrl = AttackerPageBuilder.PageUrl($"{runId}/{technique}/{trialIndex}/{state.Label}", _attackerOrigin);
        var html = AttackerPageBuilder.BuildHtml(state, technique, trialIndex);
        _ctx.ActiveTab.MockResponse(pageUrl, 200, html,
            headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

        await _ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
        await _ctx.WaitForIdle(400, 10000);

        string? value = null;
        double ms = 0;
        var pollBudgetMs = Math.Clamp(_probeTimeoutMs + 2500, 6500, 15000);
        var maxAttempts = pollBudgetMs / 100;
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var title = await _ctx.GetTitle();
            if (title != null && title.StartsWith("XSLEAK:", StringComparison.Ordinal))
            {
                var json = title["XSLEAK:".Length..];
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    value = root.TryGetProperty("value", out var v)
                        ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText()
                        : null;
                    ms = root.TryGetProperty("ms", out var m) && m.TryGetDouble(out var md) ? md : 0;
                }
                catch
                {
                    value = json;
                }
                break;
            }
            await Task.Delay(100);
        }

        var groundTruth = XsLeakTrialGroundTruth.FromNetwork(_ctx.ActiveTab.Network, state.Url, networkMark);
        return (value ?? "timeout", ms, groundTruth);
    }

    private async Task<List<XsLeakResourceApplicability.Profile>> SniffStateResourceProfilesAsync(
        IReadOnlyList<StateSpec> states)
    {
        var profiles = new List<XsLeakResourceApplicability.Profile>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var state in states)
        {
            var url = string.IsNullOrWhiteSpace(state.SetupUrl) ? state.Url : state.SetupUrl;
            if (string.IsNullOrWhiteSpace(url) || !seen.Add(url))
                continue;
            try
            {
                var resp = await SecurityProbeHttp.FetchAsync(
                    _ctx, url, "HEAD",
                    headers: null,
                    body: null,
                    timeoutMs: 8000,
                    includeBrowserCookies: true,
                    CancellationToken.None);
                var ct = SecurityProbeHttp.GetResponseHeader(resp, "Content-Type");
                if (string.IsNullOrWhiteSpace(ct) && resp.Status > 0)
                {
                    var getResp = await SecurityProbeHttp.FetchAsync(
                        _ctx, url, "GET",
                        headers: null,
                        body: null,
                        timeoutMs: 8000,
                        includeBrowserCookies: true,
                        CancellationToken.None);
                    ct = SecurityProbeHttp.GetResponseHeader(getResp, "Content-Type");
                }

                profiles.Add(XsLeakResourceApplicability.FromContentType(ct));
            }
            catch
            {
                profiles.Add(new XsLeakResourceApplicability.Profile(
                    XsLeakResourceApplicability.ResourceKind.Unknown, null));
            }
        }

        return profiles;
    }

    public static XsLeakHypothesis.HypothesisSpec? ParseHypothesisFromJson(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var secret = root.TryGetProperty("secret", out var s) ? s.GetString() : null;
            var kind = root.TryGetProperty("kind", out var k) ? k.GetString() : "value";
            var template = root.TryGetProperty("urlTemplate", out var t) ? t.GetString() : null;
            var method = root.TryGetProperty("method", out var m) ? m.GetString() : "GET";
            var bodyTemplate = root.TryGetProperty("bodyTemplate", out var bt) ? bt.GetString() : null;
            var contentType = root.TryGetProperty("contentType", out var ctProp) ? ctProp.GetString() : null;
            var formFields = new Dictionary<string, string>(StringComparer.Ordinal);
            if (root.TryGetProperty("formFields", out var ff) && ff.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in ff.EnumerateObject())
                    formFields[prop.Name] = prop.Value.GetString() ?? prop.Value.ToString();
            }

            var hit = new List<string>();
            var miss = new List<string>();
            if (root.TryGetProperty("hitValues", out var hv) && hv.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in hv.EnumerateArray())
                    if (el.GetString() is { } hs) hit.Add(hs);
            }
            if (root.TryGetProperty("missValues", out var mv) && mv.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in mv.EnumerateArray())
                    if (el.GetString() is { } ms) miss.Add(ms);
            }

            return new XsLeakHypothesis.HypothesisSpec
            {
                Secret = secret,
                Kind = kind ?? "value",
                UrlTemplate = template,
                Method = method ?? "GET",
                FormFields = formFields,
                BodyTemplate = bodyTemplate,
                ContentType = contentType,
                HitValues = hit,
                MissValues = miss
            };
        }
        catch
        {
            return null;
        }
    }

    public static List<StateSpec> ParseStatesFromJson(string? raw)
    {
        var list = new List<StateSpec>();
        if (string.IsNullOrWhiteSpace(raw)) return list;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return list;
            var i = 0;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var label = el.TryGetProperty("label", out var l) ? l.GetString() : null;
                var url = el.TryGetProperty("url", out var u) ? u.GetString() : null;
                var identity = el.TryGetProperty("identity", out var id) ? id.GetString() : null;
                var setupUrl = el.TryGetProperty("setupUrl", out var su) ? su.GetString() : null;
                var role = el.TryGetProperty("role", out var r) ? r.GetString() : null;
                var method = el.TryGetProperty("method", out var meth) ? meth.GetString() : "GET";
                var body = el.TryGetProperty("body", out var b) ? b.GetString() : null;
                var contentType = el.TryGetProperty("contentType", out var ct) ? ct.GetString() : null;
                Dictionary<string, string>? form = null;
                if (el.TryGetProperty("form", out var formEl) && formEl.ValueKind == JsonValueKind.Object)
                {
                    form = new Dictionary<string, string>(StringComparer.Ordinal);
                    foreach (var prop in formEl.EnumerateObject())
                        form[prop.Name] = prop.Value.GetString() ?? "";
                }

                if (string.IsNullOrWhiteSpace(url)) continue;
                list.Add(new StateSpec
                {
                    Label = string.IsNullOrWhiteSpace(label) ? $"state{i}" : label!,
                    Url = url!,
                    Identity = identity,
                    SetupUrl = setupUrl,
                    Role = role,
                    Method = method ?? "GET",
                    Body = body,
                    ContentType = contentType,
                    Form = form
                });
                i++;
            }
        }
        catch
        {
            /* ignore */
        }
        return list;
    }

    private static string BuildWatermarkedPoc(
        string runId,
        string technique,
        IReadOnlyList<StateSpec> states,
        string verdict)
    {
        var stateSummary = string.Join("; ", states.Select(s => $"{s.Label}={s.Url}"));
        var html = AttackerPageBuilder.BuildComparisonHtml(states, technique);
        var banner =
            $"<!-- Trowser XS-Leak PoC evidence runId={runId} technique={technique} verdict={verdict} " +
            $"states={stateSummary} For authorized local testing only; do not deploy off-session. -->\n";
        return banner + html;
    }

    private async Task<string> DetectCookieModeAsync()
    {
        try
        {
            var cookies = await _ctx.GetCookies();
            var hasSession = cookies.Any(c =>
            {
                var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                return name.Contains("session", StringComparison.OrdinalIgnoreCase)
                       || name.Contains("auth", StringComparison.OrdinalIgnoreCase)
                       || name.Equals("SID", StringComparison.OrdinalIgnoreCase);
            });
            var sameSite = cookies
                .Select(c => c.TryGetValue("sameSite", out var s) ? s?.ToString()?.ToLowerInvariant() : null)
                .Where(s => !string.IsNullOrEmpty(s))
                .Distinct()
                .ToList();
            if (!hasSession) return "no-session-cookie";
            if (sameSite.Contains("none")) return "samesite-none-present";
            if (sameSite.Contains("lax") || sameSite.Count == 0) return "samesite-lax-or-default";
            if (sameSite.Contains("strict")) return "samesite-strict";
            return "session-present";
        }
        catch
        {
            return "unknown";
        }
    }
}
