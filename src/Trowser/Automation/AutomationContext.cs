using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

/// <summary>
/// Script and API automation engine (Roslyn globals). Public members are callable from <c>.csx</c> scripts.
/// Browser methods use the active tab unless a tab-targeting overload is used.
/// </summary>
public partial class AutomationContext
{
    private readonly List<BrowserTab> _tabs = new();
    private int _activeTabIndex;
    private readonly Action<string> _log;
    private readonly Action<string, string> _logColored;
    private List<string>? _scriptLogCapture;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, TaskCompletionSource<string>> _asyncCallbacks = new();

    /// <summary>
    /// Active outbound-request trace for the current async flow, if any. Set via
    /// <see cref="BeginRequestTrace"/> and consulted by <see cref="Fetch"/> and security probes so
    /// callers passing <c>verbose: true</c> can see exactly which requests a scan issued.
    /// AsyncLocal so concurrent API operations on the same context stay isolated.
    /// </summary>
    private readonly AsyncLocal<RequestTrace?> _requestTrace = new();

    private const int MaxRefGenerationSnapshots = 96;
    private readonly object _refGenSnapshotLock = new();
    private readonly Dictionary<(int TabId, int RefGeneration), RefGenerationStateSnapshot> _refGenSnapshots = new();
    private readonly Queue<(int TabId, int RefGeneration)> _refGenSnapshotOrder = new();

    public BrowserTab ActiveTab => _tabs.Count > 0 ? _tabs[_activeTabIndex] : null!;

    public IReadOnlyList<BrowserTab> Tabs => _tabs.AsReadOnly();

    public TestAssert Assert { get; }

    public ConsoleLog Console => ActiveTab.Console;

    public NetworkLog Network => ActiveTab.Network;

    public int RefGeneration => ActiveTab.RefGeneration;

    /// <summary>When true, WebView2 accepts invalid TLS certificates for upcoming navigations.</summary>
    public bool IgnoreCertificateErrors { get; set; }

    /// <summary>True while the active tab shows a certificate error interstitial.</summary>
    public bool CertificateInterstitialActive { get; set; }

    internal void SetCertificateInterstitial(bool active) => CertificateInterstitialActive = active;

    /// <summary>
    /// Navigation scope guard. When set, restricts which URLs can be navigated to.
    /// Shared across all tabs.
    /// </summary>
    public NavigationGuard? NavigationGuard { get; set; }

    public Security.SecurityShadowManager? SecurityShadow { get; set; }

    /// <summary>Live cross-identity authz shadow. Off by default; requires <see cref="PeerRegistry"/>.</summary>
    public Security.Authz.LiveAuthzShadow? LiveAuthzShadow { get; set; }

    public TestDataService? TestDataService { get; set; }

    private readonly object _chainFeedLock = new();
    private List<Security.AutoScanPipeline.AutoScanFinding> _autoScanFindingsForChain = [];
    private List<ChainableFinding> _manualChainFindings = [];
    private List<ChainableFinding> _lastExecuteJsIngestions = [];
    private List<Security.Vpx.VpxProofRecord> _vpxProofs = [];
    private List<Security.Vpx.VpxVerdictRecord> _vpxVerdicts = [];
    private Dictionary<string, Dictionary<string, object?>> _vpxSurfaces = new(StringComparer.OrdinalIgnoreCase);
    private List<Dictionary<string, object?>> _vpxRuns = [];
    private List<Dictionary<string, object?>> _vpxAssessments = [];
    private List<Dictionary<string, object?>> _vpxArtifacts = [];
    private HashSet<string> _vpxImportedFindingIds = new(StringComparer.OrdinalIgnoreCase);
    private string? _vpxImportDocumentId;
    private Dictionary<string, object?>? _vpxImportTarget;

    /// <summary>Latest auto-scan findings for attack-chain analysis (fed by API and RunAutoScan).</summary>
    public void SetAutoScanFindingsForChain(IReadOnlyList<Security.AutoScanPipeline.AutoScanFinding> findings)
    {
        lock (_chainFeedLock)
            _autoScanFindingsForChain = findings.Count == 0 ? [] : [.. findings];
    }

    /// <summary>Merge new auto-scan findings into the chain feed (deduped by scanner/endpoint/method/title).</summary>
    public void AppendAutoScanFindingsForChain(IReadOnlyList<Security.AutoScanPipeline.AutoScanFinding> findings)
    {
        if (findings.Count == 0) return;
        lock (_chainFeedLock)
        {
            var seen = new HashSet<string>(
                _autoScanFindingsForChain.Select(AutoScanFindingDedupKey),
                StringComparer.OrdinalIgnoreCase);
            foreach (var f in findings)
            {
                if (seen.Add(AutoScanFindingDedupKey(f)))
                    _autoScanFindingsForChain.Add(f);
            }
        }
    }

    private static string AutoScanFindingDedupKey(Security.AutoScanPipeline.AutoScanFinding f) =>
        $"{f.Scanner}|{f.Endpoint}|{f.Method}|{f.Title}";

    /// <summary>Copy of auto-scan findings retained for <c>chain-findings</c> / <c>chain-analyze</c>.</summary>
    public List<Security.AutoScanPipeline.AutoScanFinding> GetAutoScanFindingsForChain()
    {
        lock (_chainFeedLock)
            return [.. _autoScanFindingsForChain];
    }

    /// <summary>User-added findings for chain analysis (via POST /api/security/chain-findings).</summary>
    public void AddManualChainFinding(ChainableFinding finding)
    {
        lock (_chainFeedLock)
        {
            var key = ChainFindingDedup.Key(finding);
            _manualChainFindings.RemoveAll(f =>
                ChainFindingDedup.Key(f).Equals(key, StringComparison.OrdinalIgnoreCase));
            _manualChainFindings.Add(finding);
        }
    }

    /// <summary>
    /// Upsert a verified finding from execute-js (deduped by source + category + endpoint).
    /// </summary>
    public void UpsertVerifiedChainFinding(ChainableFinding finding)
    {
        lock (_chainFeedLock)
        {
            var endpointKey = finding.Endpoint ?? "";
            _manualChainFindings.RemoveAll(f =>
                f.Source == finding.Source &&
                f.Category.Equals(finding.Category, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(f.Endpoint ?? "", endpointKey, StringComparison.OrdinalIgnoreCase));
            _manualChainFindings.Add(finding);
        }
    }

    public bool RemoveManualChainFinding(string id)
    {
        lock (_chainFeedLock)
            return _manualChainFindings.RemoveAll(f => f.Id == id) > 0;
    }

    public void ClearManualChainFindings()
    {
        lock (_chainFeedLock)
            _manualChainFindings.Clear();
    }

    public List<ChainableFinding> GetManualChainFindingsSnapshot()
    {
        lock (_chainFeedLock)
            return [.. _manualChainFindings];
    }

    /// <summary>Findings auto-ingested by the most recent execute-js call (consumed once by API handlers).</summary>
    public IReadOnlyList<ChainableFinding> ConsumeLastExecuteJsIngestions()
    {
        lock (_chainFeedLock)
        {
            if (_lastExecuteJsIngestions.Count == 0)
                return [];
            var copy = _lastExecuteJsIngestions.ToList();
            _lastExecuteJsIngestions.Clear();
            return copy;
        }
    }

    internal void SetLastExecuteJsIngestions(IReadOnlyList<ChainableFinding> findings)
    {
        lock (_chainFeedLock)
            _lastExecuteJsIngestions = findings.Count == 0 ? [] : [.. findings];
    }

    /// <summary>Session proof records exported as VPX <c>proofs[]</c>.</summary>
    public void AddVpxProof(Security.Vpx.VpxProofRecord proof)
    {
        lock (_chainFeedLock)
            _vpxProofs.Add(proof);
    }

    public List<Security.Vpx.VpxProofRecord> GetVpxProofsSnapshot()
    {
        lock (_chainFeedLock)
            return [.. _vpxProofs];
    }

    public void UpsertVpxVerdict(Security.Vpx.VpxVerdictRecord verdict)
    {
        lock (_chainFeedLock)
        {
            if (!string.IsNullOrEmpty(verdict.Id))
            {
                var idx = _vpxVerdicts.FindIndex(v =>
                    !string.IsNullOrEmpty(v.Id) &&
                    v.Id.Equals(verdict.Id, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                    _vpxVerdicts[idx] = verdict;
                else
                    _vpxVerdicts.Add(verdict);
                return;
            }

            _vpxVerdicts.RemoveAll(v =>
                string.IsNullOrEmpty(v.Id) &&
                v.FindingId.Equals(verdict.FindingId, StringComparison.OrdinalIgnoreCase));
            _vpxVerdicts.Add(verdict);
        }
    }

    public List<Security.Vpx.VpxVerdictRecord> GetVpxVerdictsSnapshot()
    {
        lock (_chainFeedLock)
            return [.. _vpxVerdicts];
    }

    public void UpsertVpxSurface(string id, Dictionary<string, object?> surface)
    {
        lock (_chainFeedLock)
            _vpxSurfaces[id] = surface;
    }

    public Dictionary<string, Dictionary<string, object?>> GetVpxSurfacesSnapshot()
    {
        lock (_chainFeedLock)
            return new Dictionary<string, Dictionary<string, object?>>(_vpxSurfaces, StringComparer.OrdinalIgnoreCase);
    }

    public void ReplaceVpxRuns(IReadOnlyList<Dictionary<string, object?>> runs)
    {
        lock (_chainFeedLock)
        {
            _vpxRuns.Clear();
            _vpxRuns.AddRange(runs);
        }
    }

    public void AddVpxRun(Dictionary<string, object?> run)
    {
        lock (_chainFeedLock)
        {
            if (run.TryGetValue("id", out var idObj) && idObj is string id && !string.IsNullOrWhiteSpace(id))
            {
                var idx = _vpxRuns.FindIndex(r =>
                    r.TryGetValue("id", out var existing) &&
                    existing is string eid &&
                    eid.Equals(id, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                    _vpxRuns[idx] = run;
                else
                    _vpxRuns.Add(run);
            }
            else
            {
                _vpxRuns.Add(run);
            }
        }
    }

    public List<Dictionary<string, object?>> GetVpxRunsSnapshot()
    {
        lock (_chainFeedLock)
            return _vpxRuns.Select(CloneDict).ToList();
    }

    public void AddVpxAssessment(Dictionary<string, object?> assessment)
    {
        lock (_chainFeedLock)
        {
            if (assessment.TryGetValue("id", out var idObj) && idObj is string id && !string.IsNullOrWhiteSpace(id))
            {
                var idx = _vpxAssessments.FindIndex(a =>
                    a.TryGetValue("id", out var existing) &&
                    existing is string eid &&
                    eid.Equals(id, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                    return;
            }
            _vpxAssessments.Add(assessment);
        }
    }

    public List<Dictionary<string, object?>> GetVpxAssessmentsSnapshot()
    {
        lock (_chainFeedLock)
            return _vpxAssessments.Select(CloneDict).ToList();
    }

    public void AddVpxArtifact(Dictionary<string, object?> artifact)
    {
        lock (_chainFeedLock)
        {
            if (artifact.TryGetValue("id", out var idObj) && idObj is string id && !string.IsNullOrWhiteSpace(id))
            {
                var idx = _vpxArtifacts.FindIndex(a =>
                    a.TryGetValue("id", out var existing) &&
                    existing is string eid &&
                    eid.Equals(id, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                    _vpxArtifacts[idx] = artifact;
                else
                    _vpxArtifacts.Add(artifact);
            }
            else
            {
                _vpxArtifacts.Add(artifact);
            }
        }
    }

    public List<Dictionary<string, object?>> GetVpxArtifactsSnapshot()
    {
        lock (_chainFeedLock)
            return _vpxArtifacts.Select(CloneDict).ToList();
    }

    private static Dictionary<string, object?> CloneDict(Dictionary<string, object?> src) =>
        new(src, StringComparer.OrdinalIgnoreCase);

    public void RegisterVpxImportedFindingId(string id)
    {
        lock (_chainFeedLock)
            _vpxImportedFindingIds.Add(id);
    }

    public HashSet<string> GetVpxImportedFindingIds()
    {
        lock (_chainFeedLock)
            return new HashSet<string>(_vpxImportedFindingIds, StringComparer.OrdinalIgnoreCase);
    }

    public void SetVpxImportDocumentId(string? documentId)
    {
        lock (_chainFeedLock)
            _vpxImportDocumentId = documentId;
    }

    public string? GetVpxImportDocumentId()
    {
        lock (_chainFeedLock)
            return _vpxImportDocumentId;
    }

    public void SetVpxImportTarget(Dictionary<string, object?>? target)
    {
        lock (_chainFeedLock)
            _vpxImportTarget = target;
    }

    public Dictionary<string, object?>? GetVpxImportTarget()
    {
        lock (_chainFeedLock)
            return _vpxImportTarget;
    }

    public void ClearVpxImportState()
    {
        lock (_chainFeedLock)
        {
            _vpxProofs.Clear();
            _vpxVerdicts.Clear();
            _vpxSurfaces.Clear();
            _vpxRuns.Clear();
            _vpxAssessments.Clear();
            _vpxArtifacts.Clear();
            _vpxImportedFindingIds.Clear();
            _vpxImportDocumentId = null;
            _vpxImportTarget = null;
            _manualChainFindings.RemoveAll(f => f.Source == "vpx-import");
        }
    }

    /// <summary>
    /// Clears VPX import artifacts and cross-playbook dedup seed (manual chain findings + auto-scan feed).
    /// Use between iterative playbook runs to avoid suppressed findings.
    /// </summary>
    public void ClearVpxSessionState()
    {
        ClearVpxImportState();
        ClearManualChainFindings();
        SetAutoScanFindingsForChain([]);
    }

    public Security.CallbackDetector? CallbackDetector { get; set; }

    public Security.PowerModeManager? PowerMode { get; set; }

    public Security.RedTeamWhisperManager? RedTeamWhisper { get; set; }

    public Security.SslManager? SslManager { get; set; }

    internal PlaybookRegistry? PlaybookRegistry { get; set; }

    internal IdentityStore? OrchestrateIdentityStore { get; set; }

    internal ChainPatternCatalog? OrchestrateChainCatalog { get; set; }

    /// <summary>Apply or remove Power mode on the active tab’s page (e.g. after toggling in Settings or API).</summary>
    public async Task SyncPowerModeToActivePageAsync()
    {
        if (PowerMode == null) return;
        var wv = ActiveTab?.WebView;
        if (wv?.CoreWebView2 == null) return;
        // WebView2 is owned by the UI dispatcher — REST/API calls run off that thread.
        await await wv.Dispatcher.InvokeAsync(async () =>
        {
            if (PowerMode.Config.Enabled)
                await PowerMode.ApplyAsync(wv, PowerMode.Config.ShowOverlays);
            else
                await PowerMode.RemoveAsync(wv);
        });
    }

    /// <summary>Apply or remove Power mode on every open tab (e.g. after disabling globally).</summary>
    public async Task SyncPowerModeToAllTabsAsync()
    {
        if (PowerMode == null || _tabs.Count == 0) return;
        var anchor = _tabs.FirstOrDefault(t => t.WebView != null)?.WebView;
        if (anchor == null) return;
        await await anchor.Dispatcher.InvokeAsync(async () =>
        {
            foreach (var tab in _tabs)
            {
                var wv = tab.WebView;
                if (wv?.CoreWebView2 == null) continue;
                if (PowerMode.Config.Enabled)
                    await PowerMode.ApplyAsync(wv, PowerMode.Config.ShowOverlays);
                else
                    await PowerMode.RemoveAsync(wv);
            }
        });
    }

    public bool HasMockRules => ActiveTab.HasMockRules;

    /// <summary>
    /// Default timeout (ms) for auto-waiting in action methods (Click, Type, Select, etc.).
    /// </summary>
    public int DefaultActionTimeout { get; set; } = 5000;

    /// <summary>
    /// Cancellation token for stopping running scripts. Set by ScriptEngine during execution.
    /// Checked at every async checkpoint (Sleep, Navigate, RunJs, WaitFor*, etc.).
    /// </summary>
    public CancellationToken ScriptCancellation { get; set; }

    /// <summary>
    /// Pause/resume control for script console runs. Set by ScriptEngine during execution.
    /// </summary>
    public Scripting.ScriptRunControl? ScriptRunControl { get; set; }

    /// <summary>
    /// Honor script stop and pause at async checkpoints. Call before automation work and in wait loops.
    /// </summary>
    public async Task CheckScriptExecutionAsync()
    {
        ScriptCancellation.ThrowIfCancellationRequested();
        if (ScriptRunControl != null)
            await ScriptRunControl.WaitIfRunningAsync(ScriptCancellation).ConfigureAwait(false);
    }

    /// <summary>
    /// CSS selector for the element the user right-clicked before choosing **Run Script** in the
    /// page context menu. Cleared after each script run. Use with <see cref="RunScriptTarget"/> or <see cref="This"/> directly in <c>Click</c>, <c>Type</c>, etc.
    /// </summary>
    public string? This { get; set; }

    /// <summary>
    /// Shorthand selector (Unicode …) resolved to <see cref="This"/> for <c>Click</c>, <c>Type</c>,
    /// <c>WaitForElement</c>, and other APIs that take a selector.
    /// </summary>
    public static string RunScriptTarget => "\u2026";

    /// <summary>
    /// Cancellation token for the current API operation. Set by TrowserApiServer before each
    /// gated operation. Cancelled by POST /api/abort to force-stop a stuck operation.
    /// </summary>
    public CancellationToken OperationCancellation { get; set; }

    /// <summary>
    /// Links <see cref="ScriptCancellation"/> and <see cref="OperationCancellation"/> for inject-and-poll audit checkers.
    /// Caller must dispose the returned source (e.g. <c>using var linked = LinkCheckerCancellation();</c>).
    /// </summary>
    internal CancellationTokenSource LinkCheckerCancellation()
        => CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);

    #region Tab Management Callbacks

    /// <summary>
    /// Callback to MainWindow for creating a new WebView2 control and initializing a tab.
    /// Returns the new BrowserTab after it has been fully initialized (WebView2 ready, events wired).
    /// </summary>
    public Func<string?, Task<BrowserTab>>? OnCreateTabRequested { get; set; }

    /// <summary>
    /// Callback to MainWindow when the active tab should change (for UI updates).
    /// </summary>
    public Action<int>? OnActiveTabChanged { get; set; }

    /// <summary>
    /// Callback to MainWindow when a tab is about to be removed (for cleanup).
    /// </summary>
    public Action<BrowserTab>? OnTabRemoved { get; set; }

    #endregion

    public AutomationContext(WebView2 initialWebView, Action<string> log, Action<string, string> logColored)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _logColored = logColored ?? throw new ArgumentNullException(nameof(logColored));
        Assert = new TestAssert(_logColored);

        var initialTab = new BrowserTab(initialWebView ?? throw new ArgumentNullException(nameof(initialWebView)));
        _tabs.Add(initialTab);
    }

    public void Log(string message)
    {
        _scriptLogCapture?.Add(message);
        _log(message);
    }

    public void Log(string message, string color)
    {
        _scriptLogCapture?.Add(message);
        _logColored(message, color);
    }

    /// <summary>Collect <see cref="Log"/> lines for REST/MCP script runs (not the UI console).</summary>
    internal void BeginScriptLogCapture() => _scriptLogCapture = [];

    internal IReadOnlyList<string> ConsumeScriptLogCapture()
    {
        var lines = _scriptLogCapture ?? [];
        _scriptLogCapture = null;
        return lines;
    }

    #region Tab Management (Public API for scripts and REST)

    /// <summary>
    /// True while a REST/MCP request is driving the browser. Used so agent automation
    /// defaults to an agent-owned tab instead of the tester's page.
    /// </summary>
    public bool IsAgentAutomation { get; set; }

    /// <summary>
    /// Whether the first agent mutation should stay on the active tab or prefer a dedicated agent tab.
    /// </summary>
    public AgentTabPolicy AgentTabPolicy { get; set; } = AgentTabPolicy.StayOnActive;

    /// <summary>
    /// Set when the agent explicitly <see cref="SwitchTab"/>s to a human-owned tab.
    /// Subsequent mutations stay there (with a warning) instead of bouncing back.
    /// </summary>
    private bool _agentChoseHumanTab;

    private bool _stayOnActiveTabNoticeShown;

    /// <summary>Last ownership notice from <see cref="EnsureAgentTabAsync"/> (shown in GET /api/tabs).</summary>
    public string? LastTabOwnershipWarning { get; private set; }

    /// <summary>
    /// Open a new browser tab. Optionally navigate it to a URL.
    /// When <paramref name="activate"/> is true (default), switches to the new tab.
    /// </summary>
    public async Task<int> NewTab(string? url = null, string? owner = null, bool activate = true)
    {
        if (OnCreateTabRequested == null)
            throw new InvalidOperationException("Tab creation is not available.");

        var tab = await OnCreateTabRequested(url);
        tab.Owner = TabOwners.Normalize(owner, IsAgentAutomation ? TabOwners.Agent : TabOwners.Human);
        if (tab.Owner == TabOwners.Agent)
            _agentChoseHumanTab = false;
        _tabs.Add(tab);

        var newIndex = _tabs.Count - 1;
        if (activate)
            SetActiveTab(newIndex);

        return newIndex;
    }

    /// <summary>
    /// Page-initiated window (<c>window.open</c>). Owner and activation follow automation vs human context.
    /// </summary>
    internal async Task<int> NewTabFromPageWindowAsync(BrowserTab openerTab)
    {
        var owner = ResolvePagePopupOwner(openerTab, IsAgentAutomation);
        var activate = owner == TabOwners.Human && !IsAgentAutomation;
        var idx = await NewTab(null, owner, activate);
        var tab = _tabs[idx];
        tab.OpenedByPageWindow = true;
        tab.OpenerTabId = openerTab.Id;
        return idx;
    }

    internal static string ResolvePagePopupOwner(BrowserTab openerTab, bool isAgentAutomation)
    {
        if (isAgentAutomation || openerTab.Owner == TabOwners.Agent)
            return TabOwners.Agent;
        if (openerTab.Owner == TabOwners.Shared)
            return TabOwners.Shared;
        return TabOwners.Human;
    }

    /// <summary>
    /// On the first agent mutation, open or switch to an agent-owned tab so automation
    /// does not clobber the tester's page. If the agent already switched onto a human
    /// tab, stay there and return a warning.
    /// </summary>
    public async Task<string?> EnsureAgentTabAsync()
    {
        LastTabOwnershipWarning = null;
        if (!IsAgentAutomation) return null;

        var active = ActiveTab;
        if (active == null) return null;
        if (active.Owner is TabOwners.Agent or TabOwners.Shared)
            return null;

        if (AgentTabPolicy == AgentTabPolicy.StayOnActive)
        {
            _agentChoseHumanTab = true;
            if (!_stayOnActiveTabNoticeShown)
            {
                _stayOnActiveTabNoticeShown = true;
                LastTabOwnershipWarning =
                    "Automation is using the active tab. Use browser_new_tab (owner agent) if you want a separate automation tab.";
                return LastTabOwnershipWarning;
            }

            return null;
        }

        if (_agentChoseHumanTab)
        {
            LastTabOwnershipWarning =
                "Acting on a human-owned tab. Prefer an agent tab (browser_new_tab) to avoid colliding with the tester.";
            return LastTabOwnershipWarning;
        }

        for (var i = 0; i < _tabs.Count; i++)
        {
            if (_tabs[i].Owner == TabOwners.Agent)
            {
                SetActiveTab(i);
                LastTabOwnershipWarning = "Switched to the agent tab to leave the tester's page alone.";
                return LastTabOwnershipWarning;
            }
        }

        await NewTab(null, TabOwners.Agent);
        LastTabOwnershipWarning = "Opened an agent tab for automation.";
        return LastTabOwnershipWarning;
    }

    /// <summary>
    /// Close a tab by index. If no index is given, closes the active tab.
    /// Cannot close the last remaining tab.
    /// </summary>
    public async Task CloseTab(int? tabIndex = null)
    {
        var idx = tabIndex ?? _activeTabIndex;
        if (idx < 0 || idx >= _tabs.Count)
            throw new ArgumentOutOfRangeException(nameof(tabIndex), $"Invalid tab index: {idx}. There are {_tabs.Count} tab(s).");

        if (_tabs.Count <= 1)
            throw new InvalidOperationException("Cannot close the last tab.");

        var tab = _tabs[idx];
        _tabs.RemoveAt(idx);
        OnTabRemoved?.Invoke(tab);

        if (_activeTabIndex >= _tabs.Count)
            _activeTabIndex = _tabs.Count - 1;
        else if (idx < _activeTabIndex)
            _activeTabIndex--;

        OnActiveTabChanged?.Invoke(_activeTabIndex);
        await Task.CompletedTask;
    }

    /// <summary>
    /// Switch the active tab to the given index. All subsequent browser operations
    /// will target the new active tab.
    /// </summary>
    public void SwitchTab(int tabIndex)
    {
        if (tabIndex < 0 || tabIndex >= _tabs.Count)
            throw new ArgumentOutOfRangeException(nameof(tabIndex),
                $"Invalid tab index: {tabIndex}. There are {_tabs.Count} tab(s) (0-based).");

        SetActiveTab(tabIndex);
        if (IsAgentAutomation)
            _agentChoseHumanTab = _tabs[tabIndex].Owner == TabOwners.Human;
    }

    /// <summary>
    /// Get information about all open tabs.
    /// </summary>
    public List<TabInfo> GetTabs()
    {
        return _tabs.Select((t, i) => new TabInfo
        {
            Index = i,
            Id = t.Id,
            Title = t.Title,
            Url = t.Url,
            IsActive = i == _activeTabIndex,
            Owner = t.Owner,
            NetworkEntryCount = t.Network.Count,
            ConsoleEntryCount = t.Console.Count
        }).ToList();
    }

    internal IReadOnlyList<BrowserTab> GetBrowserTabs() => _tabs.ToList();

    public int GetTabCount() => _tabs.Count;

    public int GetActiveTabIndex() => _activeTabIndex;

    /// <summary>
    /// Add an already-initialized tab to the collection (called by MainWindow during setup).
    /// Does not switch to it.
    /// </summary>
    internal void AddExistingTab(BrowserTab tab)
    {
        _tabs.Add(tab);
    }

    /// <summary>
    /// Set the active tab by index. Notifies the UI via callback.
    /// </summary>
    internal void SetActiveTab(int index)
    {
        if (index < 0 || index >= _tabs.Count) return;
        _activeTabIndex = index;
        OnActiveTabChanged?.Invoke(index);
    }

    /// <summary>
    /// Remove a tab from the internal list (called during cleanup).
    /// </summary>
    internal void RemoveTabInternal(BrowserTab tab)
    {
        var idx = _tabs.IndexOf(tab);
        if (idx >= 0)
        {
            _tabs.RemoveAt(idx);
            if (_activeTabIndex >= _tabs.Count)
                _activeTabIndex = Math.Max(0, _tabs.Count - 1);
            else if (idx < _activeTabIndex)
                _activeTabIndex--;
        }
    }

    public BrowserTab? GetTabByIndex(int index)
    {
        if (index < 0 || index >= _tabs.Count) return null;
        return _tabs[index];
    }

    public int IndexOfTab(BrowserTab tab) => _tabs.IndexOf(tab);

    public BrowserTab? GetTabById(int id) => _tabs.FirstOrDefault(t => t.Id == id);

    /// <summary>Index of a tab by <see cref="BrowserTab.Id"/>, or -1.</summary>
    public int FindTabIndexById(int id) => _tabs.FindIndex(t => t.Id == id);

    #endregion

    #region Resource Management

    /// <summary>
    /// Force a garbage collection to free memory held by script variables.
    /// Call after storing large data (e.g. GetNetworkLog()) that is no longer needed.
    /// </summary>
    public void CollectGarbage()
    {
        GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
    }

    #endregion

    #region Internal JS Helpers

    private const string DeepQueryJs = """
        function __trowserResolveFrameRoot(spec) {
            if (!spec) return document;
            function stampAndList(doc, parentId, acc, counter) {
                var iframes = doc.querySelectorAll('iframe');
                for (var i = 0; i < iframes.length; i++) {
                    var f = iframes[i];
                    var id = f.getAttribute('data-trowser-frame-id');
                    if (!id) {
                        id = 'f' + (counter.n++);
                        try { f.setAttribute('data-trowser-frame-id', id); } catch (e) {}
                    }
                    var sameOrigin = false, cd = null;
                    try {
                        cd = f.contentDocument;
                        if (cd) sameOrigin = true;
                    } catch (e3) {}
                    acc.push({ el: f, frameId: id, name: f.getAttribute('name') || f.name || '', sameOrigin: sameOrigin, parentFrameId: parentId, doc: cd });
                    if (cd) stampAndList(cd, id, acc, counter);
                }
            }
            var acc = [];
            stampAndList(window.document, null, acc, { n: 1 });
            for (var i = 0; i < acc.length; i++) {
                if (acc[i].frameId === spec || acc[i].name === spec) {
                    if (!acc[i].sameOrigin || !acc[i].doc) return null;
                    return acc[i].doc;
                }
            }
            try {
                var bySel = window.document.querySelector(spec);
                if (bySel && bySel.tagName && bySel.tagName.toLowerCase() === 'iframe') {
                    try {
                        var cd2 = bySel.contentDocument;
                        if (cd2) return cd2;
                    } catch (e5) {}
                    return null;
                }
            } catch (e6) {}
            return null;
        }
        function deepQuery(sel) {
            var root = (typeof __trowserRoot !== 'undefined' && __trowserRoot) ? __trowserRoot : document;
            if (sel.indexOf('@frame:') === 0) {
                var pipe = sel.indexOf('|');
                if (pipe > 7) {
                    var fspec = sel.substring(7, pipe);
                    var inner = sel.substring(pipe + 1);
                    var fdoc = __trowserResolveFrameRoot(fspec);
                    if (!fdoc) return null;
                    root = fdoc;
                    sel = inner;
                }
            }
            if (sel.indexOf(' >>> ') !== -1) {
                var parts = sel.split(' >>> ');
                var current = root;
                for (var i = 0; i < parts.length; i++) {
                    var found = current.querySelector(parts[i].trim());
                    if (!found) return null;
                    if (i < parts.length - 1) {
                        if (!found.shadowRoot) return null;
                        current = found.shadowRoot;
                    } else {
                        return found;
                    }
                }
                return null;
            }
            var el = root.querySelector(sel);
            if (el) return el;
            function searchShadows(searchRoot) {
                var hosts = searchRoot.querySelectorAll('*');
                for (var i = 0; i < hosts.length; i++) {
                    if (hosts[i].shadowRoot) {
                        var found = hosts[i].shadowRoot.querySelector(sel);
                        if (found) return found;
                        found = searchShadows(hosts[i].shadowRoot);
                        if (found) return found;
                    }
                }
                return null;
            }
            return searchShadows(root);
        }
        """;

    private const string DeepQueryAllJs = """
        function deepQueryAll(sel) {
            var root = (typeof __trowserRoot !== 'undefined' && __trowserRoot) ? __trowserRoot : document;
            var results = Array.from(root.querySelectorAll(sel));
            function searchShadows(searchRoot) {
                var hosts = searchRoot.querySelectorAll('*');
                for (var i = 0; i < hosts.length; i++) {
                    if (hosts[i].shadowRoot) {
                        results = results.concat(Array.from(hosts[i].shadowRoot.querySelectorAll(sel)));
                        searchShadows(hosts[i].shadowRoot);
                    }
                }
            }
            searchShadows(root);
            return results;
        }
        """;

    private const string ExtractHelpersJs = """
        function subQuery(container, sel) {
            if (sel === '.' || sel === '') return container;
            var el = container.querySelector(sel);
            if (el) return el;
            var hosts = container.querySelectorAll('*');
            for (var i = 0; i < hosts.length; i++) {
                if (hosts[i].shadowRoot) {
                    var found = hosts[i].shadowRoot.querySelector(sel);
                    if (found) return found;
                }
            }
            return null;
        }
        function extractField(container, spec) {
            var atIdx = spec.lastIndexOf('@');
            var sel, attr;
            if (atIdx > 0) {
                sel = spec.substring(0, atIdx);
                attr = spec.substring(atIdx + 1);
            } else if (atIdx === 0) {
                sel = '.';
                attr = spec.substring(1);
            } else {
                sel = spec;
                attr = null;
            }
            var el = (sel === '.' || sel === '') ? container : subQuery(container, sel);
            if (!el) return null;
            return attr ? (el.getAttribute(attr) || '') : (el.innerText || el.textContent || '').trim();
        }
        function extractTable(table) {
            var headers = [];
            var thead = table.querySelector('thead');
            if (thead) {
                var ths = thead.querySelectorAll('th, td');
                for (var i = 0; i < ths.length; i++)
                    headers.push((ths[i].innerText || ths[i].textContent || '').trim());
            }
            var tbody = table.querySelector('tbody') || table;
            var trs = Array.from(tbody.querySelectorAll('tr'));
            var startRow = 0;
            if (headers.length === 0 && trs.length > 0) {
                var firstRow = trs[0].querySelectorAll('th, td');
                for (var i = 0; i < firstRow.length; i++)
                    headers.push((firstRow[i].innerText || firstRow[i].textContent || '').trim());
                startRow = 1;
            }
            if (headers.length === 0) return [];
            var rows = [];
            for (var r = startRow; r < trs.length; r++) {
                if (thead && thead.contains(trs[r])) continue;
                var cells = trs[r].querySelectorAll('td, th');
                var obj = {};
                for (var c = 0; c < headers.length; c++) {
                    obj[headers[c]] = c < cells.length
                        ? (cells[c].innerText || cells[c].textContent || '').trim()
                        : '';
                }
                rows.push(obj);
            }
            return rows;
        }
        """;

    private const string ExtractMainJs = """
        var elements = deepQueryAll(selector);
        if (elements.length === 0) return JSON.stringify([]);
        if (!fields && elements.length === 1) {
            var el = elements[0];
            var table = el.tagName === 'TABLE' ? el : el.querySelector('table');
            if (table) {
                var result = extractTable(table);
                if (limit > 0) result = result.slice(0, limit);
                return JSON.stringify(result);
            }
        }
        if (fields) {
            var result = [];
            for (var i = 0; i < elements.length; i++) {
                if (limit > 0 && result.length >= limit) break;
                var obj = {};
                for (var key in fields) {
                    obj[key] = extractField(elements[i], fields[key]);
                }
                result.push(obj);
            }
            return JSON.stringify(result);
        }
        var result = [];
        for (var i = 0; i < elements.length; i++) {
            if (limit > 0 && result.length >= limit) break;
            result.push({ text: (elements[i].innerText || elements[i].textContent || '').trim() });
        }
        return JSON.stringify(result);
        """;

    private string BuildExtractJs(string selector, Dictionary<string, string>? fields, int limit)
    {
        var fieldsJs = "null";
        if (fields is { Count: > 0 })
        {
            var entries = fields.Select(f => $"{JsonEscape(f.Key)}:{JsonEscape(f.Value)}");
            fieldsJs = $"{{{string.Join(",", entries)}}}";
        }

        var sb = new System.Text.StringBuilder(4096);
        sb.Append("(function(){\n");
        sb.Append(DeepQueryAllJs).Append('\n');
        sb.Append(ExtractHelpersJs).Append('\n');
        sb.Append("var selector=").Append(JsonEscape(selector)).Append(";\n");
        sb.Append("var fields=").Append(fieldsJs).Append(";\n");
        sb.Append("var limit=").Append(limit).Append(";\n");
        sb.Append(ExtractMainJs).Append('\n');
        sb.Append("})()");
        return sb.ToString();
    }

    private const string LocatorHelpersJs = """
        function getAccessibleName(el) {
            var a = el.getAttribute('aria-label');
            if (a) return a.trim();
            var lb = el.getAttribute('aria-labelledby');
            if (lb) {
                var rt = el.getRootNode();
                var doc = (rt instanceof ShadowRoot) ? rt : document;
                var lbl = doc.getElementById(lb);
                if (lbl) return (lbl.innerText || lbl.textContent || '').trim();
            }
            if (el.id) {
                var rt2 = el.getRootNode();
                var doc2 = (rt2 instanceof ShadowRoot) ? rt2 : document;
                var lbl2 = doc2.querySelector('label[for="' + el.id + '"]');
                if (lbl2) return (lbl2.innerText || lbl2.textContent || '').trim();
            }
            var la = el.getAttribute('label');
            if (la) return la.trim();
            if (el.tagName === 'INPUT' || el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') {
                var parent = el.closest('label');
                if (parent) {
                    var clone = parent.cloneNode(true);
                    var inputs = clone.querySelectorAll('input,select,textarea');
                    for (var ci = 0; ci < inputs.length; ci++) inputs[ci].remove();
                    var lt = (clone.innerText || clone.textContent || '').trim();
                    if (lt) return lt;
                }
            }
            var tn = el.tagName;
            if (tn === 'A' || tn === 'BUTTON' || tn === 'SUMMARY' ||
                (el.getAttribute('role')||'') === 'button' || (el.getAttribute('role')||'') === 'link' ||
                (el.getAttribute('role')||'') === 'tab' || (el.getAttribute('role')||'') === 'menuitem') {
                var cl = el.cloneNode(true);
                var ic = cl.querySelectorAll(
                    'svg, img, [class*="icon"], [class*="Icon"], .sr-only, .visually-hidden, [aria-hidden="true"]');
                for (var ri = 0; ri < ic.length; ri++) ic[ri].remove();
                var ct = (cl.textContent || '').trim().replace(/\s+/g, ' ');
                if (ct) return ct;
            }
            var t = (el.innerText || el.textContent || '').trim();
            if (t) return t;
            if (el.value && (el.type==='submit'||el.type==='button'||el.type==='reset'))
                return el.value.trim();
            if (el.placeholder) return el.placeholder.trim();
            if (el.title) return el.title.trim();
            return '';
        }
        function isElVisible(el) {
            var cur = el;
            while (cur) {
                if (cur === document.documentElement) break;
                if (cur.nodeType !== 1) break;
                try {
                    var st = window.getComputedStyle(cur);
                    if (st.display === 'none' || st.visibility === 'hidden')
                        return false;
                } catch(e) { break; }
                if (cur.parentElement) cur = cur.parentElement;
                else {
                    var root = cur.getRootNode();
                    if (root instanceof ShadowRoot) cur = root.host;
                    else break;
                }
            }
            var rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) return false;
            return true;
        }
        function findByRole(role, name) {
            var m = {
                'button':'button,input[type=button],input[type=submit],input[type=reset],[role=button],summary',
                'link':'a[href],[role=link]',
                'textbox':'input:not([type]),input[type=text],input[type=email],input[type=url],input[type=tel],input[type=search],input[type=number],input[type=password],textarea,[role=textbox],[contenteditable=true]',
                'searchbox':'input[type=search],[role=searchbox]',
                'checkbox':'input[type=checkbox],[role=checkbox]',
                'radio':'input[type=radio],[role=radio]',
                'combobox':'select,[role=combobox],[role=listbox]',
                'option':'option,[role=option]',
                'heading':'h1,h2,h3,h4,h5,h6,[role=heading]',
                'img':'img,[role=img]',
                'list':'ul,ol,[role=list]',
                'listitem':'li,[role=listitem]',
                'navigation':'nav,[role=navigation]',
                'tab':'[role=tab]',
                'tabpanel':'[role=tabpanel]',
                'dialog':'dialog,[role=dialog],[role=alertdialog]',
                'alert':'[role=alert]',
                'menu':'[role=menu]',
                'menuitem':'[role=menuitem]',
                'switch':'[role=switch]',
                'slider':'input[type=range],[role=slider]',
                'progressbar':'progress,[role=progressbar]',
                'region':'section[aria-label],section[aria-labelledby],[role=region]',
                'form':'form,[role=form]',
                'table':'table,[role=table],[role=grid]',
                'row':'tr,[role=row]',
                'cell':'td,th,[role=cell],[role=gridcell],[role=columnheader],[role=rowheader]',
                'banner':'header,[role=banner]',
                'contentinfo':'footer,[role=contentinfo]',
                'main':'main,[role=main]',
                'search':'[role=search]',
                'separator':'hr,[role=separator]',
                'status':'[role=status]',
                'tooltip':'[role=tooltip]'
            };
            var sel = m[role.toLowerCase()] || ('[role=' + role + ']');
            var cands = deepQueryAll(sel);
            var firstMatch = null;
            for (var i = 0; i < cands.length; i++) {
                var ok = !name;
                if (name) {
                    var an = getAccessibleName(cands[i]).toLowerCase();
                    var nLC = name.toLowerCase();
                    ok = (an === nLC || an.includes(nLC));
                }
                if (ok) {
                    if (!firstMatch) firstMatch = cands[i];
                    if (isElVisible(cands[i])) return cands[i];
                }
            }
            return firstMatch;
        }
        function findByLabel(labelText) {
            var tLC = labelText.toLowerCase();
            var inputs = deepQueryAll('input,select,textarea,[contenteditable=true]');
            var firstMatch = null;
            for (var i = 0; i < inputs.length; i++) {
                var an = getAccessibleName(inputs[i]).toLowerCase();
                if (an === tLC || an.includes(tLC)) {
                    if (!firstMatch) firstMatch = inputs[i];
                    if (isElVisible(inputs[i])) return inputs[i];
                }
            }
            return firstMatch;
        }
        function normWs(s) { return s.replace(/\s+/g, ' '); }
        function childMatchesText(child, tLC, isExact) {
            var ct = normWs((child.innerText || child.textContent || '').trim().toLowerCase());
            if (isExact ? ct === tLC : ct.includes(tLC)) return true;
            var can = normWs(getAccessibleName(child).toLowerCase());
            if (can && (isExact ? can === tLC : can.includes(tLC))) return true;
            return false;
        }
        function isActionableByText(el) {
            var tag = (el.tagName || '').toUpperCase();
            if (tag === 'BUTTON' || tag === 'A' || tag === 'SUMMARY') return true;
            if (tag === 'INPUT') {
                var ty = (el.type || '').toLowerCase();
                return ty === 'submit' || ty === 'button' || ty === 'reset' || ty === 'checkbox' || ty === 'radio';
            }
            var role = (el.getAttribute('role') || '').toLowerCase();
            if (role === 'button' || role === 'link' || role === 'menuitem' || role === 'tab') return true;
            return false;
        }
        function findByText(searchText) {
            var tLC = normWs(searchText.toLowerCase());
            var all = deepQueryAll('*');
            var best = null;
            var bestVisible = null;
            var bestAction = null;
            var bestVisibleAction = null;
            for (var i = 0; i < all.length; i++) {
                var el = all[i];
                var et = normWs((el.innerText || el.textContent || '').trim().toLowerCase());
                var an = normWs(getAccessibleName(el).toLowerCase());
                var isExact = (et === tLC || an === tLC);
                if (isExact || et.includes(tLC) || (an && an.includes(tLC))) {
                    var kids = el.children;
                    var childHas = false;
                    for (var j = 0; j < kids.length; j++) {
                        if (childMatchesText(kids[j], tLC, isExact)) { childHas = true; break; }
                    }
                    if (!childHas) {
                        var act = isActionableByText(el);
                        if (isExact && isElVisible(el) && act) return el;
                        if (!bestAction) bestAction = act ? el : null;
                        if (!bestVisibleAction && isElVisible(el) && act) bestVisibleAction = el;
                        if (!best) best = el;
                        if (!bestVisible && isElVisible(el)) bestVisible = el;
                    }
                }
            }
            return bestVisibleAction || bestAction || bestVisible || best;
        }
        function findByPlaceholder(text) {
            var tLC = text.toLowerCase();
            var inputs = deepQueryAll('input[placeholder],textarea[placeholder]');
            var firstMatch = null;
            for (var i = 0; i < inputs.length; i++) {
                var ph = (inputs[i].placeholder || '').toLowerCase();
                if (ph === tLC || ph.includes(tLC)) {
                    if (!firstMatch) firstMatch = inputs[i];
                    if (isElVisible(inputs[i])) return inputs[i];
                }
            }
            return firstMatch;
        }
        function findByTestId(testId) {
            return deepQuery('[data-testid="' + testId.replace(/"/g, '\\"') + '"]');
        }
        function findByValue(valueText) {
            var tLC = valueText.toLowerCase();
            var inputs = deepQueryAll('input[type=radio],input[type=checkbox],option');
            var firstMatch = null;
            for (var i = 0; i < inputs.length; i++) {
                var v = (inputs[i].value || '').toLowerCase();
                if (v === tLC || v.includes(tLC)) {
                    if (!firstMatch) firstMatch = inputs[i];
                    if (isElVisible(inputs[i])) return inputs[i];
                }
            }
            return firstMatch;
        }
        """;

    private const string VisibilityCheckJs = """
            var cur = el;
            while (cur) {
                if (cur === document.documentElement) break;
                if (cur.nodeType !== 1) break;
                try {
                    var st = window.getComputedStyle(cur);
                    if (st.display === 'none' || st.visibility === 'hidden')
                        return JSON.stringify({s:'HIDDEN'});
                } catch(e) { break; }
                if (cur.parentElement) cur = cur.parentElement;
                else {
                    var root = cur.getRootNode();
                    if (root instanceof ShadowRoot) cur = root.host;
                    else break;
                }
            }
            var rect = el.getBoundingClientRect();
            if (rect.width === 0 && rect.height === 0) return JSON.stringify({s:'HIDDEN'});
        """;

    /// <summary>For visually hidden checkbox/radio/file inputs, try clicking the associated label (common accessible pattern).</summary>
    private const string CheckboxLabelFallbackJs = """
            function __trowserInputNeedsLabelProxy(input) {
                if (!input || !input.type) return false;
                var t = input.type.toLowerCase();
                if (t !== 'checkbox' && t !== 'radio' && t !== 'file') return false;
                var rect = input.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return true;
                try {
                    var st = window.getComputedStyle(input);
                    var op = parseFloat(st.opacity);
                    if (st.opacity === '0' || op === 0) return true;
                } catch(e) {}
                return false;
            }
            if (__trowserInputNeedsLabelProxy(el)) {
                var lbl = null;
                if (el.id) {
                    var rt = el.getRootNode();
                    var doc = (rt instanceof ShadowRoot) ? rt : document;
                    lbl = doc.querySelector('label[for="' + el.id.replace(/"/g, '\\"') + '"]');
                }
                if (!lbl) lbl = el.closest('label');
                if (lbl) {
                    var lrect = lbl.getBoundingClientRect();
                    if (lrect.width > 0 && lrect.height > 0) { el = lbl; }
                }
            }
        """;

    private string WrapWithDeepQuery(string jsBody)
    {
        return "(function() {\n" + BuildFramePreamble(_actionFrame.Value) + DeepQueryJs + "\n" + jsBody + "\n})()";
    }

    internal async Task<bool> IsActionFrameInspectableAsync()
    {
        var frame = _actionFrame.Value;
        if (string.IsNullOrWhiteSpace(frame)) return false;
        return await TryResolveInspectableFrameEntryAsync(frame) != null;
    }

    /// <summary>Run DeepQuery-scoped JS in an inspectable cross-origin frame or via same-origin preamble.</summary>
    internal async Task<string> RunDeepQueryJsAsync(string jsBody)
    {
        if (await IsActionFrameInspectableAsync())
        {
            var frame = _actionFrame.Value!;
            jsBody = StripFrameLocatorsInJsForInspectableChild(jsBody, frame);
            var js = "(function() {\n" + DeepQueryJs + "\n" + jsBody + "\n})()";
            var raw = await ExecuteJsInFrame(frame, js);
            ThrowIfFrameError(raw);
            if (string.IsNullOrEmpty(raw) || raw == "null") return "";
            var unwrapped = UnwrapJsStringResult(raw);
            return string.IsNullOrEmpty(unwrapped) ? raw : unwrapped;
        }

        var result = await RunJs(WrapWithDeepQuery(jsBody));
        ThrowIfFrameError(result);
        return result;
    }

    internal async Task<string> RunDomAutomationJsAsync(string fullScript)
    {
        if (await IsActionFrameInspectableAsync())
        {
            var frame = _actionFrame.Value!;
            fullScript = StripFrameLocatorsInJsForInspectableChild(fullScript, frame);
            var raw = await ExecuteJsInFrame(frame, fullScript);
            ThrowIfFrameError(raw);
            if (string.IsNullOrEmpty(raw) || raw == "null") return "";
            var unwrapped = UnwrapJsStringResult(raw);
            return string.IsNullOrEmpty(unwrapped) ? raw : unwrapped;
        }

        var result = await RunJs(fullScript);
        ThrowIfFrameError(result);
        return result;
    }

    /// <summary>Maps <see cref="RunScriptTarget"/> to <see cref="This"/> when the user ran the script from the context menu.</summary>
    private string ResolveRunScriptSelector(string selectorOrLocator)
    {
        if (selectorOrLocator == RunScriptTarget)
        {
            if (string.IsNullOrEmpty(This))
                throw new InvalidOperationException(
                    "Run Script context is empty. Right-click an element and choose Run Script, or pass an explicit selector.");
            return This!;
        }
        return selectorOrLocator;
    }

    private async Task<string> WaitForActionable(string selectorOrLocator, int timeoutMs,
        bool requireVisible = true, bool requireEnabled = false, bool requireHidden = false,
        bool checkObscured = false)
    {
        selectorOrLocator = ResolveRunScriptSelector(selectorOrLocator);
        selectorOrLocator = BeginFrameScope(selectorOrLocator);
        var finderExpr = BuildFinderExpression(selectorOrLocator);
        var inspectableFrame = await IsActionFrameInspectableAsync();
        var js = inspectableFrame
            ? BuildActionabilityJsInspectable(finderExpr, requireVisible, requireEnabled, requireHidden, checkObscured)
            : BuildActionabilityJs(finderExpr, requireVisible, requireEnabled, requireHidden, checkObscured);
        var elementDesc = selectorOrLocator.StartsWith("@")
            ? FormatLocatorDescription(selectorOrLocator)
            : $"'{selectorOrLocator}'";

        if (checkObscured || requireVisible)
            await TryScrollIntoView(finderExpr);

        if (timeoutMs <= 0)
        {
            var instantScrollAttempts = 0;
            while (instantScrollAttempts < 3)
            {
                var resultJson = await RunDomAutomationJsAsync(js);
                var (status, selector, detail) = ParseActionabilityResult(resultJson);
                if (status == "OK" && selector != null)
                    return await EncodeFrameSelectorAsync(selector);
                if (status is "OBSCURED" or "OFF_SCREEN" && instantScrollAttempts < 2)
                {
                    instantScrollAttempts++;
                    await TryScrollIntoView(finderExpr);
                    await Task.Delay(150, ScriptCancellation);
                    continue;
                }
                if (status == "OBSCURED")
                    throw new InvalidOperationException(FormatObscuredError(elementDesc, detail));
                if (status == "OFF_SCREEN")
                    throw new InvalidOperationException(FormatOffScreenError(elementDesc));
                break;
            }

            if (selectorOrLocator.StartsWith("@"))
                throw new InvalidOperationException($"Locator not matched: {FormatLocatorDescription(selectorOrLocator)}");
            return await EncodeFrameSelectorAsync(selectorOrLocator);
        }

        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        string lastStatus = "NOT_FOUND";
        string? lastObscuredBy = null;
        var scrollAttempts = 0;
        const int maxScrollAttempts = 3;

        while (DateTime.UtcNow < deadline)
        {
            var resultJson = await RunDomAutomationJsAsync(js);
            var (status, selector, detail) = ParseActionabilityResult(resultJson);
            if (status == "OK" && selector != null)
                return await EncodeFrameSelectorAsync(selector);
            lastStatus = status;
            if (detail != null)
                lastObscuredBy = detail;

            if (status is "OBSCURED" or "OFF_SCREEN" && scrollAttempts < maxScrollAttempts)
            {
                scrollAttempts++;
                await TryScrollIntoView(finderExpr);
                await Task.Delay(150, ScriptCancellation);
                continue;
            }

            if (status == "OBSCURED")
                throw new InvalidOperationException(FormatObscuredError(elementDesc, lastObscuredBy));

            if (status == "OFF_SCREEN")
                throw new InvalidOperationException(FormatOffScreenError(elementDesc));

            if (status == "HIDDEN" && requireVisible && scrollAttempts < maxScrollAttempts)
            {
                scrollAttempts++;
                await TryScrollIntoView(finderExpr);
                await Task.Delay(150, ScriptCancellation);
                continue;
            }

            await Task.Delay(100, ScriptCancellation);
        }

        var desc = elementDesc;
        var reason = lastStatus switch
        {
            "NOT_FOUND" => $"Element {desc} not found within {timeoutMs}ms",
            "HIDDEN" => $"Element {desc} not visible within {timeoutMs}ms",
            "NOT_HIDDEN" => $"Element {desc} not hidden within {timeoutMs}ms",
            "DISABLED" => $"Element {desc} disabled within {timeoutMs}ms",
            "OBSCURED" => FormatObscuredError(desc, lastObscuredBy),
            "OFF_SCREEN" => FormatOffScreenError(desc),
            _ => $"Element {desc} not actionable within {timeoutMs}ms: {lastStatus}"
        };
        throw new TimeoutException(reason);
    }

    private const string ScrollIntoViewHint =
        " Try POST /api/scroll with {\"ref\": N, \"scrollIntoView\": true} (or MCP browser_scroll with scrollIntoView).";

    private static string FormatObscuredError(string elementDesc, string? detail) =>
        $"Element {elementDesc} is obscured by '{detail ?? "another element"}'." + ScrollIntoViewHint;

    private static string FormatOffScreenError(string elementDesc) =>
        $"Element {elementDesc} is outside the viewport." + ScrollIntoViewHint;

    /// <summary>
    /// Attempt to scroll an element into view. Used by WaitForActionable when an element
    /// is found in the DOM but fails visibility checks (e.g. off-screen, below the fold).
    /// </summary>
    private async Task TryScrollIntoView(string finderExpr)
    {
        try
        {
            var scrollBody = "var el = " + finderExpr + @";
                if (!el) return 'NOT_FOUND';
                el.scrollIntoView({behavior:'instant',block:'center',inline:'center'});
                var p = el.parentElement;
                while (p) {
                  try {
                    if (p.scrollHeight > p.clientHeight + 4) {
                      var rect = el.getBoundingClientRect();
                      var prect = p.getBoundingClientRect();
                      if (rect.bottom > prect.bottom) p.scrollTop += (rect.bottom - prect.bottom + 8);
                      if (rect.top < prect.top) p.scrollTop -= (prect.top - rect.top + 8);
                    }
                  } catch(e) {}
                  p = p.parentElement;
                }
                return 'OK';";

            if (await IsActionFrameInspectableAsync())
            {
                var js = "(function() {\n" + DeepQueryJs + "\n" + DeepQueryAllJs + "\n" + LocatorHelpersJs + "\n" + scrollBody + "\n})()";
                await RunDomAutomationJsAsync(js);
            }
            else
            {
                var scrollJs = "(function() {\n" + BuildFramePreamble(_actionFrame.Value) + DeepQueryJs + "\n" + DeepQueryAllJs + "\n" + LocatorHelpersJs + "\n" +
                    scrollBody + "\n})()";
                await RunJs(scrollJs);
            }
        }
        catch { /* best-effort — if scroll fails, WaitForActionable continues polling */ }
    }

    private static bool IsSemanticLocator(string selectorOrLocator)
    {
        var (_, inner) = SplitFrameLocator(selectorOrLocator);
        return inner.StartsWith('@');
    }

    private static string BuildFinderExpression(string selectorOrLocator)
    {
        if (!selectorOrLocator.StartsWith("@"))
            return $"deepQuery({JsonEscape(selectorOrLocator)})";

        if (selectorOrLocator.StartsWith("@role:"))
        {
            var rest = selectorOrLocator[6..];
            var colonIdx = rest.IndexOf(':');
            var role = colonIdx >= 0 ? rest[..colonIdx] : rest;
            var name = colonIdx >= 0 && rest[(colonIdx + 1)..].Length > 0 ? rest[(colonIdx + 1)..] : null;
            return name != null
                ? $"findByRole({JsonEscape(role)}, {JsonEscape(name)})"
                : $"findByRole({JsonEscape(role)}, null)";
        }
        if (selectorOrLocator.StartsWith("@label:"))
            return $"findByLabel({JsonEscape(selectorOrLocator[7..])})";
        if (selectorOrLocator.StartsWith("@text:"))
            return $"findByText({JsonEscape(selectorOrLocator[6..])})";
        if (selectorOrLocator.StartsWith("@placeholder:"))
            return $"findByPlaceholder({JsonEscape(selectorOrLocator[13..])})";
        if (selectorOrLocator.StartsWith("@testid:"))
            return $"findByTestId({JsonEscape(selectorOrLocator[8..])})";
        if (selectorOrLocator.StartsWith("@value:"))
            return $"findByValue({JsonEscape(selectorOrLocator[7..])})";

        return $"deepQuery({JsonEscape(selectorOrLocator)})";
    }

    private const string ObscuredCheckJs = """
            function __trowserRectIntersectsViewport(r, vw, vh) {
                return r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw;
            }
            function __trowserObscuredBy(el) {
                var __doc = (typeof __trowserRoot !== 'undefined' && __trowserRoot) ? __trowserRoot : document;
                var __win = __doc.defaultView || window;
                var r = el.getBoundingClientRect();
                if (r.width <= 0 || r.height <= 0) return null;
                var vw = __win.innerWidth || __doc.documentElement.clientWidth || 0;
                var vh = __win.innerHeight || __doc.documentElement.clientHeight || 0;
                if (vw <= 0 || vh <= 0) return null;
                if (!__trowserRectIntersectsViewport(r, vw, vh)) return { offScreen: true };
                var left = Math.max(r.left, 0);
                var top = Math.max(r.top, 0);
                var right = Math.min(r.right, vw);
                var bottom = Math.min(r.bottom, vh);
                if (right <= left || bottom <= top) return { offScreen: true };
                var cx = (left + right) / 2;
                var cy = (top + bottom) / 2;
                var hit = __doc.elementFromPoint(cx, cy);
                if (!hit) return null;
                if (el === hit) return null;
                if (el.contains(hit)) return null;
                var anc = hit;
                while (anc) {
                    if (anc === el) return null;
                    anc = anc.parentElement;
                }
                var tag = hit.tagName ? hit.tagName.toLowerCase() : 'element';
                if (hit.id) return tag + '#' + hit.id;
                return tag;
            }
        """;

    private string BuildActionabilityJs(string finderExpr, bool checkVisible, bool checkEnabled,
        bool checkHidden = false, bool checkObscured = false)
    {
        var sb = new System.Text.StringBuilder(2048);
        sb.Append("(function() {\n");
        sb.Append(BuildFramePreamble(_actionFrame.Value));
        sb.Append(DeepQueryJs).Append('\n');
        sb.Append(DeepQueryAllJs).Append('\n');
        sb.Append(LocatorHelpersJs).Append('\n');
        if (checkObscured)
            sb.Append(ObscuredCheckJs).Append('\n');
        sb.Append("try{deepQueryAll('[data-trowser-loc]').forEach(function(e){e.removeAttribute('data-trowser-loc');});}catch(x){}\n");
        sb.Append("var el = ").Append(finderExpr).Append(";\n");
        sb.Append("if (!el) return JSON.stringify({s:'NOT_FOUND'});\n");
        if (checkVisible || checkHidden)
        {
            if (checkVisible)
                sb.Append(CheckboxLabelFallbackJs).Append('\n');
            sb.Append("""
            var cur = el;
            var __visHidden = false;
            while (cur) {
                if (cur === document.documentElement) break;
                if (cur.nodeType !== 1) break;
                try {
                    var st = window.getComputedStyle(cur);
                    if (st.display === 'none' || st.visibility === 'hidden')
                        { __visHidden = true; break; }
                } catch(e) { break; }
                if (cur.parentElement) cur = cur.parentElement;
                else {
                    var root = cur.getRootNode();
                    if (root instanceof ShadowRoot) cur = root.host;
                    else break;
                }
            }
            if (!__visHidden) {
                var rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) __visHidden = true;
            }
            if (checkHidden && !__visHidden) return JSON.stringify({s:'NOT_HIDDEN'});
            if (checkVisible && __visHidden) return JSON.stringify({s:'HIDDEN'});
            """.Replace("checkHidden", checkHidden ? "true" : "false").Replace("checkVisible", checkVisible ? "true" : "false"));
        }
        if (checkEnabled)
            sb.Append("if (el.disabled) return JSON.stringify({s:'DISABLED'});\n");
        if (checkObscured)
            sb.Append("""
                var __obs = __trowserObscuredBy(el);
                if (__obs) {
                    if (typeof __obs === 'object' && __obs.offScreen) return JSON.stringify({s:'OFF_SCREEN'});
                    return JSON.stringify({s:'OBSCURED', by: __obs});
                }
                """);
        sb.Append("var id = '_t_' + Math.random().toString(36).substr(2, 8);\n");
        sb.Append("el.setAttribute('data-trowser-loc', id);\n");
        sb.Append("return JSON.stringify({s:'OK', sel:'[data-trowser-loc=\"' + id + '\"]'});\n");
        sb.Append("})()");
        return sb.ToString();
    }

    private string BuildActionabilityJsInspectable(string finderExpr, bool checkVisible, bool checkEnabled,
        bool checkHidden = false, bool checkObscured = false)
    {
        var sb = new System.Text.StringBuilder(2048);
        sb.Append("(function() {\n");
        sb.Append(DeepQueryJs).Append('\n');
        sb.Append(DeepQueryAllJs).Append('\n');
        sb.Append(LocatorHelpersJs).Append('\n');
        if (checkObscured)
            sb.Append(ObscuredCheckJs).Append('\n');
        sb.Append("try{deepQueryAll('[data-trowser-loc]').forEach(function(e){e.removeAttribute('data-trowser-loc');});}catch(x){}\n");
        sb.Append("var el = ").Append(finderExpr).Append(";\n");
        sb.Append("if (!el) return JSON.stringify({s:'NOT_FOUND'});\n");
        if (checkVisible || checkHidden)
        {
            if (checkVisible)
                sb.Append(CheckboxLabelFallbackJs).Append('\n');
            sb.Append("""
            var cur = el;
            var __visHidden = false;
            while (cur) {
                if (cur === document.documentElement) break;
                if (cur.nodeType !== 1) break;
                try {
                    var st = window.getComputedStyle(cur);
                    if (st.display === 'none' || st.visibility === 'hidden')
                        { __visHidden = true; break; }
                } catch(e) { break; }
                if (cur.parentElement) cur = cur.parentElement;
                else {
                    var root = cur.getRootNode();
                    if (root instanceof ShadowRoot) cur = root.host;
                    else break;
                }
            }
            if (!__visHidden) {
                var rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) __visHidden = true;
            }
            if (checkHidden && !__visHidden) return JSON.stringify({s:'NOT_HIDDEN'});
            if (checkVisible && __visHidden) return JSON.stringify({s:'HIDDEN'});
            """.Replace("checkHidden", checkHidden ? "true" : "false").Replace("checkVisible", checkVisible ? "true" : "false"));
        }
        if (checkEnabled)
            sb.Append("if (el.disabled) return JSON.stringify({s:'DISABLED'});\n");
        if (checkObscured)
            sb.Append("""
                var __obs = __trowserObscuredBy(el);
                if (__obs) {
                    if (typeof __obs === 'object' && __obs.offScreen) return JSON.stringify({s:'OFF_SCREEN'});
                    return JSON.stringify({s:'OBSCURED', by: __obs});
                }
                """);
        sb.Append("var id = '_t_' + Math.random().toString(36).substr(2, 8);\n");
        sb.Append("el.setAttribute('data-trowser-loc', id);\n");
        sb.Append("return JSON.stringify({s:'OK', sel:'[data-trowser-loc=\"' + id + '\"]'});\n");
        sb.Append("})()");
        return sb.ToString();
    }

    /// <summary>Run the locator finder once (no polling). Returns resolved CSS selector if found, null if not.</summary>
    private async Task<string?> TryResolveLocatorOnce(string selectorOrLocator)
    {
        selectorOrLocator = ResolveRunScriptSelector(selectorOrLocator);
        selectorOrLocator = BeginFrameScope(selectorOrLocator);
        var finderExpr = BuildFinderExpression(selectorOrLocator);
        var inspectable = await IsActionFrameInspectableAsync();
        var js = inspectable
            ? BuildActionabilityJsInspectable(finderExpr, checkVisible: false, checkEnabled: false)
            : BuildActionabilityJs(finderExpr, checkVisible: false, checkEnabled: false);
        var resultJson = await RunDomAutomationJsAsync(js);
        var (status, selector, _) = ParseActionabilityResult(resultJson);
        return status == "OK" && selector != null ? selector : null;
    }

    private static (string status, string? selector, string? detail) ParseActionabilityResult(string json)
    {
        if (string.IsNullOrEmpty(json)) return ("NOT_FOUND", null, null);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var s = root.GetProperty("s").GetString() ?? "NOT_FOUND";
            string? sel = null;
            if (root.TryGetProperty("sel", out var selProp))
                sel = selProp.GetString();
            string? detail = null;
            if (root.TryGetProperty("by", out var byProp))
                detail = byProp.GetString();
            return (s, sel, detail);
        }
        catch
        {
            return ("NOT_FOUND", null, null);
        }
    }

    private static string FormatLocatorDescription(string locator)
    {
        if (locator.StartsWith("@role:"))
        {
            var rest = locator[6..];
            var ci = rest.IndexOf(':');
            if (ci >= 0 && rest[(ci + 1)..].Length > 0)
                return $"role={rest[..ci]} name=\"{rest[(ci + 1)..]}\"";
            return $"role={rest.TrimEnd(':')}";
        }
        if (locator.StartsWith("@label:")) return $"label=\"{locator[7..]}\"";
        if (locator.StartsWith("@text:")) return $"text=\"{locator[6..]}\"";
        if (locator.StartsWith("@placeholder:")) return $"placeholder=\"{locator[13..]}\"";
        if (locator.StartsWith("@testid:")) return $"testId=\"{locator[8..]}\"";
        return $"'{locator}'";
    }

    #region Easter Eggs

    /// <summary>
    /// Injects a Mandelbrot set visualization as a semi-transparent overlay on the current page.
    /// The overlay disappears on the next click, and also when the page navigates.
    /// Supports custom coordinates and zoom level.
    /// </summary>
    public async Task Mandelbrot(double centerX = -0.5, double centerY = 0.0, double zoom = 1.0, double opacity = 0.6, int maxIterations = 256)
    {
        if (zoom <= 0) zoom = 1.0;
        if (opacity < 0.05) opacity = 0.05;
        if (opacity > 1.0) opacity = 1.0;
        if (maxIterations < 32) maxIterations = 32;
        if (maxIterations > 4096) maxIterations = 4096;

        var js = MandelbrotJs(centerX, centerY, zoom, opacity, maxIterations);
        await RunJs(js);
    }

    private static string MandelbrotJs(double cx, double cy, double zoom, double opacity, int maxIter)
    {
        return $$"""
(function() {
  var old = document.getElementById('__trowser_mandelbrot');
  if (old) old.remove();
  if (window.__trowserMandelbrotDismiss) {
    window.removeEventListener('pointerdown', window.__trowserMandelbrotDismiss, true);
    window.__trowserMandelbrotDismiss = null;
  }

  var canvas = document.createElement('canvas');
  canvas.id = '__trowser_mandelbrot';
  canvas.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;pointer-events:none;opacity:{{opacity.ToString(System.Globalization.CultureInfo.InvariantCulture)}};';
  document.body.appendChild(canvas);

  var dpr = window.devicePixelRatio || 1;
  var W = Math.round(window.innerWidth * dpr);
  var H = Math.round(window.innerHeight * dpr);
  canvas.width = W;
  canvas.height = H;
  var ctx = canvas.getContext('2d');

  var MAX = {{maxIter}};
  var cx = {{cx.ToString(System.Globalization.CultureInfo.InvariantCulture)}};
  var cy = {{cy.ToString(System.Globalization.CultureInfo.InvariantCulture)}};
  var zm = {{zoom.ToString(System.Globalization.CultureInfo.InvariantCulture)}};
  var aspect = W / H;
  var rangeY = 2.4 / zm;
  var rangeX = rangeY * aspect;
  var xMin = cx - rangeX / 2, yMin = cy - rangeY / 2;

  var palette = new Array(MAX);
  for (var i = 0; i < MAX; i++) {
    var t = i / MAX;
    var r, g, b;
    if (t < 0.16) {
      var s = t / 0.16;
      r = Math.round(25 + 230 * s);
      g = Math.round(7 + 100 * s);
      b = Math.round(80 + 50 * s);
    } else if (t < 0.42) {
      var s = (t - 0.16) / 0.26;
      r = Math.round(255 - 30 * s);
      g = Math.round(107 + 148 * s);
      b = Math.round(130 - 130 * s);
    } else if (t < 0.6425) {
      var s = (t - 0.42) / 0.2225;
      r = Math.round(225 - 216 * s);
      g = Math.round(255 - 85 * s);
      b = Math.round(s * 205);
    } else if (t < 0.8575) {
      var s = (t - 0.6425) / 0.215;
      r = Math.round(9 + 25 * s);
      g = Math.round(170 - 163 * s);
      b = Math.round(205 + 50 * s);
    } else {
      var s = (t - 0.8575) / 0.1425;
      r = Math.round(34 - 9 * s);
      g = Math.round(7 + s * 0);
      b = Math.round(255 - 175 * s);
    }
    palette[i] = [r, g, b];
  }

  var imgData = ctx.createImageData(W, H);
  var data = imgData.data;

  for (var py = 0; py < H; py++) {
    var y0 = yMin + (py / H) * rangeY;
    for (var px = 0; px < W; px++) {
      var x0 = xMin + (px / W) * rangeX;
      var x = 0, y = 0, x2 = 0, y2 = 0, iter = 0;
      while (x2 + y2 <= 4 && iter < MAX) {
        y = 2 * x * y + y0;
        x = x2 - y2 + x0;
        x2 = x * x;
        y2 = y * y;
        iter++;
      }
      var idx = (py * W + px) * 4;
      if (iter === MAX) {
        data[idx] = 0; data[idx+1] = 0; data[idx+2] = 0; data[idx+3] = 255;
      } else {
        // log2(log2(|z|)); the previous log2(log2(|z|^2)) form goes negative
        // on the first escape of wide viewports and then palette[ci] is undefined.
        var mag = Math.sqrt(x2 + y2);
        var smooth = iter + 1 - Math.log2(Math.log2(mag));
        if (!isFinite(smooth)) smooth = iter;
        var ci = smooth % MAX;
        if (ci < 0) ci += MAX;
        var ci0 = Math.floor(ci);
        if (!(ci0 >= 0 && ci0 < MAX)) ci0 = 0;
        var ci1 = (ci0 + 1) % MAX;
        var frac = ci - ci0;
        if (!isFinite(frac) || frac < 0) frac = 0;
        var c0 = palette[ci0], c1 = palette[ci1];
        data[idx]   = Math.round(c0[0] + (c1[0] - c0[0]) * frac);
        data[idx+1] = Math.round(c0[1] + (c1[1] - c0[1]) * frac);
        data[idx+2] = Math.round(c0[2] + (c1[2] - c0[2]) * frac);
        data[idx+3] = 255;
      }
    }
  }
  ctx.putImageData(imgData, 0, 0);
  window.__trowserMandelbrotDismiss = function() {
    var el = document.getElementById('__trowser_mandelbrot');
    if (el) el.remove();
    window.removeEventListener('pointerdown', window.__trowserMandelbrotDismiss, true);
    window.__trowserMandelbrotDismiss = null;
  };
  window.addEventListener('pointerdown', window.__trowserMandelbrotDismiss, true);
})()
""";
    }

    #endregion

    #region Semantic Locators

    public static string ByRole(string role, string? name = null)
        => name != null ? $"@role:{role}:{name}" : $"@role:{role}:";

    public static string ByLabel(string text) => $"@label:{text}";
    public static string ByText(string text) => $"@text:{text}";
    public static string ByPlaceholder(string text) => $"@placeholder:{text}";
    public static string ByTestId(string testId) => $"@testid:{testId}";

    #endregion

    private const int RunJsTimeoutMs = 30_000;

    private async Task<string> RunJs(string script)
    {
        await CheckScriptExecutionAsync();
        var webView = ActiveTab.WebView;
        // Prefer ExecuteScriptWithResultAsync + TryGetResultAsString so Unicode (emoji, ©, etc.)
        // is returned as a decoded .NET string instead of a JSON-encoded blob that some
        // bridges/clients historically mangled into "?".
        var op = await webView.Dispatcher.InvokeAsync(async () =>
            await ExecuteScriptForResultAsync(webView.CoreWebView2, script));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation, OperationCancellation);
        timeoutCts.CancelAfter(RunJsTimeoutMs);
        try
        {
            return await op.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            if (ScriptCancellation.IsCancellationRequested || OperationCancellation.IsCancellationRequested)
                throw;

            throw new TimeoutException(
                $"JavaScript execution timed out after {RunJsTimeoutMs / 1000} seconds. " +
                "The script may have triggered a navigation (e.g. location.reload()) that destroyed the execution context.");
        }
    }

    private static async Task<string> ExecuteScriptForResultAsync(CoreWebView2 core, string script)
    {
        try
        {
            var scriptResult = await core.ExecuteScriptWithResultAsync(script);
            if (scriptResult.Succeeded)
            {
                // value != 0 means the JS result was a string (decoded Unicode, no JSON quoting).
                scriptResult.TryGetResultAsString(out var asString, out var isString);
                if (isString != 0)
                    return asString ?? "";

                // Objects/arrays/numbers/bools: JSON text (UTF-16 safe).
                var asJson = scriptResult.ResultAsJson ?? "null";
                if (asJson == "null" || asJson == "undefined")
                    return "";
                return asJson;
            }

            var jsEx = scriptResult.Exception;
            if (jsEx != null && !string.IsNullOrWhiteSpace(jsEx.Message))
                throw new InvalidOperationException($"JavaScript error: {jsEx.Message}");
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Older WebView2 runtimes may lack ExecuteScriptWithResultAsync — fall back.
            TrowserLog.Warn($"ExecuteScriptWithResultAsync unavailable ({ex.GetType().Name}); falling back to ExecuteScriptAsync.");
        }

        var json = await core.ExecuteScriptAsync(script);
        return UnwrapJsonString(json);
    }

    /// <summary>
    /// Run JavaScript that returns a Promise. Uses postMessage callback since
    /// WebView2's ExecuteScriptAsync doesn't resolve Promises in all versions.
    /// </summary>
    private async Task<string> RunJsAsync(string asyncExpressionScript, int timeoutMs = 30000)
    {
        await CheckScriptExecutionAsync();
        var startedUtc = DateTime.UtcNow;
        var id = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<string>();
        _asyncCallbacks[id] = tcs;

        var wrapper = "(function(){var _id=" + JsonEscape(id) + ";" +
            "Promise.resolve().then(function(){return " + asyncExpressionScript + ";})" +
            ".then(function(r){" +
            "  window.chrome.webview.postMessage({type:'__trowser_async',id:_id,result:" +
            "    typeof r==='string'?r:JSON.stringify(r)});" +
            "},function(e){" +
            "  window.chrome.webview.postMessage({type:'__trowser_async',id:_id,error:e.message||String(e)});" +
            "});})()";

        var webView = ActiveTab.WebView;
        try
        {
            await webView.Dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await webView.CoreWebView2.ExecuteScriptAsync(wrapper);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(new InvalidOperationException(FormatExecuteScriptFailure(ex)));
                }
            });
        }
        catch (Exception ex)
        {
            tcs.TrySetException(new InvalidOperationException(FormatExecuteScriptFailure(ex)));
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ScriptCancellation);
        cts.CancelAfter(timeoutMs);
        try
        {
            cts.Token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            if (ScriptCancellation.IsCancellationRequested)
                throw;

            throw new TimeoutException(FormatJsAsyncTimeout(timeoutMs, startedUtc, asyncExpressionScript));
        }
        finally
        {
            _asyncCallbacks.TryRemove(id, out _);
        }
    }

    private static string FormatExecuteScriptFailure(Exception ex)
    {
        var message = ex.Message;
        return string.IsNullOrWhiteSpace(message)
            ? "Script failed to execute (WebView2 rejected the script)."
            : message;
    }

    /// <summary>
    /// Called by MainWindow when a __trowser_async postMessage is received.
    /// </summary>
    public void HandleAsyncCallback(string id, string? result, string? error)
    {
        if (_asyncCallbacks.TryRemove(id, out var tcs))
        {
            if (error != null)
                tcs.TrySetException(new InvalidOperationException(error));
            else
                tcs.TrySetResult(result ?? "");
        }
    }

    private static string UnwrapJsonString(string jsonResult)
        => WebViewScriptResult.UnwrapJsonString(jsonResult);

    private static string JsonEscape(string value)
    {
        return JsonSerializer.Serialize(value);
    }

    private static string EscapeForJs(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("'", "\\'")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r");
    }

    #endregion

}
