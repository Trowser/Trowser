using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Microsoft.Win32;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Peers;
using Trowser.Recording;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;
using Trowser.Security.Vpx;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region LLM API Server

    private bool ShouldStartApiOnLaunch()
    {
        if (App.CliMode != null) return false;
        if (App.Api.ApiEnabledFromCommandLine) return App.Api.Enabled;
        return _apiUserWantsServerRunning;
    }

    private void SaveApiUserSettings()
    {
        new ApiUserSettings
        {
            RestApiKeyRequired = _apiKeyRequired,
            KeepApiKeyForNextSession = _keepApiKeyForNextSession,
            RestApiKey = _keepApiKeyForNextSession ? _apiKey : "",
            ApiServerEnabled = _apiUserWantsServerRunning,
            NavigationScope = _navigationGuard.Scope,
            SafeMode = _safeMode,
            ApiPort = _apiPort,
            ExternalMcpMode = _externalMcpMode,
            AgentTabPolicy = _automationContext?.AgentTabPolicy ?? _agentTabPolicy
        }.Save();
    }

    /// <summary>
    /// Copy the live Shadow / Power Mode / Red Team Whisper configuration and test-data
    /// preferences into <paramref name="target"/> so they persist in settings.json. These features
    /// aren't part of the LLM Settings dialog, so <see cref="LlmSettingsDialog.GetLlmSettings"/>
    /// doesn't carry them and they must be re-applied before saving.
    /// </summary>
    private void CaptureFeatureSettings(LlmSettings target)
    {
        target.Shadow = new Security.ShadowConfig
        {
            Enabled = _securityShadow.Config.Enabled,
            Audits = new HashSet<string>(_securityShadow.Config.Audits),
            Scope = _securityShadow.Config.Scope,
            Suggestions = _securityShadow.Config.Suggestions,
            Deduplication = _securityShadow.Config.Deduplication,
            NotifyGui = _securityShadow.Config.NotifyGui,
            MaxFindings = _securityShadow.Config.MaxFindings,
            FactoryGeneration = _securityShadow.Config.FactoryGeneration,
            LawsEnabled = _securityShadow.Config.LawsEnabled,
            DisabledLaws = new HashSet<string>(_securityShadow.Config.DisabledLaws),
            ActiveLawSources = _securityShadow.Config.ActiveLawSources == null
                ? null
                : new HashSet<string>(_securityShadow.Config.ActiveLawSources, StringComparer.OrdinalIgnoreCase),
            LightQuicktests = new HashSet<string>(_securityShadow.Config.LightQuicktests),
            HeavyQuicktests = new HashSet<string>(_securityShadow.Config.HeavyQuicktests),
            RunHeavyAfterQuicktest = _securityShadow.Config.RunHeavyAfterQuicktest,
            SerendipityTimerEnabled = _securityShadow.Config.SerendipityTimerEnabled,
            SerendipityIntervalSeconds = _securityShadow.Config.SerendipityIntervalSeconds,
            SerendipityRandomize = _securityShadow.Config.SerendipityRandomize,
            LightLawBudgetMs = _securityShadow.Config.LightLawBudgetMs,
            LawsMiningEnabled = _securityShadow.Config.LawsMiningEnabled
        };
        target.PowerMode = new Security.PowerModeConfig
        {
            Enabled = _powerMode.Config.Enabled,
            ShowOverlays = _powerMode.Config.ShowOverlays
        };
        target.Whisper = new Security.WhisperConfig
        {
            Enabled = _redTeamWhisper.Config.Enabled,
            NotifyGui = _redTeamWhisper.Config.NotifyGui
        };
        target.TestDataUseOnline = _testDataService.UseOnline;
        target.TestDataAsciiOnly = _testDataService.AsciiOnly;
        target.TestDataOnlineUrl = _testDataService.OnlineUrl;
        target.TestDataActiveKind = _testDataService.ActiveKind;
    }

    /// <summary>
    /// Keep the status bar and settings.json in sync when Shadow / Power / Whisper are toggled
    /// from any entry point (Settings, findings dialog, REST, MCP).
    /// </summary>
    private void OnFeatureConfigChanged()
    {
        void Apply()
        {
            UpdateShadowStatusDisplay();
            CaptureFeatureSettings(_llmSettings);
            _llmSettings.Save();
        }

        if (Dispatcher.CheckAccess())
            Apply();
        else
            Dispatcher.InvokeAsync(Apply);
    }

    private void StartApiServer()
    {
        if (!ShouldStartApiOnLaunch() || _automationContext == null || _scriptEngine == null)
        {
            UpdateApiStatusDisplay(false);
            return;
        }
        ToggleApiOn();
    }

    private void ToggleApiOn()
    {
        if (_automationContext == null || _scriptEngine == null) return;

        try
        {
            var requestedPort = _apiPort;
            _apiServer = new TrowserApiServer(
                _automationContext, _scriptEngine, Dispatcher, _playbookRegistry, _identityStore, _chainCatalog,
                _peerRegistry, _apiPort, _apiKey, _safeMode, _externalMcpMode)
            {
                ApiKeyRequired = _apiKeyRequired, SessionLogger = _sessionLogger,
                PointerStore = _pointerStore,
                DecisionStore = _decisionStore,
                SessionMemory = _sessionMemory,
                TestDataService = _testDataService, InspirationService = _inspirationService,
                CoverageService = _coverageService,
                SessionName = _sessionName,
                MirrorController = _mirrorController
            };
            _apiServer.OnShowMessage = (text, level, durationMs) =>
            {
                Dispatcher.InvokeAsync(() => ShowApiMessage(text, level, durationMs));
            };
            _apiServer.GuiRecordStart = ApiStartRecording;
            _apiServer.GuiRecordStatus = ApiRecordingStatus;
            _apiServer.GuiRecordStopAsync = ApiStopRecordingAsync;
            _apiServer.Start();
            _apiPort = _apiServer.BoundPort;
            SyncChatMcpHandlerHost();
            UpdateApiStatusDisplay(true);
            StatusText.Text = $"API server started on port {_apiPort}";
            if (_apiPort != requestedPort)
            {
                var portNotice =
                    $"Port {requestedPort} was in use; REST API is running on port {_apiPort} instead.";
                _sessionStartupNotice = string.IsNullOrEmpty(_sessionStartupNotice)
                    ? portNotice
                    : $"{_sessionStartupNotice}\n\n{portNotice}";
            }
        }
        catch (Exception ex)
        {
            ApiStatusText.Text = "API: failed";
            ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            ((Border)ApiStatusText.Parent).ToolTip = $"Failed to start API: {ex.Message}";
            StatusText.Text = $"API server failed: {ex.Message}";
        }
    }

    private void ToggleApiOff()
    {
        _apiServer?.Dispose();
        _apiServer = null;
        SyncChatMcpHandlerHost();
        UpdateApiStatusDisplay(false);
        StatusText.Text = "API server stopped";
    }

    private void UpdateApiStatusDisplay(bool running)
    {
        if (running)
        {
            var safeBadge = _safeMode ? " \U0001F6E1" : "";
            ApiStatusText.Text = $"API: :{_apiPort}{safeBadge} \u25A0";
            ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4EC9B0"));

            var tooltip = $"REST API running at http://localhost:{_apiPort}\n"
                        + "API key available in Settings\n"
                        + $"Safe mode: {(_safeMode ? "ON" : "off")}\n\n"
                        + "Click to stop";
            ((Border)ApiStatusText.Parent).ToolTip = tooltip;
        }
        else
        {
            ApiStatusText.Text = "API: off \u25B6";
            ApiStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888888"));
            ((Border)ApiStatusText.Parent).ToolTip = "Click to start the REST API server";
        }
    }

    private void UpdateScopeDisplay()
    {
        var scope = _navigationGuard.Scope;
        var displayScope = scope.Length > 50 ? scope[..47] + "..." : scope;
        ScopeStatusText.Text = _navigationGuard.IsRestricted
            ? $"\U0001F512 Scope: {displayScope}"
            : $"\U0001F513 Scope: {displayScope}";
        ScopeStatusText.Foreground = _navigationGuard.IsRestricted
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCA700"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCDDFF"));
    }

    private void ApiStatusToggle_Click(object sender, MouseButtonEventArgs e)
    {
        if (_apiServer?.IsRunning == true)
        {
            ToggleApiOff();
            _apiUserWantsServerRunning = false;
        }
        else
        {
            _apiUserWantsServerRunning = true;
            ToggleApiOn();
        }
        SaveApiUserSettings();
    }

    private void ScopeStatus_Click(object sender, MouseButtonEventArgs e)
    {
        OpenSettings_Click(sender, new RoutedEventArgs());
    }

    private NetworkInterceptDialog? _interceptDialog;
    private RequestEditorDialog? _requestEditorDialog;
    private ShadowFindingsDialog? _shadowFindingsDialog;
    private EndpointProbe.EndpointProbeDialog? _endpointProbeDialog;
    private PeerSessionsDialog? _peerSessionsDialog;
    private RaceLab.RaceLabDialog? _raceLabDialog;

    private void ShowBreakpointHitDialog(PendingRequest pending)
    {
        var dialog = new BreakpointHitDialog(pending, this);
        dialog.Show();
    }

    /// <summary>Open the breakpoint inspector for a pending request (callable from NetworkInterceptDialog).</summary>
    internal void InspectPendingRequest(PendingRequest pending)
    {
        ShowBreakpointHitDialog(pending);
    }

    internal void ApplyUserAgentOverridesToAllTabs()
    {
        if (_automationContext == null) return;
        var ua = HeaderOverrideSettings.UserAgentOverride;
        foreach (var tab in _automationContext.GetBrowserTabs())
        {
            var settings = tab.WebView.CoreWebView2?.Settings;
            if (settings == null) continue;
            tab.BaselineUserAgent ??= settings.UserAgent;
            settings.UserAgent = ua ?? tab.BaselineUserAgent;
        }
    }

    private void InterceptStatus_Click(object sender, MouseButtonEventArgs e)
    {
        if (_automationContext == null) return;

        if (_interceptDialog != null)
        {
            _interceptDialog.Activate();
            return;
        }

        var dlg = new NetworkInterceptDialog(_automationContext, this);
        _interceptDialog = dlg;
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_interceptDialog, dlg))
                _interceptDialog = null;
        };
        dlg.InterceptStateChanged += () =>
        {
            UpdateInterceptStatusDisplay();
            if (_automationContext?.ActiveTab != null)
                InterceptSettings.SaveFrom(_automationContext.ActiveTab);
        };
        dlg.Show();
    }

    private void EndpointsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_automationContext == null) return;

        if (_endpointProbeDialog != null)
        {
            _endpointProbeDialog.Activate();
            return;
        }

        var dlg = new EndpointProbe.EndpointProbeDialog(_automationContext, _playbookRegistry, this);
        _endpointProbeDialog = dlg;
        dlg.ProbeRunStarting += () =>
        {
            IsScriptPanelVisible = true;
            ClearOutput();
            StatusText.Text = "Running endpoint probes...";
        };
        dlg.ProbeRunFinished += status =>
        {
            StatusText.Text = status;
        };
        dlg.OpenInRequestEditorRequested += item => OpenRequestEditor(item);
        dlg.SendToChatRequested += SendEndpointToChat;
        dlg.TestBolaPeerRequested += () => OpenPeerSessionsForBola(dlg);
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_endpointProbeDialog, dlg))
                _endpointProbeDialog = null;
        };
        dlg.Show();
    }

    private void PeerSessionsMenu_Click(object sender, RoutedEventArgs e)
    {
        OpenPeerSessionsDialog(null);
    }

    private void RaceLabMenu_Click(object sender, RoutedEventArgs e)
    {
        OpenRaceLabDialog();
    }

    private void OpenRaceLabDialog()
    {
        if (_automationContext == null) return;

        if (_raceLabDialog != null)
        {
            _raceLabDialog.ManagePeersRequested = () => OpenPeerSessionsDialog(null);
            _raceLabDialog.Activate();
            return;
        }

        var dlg = new RaceLab.RaceLabDialog(_automationContext, _apiServer?.Peers, this);
        _raceLabDialog = dlg;
        dlg.ManagePeersRequested = () => OpenPeerSessionsDialog(null);
        dlg.AskAiRequested = prompt =>
        {
            IsChatPanelVisible = true;
            ChatPanelControl.PrefillInput(prompt);
        };
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_raceLabDialog, dlg))
                _raceLabDialog = null;
        };
        dlg.Show();
    }

    private void AuthzShadowMenu_Click(object sender, RoutedEventArgs e)
    {
        if (_liveAuthzShadow == null) return;

        if (_authzShadowDialog != null)
        {
            _authzShadowDialog.Activate();
            return;
        }

        var dlg = new Security.Authz.AuthzShadowDialog(_liveAuthzShadow, this, _automationContext);
        _authzShadowDialog = dlg;
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_authzShadowDialog, dlg))
                _authzShadowDialog = null;
        };
        dlg.Show();
    }

    private void OpenPeerSessionsForBola(EndpointProbe.EndpointProbeDialog probeDialog)
    {
        var endpoints = probeDialog.GetSelectedEndpoints();
        if (endpoints.Count == 0)
        {
            MessageBox.Show("Select at least one endpoint to test.", "Endpoint Probe",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _bolaEndpointSnapshot = endpoints.Select(e => e.Clone()).ToList();
        _bolaUseCapturedHeadersBody = probeDialog.UseCapturedHeadersBody;
        OpenPeerSessionsDialog(probeDialog);
    }

    private void OpenPeerSessionsDialog(EndpointProbe.EndpointProbeDialog? probeDialog)
    {
        if (_automationContext == null || _peerSessionManager == null) return;

        _peerSessionManager.NavigationScope = _navigationGuard.Scope;

        if (_peerSessionsDialog != null)
        {
            if (probeDialog != null)
            {
                _bolaEndpointSnapshot = probeDialog.GetSelectedEndpoints().Select(e => e.Clone()).ToList();
                _bolaUseCapturedHeadersBody = probeDialog.UseCapturedHeadersBody;
                var count = _bolaEndpointSnapshot.Count;
                _peerSessionsDialog.SetBolaContext(count, _bolaUseCapturedHeadersBody);
                _peerSessionsDialog.TestBolaRequested = async () => await RunBolaTestFromGuiAsync();
            }
            WireMirrorCallbacks(_peerSessionsDialog);
            _peerSessionsDialog.SetMirrorActive(_mirrorController?.IsActive == true);
            _peerSessionsDialog.Activate();
            return;
        }

        var dlg = new PeerSessionsDialog(_peerSessionManager, this);
        _peerSessionsDialog = dlg;
        WireMirrorCallbacks(dlg);
        dlg.SetMirrorActive(_mirrorController?.IsActive == true);

        if (probeDialog != null)
        {
            _bolaEndpointSnapshot = probeDialog.GetSelectedEndpoints().Select(e => e.Clone()).ToList();
            _bolaUseCapturedHeadersBody = probeDialog.UseCapturedHeadersBody;
            var count = _bolaEndpointSnapshot.Count;
            dlg.SetBolaContext(count, _bolaUseCapturedHeadersBody);
            dlg.TestBolaRequested += async () => await RunBolaTestFromGuiAsync();
        }

        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_peerSessionsDialog, dlg))
                _peerSessionsDialog = null;
        };
        dlg.Show();
    }

    private void WireMirrorCallbacks(PeerSessionsDialog dlg)
    {
        dlg.MirrorToggleRequested = async wantOn =>
        {
            if (_mirrorController == null) return false;

            if (!wantOn)
            {
                _mirrorController.Stop();
                UpdateMirrorStatusDisplay();
                return true;
            }

            // Ensure the recorder capture script is injected so GUI actions are mirrored.
            var activeTab = _automationContext?.ActiveTab;
            if (activeTab != null)
                await InjectRecordingScriptAsync(activeTab);

            // Read the WebView2 source here, on the UI thread — MirrorController's
            // continuations run on the thread pool and cannot touch the COM object.
            var driverUrl = _automationContext?.ActiveTab?.WebView?.CoreWebView2?.Source;

            var result = await _mirrorController.StartAsync(driverUrl);
            UpdateMirrorStatusDisplay();
            if (!result.Success)
            {
                MessageBox.Show(
                    result.Error ?? "Failed to start Mirror Mode.",
                    "Mirror Mode",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return false;
            }

            if (!string.IsNullOrEmpty(result.Warning))
                StatusText.Text = result.Warning;

            return true;
        };

        dlg.MirrorStatusProvider = () =>
        {
            if (_mirrorController == null || !_mirrorController.IsActive)
                return ([], null, new Dictionary<string, string>());

            var peers = _mirrorController.ActivePeers.Select(p => p.Name).ToList();
            var errors = _mirrorController.LastErrors.ToDictionary(
                kv => kv.Key,
                kv => $"({kv.Value.Count}) {kv.Value.LastMessage}",
                StringComparer.OrdinalIgnoreCase);
            return (peers, _mirrorController.LastWarning, errors);
        };
    }

    private void UpdateMirrorStatusDisplay()
    {
        _peerSessionsDialog?.SetMirrorActive(_mirrorController?.IsActive == true);
    }

    private async Task RunBolaTestFromGuiAsync()
    {
        if (_automationContext == null || _peerSessionManager == null) return;

        var endpoints = _bolaEndpointSnapshot;
        if (endpoints == null || endpoints.Count == 0)
        {
            MessageBox.Show("No endpoints selected for BOLA test.", "BOLA test",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var peerNames = _peerSessionManager.GetPeersForTests();
        if (peerNames.Count == 0)
        {
            MessageBox.Show("No alive peers marked for tests.", "BOLA test",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _peerSessionsDialog?.Close();
        _endpointProbeDialog?.Close();

        IsScriptPanelVisible = true;
        ClearOutput();
        StatusText.Text = "Running BOLA / authz comparison...";

        try
        {
            var authzEndpoints = AuthzComparisonService.FromProbeItems(endpoints, _bolaUseCapturedHeadersBody);
            var options = new AuthzComparisonOptions
            {
                IncludeBodyOnMismatch = true,
                EnsureOrigin = false
            };

            _automationContext.Log(
                $"BOLA test: {authzEndpoints.Count} endpoint(s) × {peerNames.Count} peer(s)" +
                (_bolaUseCapturedHeadersBody ? " (captured headers/body)" : " (URL + method only)"),
                "#888888");

            foreach (var ep in authzEndpoints)
            {
                var bodyNote = ep.Body != null ? $" body={ep.Body.Length} chars" : "";
                var hdrNote = ep.Headers != null ? $" headers={ep.Headers.Count}" : "";
                _automationContext.Log($"  → {ep.Method} {ep.Url}{hdrNote}{bodyNote}", "#858585");
                if (ep.Body is { Length: > 0 and <= 300 })
                    _automationContext.Log($"    body: {ep.Body}", "#666666");
            }

            var results = await AuthzComparisonService.RunAsync(
                _automationContext,
                _peerRegistry,
                peerNames,
                authzEndpoints,
                options);

            BolaResultLogger.LogResults(_automationContext, results);

            var bolaCount = results.Sum(r => r.Summary.BolaSuspected);
            StatusText.Text = bolaCount > 0
                ? $"BOLA test finished — {bolaCount} BOLA_SUSPECTED finding(s)"
                : "BOLA test finished";
            _bolaEndpointSnapshot = null;
        }
        catch (Exception ex)
        {
            _automationContext.Log($"BOLA test failed: {ex.Message}", "#F44747");
            StatusText.Text = $"BOLA test failed: {ex.Message}";
            _bolaEndpointSnapshot = null;
        }
    }

    private void RequestEditorButton_Click(object sender, RoutedEventArgs e)
    {
        OpenRequestEditor(null);
    }

    /// <summary>
    /// Opens (or activates) the HTTP Request Editor. When <paramref name="preset"/> is supplied,
    /// the editor is populated with that captured request, retaining all headers (auth included).
    /// </summary>
    private void OpenRequestEditor(EndpointProbe.EndpointProbeItem? preset)
    {
        if (_automationContext == null) return;

        if (_requestEditorDialog != null)
        {
            _requestEditorDialog.Activate();
        }
        else
        {
            var defaultUrl = AddressBar.Text;
            var dlg = new RequestEditorDialog(_automationContext, this, defaultUrl);
            _requestEditorDialog = dlg;
            dlg.Closed += (_, _) =>
            {
                if (ReferenceEquals(_requestEditorDialog, dlg))
                    _requestEditorDialog = null;
            };
            dlg.Show();
        }

        if (preset != null)
            _requestEditorDialog.LoadCapturedRequest(preset.Method, preset.Url, preset.RequestHeaders, preset.RequestBody);
    }

    /// <summary>
    /// Reveals the AI Assistant chat and pastes the captured request into its input box (without
    /// sending), so the user can add a question and review before submitting it to the LLM.
    /// </summary>
    private void SendEndpointToChat(EndpointProbe.EndpointProbeItem item)
    {
        IsChatPanelVisible = true;
        var prompt =
            "I captured this HTTP request while testing a web service. Help me analyze and test it:\n\n" +
            "```http\n" + item.ToHttpText() + "\n```";
        ChatPanelControl.PrefillInput(prompt);
    }

    /// <summary>
    /// Reveal the AI Assistant and paste a Shadow finding, leaving the caret
    /// after <c>Tester notes:</c> so the tester can add context before sending.
    /// </summary>
    private void SendShadowFindingToChat(Security.ShadowFinding finding)
    {
        IsChatPanelVisible = true;
        var sb = new StringBuilder();
        sb.AppendLine("Investigate this Shadow finding and its importance.");
        sb.AppendLine();
        sb.AppendLine($"Title: {finding.Title}");
        sb.AppendLine($"Severity: {finding.Severity}");
        sb.AppendLine($"Audit: {finding.Audit}");
        if (!string.IsNullOrWhiteSpace(finding.Url))
            sb.AppendLine($"URL: {finding.Url}");
        if (!string.IsNullOrWhiteSpace(finding.Description))
            sb.AppendLine($"Description: {finding.Description}");
        if (!string.IsNullOrWhiteSpace(finding.Recommendation))
            sb.AppendLine($"Recommendation: {finding.Recommendation}");
        sb.AppendLine($"Occurrences: {finding.Occurrences}");
        if (finding.Occurrences > 1 && finding.FormatSeenOnDomains() is { } domains)
            sb.AppendLine("Domains: " + domains);
        ChatPanelControl.PrefillWithTesterNotes(sb.ToString());
    }

    /// <summary>
    /// Reveals the AI Assistant chat and pastes element metadata into its input box (without
    /// sending), so the user can review and submit a focused testing request to the LLM.
    /// </summary>
    private async Task SendElementToChatAsync(ContextMenuElementInfo element)
    {
        if (_automationContext == null) return;

        await _automationContext.GetInteractiveElements();
        int? refNum = null;
        if (!string.IsNullOrWhiteSpace(element.Selector))
            refNum = await _automationContext.FindRefForSelectorAsync(element.Selector);

        var url = await _automationContext.GetCurrentUrl();
        var title = _automationContext.ActiveTab.Title;
        var refGeneration = _automationContext.RefGeneration;

        var sb = new StringBuilder();
        sb.AppendLine("This element is of great interest. Help me analyze and test it:");
        sb.AppendLine();
        if (!string.IsNullOrWhiteSpace(url) || !string.IsNullOrWhiteSpace(title))
        {
            sb.Append("Page: ");
            if (!string.IsNullOrWhiteSpace(url))
                sb.Append(url);
            if (!string.IsNullOrWhiteSpace(title))
                sb.Append(string.IsNullOrWhiteSpace(url) ? title : $" ({title})");
            sb.AppendLine();
        }
        sb.AppendLine($"refGeneration: {refGeneration}");
        sb.AppendLine();
        sb.AppendLine("Element:");
        if (refNum.HasValue)
            sb.AppendLine($"- ref: {refNum.Value} (preferred for browser_click, browser_type, etc.)");
        if (!string.IsNullOrWhiteSpace(element.Selector))
            sb.AppendLine($"- selector: {element.Selector}");
        if (!string.IsNullOrWhiteSpace(element.Tag))
            sb.AppendLine($"- tag: {element.Tag}");
        if (!string.IsNullOrWhiteSpace(element.Role))
            sb.AppendLine($"- role: {element.Role}");
        if (!string.IsNullOrWhiteSpace(element.Label))
            sb.AppendLine($"- label: {element.Label}");
        if (!string.IsNullOrWhiteSpace(element.Text))
            sb.AppendLine($"- text: {element.Text}");
        if (!string.IsNullOrWhiteSpace(element.InputType))
            sb.AppendLine($"- inputType: {element.InputType}");
        if (!string.IsNullOrWhiteSpace(element.Placeholder))
            sb.AppendLine($"- placeholder: {element.Placeholder}");
        if (!string.IsNullOrWhiteSpace(element.TestId))
            sb.AppendLine($"- testId: {element.TestId}");
        if (!string.IsNullOrWhiteSpace(element.Href))
            sb.AppendLine($"- href: {element.Href}");

        sb.AppendLine();
        if (refNum.HasValue)
            sb.Append($"Target this element with ref: {refNum.Value}");
        else if (!string.IsNullOrWhiteSpace(element.Selector))
            sb.Append($"Target this element with selector: {element.Selector}");
        else if (!string.IsNullOrWhiteSpace(element.Role) && !string.IsNullOrWhiteSpace(element.Label))
            sb.Append($"Target with role \"{element.Role}\" and name \"{element.Label}\"");
        else if (!string.IsNullOrWhiteSpace(element.Text))
            sb.Append($"Target with byText: \"{element.Text}\"");
        else
            sb.Append("Call browser_snapshot to locate this element on the page");

        sb.Append(". Call browser_snapshot first if refs may be stale.");

        // Consolidation (P1): Send to Chat also drops a human pointer so the element lands in the
        // shared pointer store and can be re-rendered / handed off, not just pasted into chat.
        Pointers.Pointer? pointer = null;
        try
        {
            pointer = await CreateHumanPointerFromElementAsync(
                _automationContext, element, Pointers.PointerKinds.Element, caption: null, knownRef: refNum);
        }
        catch (Exception ex) { TrowserLog.Warn($"Send-to-chat pointer failed: {ex.Message}"); }

        if (pointer != null)
            sb.Append($"\n\n(Pointer {pointer.Id} recorded for this element — see GET /api/pointers.)");

        IsChatPanelVisible = true;
        ChatPanelControl.PrefillInput(sb.ToString());
    }

    private void UpdateInterceptStatusDisplay()
    {
        if (_automationContext == null) return;

        var mockCount = _automationContext.GetMockRules().Count(r => r.Enabled);
        var interceptCount = _automationContext.GetInterceptRules().Count(r => r.Enabled);
        var pendingCount = _automationContext.PendingRequestCount;

        if (pendingCount > 0)
        {
            InterceptStatusText.Text = $"Net: {pendingCount} pending!";
            InterceptStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#CCA700"));
        }
        else if (mockCount > 0 || interceptCount > 0)
        {
            var parts = new List<string>();
            if (mockCount > 0) parts.Add($"{mockCount} mock{(mockCount > 1 ? "s" : "")}");
            if (interceptCount > 0) parts.Add($"{interceptCount} bp{(interceptCount > 1 ? "s" : "")}");
            InterceptStatusText.Text = $"Net: {string.Join(", ", parts)}";
            InterceptStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#4EC9B0"));
        }
        else
        {
            InterceptStatusText.Text = "Net: idle";
            InterceptStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#888888"));
        }

        var tooltip = "Network interception\n";
        tooltip += $"Mock rules: {mockCount}\n";
        tooltip += $"Breakpoints: {interceptCount}\n";
        tooltip += $"Pending requests: {pendingCount}\n\n";
        tooltip += "Click to manage";
        ((Border)InterceptStatusText.Parent).ToolTip = tooltip;
    }

    private void ShadowStatus_Click(object sender, MouseButtonEventArgs e)
    {
        if (_shadowFindingsDialog != null)
        {
            _shadowFindingsDialog.Activate();
            return;
        }

        var dlg = new ShadowFindingsDialog(this, _securityShadow, _lawService);
        _shadowFindingsDialog = dlg;
        dlg.AskAiRequested += SendShadowFindingToChat;
        dlg.SettingsRequested += ShowExperimentalSettings;
        dlg.ShadowConfigPersistRequested += OnFeatureConfigChanged;
        dlg.OpenLawInEditorRequested += OpenLawSourceInScriptConsole;
        dlg.LawCodeEditRequested += code =>
        {
            ScriptInput.Text = code;
            IsScriptPanelVisible = true;
            StatusText.Text = "Law source loaded into Script Console";
        };
        dlg.LawCopiedToUser += (path, createdNew) =>
        {
            StatusText.Text = createdNew
                ? $"Copied Law to {path} (editable; embedded copy unchanged)"
                : $"Appended Law to existing file {path}";
        };
        dlg.UserLawDeleted += path => StatusText.Text = $"Deleted user Law file: {path}";
        _lawService.ShadowHeavyCompleted += report =>
        {
            StatusText.Text = report.SummaryLine;
            if (_securityShadow.Config.NotifyGui && report.Ran && report.LawFailures > 0)
                ShowApiMessage(report.SummaryLine, "warning", 6000);
        };
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_shadowFindingsDialog, dlg))
                _shadowFindingsDialog = null;
        };
        dlg.Show();
    }

    private void UpdateShadowStatusDisplay()
    {
        if (!_securityShadow.Enabled)
        {
            ShadowStatusText.Text = "Shadow: off";
            ShadowStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#888888"));
            ((Border)ShadowStatusText.Parent).ToolTip = "Shadow — off\nClick to view findings\nEnable via Settings... on that dialog, or Settings → Experimental";
            return;
        }

        var total = _securityShadow.FindingsCount;
        var highCount = _securityShadow.GetFindings(minSeverity: Security.Severity.High).Count;

        if (highCount > 0)
        {
            ShadowStatusText.Text = $"Shadow: {highCount} HIGH";
            ShadowStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#CCA700"));
        }
        else if (total > 0)
        {
            ShadowStatusText.Text = $"Shadow: {total} finding{(total != 1 ? "s" : "")}";
            ShadowStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#4EC9B0"));
        }
        else
        {
            ShadowStatusText.Text = "Shadow: on";
            ShadowStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#4EC9B0"));
        }

        var tooltip = $"Shadow — active\n";
        tooltip += $"Pages audited: {_securityShadow.PagesAudited}\n";
        tooltip += $"Findings: {total} ({highCount} high/critical)\n";
        tooltip += $"Scope: {_securityShadow.Config.Scope}\n\n";
        tooltip += "Click to view findings";
        ((Border)ShadowStatusText.Parent).ToolTip = tooltip;
    }

    #endregion

    #region Chat Panel

    /// <summary>The built-in chat's own tool handler; separate from the API server's, so safe mode is pushed to both.</summary>
    private McpHandler? _chatMcpHandler;

    /// <summary>
    /// Host-backed MCP tools (<c>browser_ping</c>, <c>browser_security</c>, etc.) delegate to
    /// <see cref="TrowserApiServer"/>; keep the chat handler wired whenever the REST server toggles.
    /// </summary>
    private void SyncChatMcpHandlerHost()
    {
        if (_chatMcpHandler == null) return;
        _chatMcpHandler.Host = _apiServer is { IsRunning: true } ? _apiServer : null;
    }

    private void InitializeChatPanel()
    {
        if (_automationContext == null) return;

        var screenshotDir = Path.Combine(Path.GetTempPath(), "trowser-screenshots");
        Directory.CreateDirectory(screenshotDir);
        var mcpHandler = new McpHandler(_automationContext, screenshotDir, _scriptEngine)
        {
            Mode = _llmSettings.Mode,
            SafeMode = _safeMode,
            TestDataService = _testDataService,
            InspirationService = _inspirationService,
            CoverageService = _coverageService,
            SessionLogger = _sessionLogger,
            SessionMemory = _sessionMemory,
            SessionName = _sessionName
        };
        _chatMcpHandler = mcpHandler;
        SyncChatMcpHandlerHost();

        async Task<SessionMetadata> GetMetadata()
        {
            var url = "";
            try
            {
                var webView = _automationContext.ActiveTab?.WebView;
                // Already on the UI thread (Compact click): read Source directly.
                // GetCurrentUrl() uses Dispatcher.InvokeAsync and must not be
                // sync-waited while the dispatcher is blocked.
                if (webView?.Dispatcher.CheckAccess() == true)
                    url = webView.Source?.ToString() ?? "";
                else
                    url = await _automationContext.GetCurrentUrl().ConfigureAwait(false);
            }
            catch
            {
                /* best effort */
            }

            return new SessionMetadata
            {
                Url = url,
                Title = _automationContext.ActiveTab?.Title,
                TabCount = _automationContext.Tabs.Count,
                SessionName = _sessionName,
                SafetyMode = _safeMode ? "safe" : "active"
            };
        }

        var compaction = new LlmContextCompaction(_sessionLogger, _sessionMemory, GetMetadata);
        _sessionMemory.RebuildFrom(_sessionLogger);
        ChatPanelControl.Initialize(mcpHandler, _llmSettings, compaction);
        _lawService.CreateLlmClientForAuthoring = () => new LlmClient(_llmSettings, new LlmToolExecutor(mcpHandler));
        ChatPanelControl.QuicktestRequested += OnQuicktestRequested;
        ChatPanelControl.ShowAsHtmlRequested += OnShowChatAsHtml;
        ChatPanelControl.CloseRequested += () => IsChatPanelVisible = false;
        ChatPanelControl.ConfigureRequested += () => OpenLlmSettings_Click(this, new RoutedEventArgs());
    }

    private void OnQuicktestRequested(string quicktestName)
    {
        var resourceName = ResolveQuicktestResourceName(quicktestName);
        if (resourceName == null) return;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null) return;
        using var reader = new StreamReader(stream);
        ScriptInput.Text = reader.ReadToEnd();
        IsScriptPanelVisible = true;
        _ = RunCurrentScriptAsync();
    }

    /// <summary>
    /// Resolves a quicktest id to a manifest resource name. Accepts a dotted subpath
    /// (e.g. <c>Usability.ResponsiveAccessibility</c>) or a unique script leaf name.
    /// </summary>
    private static string? ResolveQuicktestResourceName(string quicktestName)
    {
        if (string.IsNullOrWhiteSpace(quicktestName)) return null;

        const string prefix = "Trowser.Resources.Quicktests.";
        var assembly = Assembly.GetExecutingAssembly();
        var names = assembly.GetManifestResourceNames();
        var direct = $"{prefix}{quicktestName.Trim()}.csx";
        if (names.Contains(direct))
            return direct;

        var suffix = $".{quicktestName.Trim()}.csx";
        var matches = names
            .Where(n => n.StartsWith(prefix, StringComparison.Ordinal) && n.EndsWith(suffix, StringComparison.Ordinal))
            .ToList();

        return matches.Count == 1 ? matches[0] : null;
    }

    private async void OnShowChatAsHtml(string html)
    {
        if (_automationContext == null || !_isWebViewReady) return;

        await OpenHtmlInTabAsync(html, "trowser://ai-session");
    }

    private void ChatToggleButton_Click(object sender, RoutedEventArgs e)
    {
        IsChatPanelVisible = !IsChatPanelVisible;
    }

    private void StrangeMomentButton_Click(object sender, RoutedEventArgs e)
    {
        OpenStrangeMoment();
    }

    /// <summary>
    /// <c>!?</c> / Ctrl+Shift+L. Snip a rectangle over a frozen page bitmap to drop a human pointer,
    /// then reveal the AI Assistant prefilled with the checkpoint-bounded handoff payload (never
    /// auto-sent). Implemented in <see cref="OpenStrangeMomentAsync"/> (MainWindow.xaml.Pointers.cs).
    /// </summary>
    private void OpenStrangeMoment()
    {
        _ = OpenStrangeMomentAsync();
    }

    private void MoreMenuButton_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu
        {
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30")),
            BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46")),
            PlacementTarget = MoreMenuButton,
            Placement = PlacementMode.Bottom,
            HasDropShadow = true
        };

        menu.Items.Add(CreateDarkMenuItem("Journal  (Ctrl+J)", JournalToggleMenu_Click));
        menu.Items.Add(CreateDarkMenuItem("AI Assistant  (Ctrl+L)", ChatToggleButton_Click));
        menu.Items.Add(CreateDarkMenuItem("Script Console  (Ctrl+0)", ScriptToggleButton_Click));
        menu.Items.Add(new Separator { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46")), Margin = new Thickness(0, 2, 0, 2) });
        menu.Items.Add(CreateDarkMenuItem("Session Log...", SessionLogMenu_Click));
        menu.Items.Add(CreateDarkMenuItem("Peer sessions...", PeerSessionsMenu_Click));
        menu.Items.Add(CreateDarkMenuItem("Race Lab...", RaceLabMenu_Click));
        menu.Items.Add(CreateDarkMenuItem("Live Authz Shadow...", AuthzShadowMenu_Click));
        menu.Items.Add(new Separator { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46")), Margin = new Thickness(0, 2, 0, 2) });
        menu.Items.Add(CreateDarkMenuItem("Test data...  (Ctrl+D)", OpenTestData_Click));
        menu.Items.Add(CreateDarkMenuItem("LLM Settings...", OpenLlmSettings_Click));
        menu.Items.Add(CreateDarkMenuItem("Settings...", OpenSettings_Click));
        menu.Items.Add(new Separator { Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3F3F46")), Margin = new Thickness(0, 2, 0, 2) });
        menu.Items.Add(CreateDarkMenuItem("Introduction", ManualTrowser_Click));
        menu.Items.Add(CreateDarkMenuItem("Help", HelpPaper_Click));
        menu.Items.Add(CreateDarkMenuItem("About Trowser", AboutTrowser_Click));

        menu.IsOpen = true;
    }

    private async void VpxExport_Click()
    {
        if (_automationContext == null)
        {
            StatusText.Text = "Browser not ready — wait for the page to finish loading.";
            return;
        }

        string? baseUrl = null;
        try { baseUrl = await _automationContext.GetCurrentUrl(); } catch { /* best effort */ }

        var dlg = new SaveFileDialog
        {
            Filter = "VPX document (*.vpx.json)|*.vpx.json|JSON (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".vpx.json",
            FileName = VpxSessionIo.SuggestFileName(baseUrl),
            Title = "Export VPX findings"
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            var result = VpxSessionIo.ExportToFile(
                _automationContext, dlg.FileName, _sessionLogger, "compact", baseUrl);
            StatusText.Text = $"Exported {result.FindingCount} finding(s) to {dlg.FileName}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "VPX Export failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void VpxImport_Click()
    {
        if (_automationContext == null)
        {
            StatusText.Text = "Browser not ready — wait for the page to finish loading.";
            return;
        }

        var dlg = new OpenFileDialog
        {
            Filter = "VPX document (*.vpx.json)|*.vpx.json|JSON (*.json)|*.json|All files (*.*)|*.*",
            Title = "Import VPX findings"
        };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            var result = VpxSessionIo.ImportFromFile(_automationContext, dlg.FileName, "merge");
            StatusText.Text =
                $"Imported {result.FindingsImported} finding(s) (skipped {result.FindingsSkipped}) from {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "VPX Import failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static MenuItem CreateDarkMenuItem(string header, RoutedEventHandler onClick)
    {
        var fg = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#CCCCCC"));
        var menuBg = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30"));
        var hoverBg = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3E3E42"));

        var template = new ControlTemplate(typeof(MenuItem));
        var border = new FrameworkElementFactory(typeof(Border));
        border.Name = "Bd";
        border.SetValue(Border.BackgroundProperty, menuBg);
        border.SetValue(Border.PaddingProperty, new Thickness(12, 6, 12, 6));
        var content = new FrameworkElementFactory(typeof(ContentPresenter));
        content.SetValue(ContentPresenter.ContentSourceProperty, "Header");
        content.SetValue(ContentPresenter.RecognizesAccessKeyProperty, true);
        border.AppendChild(content);
        template.VisualTree = border;

        var highlight = new Trigger { Property = MenuItem.IsHighlightedProperty, Value = true };
        highlight.Setters.Add(new Setter(Border.BackgroundProperty, hoverBg, "Bd"));
        template.Triggers.Add(highlight);

        var item = new MenuItem
        {
            Header = header,
            Foreground = fg,
            Template = template
        };
        item.Click += onClick;
        return item;
    }

    private void OpenTestData_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new TestDataDialog(this, _testDataService);
        dialog.ShowDialog();

        // The dialog writes its toggles back onto the service when it closes; persist them.
        CaptureFeatureSettings(_llmSettings);
        _llmSettings.Save();
    }

    private async Task CopyRandomTestDataAsync()
    {
        try
        {
            var text = await _testDataService.GetRandomAsync();
            if (text != null)
            {
                Clipboard.SetText(text);
                var kindLabel = _testDataService.ActiveKind == TestDataKind.Payloads ? "Payload" : "Test data";
                StatusText.Text = $"{kindLabel} copied: {(text.Length > 60 ? text[..60] + "…" : text)}";
            }
            else
            {
                var kindLabel = _testDataService.ActiveKind == TestDataKind.Payloads ? "payloads" : "test strings";
                StatusText.Text = $"No {kindLabel} available — open Test Data dialog to add entries";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Test data error: {ex.Message}";
        }
    }

    private void ShowExperimentalSettings(Window owner)
    {
        var expDialog = new ExperimentalDialog(
            owner, _securityShadow.Config, _powerMode.Config, _redTeamWhisper.Config,
            onVpxExport: VpxExport_Click, onVpxImport: VpxImport_Click);
        if (expDialog.ShowDialog() != true)
            return;

        _securityShadow.Configure(
            expDialog.ShadowEnabled,
            expDialog.ShadowAudits,
            expDialog.ShadowScope,
            notifyGui: expDialog.ShadowNotifyGui);
        ApplyShadowLawSettings(expDialog);
        _powerMode.Configure(expDialog.PowerModeEnabled, expDialog.PowerModeShowOverlays);
        _redTeamWhisper.Configure(expDialog.WhisperEnabled, expDialog.WhisperNotifyGui);
        if (_automationContext != null)
            _ = _automationContext.SyncPowerModeToAllTabsAsync();
    }

    private void ApplyShadowLawSettings(ExperimentalDialog exp) =>
        ApplyShadowLawSettings(
            exp.ShadowLawsEnabled,
            exp.ShadowLawsMining,
            exp.ShadowRunHeavyAfterQuicktest,
            exp.ShadowSerendipityTimer);

    private void ApplyShadowLawSettings(bool lawsEnabled, bool lawsMining, bool runHeavyAfterScript, bool serendipity)
    {
        _securityShadow.Config.LawsEnabled = lawsEnabled;
        _securityShadow.Config.LawsMiningEnabled = lawsMining;
        _securityShadow.Config.RunHeavyAfterQuicktest = runHeavyAfterScript;
        _securityShadow.Config.SerendipityTimerEnabled = serendipity;
        _lawService.ConfigureSerendipityTimer(
            serendipity,
            _llmSettings.Shadow.SerendipityIntervalSeconds,
            _llmSettings.Shadow.SerendipityRandomize);
        OnFeatureConfigChanged();
    }

    private void OpenLlmSettings_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new LlmSettingsDialog(this, _llmSettings, _apiPort, _apiKey);
        if (dialog.ShowDialog() != true)
            return;

        _llmSettings = dialog.GetLlmSettings();
        CaptureFeatureSettings(_llmSettings);
        _llmSettings.Save();
        // Built-in AI Assistant InteractionMode is separate from ExternalMcpMode.
        ChatPanelControl.UpdateSettings(_llmSettings);
        StatusText.Text = "LLM settings updated";
    }

    private void OpenSettings_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SettingsDialog(this, _navigationGuard.Scope, _apiPort,
            _llmSettings.ProxyEnabled, _llmSettings.ProxyUrl,
            _safeMode, _apiKey, _apiKeyRequired, _keepApiKeyForNextSession,
            _securityShadow.Config, _powerMode.Config, _redTeamWhisper.Config, _sslManager,
            onVpxExport: VpxExport_Click, onVpxImport: VpxImport_Click);
        if (dialog.ShowDialog() == true)
        {
            _navigationGuard.SetScope(dialog.ScopeValue);
            if (_automationContext != null)
                _automationContext.NavigationGuard = _navigationGuard;
            UpdateScopeDisplay();

            _safeMode = dialog.SafeModeValue;
            if (_chatMcpHandler != null)
                _chatMcpHandler.SafeMode = _safeMode;
            var previousKey = _apiKey;
            _apiKey = string.IsNullOrWhiteSpace(dialog.RestApiKey) ? TrowserApiKey.Generate() : dialog.RestApiKey.Trim();
            _apiKeyRequired = dialog.ApiKeyRequired;
            _keepApiKeyForNextSession = dialog.KeepApiKeyForNextSession;
            if (_apiServer != null)
            {
                _apiServer.SafeMode = _safeMode;
                _apiServer.ApiKeyRequired = _apiKeyRequired;
                _apiServer.ExternalMcpMode = _externalMcpMode;
            }

            if (previousKey != _apiKey && _apiServer?.IsRunning == true)
            {
                ToggleApiOff();
                ToggleApiOn();
            }

            var newPort = dialog.PortValue;
            if (newPort != _apiPort)
            {
                var wasRunning = _apiServer?.IsRunning == true;
                if (wasRunning) ToggleApiOff();
                _apiPort = newPort;
                if (wasRunning) ToggleApiOn();
            }

            UpdateApiStatusDisplay(_apiServer?.IsRunning == true);

            _securityShadow.Configure(
                dialog.ShadowEnabled,
                dialog.ShadowAudits,
                dialog.ShadowScope,
                notifyGui: dialog.ShadowNotifyGui);
            ApplyShadowLawSettings(
                dialog.ShadowLawsEnabled,
                dialog.ShadowLawsMining,
                dialog.ShadowRunHeavyAfterQuicktest,
                dialog.ShadowSerendipityTimer);
            UpdateShadowStatusDisplay();

            _powerMode.Configure(dialog.PowerModeEnabled, dialog.PowerModeShowOverlays);
            _redTeamWhisper.Configure(dialog.WhisperEnabled, dialog.WhisperNotifyGui);
            if (_automationContext != null)
                _ = _automationContext.SyncPowerModeToAllTabsAsync();

            var oldProxy = (_llmSettings.ProxyEnabled, _llmSettings.ProxyUrl);
            _llmSettings.ProxyEnabled = dialog.ProxyEnabled;
            _llmSettings.ProxyUrl = dialog.ProxyUrl;
            CaptureFeatureSettings(_llmSettings);
            _llmSettings.Save();

            var proxyChanged = oldProxy != (_llmSettings.ProxyEnabled, _llmSettings.ProxyUrl);

            if (proxyChanged)
            {
                StatusText.Text = "Settings updated \u2014 restart Trowser for proxy changes to take effect";
                MessageBox.Show(this,
                    "Proxy settings are applied when the browser engine starts.\nPlease restart Trowser for the changes to take effect.",
                    "Restart Required", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                StatusText.Text = "Settings updated";
            }

            SaveApiUserSettings();
        }
    }

    private async void ManualTrowser_Click(object sender, RoutedEventArgs e)
    {
        await OpenIntroductionInNewTabAsync();
    }

    private const string HelpPaperUrl = "https://www.thetesteye.com/papers/TamingTheTrowser.pdf";

    private async void HelpPaper_Click(object sender, RoutedEventArgs e)
    {
        await OpenWelcomeTargetInNewTabAsync(HelpPaperUrl);
    }

    private void AboutTrowser_Click(object sender, RoutedEventArgs e)
    {
        new AboutDialog(this).ShowDialog();
    }

    #endregion
}
