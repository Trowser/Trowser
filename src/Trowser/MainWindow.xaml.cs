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
using Trowser.SessionLog;

namespace Trowser;

/// <summary>
/// Main window - browser chrome with tab strip, navigation bar, WebView2 tabs, status bar, and script console.
/// </summary>
public partial class MainWindow : Window, INotifyPropertyChanged
{
    private bool _isScriptPanelVisible;
    private AutomationContext? _automationContext;
    private ScriptEngine? _scriptEngine;
    private TrowserApiServer? _apiServer;
    private bool _isWebViewReady;
    private NavigationGuard _navigationGuard = null!;
    private int _apiPort;
    private string _apiKey = null!;
    private bool _apiKeyRequired = true;
    private bool _keepApiKeyForNextSession;
    /// <summary>Whether the user wants the REST server on; persisted. Command line can override for this session.</summary>
    private bool _apiUserWantsServerRunning;
    private bool _safeMode;
    private ExternalMcpMode _externalMcpMode = ExternalMcpMode.Core;
    private AgentTabPolicy _agentTabPolicy = AgentTabPolicy.StayOnActive;

    private readonly List<string> _cliOutputLines = new();
    private const string ScriptPauseIcon = "II";
    private ScriptRunControl? _playRun;
    private ScriptRunControl? _scriptConsoleRun;
    private string? _playRunStatusText;
    private readonly ScriptRecorder _recorder = new();
    private bool _recorderAddressBarNav;
    /// <summary>When true, OnClosing may proceed even if a recording was just finalized.</summary>
    private bool _allowCloseDespiteRecording;
    private bool _isWatchModeActive;
    private bool _watchModeRunning;
    private bool _isChatPanelVisible;
    private LlmSettings _llmSettings = null!;
    private CoreWebView2Environment? _webView2Environment;
    private bool _browserShutdown;
    private readonly SessionLogger _sessionLogger = new();
    private readonly Pointers.PointerStore _pointerStore = new();
    private readonly Decisions.DecisionStore _decisionStore = new();
    private readonly SessionMemory _sessionMemory = new();
    private SessionLogSettings _sessionLogSettings = null!;
    private GuiSettings _guiSettings = null!;
    private UrlCompletionStore _urlCompletion = null!;
    private readonly TestDataService _testDataService = new();
    private readonly InspirationService _inspirationService = new();
    private readonly CoverageService _coverageService = new();
    private readonly Security.SecurityShadowManager _securityShadow = new();
    private readonly Laws.LawService _lawService = new();
    private Security.Authz.LiveAuthzShadow? _liveAuthzShadow;
    private Security.Authz.AuthzShadowDialog? _authzShadowDialog;
    private readonly Security.CallbackDetector _callbackDetector = new();
    private readonly Security.PowerModeManager _powerMode = new();
    private readonly Security.RedTeamWhisperManager _redTeamWhisper = new();
    private readonly Security.SslManager _sslManager = Security.SslManager.Load();
    private readonly PlaybookRegistry _playbookRegistry = new();
    private readonly IdentityStore _identityStore = new();
    private readonly ChainPatternCatalog _chainCatalog = new();
    private readonly PeerRegistry _peerRegistry = new();
    private PeerSessionManager? _peerSessionManager;
    private Peers.MirrorController? _mirrorController;
    private List<EndpointProbe.EndpointProbeItem>? _bolaEndpointSnapshot;
    private bool _bolaUseCapturedHeadersBody = true;

    /// <summary>
    /// When true, a tab opened by the page (<c>window.open</c> / <c>target=_blank</c>)
    /// gets DevTools before it navigates. Set by F12 / Inspect; cleared when a window
    /// probe shows no DevTools windows remain (after the probe has succeeded at least once).
    /// </summary>
    private bool _followDevToolsOnNewTabs;
    private bool _devToolsWindowProbeHasSucceeded;

    /// <summary>
    /// One-shot: the next <see cref="CreateNewTabAsync"/> is a page-initiated window
    /// (see <see cref="Tab_NewWindowRequested"/>). Ctrl+T, the new-tab button, reports,
    /// and script/API <c>NewTab</c> leave this false.
    /// </summary>
    private bool _openDevToolsForPageOpenedTab;

    /// <summary>
    /// One-shot: skip Navigate in <see cref="CreateNewTabAsync"/> so WebView2 can assign
    /// the CoreWebView2 via <c>NewWindowRequestedEventArgs.NewWindow</c> and preserve
    /// <c>window.opener</c>.
    /// </summary>
    private bool _deferNextTabNavigation;

    /// <summary>Default and bounds for persisted panel split ratios (fraction of content area).</summary>
    private const double DefaultPanelFraction = 0.25;
    private const double MinPanelFraction = 0.12;
    private const double MaxPanelFraction = 0.55;

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool IsScriptPanelVisible
    {
        get => _isScriptPanelVisible;
        set
        {
            if (_isScriptPanelVisible != value)
            {
                _isScriptPanelVisible = value;
                OnPropertyChanged();

                if (value)
                    ApplyScriptPanelSplit();
                else
                {
                    RootGrid.RowDefinitions[2].Height = new GridLength(1, GridUnitType.Star);
                    RootGrid.RowDefinitions[4].Height = GridLength.Auto;
                }
            }
        }
    }

    public bool IsChatPanelVisible
    {
        get => _isChatPanelVisible;
        set
        {
            if (_isChatPanelVisible != value)
            {
                // Persist the current drag size before collapsing so reopening restores it (not the stale default).
                if (!value) CapturePanelSplits();
                _isChatPanelVisible = value;
                OnPropertyChanged();
                ApplyContentColumnSplits();
            }
        }
    }

    private bool _isJournalPanelVisible;

    /// <summary>Left-docked Journal panel visibility (Ctrl+J / View menu).</summary>
    public bool IsJournalPanelVisible
    {
        get => _isJournalPanelVisible;
        set
        {
            if (_isJournalPanelVisible != value)
            {
                // Persist the current drag size before collapsing so reopening restores it (not the stale default).
                if (!value) CapturePanelSplits();
                _isJournalPanelVisible = value;
                OnPropertyChanged();
                ApplyContentColumnSplits();
                if (value)
                    _ = ShowJournalPanelAsync(autoStartLogging: false);
            }
        }
    }

    /// <summary>Convenience accessor for the active tab's WebView2.</summary>
    private WebView2? ActiveWebView => _automationContext?.ActiveTab?.WebView;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        _llmSettings = LlmSettings.Load();
        var apiUser = ApiUserSettings.Load();
        _guiSettings = GuiSettings.Load();
        _urlCompletion = UrlCompletionStore.Load();

        // Scope, port, and safe mode persist via api-user.json; a command-line flag (or CLI mode)
        // overrides the persisted value for that run.
        var cli = App.CliMode != null;
        var scope = (cli || App.Api.ScopeFromCommandLine) ? App.Api.Scope : apiUser.NavigationScope;
        var allowFileUrls = (cli || App.Api.AllowFileUrlsFromCommandLine)
            ? App.Api.AllowFileUrls
            : apiUser.AllowFileUrls;
        _navigationGuard = new NavigationGuard(scope, allowFileUrls);
        _apiPort = (cli || App.Api.PortFromCommandLine) ? App.Api.Port : apiUser.ApiPort;
        _safeMode = (cli || App.Api.SafeModeFromCommandLine) ? App.Api.SafeMode : apiUser.SafeMode;
        _externalMcpMode = apiUser.ExternalMcpMode;
        _agentTabPolicy = apiUser.AgentTabPolicy;

        // Security features and test-data preferences persist in settings.json.
        _securityShadow.Configure(
            _llmSettings.Shadow.Enabled,
            new HashSet<string>(_llmSettings.Shadow.Audits),
            _llmSettings.Shadow.Scope,
            _llmSettings.Shadow.Suggestions,
            _llmSettings.Shadow.Deduplication,
            _llmSettings.Shadow.NotifyGui);
        _securityShadow.Config.MaxFindings = _llmSettings.Shadow.MaxFindings;
        _securityShadow.Config.LawsEnabled = _llmSettings.Shadow.LawsEnabled;
        _securityShadow.Config.DisabledLaws = new HashSet<string>(_llmSettings.Shadow.DisabledLaws);
        _securityShadow.Config.ActiveLawSources = _llmSettings.Shadow.ActiveLawSources == null
            ? null
            : new HashSet<string>(_llmSettings.Shadow.ActiveLawSources, StringComparer.OrdinalIgnoreCase);
        _securityShadow.Config.LightQuicktests = new HashSet<string>(_llmSettings.Shadow.LightQuicktests);
        _securityShadow.Config.HeavyQuicktests = new HashSet<string>(_llmSettings.Shadow.HeavyQuicktests);
        _securityShadow.Config.RunHeavyAfterQuicktest = _llmSettings.Shadow.RunHeavyAfterQuicktest;
        _securityShadow.Config.SerendipityTimerEnabled = _llmSettings.Shadow.SerendipityTimerEnabled;
        _securityShadow.Config.SerendipityIntervalSeconds = _llmSettings.Shadow.SerendipityIntervalSeconds;
        _securityShadow.Config.SerendipityRandomize = _llmSettings.Shadow.SerendipityRandomize;
        _securityShadow.Config.LightLawBudgetMs = _llmSettings.Shadow.LightLawBudgetMs;
        _securityShadow.Config.LawsMiningEnabled = _llmSettings.Shadow.LawsMiningEnabled;
        _powerMode.Configure(_llmSettings.PowerMode.Enabled, _llmSettings.PowerMode.ShowOverlays);
        _redTeamWhisper.Configure(_llmSettings.Whisper.Enabled, _llmSettings.Whisper.NotifyGui);
        _testDataService.UseOnline = _llmSettings.TestDataUseOnline;
        _testDataService.AsciiOnly = _llmSettings.TestDataAsciiOnly;
        _testDataService.OnlineUrl = _llmSettings.TestDataOnlineUrl;
        _testDataService.ActiveKind = _llmSettings.TestDataActiveKind;

        // Persist + refresh status whenever Shadow / Power / Whisper are toggled (Settings, findings dialog, API, MCP).
        _securityShadow.ConfigChanged += OnFeatureConfigChanged;
        _powerMode.ConfigChanged += OnFeatureConfigChanged;
        _redTeamWhisper.ConfigChanged += OnFeatureConfigChanged;

        _apiKeyRequired = apiUser.RestApiKeyRequired;
        _keepApiKeyForNextSession = apiUser.KeepApiKeyForNextSession;
        if (App.Api.ApiKeyFromCommandLine)
            _apiKey = App.Api.ApiKey;
        else if (_keepApiKeyForNextSession && !string.IsNullOrEmpty(apiUser.RestApiKey))
            _apiKey = apiUser.RestApiKey;
        else
            _apiKey = TrowserApiKey.Generate();
        if (App.CliMode != null)
            _apiUserWantsServerRunning = false;
        else if (App.Api.ApiEnabledFromCommandLine)
            _apiUserWantsServerRunning = App.Api.Enabled;
        else
            _apiUserWantsServerRunning = apiUser.ApiServerEnabled;
        _sessionLogSettings = SessionLogSettings.Load();
        _sessionLogger.Settings = _sessionLogSettings;
        UpdateScopeDisplay();
        PopulateQuickTests();
        SetupScriptOutputContextMenu();
        ApplyGuiSettings();
        RestoreSessionLoggingIfEnabled();
        WirePointerOverlayAutoShow();
        WireDecisions();

        Loaded += MainWindow_Loaded;
    }

    /// <summary>
    /// Restore persisted window placement and panel visibility. New users get a maximized window
    /// with the chat and script console panels open (see <see cref="GuiSettings"/> defaults).
    /// </summary>
    private void ApplyGuiSettings()
    {
        IsChatPanelVisible = _guiSettings.ChatPanelVisible;
        IsScriptPanelVisible = _guiSettings.ScriptPanelVisible;
        // Restore journal visibility without going through the setter: that path
        // auto-starts logging (user opened the panel). A previously open panel
        // must not override an explicit Stop Logging preference.
        _isJournalPanelVisible = _guiSettings.JournalPanelVisible;
        OnPropertyChanged(nameof(IsJournalPanelVisible));
        ApplyContentColumnSplits();

        // In CLI mode the window is hidden/minimized by App; don't fight that with saved geometry.
        if (App.CliMode != null)
            return;

        if (_guiSettings.WindowWidth is > 0 && _guiSettings.WindowHeight is > 0)
        {
            var vsLeft = SystemParameters.VirtualScreenLeft;
            var vsTop = SystemParameters.VirtualScreenTop;
            var vsWidth = SystemParameters.VirtualScreenWidth;
            var vsHeight = SystemParameters.VirtualScreenHeight;

            var width = Math.Min(_guiSettings.WindowWidth.Value, vsWidth);
            var height = Math.Min(_guiSettings.WindowHeight.Value, vsHeight);

            // Clamp so the title bar stays reachable even if a monitor was disconnected.
            var left = Math.Max(vsLeft, Math.Min(_guiSettings.WindowLeft ?? Left, vsLeft + vsWidth - 100));
            var top = Math.Max(vsTop, Math.Min(_guiSettings.WindowTop ?? Top, vsTop + vsHeight - 100));

            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = left;
            Top = top;
            Width = width;
            Height = height;
        }

        WindowState = _guiSettings.WindowMaximized ? WindowState.Maximized : WindowState.Normal;
    }

    private static double ClampPanelFraction(double fraction) =>
        double.IsFinite(fraction) && fraction > 0
            ? Math.Clamp(fraction, MinPanelFraction, MaxPanelFraction)
            : DefaultPanelFraction;

    /// <summary>
    /// Apply the horizontal content-area split across the (optional) left Journal panel,
    /// the browser, and the (optional) right chat panel using star ratios. Columns:
    /// 0 = journal, 1 = journal splitter, 2 = browser, 3 = chat splitter, 4 = chat.
    /// Hidden side panels collapse to Auto so their splitters take no space.
    /// </summary>
    private void ApplyContentColumnSplits()
    {
        var cols = ContentColumnsGrid.ColumnDefinitions;

        var journalFraction = IsJournalPanelVisible ? ClampPanelFraction(_guiSettings.JournalPanelFraction) : 0;
        var chatFraction = IsChatPanelVisible ? ClampPanelFraction(_guiSettings.ChatPanelFraction) : 0;
        // Keep the browser as the dominant column even if both side panels are open.
        var browserFraction = Math.Max(0.3, 1.0 - journalFraction - chatFraction);

        cols[0].Width = IsJournalPanelVisible ? new GridLength(journalFraction, GridUnitType.Star) : GridLength.Auto;
        cols[2].Width = new GridLength(browserFraction, GridUnitType.Star);
        cols[4].Width = IsChatPanelVisible ? new GridLength(chatFraction, GridUnitType.Star) : GridLength.Auto;
    }

    /// <summary>Apply the persisted browser/script-console vertical split using star ratios.</summary>
    private void ApplyScriptPanelSplit()
    {
        var scriptFraction = ClampPanelFraction(_guiSettings.ScriptPanelFraction);
        var browserFraction = 1.0 - scriptFraction;
        RootGrid.RowDefinitions[2].Height = new GridLength(browserFraction, GridUnitType.Star);
        RootGrid.RowDefinitions[4].Height = new GridLength(scriptFraction, GridUnitType.Star);
    }

    /// <summary>Read current star ratios from the grid after the user has dragged a splitter.</summary>
    private void CapturePanelSplits()
    {
        var cols = ContentColumnsGrid.ColumnDefinitions;
        // Total star weight across the three content columns (journal/browser/chat).
        var starTotal = 0.0;
        if (cols[0].Width.IsStar) starTotal += cols[0].Width.Value;
        if (cols[2].Width.IsStar) starTotal += cols[2].Width.Value;
        if (cols[4].Width.IsStar) starTotal += cols[4].Width.Value;

        if (starTotal > 0)
        {
            if (IsJournalPanelVisible && cols[0].Width.IsStar)
                _guiSettings.JournalPanelFraction = ClampPanelFraction(cols[0].Width.Value / starTotal);
            if (IsChatPanelVisible && cols[4].Width.IsStar)
                _guiSettings.ChatPanelFraction = ClampPanelFraction(cols[4].Width.Value / starTotal);
        }

        if (IsScriptPanelVisible)
        {
            var rows = RootGrid.RowDefinitions;
            if (rows[2].Height.IsStar && rows[4].Height.IsStar)
            {
                var total = rows[2].Height.Value + rows[4].Height.Value;
                if (total > 0)
                    _guiSettings.ScriptPanelFraction = ClampPanelFraction(rows[4].Height.Value / total);
            }
        }
    }

    /// <summary>Persist window placement and panel visibility to user-gui.json.</summary>
    private void SaveGuiSettings()
    {
        // Never capture the hidden/minimized geometry used by CLI runs.
        if (App.CliMode != null)
            return;

        _guiSettings.WindowMaximized = WindowState == WindowState.Maximized;

        // RestoreBounds gives the normal (non-maximized/minimized) rectangle.
        var bounds = RestoreBounds;
        if (!bounds.IsEmpty)
        {
            _guiSettings.WindowLeft = bounds.Left;
            _guiSettings.WindowTop = bounds.Top;
            _guiSettings.WindowWidth = bounds.Width;
            _guiSettings.WindowHeight = bounds.Height;
        }

        _guiSettings.ChatPanelVisible = IsChatPanelVisible;
        _guiSettings.ScriptPanelVisible = IsScriptPanelVisible;
        _guiSettings.JournalPanelVisible = IsJournalPanelVisible;
        CapturePanelSplits();
        _guiSettings.Save();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        WireScriptInputContextMenu();

        // The window may already be maximized at startup (StateChanged won't have fired), so make
        // sure the maximize overscan compensation is applied for the initial paint too.
        Window_StateChanged(this, EventArgs.Empty);

        if (!App.NoSplash && App.CliMode == null)
            ShowSplashOverlay();

        await InitializeFirstTabAsync();
    }

    private void ShowSplashOverlay()
    {
        var splash = new Window
        {
            Width = 800,
            Height = 200,
            WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF9552")),
            ShowInTaskbar = false,
            Topmost = true,
            Owner = this,
            Content = new TextBlock
            {
                Text = "understand what is important, then test it",
                Foreground = Brushes.White,
                FontSize = 32,
                FontFamily = new FontFamily("Segoe UI"),
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                TextAlignment = TextAlignment.Center
            }
        };

        splash.Show();

        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            splash.Close();
        };
        timer.Start();
    }

    private void ShowInspirationOverlay()
    {
        var message = _inspirationService.GetRandom();
        if (message == null)
            return;

        var overlay = new Window
        {
            Width = 800,
            Height = 200,
            WindowStyle = WindowStyle.None,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF9552")),
            ShowInTaskbar = false,
            Topmost = true,
            Owner = this,
            Content = new TextBlock
            {
                Text = message,
                Foreground = Brushes.White,
                FontSize = 32,
                FontFamily = new FontFamily("Segoe UI"),
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(30, 0, 30, 0)
            }
        };

        overlay.MouseDown += (_, _) => overlay.Close();
        overlay.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape)
                overlay.Close();
        };

        overlay.Show();
    }

    private string? _browserExeFolder;
    private string _sessionName = null!;
    private string? _sessionDataFolder;
    private bool _ephemeralSession;
    private FileStream? _sessionLock;
    private string? _sessionStartupNotice;

    private async Task<CoreWebView2Environment> CreateWebView2EnvironmentAsync()
    {
        var options = new CoreWebView2EnvironmentOptions();
        if (_llmSettings.ProxyEnabled && !string.IsNullOrWhiteSpace(_llmSettings.ProxyUrl))
            options.AdditionalBrowserArguments = $"--proxy-server={_llmSettings.ProxyUrl}";

        // Use bundled WebView2 runtime if present next to the exe
        // (AppContext.BaseDirectory is wrong in single-file publish — points to temp extraction dir)
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath)!;
        var bundledRuntime = Path.Combine(exeDir, "WebView2Runtime");
        if (Directory.Exists(bundledRuntime))
            _browserExeFolder = bundledRuntime;

        _sessionName = App.Api.SessionName;
        _ephemeralSession = App.Api.Ephemeral;
        _sessionStartupNotice = null;

        var sessionsRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Trowser", "Sessions");

        if (_ephemeralSession)
        {
            AssignEphemeralSessionFolder(sessionsRoot);
        }
        else if (!TryAcquireNamedSessionLock(sessionsRoot, _sessionName))
        {
            if (App.Api.SessionNameFromCommandLine)
            {
                throw new InvalidOperationException(
                    $"Session \"{_sessionName}\" is already in use by another Trowser instance. " +
                    "Choose a different --session name or close the other instance.");
            }

            var lockedSession = _sessionName;
            TrowserLog.Info(
                $"Session \"{lockedSession}\" is locked by another instance; starting isolated ephemeral session.");
            _ephemeralSession = true;
            _sessionName = $"{lockedSession}-isolated";
            _sessionStartupNotice =
                $"Session \"{lockedSession}\" is already open in another Trowser window. " +
                "This instance uses an isolated browser profile (cookies won't persist). " +
                "Use --session <name> for a persistent named second instance.";
            AssignEphemeralSessionFolder(sessionsRoot);
        }

        TrowserLog.Info($"Session \"{_sessionName}\" using WebView2 data folder: {_sessionDataFolder}");

        return await CoreWebView2Environment.CreateAsync(_browserExeFolder, _sessionDataFolder, options);
    }

    private void AssignEphemeralSessionFolder(string sessionsRoot)
    {
        var folderName = $"tmp-{Guid.NewGuid():N}";
        _sessionDataFolder = Path.Combine(sessionsRoot, folderName);
        Directory.CreateDirectory(_sessionDataFolder);
        EphemeralSessionCleanup.RemoveStaleFolders(sessionsRoot, _sessionDataFolder);
    }

    private bool TryAcquireNamedSessionLock(string sessionsRoot, string sessionName)
    {
        _sessionDataFolder = Path.Combine(sessionsRoot, sessionName);
        Directory.CreateDirectory(_sessionDataFolder);

        var lockPath = Path.Combine(_sessionDataFolder, "session.lock");
        try
        {
            _sessionLock = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            _sessionLock = null;
            return false;
        }
    }

    private void ShowSessionStartupNoticeIfNeeded()
    {
        if (string.IsNullOrEmpty(_sessionStartupNotice))
            return;

        ShowApiMessage(_sessionStartupNotice, "info", 12000);
        _sessionStartupNotice = null;
    }

    /// <summary>
    /// Initialize the first browser tab and set up the automation infrastructure.
    /// </summary>
    private async Task InitializeFirstTabAsync()
    {
        try
        {
            StatusText.Text = "Initializing browser engine...";

            _webView2Environment = await CreateWebView2EnvironmentAsync();

            var webView = new WebView2();
            // Paint the web surface with the dark theme color so the tab doesn't flash white before navigation.
            webView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 30, 30, 30);
            TabContentArea.Children.Add(webView);

            await webView.EnsureCoreWebView2Async(_webView2Environment);

            var settings = webView.CoreWebView2.Settings;
            settings.UserAgent += $" Trowser/{App.Version}";
            HeaderOverrideSettings.EnsureLoaded();

            _automationContext = new AutomationContext(webView, LogToOutput, LogColoredToOutput);
            _automationContext.AgentTabPolicy = _agentTabPolicy;
            if (!string.IsNullOrEmpty(_sessionDataFolder))
            {
                _automationContext.DownloadDirectory = Path.Combine(_sessionDataFolder, "downloads");
                Directory.CreateDirectory(_automationContext.DownloadDirectory);
            }
            _automationContext.NavigationGuard = _navigationGuard;
            _peerSessionManager = new PeerSessionManager(_peerRegistry, _navigationGuard.Scope);
            _mirrorController = new Peers.MirrorController(_peerSessionManager);
            _mirrorController.MirrorStateChanged += () =>
                Dispatcher.InvokeAsync(UpdateMirrorStatusDisplay);
            _automationContext.PeerRegistry = _peerRegistry;
            _automationContext.PeerSessionManager = _peerSessionManager;

            // Wire up tab management callbacks (marshal to UI thread — API calls run on thread pool)
            _automationContext.OnCreateTabRequested = async (url) =>
                await await Dispatcher.InvokeAsync(() => CreateNewTabAsync(url));
            _automationContext.OnActiveTabChanged = OnActiveTabChangedByContext;
            _automationContext.OnTabRemoved = OnTabRemovedByContext;

            _automationContext.SecurityShadow = _securityShadow;
            _lawService.Wire(_automationContext, _securityShadow);
            _automationContext.Laws = _lawService;

            WireUpTabEvents(_automationContext.ActiveTab);
            InterceptSettings.LoadInto(_automationContext.ActiveTab);
            var firstTab = _automationContext.ActiveTab;
            firstTab.BaselineUserAgent = firstTab.WebView.CoreWebView2.Settings.UserAgent;
            var firstUa = HeaderOverrideSettings.UserAgentOverride;
            if (firstUa != null)
                firstTab.WebView.CoreWebView2.Settings.UserAgent = firstUa;
            HeaderOverrideSettings.Changed += () =>
                Dispatcher.Invoke(ApplyUserAgentOverridesToAllTabs);
            UpdateInterceptStatusDisplay();
            UpdateShadowStatusDisplay();

            _isWebViewReady = true;
            StatusText.Text = "Ready";

            RebuildTabStrip();

            if (App.CliMode != null)
            {
                WireAutomationServices();
                StartApiServer();
                InitializeChatPanel();
                InitializeJournalPanel();
                ShowSessionStartupNoticeIfNeeded();
                if (IsJournalPanelVisible)
                    _ = ShowJournalPanelAsync(autoStartLogging: false);
                _ = InitializeLawsInBackgroundAsync();
                await RunCliModeAsync(App.CliMode);
                return;
            }

            NavigateToWelcomePage();

            // Roslyn (script engine + Law compile), API, and chat/journal after the welcome page paints.
            _ = Dispatcher.InvokeAsync(FinishHeavyStartupAsync, DispatcherPriority.ApplicationIdle);
        }
        catch (Exception ex)
        {
            if (App.CliMode != null)
            {
                CliWriteLine(WebView2Checker.GetCliDiagnostic(ex));
                ExitCli(2);
                return;
            }

            StatusText.Text = WebView2Checker.HandleFailure(ex, _browserExeFolder);
        }
    }

    /// <summary>
    /// Script engine, authz shadow, and panel/API wiring — deferred so welcome.html shows first.
    /// </summary>
    private void WireAutomationServices()
    {
        if (_scriptEngine != null || _automationContext == null)
            return;

        _scriptEngine = new ScriptEngine(_automationContext);
        _liveAuthzShadow = new Security.Authz.LiveAuthzShadow(_automationContext);
        _liveAuthzShadow.DecisionStore = _decisionStore;
        _automationContext.LiveAuthzShadow = _liveAuthzShadow;
        _automationContext.CallbackDetector = _callbackDetector;
        _automationContext.PowerMode = _powerMode;
        _automationContext.RedTeamWhisper = _redTeamWhisper;
        _automationContext.SslManager = _sslManager;
        _automationContext.PlaybookRegistry = _playbookRegistry;
        _automationContext.OrchestrateIdentityStore = _identityStore;
        _automationContext.OrchestrateChainCatalog = _chainCatalog;
        _automationContext.TestDataService = _testDataService;

        _redTeamWhisper.CluesGenerated += clues =>
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (!_redTeamWhisper.Config.NotifyGui) return;
                var lines = string.Join(" \u2022 ", clues.Take(2).Select(c => c.Title));
                if (clues.Count > 2) lines += $" (+{clues.Count - 2} more)";
                var toast = "Whisper: " + lines;
                ShowApiMessage(toast, "info", 8000, Security.WhisperClue.FormatCopy(toast, clues));
            });
        };

        _securityShadow.FindingsAdded += (count, severity) =>
        {
            Dispatcher.InvokeAsync(() =>
            {
                UpdateShadowStatusDisplay();
                if (_securityShadow.Config.NotifyGui && severity >= Security.Severity.High)
                    ShowApiMessage(
                        $"Shadow: {count} new finding(s) — {severity} severity detected",
                        "warning", 5000);
            });
        };
    }

    private async Task FinishHeavyStartupAsync()
    {
        try
        {
            WireAutomationServices();
            StartApiServer();
            InitializeChatPanel();
            InitializeJournalPanel();
            ShowSessionStartupNoticeIfNeeded();
            if (IsJournalPanelVisible)
                _ = ShowJournalPanelAsync(autoStartLogging: false);
            _ = InitializeLawsInBackgroundAsync();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Deferred startup failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Roslyn compilation of Law files is cold-start heavy; runs after script engine/API startup.
    /// </summary>
    private async Task InitializeLawsInBackgroundAsync()
    {
        try
        {
            await Task.Run(() => _lawService.ReloadAllAsync()).ConfigureAwait(false);
            await Dispatcher.InvokeAsync(() =>
            {
                _lawService.StartWatchingUserLaws();
                _lawService.ConfigureSerendipityTimer(
                    _llmSettings.Shadow.SerendipityTimerEnabled,
                    _llmSettings.Shadow.SerendipityIntervalSeconds,
                    _llmSettings.Shadow.SerendipityRandomize);
            });
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Background Law load failed: {ex.Message}");
        }
    }

    private async void Tab_ReapplyDialogConfig(BrowserTab tab, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (!e.IsSuccess) return;
        if (tab.DialogAccept && tab.DialogPromptText == null) return;

        try
        {
            if (_automationContext != null)
                await _automationContext.ApplyDialogConfig();
        }
        catch (Exception ex) { TrowserLog.Warn($"Dialog config reapply failed: {ex.Message}"); }
    }

    private async void Tab_ReapplyEmulation(BrowserTab tab, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (!e.IsSuccess) return;
        // Permissions are origin-scoped; only refresh the active automation tab.
        if (_automationContext == null || !ReferenceEquals(tab, _automationContext.ActiveTab))
            return;
        try
        {
            await _automationContext.ReapplyEmulationAfterNavigationAsync();
        }
        catch (Exception ex) { TrowserLog.Warn($"Emulation reapply failed: {ex.Message}"); }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_recorder.IsRecording && !_allowCloseDespiteRecording)
        {
            e.Cancel = true;
            _ = FinalizeRecordingGuiAsync(closeAfter: true);
            return;
        }

        // RestoreBounds is still valid here (the HWND may be gone by OnClosed).
        try { SaveGuiSettings(); }
        catch (Exception ex) { TrowserLog.Warn($"Failed to persist GUI settings on close: {ex.Message}"); }
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        // Recording should already have been finalized in OnClosing; best-effort discard if not.
        if (_recorder.IsRecording)
        {
            var leftover = _recorder.Stop();
            leftover?.DeleteTempFiles();
            ClearRecordingCapture();
        }
        try { _mirrorController?.Stop(); } catch { /* best effort */ }
        DisposeApiServer();
        base.OnClosed(e);
    }

    /// <summary>
    /// Dispose the API server's HttpListener to release the HTTP.sys URL prefix.
    /// Safe to call multiple times (idempotent) — called from OnClosed and from
    /// App-level safety-net handlers (ProcessExit, UnhandledException).
    /// </summary>
    internal void DisposeApiServer()
    {
        try
        {
            _apiServer?.Dispose();
            _apiServer = null;
            SyncChatMcpHandlerHost();
        }
        catch { /* best effort */ }

        ShutdownBrowser();
        CleanupEphemeralSession();
    }

    /// <summary>
    /// Release WebView2 controls and environment so the user-data folder can be deleted.
    /// Idempotent — safe from OnClosed and ProcessExit safety nets.
    /// </summary>
    private void ShutdownBrowser()
    {
        if (_browserShutdown)
            return;

        void DoShutdown()
        {
            _browserShutdown = true;
            _isWebViewReady = false;

            if (_automationContext != null)
            {
                foreach (var tab in _automationContext.Tabs.ToList())
                {
                    try { tab.WebView.Dispose(); }
                    catch { /* best effort */ }
                }
            }

            try { TabContentArea.Children.Clear(); }
            catch { /* best effort */ }

            _webView2Environment = null;
        }

        try
        {
            if (Dispatcher.CheckAccess())
                DoShutdown();
            else
                Dispatcher.Invoke(DoShutdown);
        }
        catch
        {
            try { DoShutdown(); }
            catch { /* UI thread may already be gone */ }
        }
    }

    private void CleanupEphemeralSession()
    {
        try { _sessionLock?.Dispose(); _sessionLock = null; }
        catch { /* best effort */ }

        if (!_ephemeralSession || string.IsNullOrEmpty(_sessionDataFolder))
            return;

        var folder = _sessionDataFolder;
        _sessionDataFolder = null;
        _ephemeralSession = false;

        if (EphemeralSessionCleanup.TryDeleteDirectory(folder))
        {
            TrowserLog.Info($"Cleaned up ephemeral session folder: {folder}");
            return;
        }

        TrowserLog.Warn(
            $"Could not clean up ephemeral session folder (will retry on next launch): {folder}");
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

}
