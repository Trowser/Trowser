using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
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
using Trowser.Recording;
using Trowser.Security.Sse;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;
using Trowser.SessionLog;

namespace Trowser;

public partial class MainWindow
{
    #region Tab Management

    /// <summary>
    /// Create a new browser tab with its own WebView2. Called by AutomationContext.NewTab().
    /// </summary>
    private async Task<BrowserTab> CreateNewTabAsync(string? url)
    {
        // Copy before the first await so a concurrent Ctrl+T cannot inherit this flag.
        var fromPageWindow = _openDevToolsForPageOpenedTab;
        _openDevToolsForPageOpenedTab = false;

        var webView = new WebView2();
        // Paint the web surface with the dark theme color so new/blank tabs don't flash white before navigation.
        webView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 30, 30, 30);
        webView.Visibility = Visibility.Collapsed;
        TabContentArea.Children.Add(webView);

        await webView.EnsureCoreWebView2Async(_webView2Environment);

        webView.CoreWebView2.Settings.UserAgent += $" Trowser/{App.Version}";

        var tab = new BrowserTab(webView);
        tab.BaselineUserAgent = webView.CoreWebView2.Settings.UserAgent;
        var uaOverride = HeaderOverrideSettings.UserAgentOverride;
        if (uaOverride != null)
            webView.CoreWebView2.Settings.UserAgent = uaOverride;
        WireUpTabEvents(tab);
        InterceptSettings.LoadInto(tab);

        // Only page-initiated windows (window.open / target=_blank). Ctrl+T, reports, and
        // API NewTab must not spawn extra DevTools windows.
        if (fromPageWindow)
            await MaybeOpenDevToolsOnNewTabAsync(webView.CoreWebView2);

        // NewWindowRequested assigns e.NewWindow and lets WebView2 navigate so opener is preserved.
        var deferNav = _deferNextTabNavigation;
        _deferNextTabNavigation = false;
        if (!deferNav)
        {
            if (!string.IsNullOrEmpty(url))
            {
                var normalizedUrl = NormalizeUrl(url);
                if (_navigationGuard.IsAllowed(normalizedUrl))
                {
                    var tcs = new TaskCompletionSource<bool>();
                    void handler(object? s, CoreWebView2NavigationCompletedEventArgs e)
                    {
                        webView.CoreWebView2.NavigationCompleted -= handler;
                        tcs.TrySetResult(e.IsSuccess);
                    }
                    webView.CoreWebView2.NavigationCompleted += handler;
                    webView.CoreWebView2.Navigate(normalizedUrl);
                    await tcs.Task;
                }
            }
            else
            {
                webView.CoreWebView2.Navigate("about:blank");
            }
        }

        return tab;
    }

    /// <summary>
    /// Open DevTools on a page-opened WebView2 before it navigates, when the tester already
    /// has DevTools open (or just pressed F12).
    /// </summary>
    private async Task MaybeOpenDevToolsOnNewTabAsync(CoreWebView2 newCore)
    {
        var pids = GetWebViewBrowserProcessIds(newCore);
        var visible = DevToolsWindowProbe.CountVisible(pids);
        if (visible > 0)
        {
            _followDevToolsOnNewTabs = true;
            _devToolsWindowProbeHasSucceeded = true;
        }
        else if (_devToolsWindowProbeHasSucceeded)
        {
            _followDevToolsOnNewTabs = false;
        }

        if (!_followDevToolsOnNewTabs)
            return;

        newCore.OpenDevToolsWindow();

        var deadline = DateTime.UtcNow.AddMilliseconds(400);
        while (DateTime.UtcNow < deadline)
        {
            if (DevToolsWindowProbe.CountVisible(pids) > visible)
                break;
            await Task.Delay(40);
        }
    }

    private IReadOnlyCollection<uint> GetWebViewBrowserProcessIds(CoreWebView2 extra)
    {
        var ids = new HashSet<uint>();
        if (_automationContext != null)
        {
            foreach (var existing in _automationContext.Tabs)
            {
                var id = existing.WebView.CoreWebView2?.BrowserProcessId ?? 0;
                if (id != 0)
                    ids.Add(id);
            }
        }

        if (extra.BrowserProcessId != 0)
            ids.Add(extra.BrowserProcessId);

        return ids;
    }

    /// <summary>F12 / explicit OpenDevToolsWindow from the Trowser UI.</summary>
    private void OpenDevToolsFromUi()
    {
        _followDevToolsOnNewTabs = true;
        if (_isWebViewReady)
            ActiveWebView?.CoreWebView2?.OpenDevToolsWindow();
    }

    /// <summary>
    /// Wire up all WebView2 events for a new tab.
    /// Each event handler captures the BrowserTab reference for state isolation.
    /// </summary>
    private void WireUpTabEvents(BrowserTab tab)
    {
        var webView = tab.WebView;
        var coreWv2 = webView.CoreWebView2;

        coreWv2.NavigationStarting += (s, e) => Tab_NavigationStarting(tab, e);
        coreWv2.NavigationCompleted += (s, e) => Tab_NavigationCompleted(tab, e);
        coreWv2.DocumentTitleChanged += (s, e) => Tab_DocumentTitleChanged(tab);
        coreWv2.SourceChanged += (s, e) => Tab_SourceChanged(tab);
        coreWv2.NewWindowRequested += (s, e) => Tab_NewWindowRequested(tab, e);

        // Console capture + runtime sensor / iframe web messages
        coreWv2.WebMessageReceived += (s, e) => Tab_WebMessageReceived(tab, e);
        coreWv2.FrameCreated += (s, e) => Tab_FrameCreated(tab, e);
        coreWv2.NavigationCompleted += (s, e) => Tab_InjectConsoleCapture(tab, e);
        coreWv2.NavigationCompleted += (s, e) => Tab_ReapplyDialogConfig(tab, e);
        coreWv2.NavigationCompleted += (s, e) => Tab_ReapplyEmulation(tab, e);

        // Network capture and mock interception
        coreWv2.WebResourceResponseReceived += (s, e) => Tab_WebResourceResponseReceived(tab, e);
        coreWv2.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
        coreWv2.WebResourceRequested += (s, e) => Tab_WebResourceRequested(tab, e);

        // CDP Network events for Set-Cookie header capture (WebView2 strips Set-Cookie for security)
        EnableCdpNetworkCapture(tab, coreWv2);

        // Download capture (defer default UI; log to tab.Downloads)
        _automationContext?.AttachDownloadHandler(tab, coreWv2);
        WireDownloadNotifications(tab);

        // Shadow: monitor network and console for ambient analysis
        // OOB Callbacks: detect requests to callback domains
        tab.Network.EntryAdded += entry =>
        {
            var pageUrl = tab.WebView.CoreWebView2?.Source ?? "";
            _securityShadow.OnNetworkEntry(entry, pageUrl);
            _lawService.OnNetworkEntry(entry, pageUrl);
            _liveAuthzShadow?.OnNetworkEntry(entry, pageUrl);
            _callbackDetector.OnNetworkEntry(entry);
            if (entry.IsEventStream && !string.IsNullOrEmpty(entry.ResponseBody))
                tab.Sse.OnNetworkEntryBodyUpdated(tab, entry.Id);
        };
        tab.Network.EntryBodyUpdated += id => tab.Sse.OnNetworkEntryBodyUpdated(tab, id);
        EnsureSseLiveBodyPoll(tab);
        tab.Console.EntryAdded += entry =>
        {
            var pageUrl = tab.WebView.CoreWebView2?.Source ?? "";
            _securityShadow.OnConsoleEntry(entry, pageUrl);
            _lawService.OnConsoleEntry(entry, pageUrl);
        };

        // Context menu for recording assertions
        coreWv2.ContextMenuRequested += (s, e) => Tab_ContextMenuRequestedAsync(tab, e);

        // Intercept keyboard shortcuts before WebView2 consumes them (e.g. Ctrl+N)
        webView.PreviewKeyDown += Tab_PreviewKeyDown;

        coreWv2.ServerCertificateErrorDetected += (_, e) =>
        {
            if (_automationContext?.IgnoreCertificateErrors == true)
            {
                e.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
                _automationContext.SetCertificateInterstitial(false);
                return;
            }

            _automationContext?.SetCertificateInterstitial(true);
        };

        // Client certificate selection for mutual TLS
        coreWv2.ClientCertificateRequested += (s, e) => Tab_ClientCertificateRequested(e);

        // JS hook for fast dialog handling; ScriptDialogOpening covers pages/contexts the hook misses.
        _ = coreWv2.AddScriptToExecuteOnDocumentCreatedAsync(DialogInterceptionScript);
        coreWv2.ScriptDialogOpening += (_, e) => Tab_ScriptDialogOpening(tab, e);

        // WebMCP tool detection — runs before any page script to intercept registerTool calls
        _ = coreWv2.AddScriptToExecuteOnDocumentCreatedAsync(WebMcpInterceptionScript);

        // WebSocket hook for send/close API and message-level testing
        _ = coreWv2.AddScriptToExecuteOnDocumentCreatedAsync(Trowser.Security.WebSocket.WebSocketJsBridge.HookScript);

        tab.WebSocket.ConnectionCreated += conn =>
        {
            if (_automationContext?.SecurityShadow != null)
                _securityShadow.OnWebSocketConnection(conn, _automationContext);
            _liveAuthzShadow?.NoteWebSocket(conn.Url);
        };
    }

    private const string WebMcpInterceptionScript = """
        (function() {
            window.__trowserWebMcp = { tools: {} };
            function hookMC(mc) {
                if (mc._tHooked) return;
                mc._tHooked = true;
                if (typeof mc.registerTool === 'function') {
                    var origRT = mc.registerTool.bind(mc);
                    mc.registerTool = function(td) {
                        var reg = origRT(td);
                        window.__trowserWebMcp.tools[td.name] = {
                            name: td.name,
                            description: td.description || '',
                            inputSchema: td.inputSchema || {},
                            annotations: td.annotations || null,
                            _exec: td.execute
                        };
                        if (reg && typeof reg.unregister === 'function') {
                            var origUn = reg.unregister.bind(reg);
                            reg.unregister = function() {
                                delete window.__trowserWebMcp.tools[td.name];
                                return origUn();
                            };
                        }
                        return reg;
                    };
                }
                if (typeof mc.provideContext === 'function') {
                    var origPC = mc.provideContext.bind(mc);
                    mc.provideContext = function(ctx) {
                        if (ctx && Array.isArray(ctx.tools)) {
                            ctx.tools.forEach(function(td) {
                                window.__trowserWebMcp.tools[td.name] = {
                                    name: td.name,
                                    description: td.description || '',
                                    inputSchema: td.inputSchema || {},
                                    annotations: td.annotations || null,
                                    _exec: td.execute
                                };
                            });
                        }
                        return origPC(ctx);
                    };
                }
            }
            if (navigator.modelContext) hookMC(navigator.modelContext);
            try {
                var _mc = navigator.modelContext || null;
                Object.defineProperty(navigator, 'modelContext', {
                    get: function() { return _mc; },
                    set: function(v) { _mc = v; if (v) hookMC(v); },
                    configurable: true, enumerable: true
                });
            } catch(e) {}
        })();
        """;

    /// <summary>
    /// Called by AutomationContext when the active tab changes (e.g. from script SwitchTab()).
    /// Updates the UI to show the correct tab.
    /// </summary>
    private void OnActiveTabChangedByContext(int newIndex)
    {
        Dispatcher.Invoke(() =>
        {
            UpdateActiveTabVisibility();
            UpdateNavigationUI();
            RebuildTabStrip();
            if (_powerMode.Config.Enabled && _automationContext?.ActiveTab != null)
                _ = ApplyPowerModeAfterNavAsync(_automationContext.ActiveTab, _automationContext.ActiveTab.WebView.CoreWebView2?.Source ?? "");
        });
    }

    /// <summary>
    /// Called by AutomationContext when a tab is removed.
    /// </summary>
    private void OnTabRemovedByContext(BrowserTab tab)
    {
        Dispatcher.Invoke(() =>
        {
            TabContentArea.Children.Remove(tab.WebView);
            RebuildTabStrip();
        });
    }

    /// <summary>
    /// Show only the active tab's WebView2, hide all others.
    /// </summary>
    private void UpdateActiveTabVisibility()
    {
        if (_automationContext == null) return;

        var activeTab = _automationContext.ActiveTab;
        foreach (var tab in _automationContext.Tabs)
        {
            tab.WebView.Visibility = tab == activeTab
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
    }

    /// <summary>
    /// Update address bar, nav buttons, and title based on the active tab.
    /// </summary>
    private void UpdateNavigationUI()
    {
        if (_automationContext == null) return;

        var activeTab = _automationContext.ActiveTab;
        if (activeTab == null) return;

        var webView = activeTab.WebView;
        var displayUrl = DisplayUrl(webView.Source?.ToString());
        AddressBar.Text = displayUrl;

        SetWindowTitleFromPage(string.IsNullOrEmpty(activeTab.Title) ? null : activeTab.Title);

        UpdateNavigationButtons();
    }

    private string DisplayUrl(string? url)
    {
        var overrideUrl = _automationContext?.ActiveTab?.DisplayUrlOverride;
        if (overrideUrl != null && (string.IsNullOrEmpty(url) || url.StartsWith("data:") || url == "about:blank"))
            return overrideUrl;
        if (string.IsNullOrEmpty(url) || url.StartsWith("data:"))
            return "Trowser - Exploratory Tester's Companion";
        if (url == "about:blank")
            return "";
        return url;
    }

    #endregion

    #region Tab Strip UI

    /// <summary>
    /// Rebuild the visual tab strip from scratch. Called when tabs are added, removed, or switched.
    /// </summary>
    private void RebuildTabStrip()
    {
        TabStrip.Children.Clear();
        if (_automationContext == null) return;

        var tabs = _automationContext.Tabs;
        var activeIndex = _automationContext.GetActiveTabIndex();

        for (int i = 0; i < tabs.Count; i++)
        {
            var tab = tabs[i];
            var isActive = i == activeIndex;
            var tabIndex = i;

            var tabItem = BuildTabStripItem(tab, isActive, tabIndex);
            TabStrip.Children.Add(tabItem);
        }
    }

    /// <summary>
    /// Build a single tab strip item (Border with title text and close button).
    /// </summary>
    private Border BuildTabStripItem(BrowserTab tab, bool isActive, int tabIndex)
    {
        var hasPageTitle = !string.IsNullOrEmpty(tab.Title) && tab.Title != "New Tab";
        var fullTitle = hasPageTitle
            ? tab.Title
            : (string.IsNullOrEmpty(tab.Url) ? "New Tab" : tab.Url);
        var title = hasPageTitle
            ? tab.Title
            : (string.IsNullOrEmpty(tab.Url) ? "New Tab" : ShortenUrl(tab.Url));

        if (title.Length > 30)
            title = title[..27] + "...";

        var owner = tab.Owner ?? TabOwners.Human;
        var badge = new TextBlock
        {
            Text = TabOwners.Badge(owner),
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(owner switch
            {
                TabOwners.Agent => "#DCDCAA",
                TabOwners.Shared => "#4EC9B0",
                _ => "#9CDCFE"
            })),
            FontSize = 10,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0),
            ToolTip = TabOwners.Label(owner)
        };

        var titleText = new TextBlock
        {
            Text = title,
            Foreground = new SolidColorBrush(isActive
                ? (Color)ColorConverter.ConvertFromString("#FFFFFF")
                : (Color)ColorConverter.ConvertFromString("#999999")),
            VerticalAlignment = VerticalAlignment.Center,
            FontSize = 12,
            FontFamily = new FontFamily("Segoe UI"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            MaxWidth = 150,
            Margin = new Thickness(4, 0, 4, 0)
        };

        var closeBtn = new Button
        {
            Content = "\u2715",
            FontSize = 9,
            Width = 18,
            Height = 18,
            Margin = new Thickness(2, 0, 4, 0),
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#888888")),
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Close Tab (Ctrl+W)"
        };
        closeBtn.Click += (s, e) =>
        {
            e.Handled = true;
            CloseTabByIndex(tabIndex);
        };

        var panel = new DockPanel { VerticalAlignment = VerticalAlignment.Center };
        DockPanel.SetDock(closeBtn, Dock.Right);
        panel.Children.Add(closeBtn);
        DockPanel.SetDock(badge, Dock.Left);
        panel.Children.Add(badge);
        panel.Children.Add(titleText);

        var border = new Border
        {
            Background = new SolidColorBrush(isActive
                ? (Color)ColorConverter.ConvertFromString("#2D2D30")
                : (Color)ColorConverter.ConvertFromString("#252526")),
            BorderBrush = new SolidColorBrush(isActive
                ? (Color)ColorConverter.ConvertFromString("#007ACC")
                : (Color)ColorConverter.ConvertFromString("#3F3F46")),
            BorderThickness = new Thickness(0, 0, 0, isActive ? 2 : 0),
            CornerRadius = new CornerRadius(4, 4, 0, 0),
            Margin = new Thickness(1, 0, 1, 0),
            MinWidth = 80,
            MaxWidth = 200,
            VerticalAlignment = VerticalAlignment.Stretch,
            Cursor = Cursors.Hand,
            Child = panel,
            ToolTip = fullTitle
        };

        // Tabs sit inside the window's caption area; without this the WindowChrome
        // caption swallows clicks and drags the window instead of switching tabs.
        System.Windows.Shell.WindowChrome.SetIsHitTestVisibleInChrome(border, true);

        border.MouseLeftButtonDown += (s, e) =>
        {
            if (_automationContext != null && tabIndex < _automationContext.Tabs.Count)
            {
                _automationContext.SwitchTab(tabIndex);
            }
        };

        // Middle-click to close
        border.MouseDown += (s, e) =>
        {
            if (e.ChangedButton == MouseButton.Middle)
            {
                CloseTabByIndex(tabIndex);
                e.Handled = true;
            }
        };

        // Hover effect
        border.MouseEnter += (s, e) =>
        {
            if (!isActive)
                border.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2A2A2E"));
        };
        border.MouseLeave += (s, e) =>
        {
            if (!isActive)
                border.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#252526"));
        };

        return border;
    }

    private static string ShortenUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return uri.Host + (uri.AbsolutePath == "/" ? "" : uri.AbsolutePath);
        return url;
    }

    private void NewTabButton_Click(object sender, RoutedEventArgs e)
    {
        _ = CreateNewTabFromUIAsync(null);
    }

    private async Task CreateNewTabFromUIAsync(string? url)
    {
        if (_automationContext == null)
        {
            _openDevToolsForPageOpenedTab = false;
            return;
        }

        try
        {
            await _automationContext.NewTab(url, TabOwners.Human);
            UpdateActiveTabVisibility();
            UpdateNavigationUI();

            if (string.IsNullOrEmpty(url))
                FocusAddressBar(deferred: true);
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to create tab: {ex.Message}";
        }
    }

    private void FocusAddressBar(bool deferred = false)
    {
        void focus()
        {
            AddressBar.Focus();
            AddressBar.SelectAll();
        }

        if (deferred)
            Dispatcher.BeginInvoke(focus, DispatcherPriority.Input);
        else
            focus();
    }

    private async void CloseTabByIndex(int tabIndex)
    {
        if (_automationContext == null) return;
        if (_automationContext.Tabs.Count <= 1) return;

        try
        {
            await _automationContext.CloseTab(tabIndex);
            UpdateActiveTabVisibility();
            UpdateNavigationUI();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to close tab: {ex.Message}";
        }
    }

    #endregion

    #region Tab WebView2 Events

    /// <summary>
    /// Schemes that WebView2 handles internally. Any other absolute URI scheme
    /// is treated as an external protocol and launched via the OS shell — this
    /// mirrors Chrome/Edge behaviour for bankid://, swish://, tel:, mailto:, etc.
    /// </summary>
    private static readonly HashSet<string> InternalSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https", "file", "about", "data", "blob", "javascript", "edge"
    };

    private static bool IsExternalProtocol(string url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        return !InternalSchemes.Contains(uri.Scheme);
    }

    /// <summary>
    /// URL schemes that are never handed to the OS shell, regardless of user confirmation.
    /// These protocol handlers have documented abuse-to-RCE histories (e.g. ms-msdt/Follina,
    /// search-ms) or invoke installers/shells directly.
    /// </summary>
    private static readonly HashSet<string> BlockedExternalSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ms-msdt", "search", "search-ms", "ms-search", "ms-officecmd",
        "ms-cxh", "ms-cxh-full", "ms-appinstaller", "shell", "hcp",
        "ldap", "ldaps", "vscode", "vsls"
    };

    /// <summary>
    /// Launches an external protocol via the OS shell — but only after (1) rejecting a hard-coded
    /// set of dangerous schemes and (2) obtaining explicit user confirmation, mirroring the
    /// "Open external application?" prompt that Chrome/Edge show. Web content can trigger this
    /// (navigation / window.open), so silent ShellExecute of attacker-controlled URIs is not safe.
    /// </summary>
    private void LaunchExternalProtocol(string url)
    {
        var scheme = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Scheme : "external";

        if (BlockedExternalSchemes.Contains(scheme))
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Blocked potentially dangerous external protocol: {scheme}://";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            });
            return;
        }

        var approved = Dispatcher.Invoke(() =>
        {
            var display = url.Length > 300 ? url[..300] + "\u2026" : url;
            var result = System.Windows.MessageBox.Show(
                this,
                $"This page is trying to open an external application using the \"{scheme}://\" protocol:\n\n" +
                $"{display}\n\n" +
                "Only allow this if you trust the current page. Open the external application?",
                "Open external application?",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Warning,
                System.Windows.MessageBoxResult.No);
            return result == System.Windows.MessageBoxResult.Yes;
        });

        if (!approved)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Blocked {scheme}:// (not confirmed)";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            });
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Opened {scheme}:// URL in external application";
                StatusText.Foreground = new SolidColorBrush(Colors.White);
            });
        }
        catch (Exception)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"No application registered for {scheme}:// protocol";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            });
        }
    }

    private void Tab_NavigationStarting(BrowserTab tab, CoreWebView2NavigationStartingEventArgs e)
    {
        // A full document navigation is starting; any same-document soft navigation that was pending
        // is superseded and its post-navigation features will be handled by NavigationCompleted instead.
        tab.FullNavigationInProgress = true;
        CancelPendingSoftNavigation(tab);

        // The dark surface (set at tab creation) only exists to avoid a white flash on the empty/blank tab.
        // Once a real page loads, restore the normal white default so pages that don't set their own
        // background stay readable (dark-on-dark otherwise). about:blank keeps the dark surface.
        if (!e.Uri.StartsWith("about:blank", StringComparison.OrdinalIgnoreCase)
            && tab.WebView.DefaultBackgroundColor != System.Drawing.Color.White)
        {
            tab.WebView.DefaultBackgroundColor = System.Drawing.Color.White;
        }

        if (IsExternalProtocol(e.Uri))
        {
            e.Cancel = true;
            LaunchExternalProtocol(e.Uri);
            return;
        }

        if (!_navigationGuard.IsAllowed(e.Uri))
        {
            e.Cancel = true;
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Blocked: {e.Uri} is outside the navigation scope";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            });
            return;
        }

        tab.Console.MarkNavigationBoundary();
        tab.Network.MarkNavigationBoundary();
        _securityShadow.BeginPage();

        // The pointed-at DOM is about to be torn down — dismiss the overlay now so it doesn't flash
        // stale chips during the load (RunAmbientNavigationFeatures also covers SPA route changes).
        if (IsActiveTab(tab))
            DismissPointerOverlayForNavigation();

        if (!e.Uri.StartsWith("data:"))
        {
            tab.DisplayUrlOverride = null;
            tab.CurrentMainDocumentNavigationUrl = e.Uri;
        }

        Dispatcher.Invoke(() =>
        {
            StatusText.Text = $"Loading {e.Uri}...";
            StatusText.Foreground = new SolidColorBrush(Colors.White);

            if (IsActiveTab(tab))
                AddressBar.Text = DisplayUrl(e.Uri);
        });
    }

    private void Tab_ScriptDialogOpening(BrowserTab tab, CoreWebView2ScriptDialogOpeningEventArgs e)
    {
        tab.NativeScriptDialogOpen = true;
        try
        {
            var kind = e.Kind switch
            {
                CoreWebView2ScriptDialogKind.Alert => "alert",
                CoreWebView2ScriptDialogKind.Confirm => "confirm",
                CoreWebView2ScriptDialogKind.Prompt => "prompt",
                CoreWebView2ScriptDialogKind.Beforeunload => "beforeunload",
                _ => e.Kind.ToString().ToLowerInvariant()
            };

            tab.LastDialog = new Automation.DialogInfo
            {
                Type = kind,
                Message = e.Message ?? "",
                DefaultValue = e.Kind == CoreWebView2ScriptDialogKind.Prompt ? e.DefaultText : null
            };

            if (e.Kind == CoreWebView2ScriptDialogKind.Alert)
            {
                e.Accept();
                return;
            }

            if (e.Kind == CoreWebView2ScriptDialogKind.Confirm
                || e.Kind == CoreWebView2ScriptDialogKind.Beforeunload)
            {
                if (tab.DialogAccept)
                    e.Accept();
                return;
            }

            if (e.Kind == CoreWebView2ScriptDialogKind.Prompt)
            {
                if (!tab.DialogAccept)
                    return;
                e.ResultText = tab.DialogPromptText
                               ?? e.DefaultText
                               ?? "";
                e.Accept();
            }
        }
        finally
        {
            tab.NativeScriptDialogOpen = false;
        }
    }

    private void Tab_NavigationCompleted(BrowserTab tab, CoreWebView2NavigationCompletedEventArgs e)
    {
        // The full document navigation has settled (success or failure); subsequent SourceChanged
        // events without a new NavigationStarting are same-document SPA route changes.
        tab.FullNavigationInProgress = false;

        if (IsActiveTab(tab))
        {
            if (e.IsSuccess)
                _automationContext?.SetCertificateInterstitial(false);
            else if (e.WebErrorStatus.ToString().Contains("Certificate", StringComparison.OrdinalIgnoreCase))
                _automationContext?.SetCertificateInterstitial(true);
        }

        Dispatcher.Invoke(() =>
        {
            if (IsActiveTab(tab))
            {
                StatusText.Foreground = new SolidColorBrush(Colors.White);
                StatusText.Text = _recorder.IsRecording
                    ? "Recording\u2026"
                    : (e.IsSuccess ? "Ready" : $"Navigation failed: {e.WebErrorStatus}");
                UpdateNavigationButtons();
            }
        });

        if (e.IsSuccess && _recorder.IsRecording && IsActiveTab(tab))
        {
            if (_recorderAddressBarNav)
            {
                // Address-bar navigation: Navigate() was already written in NavigateTo,
                // just update the URL tracker and re-inject. Skip RecordNavigation to
                // avoid duplicate output and to absorb any redirect chain.
                _recorderAddressBarNav = false;
            }
            else
            {
                var url = tab.WebView.CoreWebView2?.Source ?? "";
                _recorder.RecordNavigation(url);
            }
            _ = InjectRecordingScriptAsync(tab);
        }
        else if (e.IsSuccess && IsActiveTab(tab) &&
                 (_sessionLogger.IsLogging || _mirrorController is { IsActive: true }))
        {
            // Session logging and Mirror Mode need the recording JS injected to capture browser actions
            _ = InjectRecordingScriptAsync(tab);
        }

        // Human-readable navigation narration (feeds "Add to bug" repro steps).
        if (e.IsSuccess && IsActiveTab(tab) && (_recorder.IsRecording || _sessionLogger.IsLogging))
            RecordNavigationNarration(tab.WebView.CoreWebView2?.Source ?? "");

        if (e.IsSuccess)
        {
            var url = tab.WebView.CoreWebView2?.Source ?? "";
            tab.LastNavigationSignalUrl = url;
            // This authoritative completion supersedes any soft-navigation debounce still pending
            // (e.g. a fragment navigation that raised both SourceChanged and NavigationCompleted).
            CancelPendingSoftNavigation(tab);
            RunAmbientNavigationFeatures(tab, url);
        }
    }

    /// <summary>
    /// Run the post-navigation automation features that should react to <em>any</em> navigation the
    /// user perceives as loading a new page: full document loads (from <see cref="Tab_NavigationCompleted"/>)
    /// and same-document SPA route changes (from <see cref="Tab_SoftNavigationCompleted"/>).
    /// </summary>
    private void RunAmbientNavigationFeatures(BrowserTab tab, string url)
    {
        // The page the agent pointed at just changed — dismiss the pointer overlay (the pointers
        // stay in the store; the overlay returns only when the agent points at the new page).
        if (IsActiveTab(tab))
            DismissPointerOverlayForNavigation();

        if (_isWatchModeActive && !_watchModeRunning && IsActiveTab(tab))
            _ = RunWatchModeScriptAsync();

        if (_securityShadow.Enabled)
            _ = _securityShadow.OnNavigationCompletedAsync(tab.WebView, url, tab);

        // Laws read facts from the active tab, so a background-tab load would evaluate the wrong page.
        if (_securityShadow.Enabled && _securityShadow.Config.LawsEnabled && IsActiveTab(tab))
            _ = _lawService.RunAfterNavigationAsync();

        if (_powerMode.Config.Enabled)
            _ = ApplyPowerModeAfterNavAsync(tab, url);
        else
            _ = _powerMode.RemoveAsync(tab.WebView);

        if (_redTeamWhisper.Config.Enabled && IsActiveTab(tab))
            _ = RunWhisperAfterNavAsync(tab, url);

        if (_automationContext?.ScreenCurtainEnabled == true)
            _ = ApplyScreenCurtainAfterNavAsync(tab);
        else if (_automationContext != null)
            _ = _automationContext.ScreenCurtain.RemoveAsync(tab.WebView);
    }

    private async Task ApplyScreenCurtainAfterNavAsync(BrowserTab tab)
    {
        try
        {
            await Task.Delay(150);
            if (_automationContext == null || !_automationContext.ScreenCurtainEnabled) return;
            await _automationContext.ScreenCurtain.ApplyAsync(tab.WebView);
        }
        catch
        {
            /* navigated away */
        }
    }

    private async Task ApplyPowerModeAfterNavAsync(BrowserTab tab, string url)
    {
        try
        {
            await Task.Delay(150);
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return;
            await _powerMode.ApplyAsync(tab.WebView, _powerMode.Config.ShowOverlays);
        }
        catch
        {
            /* navigated away */
        }
    }

    private async Task RunWhisperAfterNavAsync(BrowserTab tab, string url)
    {
        try
        {
            await Task.Delay(450);
            await _redTeamWhisper.AnalyzeAsync(tab.WebView, url, tab.Network);
        }
        catch
        {
            /* ignore */
        }
    }

    private void Tab_DocumentTitleChanged(BrowserTab tab)
    {
        Dispatcher.Invoke(() =>
        {
            tab.Title = tab.WebView.CoreWebView2?.DocumentTitle ?? "New Tab";

            if (IsActiveTab(tab))
                SetWindowTitleFromPage(string.IsNullOrEmpty(tab.Title) ? null : tab.Title);

            RebuildTabStrip();
        });
    }

    private void Tab_SourceChanged(BrowserTab tab)
    {
        Dispatcher.Invoke(() =>
        {
            var newUrl = tab.WebView.Source?.ToString() ?? "";
            tab.Url = newUrl;

            if (IsActiveTab(tab))
            {
                AddressBar.Text = DisplayUrl(tab.Url);
                UpdateNavigationButtons();
            }

            RebuildTabStrip();

            MaybeScheduleSoftNavigation(tab, newUrl);
        });
    }

    // SPA sites change routes with the History API (pushState/replaceState) or hash fragments
    // (e.g. "#/page"). WebView2 raises SourceChanged for these but usually skips NavigationStarting
    // and NavigationCompleted, so features that hook NavigationCompleted (watch mode, security
    // shadow, etc.) never fire. We treat a same-document URL change as a "soft navigation" and run
    // the same ambient features, so different kinds of sites are supported consistently.
    private const int SoftNavigationDebounceMs = 250;
    private readonly ConditionalWeakTable<BrowserTab, DispatcherTimer> _softNavTimers = new();
    private readonly ConditionalWeakTable<BrowserTab, DispatcherTimer> _sseLivePollTimers = new();

    /// <summary>
    /// Decide whether a SourceChanged represents a soft (same-document) navigation and, if so,
    /// schedule the post-navigation features. Full document loads are ignored here because they are
    /// handled by <see cref="Tab_NavigationCompleted"/>.
    /// </summary>
    private void EnsureSseLiveBodyPoll(BrowserTab tab)
    {
        if (_sseLivePollTimers.TryGetValue(tab, out _))
            return;

        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        timer.Tick += async (_, _) =>
        {
            if (tab.WebView.CoreWebView2 == null) return;
            if (tab.Sse.GetConnections(stateFilter: "open").Count == 0) return;
            try { await SseCdpLiveBodySync.PollOpenStreamsAsync(tab); }
            catch { /* best-effort */ }
        };
        timer.Start();
        _sseLivePollTimers.Add(tab, timer);
    }

    private void MaybeScheduleSoftNavigation(BrowserTab tab, string newUrl)
    {
        if (string.IsNullOrEmpty(newUrl))
            return;

        // A full document navigation is in flight; NavigationCompleted will run the features.
        if (tab.FullNavigationInProgress)
            return;

        // Already treated this exact URL as a navigation (full or soft).
        if (string.Equals(newUrl, tab.LastNavigationSignalUrl, StringComparison.Ordinal))
            return;

        // Only web/document routes are meaningful navigations for automation features.
        if (!IsSoftNavigable(newUrl))
        {
            tab.LastNavigationSignalUrl = newUrl;
            return;
        }

        // Record eagerly so a burst of pushState/replaceState/hashchange updates collapses to a
        // single logical navigation. The debounce timer fires the features once the URL settles.
        tab.LastNavigationSignalUrl = newUrl;

        if (!_softNavTimers.TryGetValue(tab, out var timer))
        {
            timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(SoftNavigationDebounceMs) };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                if (tab.FullNavigationInProgress)
                    return;
                var url = tab.WebView.CoreWebView2?.Source ?? tab.Url;
                Tab_SoftNavigationCompleted(tab, url);
            };
            _softNavTimers.Add(tab, timer);
        }

        timer.Stop();
        timer.Start();
    }

    /// <summary>Runs post-navigation features for a settled same-document SPA route change.</summary>
    private void Tab_SoftNavigationCompleted(BrowserTab tab, string url)
    {
        if (string.IsNullOrEmpty(url) || tab.FullNavigationInProgress)
            return;

        // Treat the route change like a page load for "since navigation" console/network grouping.
        tab.Console.MarkNavigationBoundary();
        tab.Network.MarkNavigationBoundary();
        _securityShadow.BeginPage();

        if (IsActiveTab(tab) && !_recorder.IsRecording)
            StatusText.Text = "Route changed (SPA)";

        RunAmbientNavigationFeatures(tab, url);
    }

    private void CancelPendingSoftNavigation(BrowserTab tab)
    {
        if (_softNavTimers.TryGetValue(tab, out var timer))
            timer.Stop();
    }

    private static bool IsSoftNavigable(string url) =>
        url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("file://", StringComparison.OrdinalIgnoreCase);

    private void Tab_NewWindowRequested(BrowserTab tab, CoreWebView2NewWindowRequestedEventArgs e)
    {
        if (IsExternalProtocol(e.Uri))
        {
            e.Handled = true;
            LaunchExternalProtocol(e.Uri);
            return;
        }

        if (!_navigationGuard.IsAllowed(e.Uri))
        {
            e.Handled = true;
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Blocked: {e.Uri} is outside the navigation scope";
                StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44747"));
            });
            return;
        }

        // Defer so we can create a CoreWebView2 and assign e.NewWindow — required to preserve
        // window.opener (navigating a fresh tab by URL alone breaks opener / postMessage popups).
        var deferral = e.GetDeferral();
        e.Handled = true;
        _ = CompleteNewWindowAsync(tab, e, deferral);
    }

    private async Task CompleteNewWindowAsync(
        BrowserTab openerTab,
        CoreWebView2NewWindowRequestedEventArgs e,
        CoreWebView2Deferral deferral)
    {
        try
        {
            _openDevToolsForPageOpenedTab = true;
            _deferNextTabNavigation = true;

            await await Dispatcher.InvokeAsync(async () =>
            {
                if (_automationContext == null)
                    return;

                var idx = await _automationContext.NewTabFromPageWindowAsync(openerTab);
                var newTab = _automationContext.Tabs[idx];
                // New tabs have empty mock/intercept lists — copy from the opener so
                // fixture mocks (and session intercept rules) still apply to popups.
                newTab.CopyNetworkRulesFrom(openerTab);
                e.NewWindow = newTab.WebView.CoreWebView2;
                UpdateActiveTabVisibility();
                UpdateNavigationUI();
            });
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"NewWindowRequested failed: {ex.Message}");
            _deferNextTabNavigation = false;
            _openDevToolsForPageOpenedTab = false;
        }
        finally
        {
            deferral.Complete();
        }
    }

    private void Tab_FrameCreated(BrowserTab tab, CoreWebView2FrameCreatedEventArgs e)
    {
        var frame = e.Frame;
        var entry = tab.Frames.Register(frame);
        // Iframes cannot reach the top-level WebMessageReceived; wire each frame so the
        // runtime sensor (and other host bridges) work inside child frames (same- and cross-origin).
        frame.WebMessageReceived += (s, args) =>
            Tab_WebMessageReceived(tab, args, entry.Name, entry.Origin ?? FrameRegistry.TryOrigin(entry.Url), isFrame: true);

        // Nested frames
        try
        {
            frame.FrameCreated += (_, nested) =>
            {
                var child = tab.Frames.Register(nested.Frame, entry.FrameId);
                nested.Frame.WebMessageReceived += (s2, args2) =>
                    Tab_WebMessageReceived(tab, args2, child.Name, child.Origin ?? FrameRegistry.TryOrigin(child.Url), isFrame: true);
            };
        }
        catch
        {
            /* FrameCreated on child frames may be unavailable on older runtimes */
        }
    }

    private static string? TryGetFrameOrigin(CoreWebView2Frame frame)
    {
        try
        {
            var src = frame.GetType().GetProperty("Source")?.GetValue(frame) as string;
            if (!string.IsNullOrEmpty(src) && Uri.TryCreate(src, UriKind.Absolute, out var uri))
                return uri.GetLeftPart(UriPartial.Authority);
            return string.IsNullOrEmpty(frame.Name) ? null : frame.Name;
        }
        catch
        {
            return null;
        }
    }

    private bool IsActiveTab(BrowserTab tab)
    {
        return _automationContext?.ActiveTab == tab;
    }

    private void Tab_ClientCertificateRequested(CoreWebView2ClientCertificateRequestedEventArgs e)
    {
        var thumbprint = _sslManager.GetActiveThumbprint();
        if (string.IsNullOrEmpty(thumbprint))
            return; // No active cert — let WebView2 handle normally (show picker or skip)

        // Find matching certificate from WebView2's available certs
        foreach (var cert in e.MutuallyTrustedCertificates)
        {
            if (string.Equals(cert.DerEncodedSerialNumber, thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                e.SelectedCertificate = cert;
                e.Handled = true;
                return;
            }
        }

        // Also try matching by the PEM fingerprint
        // WebView2 exposes certificates that the OS cert store knows about,
        // so the active cert should be present if it was installed
        foreach (var cert in e.MutuallyTrustedCertificates)
        {
            // Match by display name or subject as fallback
            var activeInfo = _sslManager.GetActive();
            if (activeInfo != null &&
                cert.Subject.Contains(activeInfo.Subject.Replace("CN=", ""), StringComparison.OrdinalIgnoreCase))
            {
                e.SelectedCertificate = cert;
                e.Handled = true;
                return;
            }
        }
    }

    private void UpdateNavigationButtons()
    {
        var wv = ActiveWebView;
        if (wv != null)
        {
            BackButton.IsEnabled = wv.CanGoBack;
            ForwardButton.IsEnabled = wv.CanGoForward;
        }
    }

    private void WireDownloadNotifications(BrowserTab tab)
    {
        void OnDownloadEvent(DownloadEntry entry) => NotifyDownloadIfTerminal(tab, entry);

        tab.Downloads.EntryAdded += OnDownloadEvent;
        tab.Downloads.EntryUpdated += OnDownloadEvent;
    }

    private void NotifyDownloadIfTerminal(BrowserTab tab, DownloadEntry entry)
    {
        if (entry.State == DownloadState.Completed)
        {
            Dispatcher.Invoke(() =>
            {
                var size = FormatDownloadSize(entry.BytesReceived);
                var message = $"Downloaded {entry.SuggestedFileName} ({size})";
                if (!string.IsNullOrEmpty(entry.Path))
                    message += $"\n{entry.Path}";

                ShowApiMessage(message, "info", 9000, entry.Path);
                if (IsActiveTab(tab))
                {
                    StatusText.Foreground = new SolidColorBrush(Colors.White);
                    StatusText.Text = $"Downloaded {entry.SuggestedFileName} ({size})";
                }
            });
            return;
        }

        if (entry.State is DownloadState.Interrupted or DownloadState.Cancelled)
        {
            Dispatcher.Invoke(() =>
            {
                var reason = string.IsNullOrEmpty(entry.InterruptReason)
                    ? entry.State.ToString()
                    : $"{entry.State}: {entry.InterruptReason}";
                ShowApiMessage($"Download failed — {entry.SuggestedFileName} ({reason})", "warning", 9000);
            });
        }
    }

    private static string FormatDownloadSize(long bytes)
    {
        if (bytes < 1024)
            return bytes.ToString(CultureInfo.InvariantCulture) + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024.0).ToString("0.#", CultureInfo.InvariantCulture) + " KB";
        return (bytes / (1024.0 * 1024.0)).ToString("0.#", CultureInfo.InvariantCulture) + " MB";
    }

    #endregion
}
