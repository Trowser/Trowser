using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Trowser.Automation;
using Trowser.EndpointProbe;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Modeless dialog for composing and sending arbitrary HTTP requests.
/// Compose tab: browser navigation and HttpClient. Raw tab: HTTP/1.x bytes on TCP/TLS.
/// </summary>
public class RequestEditorDialog : Window
{
    private readonly AutomationContext _context;

    // Saved requests
    private List<SavedHttpRequest> _savedRequests;
    private readonly ComboBox _savedRequestsCombo;

    // Compose fields
    private readonly ComboBox _methodCombo;
    private readonly TextBox _urlBox;
    private readonly TextBox _headersBox;
    private readonly TextBox _bodyBox;
    private readonly CheckBox _followRedirectsCheck;
    private readonly TextBox _composeRepeatBox;
    private readonly TextBox _rawRepeatBox;

    // Raw tab
    private readonly TextBox _rawTargetUrl;
    private readonly TextBox _rawRequestLine;
    private readonly TextBox _rawHeadersBox;
    private readonly TextBox _rawBodyBox;
    private readonly TextBox _rawPreviewBox;
    private readonly TabControl _tabs;
    private bool _suppressTabSync;
    private bool _suppressRepeatSync;
    private int _lastTabIndex;

    private const int ComposeTabIndex = 0;
    private const int RawTabIndex = 1;
    private const int MaxRepeatCount = 50;

    // Response display
    private readonly StackPanel _responseSection;
    private readonly TextBlock _responseStatus;
    private readonly TextBlock _responseTime;
    private readonly TextBox _responseHeadersBox;
    private readonly TextBox _responseBodyBox;
    private readonly TextBox _requestSentBox;
    private readonly TextBlock _requestSentLabel;
    private readonly TextBlock _loadingText;
    private readonly TextBlock _sendNote;
    private readonly TextBlock _repeatResultText;
    private readonly Button _overrideBtn;
    private HeaderOverrideDialog? _overrideDialog;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentOrange = Bc("#CE9178");
    private static readonly SolidColorBrush AccentYellow = Bc("#CCA700");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");

    private static readonly string[] HttpMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "M-SEARCH", "QUERY"];

    public RequestEditorDialog(AutomationContext context, Window owner, string? defaultUrl)
    {
        _context = context;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "HTTP Request Editor";
        Width = 800;
        Height = 780;
        MinWidth = 550;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        _savedRequests = RequestSettings.Load();

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };

        var root = new StackPanel { Margin = new Thickness(20, 16, 20, 8) };

        // ─── Saved Requests ───
        AddSectionHeader(root, "Saved Requests");

        var savedRow = new DockPanel { Margin = new Thickness(0, 4, 0, 0) };

        var savedButtons = new StackPanel { Orientation = Orientation.Horizontal };
        DockPanel.SetDock(savedButtons, Dock.Right);

        var saveBtn = CreateSmallButton("Save", AccentGreen);
        saveBtn.Click += SaveRequest_Click;
        savedButtons.Children.Add(saveBtn);

        var saveAsBtn = CreateSmallButton("Save As\u2026", Bc("#3F3F46"));
        saveAsBtn.Margin = new Thickness(4, 0, 0, 0);
        saveAsBtn.Click += SaveRequestAs_Click;
        savedButtons.Children.Add(saveAsBtn);

        var deleteBtn = CreateSmallButton("Delete", AccentRed);
        deleteBtn.Margin = new Thickness(4, 0, 0, 0);
        deleteBtn.Click += DeleteRequest_Click;
        savedButtons.Children.Add(deleteBtn);

        savedRow.Children.Add(savedButtons);

        var savedLeft = new StackPanel { Orientation = Orientation.Horizontal };

        var importCurlBtn = CreateSmallButton("Import\u2026", Bc("#3F3F46"));
        importCurlBtn.ToolTip = "Load the Compose tab from a pasted curl command (bash / Copy as cURL from Chrome or this editor)";
        importCurlBtn.Click += ImportCurl_Click;
        savedLeft.Children.Add(importCurlBtn);

        _savedRequestsCombo = CreateStyledComboBox(false);
        _savedRequestsCombo.Margin = new Thickness(8, 0, 8, 0);
        _savedRequestsCombo.SelectionChanged += SavedRequestsCombo_SelectionChanged;
        savedLeft.Children.Add(_savedRequestsCombo);

        savedRow.Children.Add(savedLeft);

        root.Children.Add(savedRow);

        _tabs = CreateDarkTabControl();
        _tabs.Margin = new Thickness(0, 10, 0, 0);

        var composePanel = new StackPanel();
        AddHint(composePanel, "Send (Browser) navigates this tab (page cookies and session). Send (Direct) uses HttpClient (bypasses CORS; no cookie jar unless you set Cookie). For Transfer-Encoding, Content-Length, or HTTP/1.x version tokens, use the Raw tab.");

        var urlRow = new Grid { Margin = new Thickness(0, 6, 0, 0) };
        urlRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        urlRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _methodCombo = CreateStyledComboBox(true);
        _methodCombo.Width = 94;
        foreach (var m in HttpMethods)
            _methodCombo.Items.Add(m);
        _methodCombo.SelectedIndex = 0;
        Grid.SetColumn(_methodCombo, 0);
        urlRow.Children.Add(_methodCombo);

        _urlBox = CreateInputBox(defaultUrl ?? "");
        _urlBox.Margin = new Thickness(4, 0, 0, 0);
        Grid.SetColumn(_urlBox, 1);
        urlRow.Children.Add(_urlBox);
        composePanel.Children.Add(urlRow);

        var urlLabels = new Grid { Margin = new Thickness(0, 1, 0, 0) };
        urlLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        urlLabels.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        AddMicroLabel(urlLabels, "Method", 0);
        AddMicroLabel(urlLabels, "URL", 1, new Thickness(4, 0, 0, 0));
        composePanel.Children.Add(urlLabels);

        var headersLabelRow = new DockPanel { Margin = new Thickness(0, 10, 0, 2) };
        var loadHeadersBtn = CreateSmallButton("Load Session Headers", Bc("#3F3F46"));
        loadHeadersBtn.ToolTip = "Populate with headers from the last page navigation in this session";
        loadHeadersBtn.Click += LoadSessionHeaders_Click;
        DockPanel.SetDock(loadHeadersBtn, Dock.Right);
        headersLabelRow.Children.Add(loadHeadersBtn);
        headersLabelRow.Children.Add(new TextBlock
        {
            Text = "Headers",
            Foreground = FgDim,
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center
        });
        composePanel.Children.Add(headersLabelRow);

        _headersBox = CreateMultilineBox("", 4);
        _headersBox.ToolTip = "One header per line: Name: Value";
        composePanel.Children.Add(_headersBox);

        composePanel.Children.Add(new TextBlock
        {
            Text = "Send (Browser): Chromium supplies Host, Connection, Content-Length, and the cookie jar. Send (Direct): HttpClient computes Content-Length and ignores Transfer-Encoding. Use the Raw tab to send those headers as written.",
            Foreground = AccentOrange,
            FontSize = 10,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap
        });

        AddFieldLabel(composePanel, "Body");
        _bodyBox = CreateMultilineBox("", 5);
        composePanel.Children.Add(_bodyBox);

        _followRedirectsCheck = new CheckBox
        {
            Content = "Follow redirects",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 6, 0, 0),
            IsChecked = false,
            ToolTip = "When unchecked, 3xx redirect responses are returned as-is (Direct only)"
        };
        composePanel.Children.Add(_followRedirectsCheck);

        var sendRow = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
        var sendBrowserBtn = CreateActionButton("Send (Browser) \u25B6", AccentGreen,
            "Navigate this tab with the method, URL, and body. Chromium supplies Host/Connection/cookies; extra headers are applied to this navigation when WebView2 allows it. GET and POST only.");
        sendBrowserBtn.Click += SendBrowser_Click;
        sendRow.Children.Add(sendBrowserBtn);

        var sendDirectBtn = CreateActionButton("Send (Direct)", AccentBlue,
            "Send via HttpClient from Trowser — bypasses CORS, no browser cookie jar, no system proxy. Content-Length is computed; Transfer-Encoding is not sent.");
        sendDirectBtn.Margin = new Thickness(8, 0, 0, 4);
        sendDirectBtn.Click += SendDirect_Click;
        sendRow.Children.Add(sendDirectBtn);

        _composeRepeatBox = CreateRepeatCountBox();
        AddRepeatCount(sendRow, _composeRepeatBox, new Thickness(12, 0, 8, 4));

        var authControlBtn = CreateActionButton("Identify auth controls\u2026", AccentOrange,
            "Replay this request as baseline, then omit and one-character-tamper each auth-related cookie, header, and token field. Requires Active safety (not --safe).");
        authControlBtn.Margin = new Thickness(0, 0, 8, 4);
        authControlBtn.Click += IdentifyAuthControls_Click;
        sendRow.Children.Add(authControlBtn);

        var curlBtn = CreateActionButton("cURL to clipboard (bash)", Bc("#3F3F46"),
            "Copy a one-line bash curl command (Chrome DevTools style). Browser headers such as User-Agent, Sec-Fetch-*, and Accept-Language are left out.");
        curlBtn.Margin = new Thickness(0, 0, 0, 4);
        curlBtn.Click += CopyCurl_Click;
        sendRow.Children.Add(curlBtn);
        composePanel.Children.Add(sendRow);

        var rawPanel = new StackPanel();
        AddHint(rawPanel, "HTTP/1.x bytes on a new TCP/TLS connection. The request line (including the version token), headers, and body go on the wire as shown in the preview. Session header overrides are not applied.");

        AddFieldLabel(rawPanel, "Target URL (connect / SNI)");
        _rawTargetUrl = CreateInputBox(defaultUrl ?? "");
        rawPanel.Children.Add(_rawTargetUrl);

        var rawLineRow = new DockPanel { Margin = new Thickness(0, 8, 0, 2) };
        var loadComposeBtn = CreateSmallButton("Load from Compose", Bc("#3F3F46"));
        loadComposeBtn.ToolTip = "Copy method, path, headers, and body from the Compose tab";
        loadComposeBtn.Click += LoadFromCompose_Click;
        DockPanel.SetDock(loadComposeBtn, Dock.Right);
        rawLineRow.Children.Add(loadComposeBtn);
        rawLineRow.Children.Add(new TextBlock
        {
            Text = "Request line",
            Foreground = FgDim,
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center
        });
        rawPanel.Children.Add(rawLineRow);

        _rawRequestLine = CreateInputBox("GET / HTTP/1.1");
        rawPanel.Children.Add(_rawRequestLine);

        AddFieldLabel(rawPanel, "Headers (verbatim — duplicates and TE/CL are sent)");
        _rawHeadersBox = CreateMultilineBox("", 5);
        rawPanel.Children.Add(_rawHeadersBox);

        AddFieldLabel(rawPanel, "Body");
        _rawBodyBox = CreateMultilineBox("", 4);
        rawPanel.Children.Add(_rawBodyBox);

        AddFieldLabel(rawPanel, "Bytes preview");
        _rawPreviewBox = CreateMultilineBox("", 4);
        _rawPreviewBox.IsReadOnly = true;
        _rawPreviewBox.Foreground = FgDim;
        rawPanel.Children.Add(_rawPreviewBox);

        var sendRawBtn = CreateActionButton("Send Raw", AccentOrange,
            "Write the preview bytes on a new HTTP/1.1 TCP/TLS connection. No cookie jar, no proxy, no redirects.");
        sendRawBtn.Margin = new Thickness(0, 12, 0, 0);
        sendRawBtn.HorizontalAlignment = HorizontalAlignment.Left;
        sendRawBtn.Click += SendRaw_Click;

        var curlRawBtn = CreateActionButton("cURL to clipboard (bash)", Bc("#3F3F46"),
            "Copy a one-line bash curl command from this tab's target URL, request-line method, headers, and body.");
        curlRawBtn.Margin = new Thickness(0, 12, 0, 0);
        curlRawBtn.Click += CopyCurlFromRaw_Click;

        var rawSendRow = new WrapPanel { Margin = new Thickness(0, 0, 0, 0) };
        rawSendRow.Children.Add(sendRawBtn);
        _rawRepeatBox = CreateRepeatCountBox();
        AddRepeatCount(rawSendRow, _rawRepeatBox, new Thickness(12, 12, 8, 0));
        rawSendRow.Children.Add(curlRawBtn);
        _composeRepeatBox.TextChanged += (_, _) => SyncRepeatCount(_composeRepeatBox, _rawRepeatBox);
        _rawRepeatBox.TextChanged += (_, _) => SyncRepeatCount(_rawRepeatBox, _composeRepeatBox);
        rawPanel.Children.Add(rawSendRow);

        _rawTargetUrl.TextChanged += (_, _) => RefreshRawPreview();
        _rawRequestLine.TextChanged += (_, _) => RefreshRawPreview();
        _rawHeadersBox.TextChanged += (_, _) => RefreshRawPreview();
        _rawBodyBox.TextChanged += (_, _) => RefreshRawPreview();

        _tabs.Items.Add(CreateTabItem("Compose", composePanel));
        _tabs.Items.Add(CreateTabItem("Raw", rawPanel));
        _tabs.SelectionChanged += Tabs_SelectionChanged;
        root.Children.Add(_tabs);

        // ─── Loading indicator ───
        _loadingText = new TextBlock
        {
            Text = "\u23F3 Sending request\u2026",
            Foreground = AccentBlue,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 0),
            Visibility = Visibility.Collapsed
        };
        root.Children.Add(_loadingText);

        // ─── Response section (hidden until response arrives) ───
        _responseSection = new StackPanel { Visibility = Visibility.Collapsed };
        AddSectionHeader(_responseSection, "Response", 14);

        _repeatResultText = new TextBlock
        {
            Foreground = FgText,
            FontSize = 11,
            FontFamily = new FontFamily("Consolas"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 6, 0, 2),
            Visibility = Visibility.Collapsed
        };
        _responseSection.Children.Add(_repeatResultText);

        var statusRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(0, 4, 0, 0)
        };

        _responseStatus = new TextBlock
        {
            Foreground = FgText,
            FontSize = 13,
            FontFamily = new FontFamily("Consolas"),
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        };
        statusRow.Children.Add(_responseStatus);

        _responseTime = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 13,
            FontFamily = new FontFamily("Consolas"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0)
        };
        statusRow.Children.Add(_responseTime);
        _responseSection.Children.Add(statusRow);

        _sendNote = new TextBlock
        {
            Foreground = AccentOrange,
            FontSize = 11,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed
        };
        _responseSection.Children.Add(_sendNote);

        _requestSentLabel = new TextBlock
        {
            Text = "Request sent",
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 8, 0, 2),
            Visibility = Visibility.Collapsed
        };
        _responseSection.Children.Add(_requestSentLabel);
        _requestSentBox = CreateMultilineBox("", 4);
        _requestSentBox.IsReadOnly = true;
        _requestSentBox.Visibility = Visibility.Collapsed;
        _responseSection.Children.Add(_requestSentBox);

        AddFieldLabel(_responseSection, "Response Headers");
        _responseHeadersBox = CreateMultilineBox("", 4);
        _responseHeadersBox.IsReadOnly = true;
        _responseSection.Children.Add(_responseHeadersBox);

        AddFieldLabel(_responseSection, "Response Body");
        _responseBodyBox = CreateMultilineBox("", 8);
        _responseBodyBox.IsReadOnly = true;
        _responseSection.Children.Add(_responseBodyBox);

        root.Children.Add(_responseSection);

        scroll.Content = root;
        Grid.SetRow(scroll, 0);
        rootGrid.Children.Add(scroll);

        // ─── Bottom bar ───
        var bottomBar = new DockPanel { Margin = new Thickness(20, 8, 20, 12) };

        var closeBtn = CreateStyledButton("Close");
        closeBtn.Click += (_, _) => Close();
        DockPanel.SetDock(closeBtn, Dock.Right);
        bottomBar.Children.Add(closeBtn);

        var ioPanel = new StackPanel { Orientation = Orientation.Horizontal };
        var exportBtn = CreateSmallButton("Export\u2026", Bc("#3F3F46"));
        exportBtn.Click += Export_Click;
        ioPanel.Children.Add(exportBtn);

        var importBtn = CreateSmallButton("Import\u2026", Bc("#3F3F46"));
        importBtn.Margin = new Thickness(6, 0, 0, 0);
        importBtn.Click += Import_Click;
        ioPanel.Children.Add(importBtn);

        _overrideBtn = CreateSmallButton("Override\u2026", Bc("#3F3F46"));
        _overrideBtn.Margin = new Thickness(6, 0, 0, 0);
        _overrideBtn.ToolTip = "Session headers applied to all WebView2 browsing (replace if present, add if missing). Direct and Raw ignore these.";
        _overrideBtn.Click += Override_Click;
        ioPanel.Children.Add(_overrideBtn);

        DockPanel.SetDock(ioPanel, Dock.Left);
        bottomBar.Children.Add(ioPanel);

        Grid.SetRow(bottomBar, 1);
        rootGrid.Children.Add(bottomBar);

        Content = rootGrid;

        RefreshSavedRequestsCombo();
        PopulateFromLastNavigation(defaultUrl);
        LoadFromCompose_Click(this, new RoutedEventArgs());
        RefreshOverrideButton();
        HeaderOverrideSettings.Changed += OnHeaderOverridesChanged;
        Closed += (_, _) => HeaderOverrideSettings.Changed -= OnHeaderOverridesChanged;
    }

    private void OnHeaderOverridesChanged()
    {
        if (!Dispatcher.CheckAccess())
            Dispatcher.Invoke(RefreshOverrideButton);
        else
            RefreshOverrideButton();
    }

    private void RefreshOverrideButton()
    {
        var n = HeaderOverrideSettings.EnabledCount;
        _overrideBtn.Content = n > 0 ? $"Override ({n})\u2026" : "Override\u2026";
    }

    private void Override_Click(object sender, RoutedEventArgs e)
    {
        if (_overrideDialog != null)
        {
            _overrideDialog.Activate();
            return;
        }

        var dlg = new HeaderOverrideDialog(this);
        _overrideDialog = dlg;
        dlg.Closed += (_, _) =>
        {
            if (ReferenceEquals(_overrideDialog, dlg))
                _overrideDialog = null;
        };
        dlg.Show();
    }

    // ─────────────────── Populate from session ───────────────────

    private void PopulateFromLastNavigation(string? fallbackUrl)
    {
        var entries = _context.Network.Entries;
        var docEntry = entries
            .Where(e => e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase))
            .LastOrDefault();

        if (docEntry != null)
        {
            _urlBox.Text = docEntry.Url;
            SetMethodCombo(docEntry.Method);
            _headersBox.Text = FormatHeaders(docEntry.RequestHeaders);
            _bodyBox.Text = docEntry.RequestBody ?? "";
        }
        else if (!string.IsNullOrWhiteSpace(fallbackUrl) &&
                 !fallbackUrl.StartsWith("Trowser", StringComparison.OrdinalIgnoreCase))
        {
            _urlBox.Text = fallbackUrl;
        }
    }

    private void LoadSessionHeaders_Click(object sender, RoutedEventArgs e)
    {
        var entries = _context.Network.Entries;
        var docEntry = entries
            .Where(en => en.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase))
            .LastOrDefault();

        if (docEntry != null)
        {
            _headersBox.Text = FormatHeaders(docEntry.RequestHeaders);
        }
        else
        {
            MessageBox.Show(
                "No page navigation found in the network log.\nBrowse to a page first so headers can be captured.",
                "No Session Headers",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    // ─────────────────── Send (Browser) ───────────────────

    private void SendBrowser_Click(object sender, RoutedEventArgs e)
    {
        var url = EnsureNavigableUrl(_urlBox.Text.Trim());
        if (string.IsNullOrEmpty(url)) return;

        var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
        var headers = ParseHeaders(_headersBox.Text);
        var body = string.IsNullOrEmpty(_bodyBox.Text.Trim()) ? null : _bodyBox.Text;

        if (method is not ("GET" or "POST"))
        {
            MessageBox.Show(
                "Send (Browser) uses WebView2 navigation, which only supports GET and POST.\n\n" +
                "Use Send (Direct) for " + method + " and other methods.",
                "Unsupported method",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var tab = _context.ActiveTab;
        var webView = tab?.WebView;
        var coreWv = webView?.CoreWebView2;
        if (tab == null || webView == null || coreWv == null)
        {
            MessageBox.Show("No active browser tab available.", "Send Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_context.NavigationGuard != null && !_context.NavigationGuard.IsAllowed(url))
        {
            MessageBox.Show($"{url} is outside the navigation scope.", "Send Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var overlay = RequestEditorHttp.ForBrowserNavigation(headers);
            if (overlay.Count > 0)
                tab.ArmRequestHeaderOverlay(method, url, overlay);

            if (method == "GET")
            {
                // Same path as pressing Enter in the address bar. Do not use
                // NavigateWithWebResourceRequest for GET: it plus a full captured
                // header dump often writes the URL without starting the load.
                if (IsSameDocumentUrl(coreWv.Source, url))
                    coreWv.Reload();
                else if (Owner is MainWindow main)
                    main.NavigateTo(url);
                else
                    coreWv.Navigate(url);
            }
            else
            {
                Stream? bodyStream = body != null
                    ? new MemoryStream(Encoding.UTF8.GetBytes(body))
                    : null;
                var contentType = overlay.TryGetValue("Content-Type", out var ct) ? $"Content-Type: {ct}\r\n" : "";
                var request = coreWv.Environment.CreateWebResourceRequest(
                    url, method, bodyStream, contentType);
                coreWv.NavigateWithWebResourceRequest(request);
            }

            Close();
        }
        catch (Exception ex)
        {
            tab.ClearRequestHeaderOverlay();
            MessageBox.Show($"Failed to send request in browser:\n{ex.Message}", "Send Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static bool IsSameDocumentUrl(string? current, string target)
    {
        if (string.IsNullOrEmpty(current) || string.IsNullOrEmpty(target))
            return false;
        if (!Uri.TryCreate(current, UriKind.Absolute, out var cur))
            return false;
        if (!Uri.TryCreate(target, UriKind.Absolute, out var tgt))
            return false;
        return Uri.Compare(cur, tgt,
            UriComponents.SchemeAndServer | UriComponents.Path | UriComponents.Query | UriComponents.Fragment,
            UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;
    }

    private static string EnsureNavigableUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
            return url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeFile))
            return url;
        if (url.StartsWith("localhost", StringComparison.OrdinalIgnoreCase) &&
            (url.Length == 9 || url[9] is ':' or '/'))
            return "http://" + url;
        if (!url.Contains("://", StringComparison.Ordinal) && url.Contains('.') && !url.Contains(' '))
            return "https://" + url;
        return url;
    }

    // ─────────────────── Raw tab ───────────────────

    private void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressTabSync || !ReferenceEquals(e.OriginalSource, _tabs))
            return;

        var index = _tabs.SelectedIndex;
        if (index == _lastTabIndex)
            return;

        _suppressTabSync = true;
        try
        {
            if (index == RawTabIndex)
                CopyComposeToRaw();
            else if (index == ComposeTabIndex)
                CopyRawToCompose();
            _lastTabIndex = index;
        }
        finally
        {
            _suppressTabSync = false;
        }
    }

    private void LoadFromCompose_Click(object sender, RoutedEventArgs e) => CopyComposeToRaw();

    private void CopyComposeToRaw()
    {
        var url = _urlBox.Text.Trim();
        _rawTargetUrl.Text = url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            _rawRequestLine.Text = RawHttpClient.DefaultRequestLine(_methodCombo.Text ?? "GET", uri);
        else
            _rawRequestLine.Text = $"{(_methodCombo.Text ?? "GET").Trim()} / HTTP/1.1";
        _rawHeadersBox.Text = _headersBox.Text;
        _rawBodyBox.Text = _bodyBox.Text;
        RefreshRawPreview();
    }

    private void CopyRawToCompose()
    {
        var method = MethodFromRequestLine(_rawRequestLine.Text);
        _urlBox.Text = RequestEditorMapping.ComposeUrl(_rawTargetUrl.Text, _rawRequestLine.Text);
        SetMethodCombo(method);
        _headersBox.Text = _rawHeadersBox.Text;
        _bodyBox.Text = _rawBodyBox.Text;
    }

    private void RefreshRawPreview()
    {
        try
        {
            var targetText = _rawTargetUrl.Text.Trim();
            if (!Uri.TryCreate(targetText, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                _rawPreviewBox.Text = "(set an http(s) Target URL to preview)";
                return;
            }

            var line = _rawRequestLine.Text.Trim();
            if (line.Length == 0)
                line = RawHttpClient.DefaultRequestLine("GET", uri);

            var built = RawHttpClient.BuildRequest(line, _rawHeadersBox.Text, _rawBodyBox.Text, uri);
            _rawPreviewBox.Text = built.RequestSent;
        }
        catch (Exception ex)
        {
            _rawPreviewBox.Text = ex.Message;
        }
    }

    private async void SendRaw_Click(object sender, RoutedEventArgs e)
    {
        var targetText = _rawTargetUrl.Text.Trim();
        if (!Uri.TryCreate(targetText, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            MessageBox.Show("Target URL must be an absolute http or https URL.", "Send Raw",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var line = _rawRequestLine.Text.Trim();
        if (line.Length == 0)
            line = RawHttpClient.DefaultRequestLine("GET", uri);

        var count = ReadRepeatCount(_rawRepeatBox);
        var headerBlock = _rawHeadersBox.Text;
        var body = _rawBodyBox.Text;

        _loadingText.Text = count > 1
            ? $"\u23F3 Sending {count} concurrent raw requests\u2026"
            : "\u23F3 Sending raw HTTP/1.x request\u2026";
        _loadingText.Visibility = Visibility.Visible;
        _responseSection.Visibility = Visibility.Collapsed;

        try
        {
            if (count == 1)
            {
                var result = await RawHttpClient.SendAsync(uri, line, headerBlock, body);
                if (!IsLoaded) return;
                _loadingText.Visibility = Visibility.Collapsed;
                ShowRawResult(result, targetText);
                return;
            }

            var sw = Stopwatch.StartNew();
            var tasks = Enumerable.Range(0, count).Select(async _ =>
            {
                var result = await RawHttpClient.SendAsync(uri, line, headerBlock, body);
                var failed = result.Status == 0 && (result.Error != null || result.TimedOut);
                return (
                    result,
                    status: result.Status,
                    ms: (int)result.DurationMs,
                    error: failed ? (result.Error ?? "Timed out") : null);
            });

            var results = await Task.WhenAll(tasks);
            sw.Stop();
            if (!IsLoaded) return;

            _loadingText.Visibility = Visibility.Collapsed;
            ShowRawResult(results[^1].result, targetText);
            var rows = results.Select(r => (r.status, r.ms, r.error)).ToList();
            ShowRepeatSummary(
                FormatRepeatSummary(count, sw.ElapsedMilliseconds, rows),
                rows.Any(r => r.error != null) ? AccentYellow : AccentGreen);
        }
        catch (Exception ex)
        {
            if (!IsLoaded) return;
            _loadingText.Visibility = Visibility.Collapsed;
            ShowResponseError($"Raw request failed:\n{ex.Message}");
            ShowRepeatSummary($"\u274C Replay failed: {ex.Message}", AccentRed);
        }
    }

    private void ShowRawResult(RawHttpClient.RawResult result, string targetText)
    {
        if (result.Error != null && result.Status == 0 && !result.TimedOut)
        {
            ShowResponseError($"Raw request failed:\n{result.Error}");
            ShowRequestSent(result.RequestSent);
            return;
        }

        var note = result.TimedOut
            ? "Timed out waiting for a complete response (partial body may be shown)."
            : result.HostWasAdded
                ? "Host was added because the header block had no Host line."
                : null;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in result.Headers)
        {
            var colon = h.IndexOf(':');
            if (colon <= 0) continue;
            var name = h[..colon].Trim();
            var value = h[(colon + 1)..].Trim();
            if (headers.TryGetValue(name, out var existing))
                headers[name] = existing + ", " + value;
            else
                headers[name] = value;
        }

        var status = result.Status;
        var ok = status is >= 200 and < 300;
        ShowResponse(status == 0 && result.TimedOut ? 0 : status,
            result.TimedOut && status == 0 ? "Timeout" : result.StatusText,
            ok, false, targetText, headers, result.Body, null, result.DurationMs);
        if (note != null)
        {
            _sendNote.Text = note;
            _sendNote.Visibility = Visibility.Visible;
        }
        ShowRequestSent(result.RequestSent);
    }

    private void ShowRequestSent(string? requestSent)
    {
        if (string.IsNullOrEmpty(requestSent))
        {
            _requestSentLabel.Visibility = Visibility.Collapsed;
            _requestSentBox.Visibility = Visibility.Collapsed;
            _requestSentBox.Text = "";
            return;
        }

        _requestSentLabel.Visibility = Visibility.Visible;
        _requestSentBox.Visibility = Visibility.Visible;
        _requestSentBox.Text = requestSent;
    }

    // ─────────────────── Send (Direct) ───────────────────

    private async void SendDirect_Click(object sender, RoutedEventArgs e)
    {
        var url = _urlBox.Text.Trim();
        if (string.IsNullOrEmpty(url)) return;

        var count = ReadRepeatCount(_composeRepeatBox);
        if (count > 1)
        {
            await SendDirectRepeatedAsync(url, count);
            return;
        }

        var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
        var headerDict = ParseHeaders(_headersBox.Text);
        var bodyText = _bodyBox.Text;

        _loadingText.Text = "\u23F3 Sending request via HttpClient\u2026";
        _loadingText.Visibility = Visibility.Visible;
        _responseSection.Visibility = Visibility.Collapsed;

        try
        {
            var request = new HttpRequestMessage(new HttpMethod(method), url)
            {
                Version = HttpVersion.Version11,
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
            };

            if (!string.IsNullOrEmpty(bodyText))
                request.Content = new StringContent(bodyText, Encoding.UTF8);

            var skipped = RequestEditorHttp.ApplyHeaders(request, headerDict);

            using var handler = RequestEditorHttp.CreateHandler(
                allowAutoRedirect: _followRedirectsCheck.IsChecked == true,
                automaticDecompression: true);
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

            var sw = Stopwatch.StartNew();
            var response = await client.SendAsync(request);
            var respBody = await response.Content.ReadAsStringAsync();
            sw.Stop();
            var respHeaders = new Dictionary<string, string>();
            foreach (var h in response.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);
            foreach (var h in response.Content.Headers)
                respHeaders[h.Key] = string.Join(", ", h.Value);

            var status = (int)response.StatusCode;
            var statusText = response.ReasonPhrase ?? "";

            _loadingText.Visibility = Visibility.Collapsed;
            ShowResponse(status, statusText, status is >= 200 and < 300, false, url, respHeaders, respBody, skipped, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            _loadingText.Visibility = Visibility.Collapsed;
            ShowResponseError($"Direct request failed:\n{ex.Message}");
        }
    }

    private async Task SendDirectRepeatedAsync(string url, int count)
    {
        var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
        var headerDict = ParseHeaders(_headersBox.Text);
        var bodyText = _bodyBox.Text;
        var followRedirects = _followRedirectsCheck.IsChecked == true;

        _loadingText.Text = $"\u23F3 Sending {count} concurrent requests\u2026";
        _loadingText.Visibility = Visibility.Visible;
        _responseSection.Visibility = Visibility.Collapsed;

        try
        {
            using var handler = RequestEditorHttp.CreateHandler(
                allowAutoRedirect: followRedirects,
                automaticDecompression: true);
            handler.MaxConnectionsPerServer = count;
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

            var sw = Stopwatch.StartNew();
            var tasks = Enumerable.Range(0, count).Select(async i =>
            {
                var reqSw = Stopwatch.StartNew();
                try
                {
                    using var request = new HttpRequestMessage(new HttpMethod(method), url)
                    {
                        Version = HttpVersion.Version11,
                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                    };
                    if (!string.IsNullOrEmpty(bodyText))
                        request.Content = new StringContent(bodyText, Encoding.UTF8);
                    var skipped = RequestEditorHttp.ApplyHeaders(request, headerDict);

                    using var response = await client.SendAsync(request);

                    string? respBody = null;
                    Dictionary<string, string>? respHeaders = null;
                    var statusText = "";
                    if (i == count - 1)
                    {
                        respBody = await response.Content.ReadAsStringAsync();
                        statusText = response.ReasonPhrase ?? "";
                        respHeaders = new Dictionary<string, string>();
                        foreach (var h in response.Headers)
                            respHeaders[h.Key] = string.Join(", ", h.Value);
                        foreach (var h in response.Content.Headers)
                            respHeaders[h.Key] = string.Join(", ", h.Value);
                    }

                    reqSw.Stop();
                    return (
                        status: (int)response.StatusCode,
                        ms: (int)reqSw.ElapsedMilliseconds,
                        error: (string?)null,
                        statusText,
                        headers: respHeaders,
                        body: respBody,
                        skipped: (List<string>?)skipped);
                }
                catch (Exception ex)
                {
                    reqSw.Stop();
                    return (
                        status: 0,
                        ms: (int)reqSw.ElapsedMilliseconds,
                        error: (string?)ex.Message,
                        statusText: "",
                        headers: (Dictionary<string, string>?)null,
                        body: (string?)null,
                        skipped: (List<string>?)null);
                }
            });

            var results = await Task.WhenAll(tasks);
            sw.Stop();
            if (!IsLoaded) return;

            _loadingText.Visibility = Visibility.Collapsed;
            var last = results[^1];
            if (last.error != null)
                ShowResponseError($"Direct request failed:\n{last.error}");
            else
            {
                var status = last.status;
                ShowResponse(status, last.statusText, status is >= 200 and < 300, false, url,
                    last.headers ?? new Dictionary<string, string>(), last.body ?? "", last.skipped, last.ms);
            }

            var rows = results.Select(r => (r.status, r.ms, r.error)).ToList();
            ShowRepeatSummary(
                FormatRepeatSummary(count, sw.ElapsedMilliseconds, rows),
                rows.Any(r => r.error != null) ? AccentYellow : AccentGreen);
        }
        catch (Exception ex)
        {
            if (!IsLoaded) return;
            _loadingText.Visibility = Visibility.Collapsed;
            ShowResponseError($"Direct request failed:\n{ex.Message}");
            ShowRepeatSummary($"\u274C Replay failed: {ex.Message}", AccentRed);
        }
    }

    // ─────────────────── cURL to clipboard ───────────────────

    private void CopyCurl_Click(object sender, RoutedEventArgs e)
    {
        var url = EnsureNavigableUrl(_urlBox.Text.Trim());
        if (string.IsNullOrWhiteSpace(url))
        {
            MessageBox.Show("Enter a URL first.", "cURL to clipboard",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
            var command = CurlCommandBuilder.ToCommandLine(
                method,
                url,
                ParseHeaders(_headersBox.Text),
                string.IsNullOrEmpty(_bodyBox.Text) ? null : _bodyBox.Text,
                _followRedirectsCheck.IsChecked == true);
            Clipboard.SetText(command);

            if (sender is Button btn)
                FlashCopied(btn);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not copy cURL command:\n{ex.Message}", "cURL to clipboard",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CopyCurlFromRaw_Click(object sender, RoutedEventArgs e)
    {
        var url = EnsureNavigableUrl(_rawTargetUrl.Text.Trim());
        if (string.IsNullOrWhiteSpace(url))
        {
            MessageBox.Show("Enter a Target URL first.", "cURL to clipboard",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var method = MethodFromRequestLine(_rawRequestLine.Text);
            var command = CurlCommandBuilder.ToCommandLine(
                method,
                url,
                ParseHeaders(_rawHeadersBox.Text),
                string.IsNullOrEmpty(_rawBodyBox.Text) ? null : _rawBodyBox.Text,
                followRedirects: false);
            Clipboard.SetText(command);
            if (sender is Button btn)
                FlashCopied(btn);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not copy cURL command:\n{ex.Message}", "cURL to clipboard",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string MethodFromRequestLine(string requestLine)
        => RequestEditorMapping.MethodFromRequestLine(requestLine);

    private static void FlashCopied(Button btn)
    {
        var previous = btn.Content;
        btn.Content = "Copied";
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1500) };
        timer.Tick += (_, _) =>
        {
            btn.Content = previous;
            timer.Stop();
        };
        timer.Start();
    }

    // ─────────────────── Auth Control Identifier ───────────────────

    private async void IdentifyAuthControls_Click(object sender, RoutedEventArgs e)
    {
        var url = _urlBox.Text.Trim();
        if (string.IsNullOrEmpty(url))
        {
            MessageBox.Show("Enter a URL first.", "Auth Control Identifier",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
        var confirm = MessageBox.Show(
            $"This will replay {method} {url} as a baseline, then omit and one-character-tamper " +
            "each auth-related cookie, header, and token field (1 + 2×N requests).\n\n" +
            "State-changing methods may modify server data. Continue?",
            "Auth Control Identifier",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
            return;

        var headers = ParseHeaders(_headersBox.Text);
        var body = string.IsNullOrEmpty(_bodyBox.Text.Trim()) ? null : _bodyBox.Text;
        var endpoint = new EndpointProbeItem
        {
            Method = method,
            Url = url,
            RequestHeaders = headers,
            RequestBody = body
        };

        _loadingText.Text = "\u23F3 Identifying auth controls\u2026";
        _loadingText.Visibility = Visibility.Visible;

        try
        {
            var probe = new AuthControlIdentifier(_context, (msg, color) => _context.Log(msg, color));
            var result = await probe.RunAsync(new AuthControlIdentifier.ProbeOptions
            {
                Endpoints = [endpoint],
                AllHeaders = false,
                TimeoutMs = 12_000
            });

            AuthControlIdentifier.LogMarkdownTable((msg, color) => _context.Log(msg, color), result);

            _loadingText.Visibility = Visibility.Collapsed;

            var dlg = new AuthControlResultsDialog(Owner ?? this, result);
            dlg.OpenInRequestEditorRequested += item =>
                LoadCapturedRequest(item.Method, item.Url, item.RequestHeaders, item.RequestBody);
            dlg.Show();
        }
        catch (Exception ex)
        {
            _loadingText.Visibility = Visibility.Collapsed;
            MessageBox.Show($"Auth Control Identifier failed:\n{ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ─────────────────── Response display ───────────────────

    private void ShowResponse(int status, string statusText, bool ok, bool redirected,
        string finalUrl, Dictionary<string, string> headers, string body, List<string>? skippedHeaders = null,
        long? elapsedMs = null)
    {
        ClearRepeatSummary();
        var statusLine = $"{status} {statusText}";
        if (redirected) statusLine += $"  \u2192 {finalUrl}";

        _responseStatus.Text = statusLine;
        _responseStatus.Foreground = ok ? AccentGreen : status >= 500 ? AccentRed : AccentOrange;
        SetResponseTime(elapsedMs);
        _responseHeadersBox.Text = FormatHeaders(headers);
        _responseBodyBox.Text = TryFormatJson(body);
        _responseSection.Visibility = Visibility.Visible;
        ShowRequestSent(null);

        if (skippedHeaders is { Count: > 0 })
        {
            _sendNote.Text = "Not applied by HttpClient: " + string.Join(", ", skippedHeaders) +
                             ". Content-Length is computed automatically. Content-Type requires a body.";
            _sendNote.Visibility = Visibility.Visible;
        }
        else
        {
            _sendNote.Text = "";
            _sendNote.Visibility = Visibility.Collapsed;
        }
    }

    private void ShowResponseError(string message)
    {
        ClearRepeatSummary();
        _responseStatus.Text = "Error";
        _responseStatus.Foreground = AccentRed;
        SetResponseTime(null);
        _responseHeadersBox.Text = "";
        _responseBodyBox.Text = message;
        _responseSection.Visibility = Visibility.Visible;
        _sendNote.Text = "";
        _sendNote.Visibility = Visibility.Collapsed;
        ShowRequestSent(null);
    }

    private void ClearRepeatSummary()
    {
        _repeatResultText.Text = "";
        _repeatResultText.Visibility = Visibility.Collapsed;
    }

    private void ShowRepeatSummary(string text, Brush foreground)
    {
        _repeatResultText.Text = text;
        _repeatResultText.Foreground = foreground;
        _repeatResultText.Visibility = Visibility.Visible;
    }

    private void SyncRepeatCount(TextBox source, TextBox other)
    {
        if (_suppressRepeatSync || other.Text == source.Text)
            return;
        _suppressRepeatSync = true;
        other.Text = source.Text;
        _suppressRepeatSync = false;
    }

    private static int ReadRepeatCount(TextBox box)
    {
        if (!int.TryParse(box.Text.Trim(), out var count) || count < 1)
            count = 1;
        return Math.Min(count, MaxRepeatCount);
    }

    /// <summary>
    /// Same lines as Replay in the network breakpoint dialog.
    /// </summary>
    private static string FormatRepeatSummary(int count, long elapsedMs, IReadOnlyList<(int status, int ms, string? error)> results)
    {
        var timings = results.Where(r => r.status > 0).Select(r => r.ms).OrderBy(t => t).ToArray();
        var statusGroups = results.GroupBy(r => r.status).Select(g => $"{g.Key}: {g.Count()}");
        var errorCount = results.Count(r => r.error != null);

        var sb = new StringBuilder();
        sb.AppendLine($"\u2705 Replay complete — {count} requests in {elapsedMs}ms");
        sb.AppendLine($"Status codes: {string.Join(", ", statusGroups)}");
        if (timings.Length > 0)
        {
            sb.AppendLine($"Timing: avg={timings.Average():F0}ms  min={timings.First()}ms  max={timings.Last()}ms  p95={timings[(int)(timings.Length * 0.95)]}ms");
        }
        if (errorCount > 0)
            sb.AppendLine($"Errors: {errorCount}");
        return sb.ToString().TrimEnd();
    }

    private void SetResponseTime(long? elapsedMs)
    {
        if (elapsedMs is { } ms)
        {
            _responseTime.Text = $"{ms} ms";
            _responseTime.Visibility = Visibility.Visible;
        }
        else
        {
            _responseTime.Text = "";
            _responseTime.Visibility = Visibility.Collapsed;
        }
    }

    // ─────────────────── Saved requests ───────────────────

    private void RefreshSavedRequestsCombo()
    {
        _savedRequestsCombo.SelectionChanged -= SavedRequestsCombo_SelectionChanged;
        _savedRequestsCombo.Items.Clear();

        _savedRequestsCombo.Items.Add(new ComboBoxItem
        {
            Content = "(New request)",
            Foreground = FgDim,
            FontStyle = FontStyles.Italic
        });

        foreach (var r in _savedRequests)
        {
            _savedRequestsCombo.Items.Add(new ComboBoxItem
            {
                Content = $"{r.Method}  {r.Name}",
                Tag = r.Name,
                Foreground = FgText
            });
        }

        _savedRequestsCombo.SelectedIndex = 0;
        _savedRequestsCombo.SelectionChanged += SavedRequestsCombo_SelectionChanged;
    }

    private void SavedRequestsCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_savedRequestsCombo.SelectedIndex <= 0) return;

        var item = _savedRequestsCombo.SelectedItem as ComboBoxItem;
        var name = item?.Tag as string;
        if (name == null) return;

        var req = _savedRequests.Find(r => r.Name == name);
        if (req == null) return;

        LoadRequest(req);
    }

    private void LoadRequest(SavedHttpRequest req)
    {
        _suppressTabSync = true;
        try
        {
            _responseSection.Visibility = Visibility.Collapsed;
            if (req.IsRaw)
            {
                _rawTargetUrl.Text = req.Url;
                _rawRequestLine.Text = string.IsNullOrWhiteSpace(req.RequestLine)
                    ? RequestEditorMapping.FallbackRequestLine(req.Method, req.Url)
                    : req.RequestLine;
                _rawHeadersBox.Text = req.HeaderText ?? "";
                _rawBodyBox.Text = req.Body ?? "";
                RefreshRawPreview();
                _tabs.SelectedIndex = RawTabIndex;
                _lastTabIndex = RawTabIndex;
            }
            else
            {
                _urlBox.Text = req.Url;
                SetMethodCombo(req.Method);
                _headersBox.Text = req.Headers != null ? FormatHeaders(req.Headers) : "";
                _bodyBox.Text = req.Body ?? "";
                _tabs.SelectedIndex = ComposeTabIndex;
                _lastTabIndex = ComposeTabIndex;
            }
        }
        finally
        {
            _suppressTabSync = false;
        }
    }

    /// <summary>
    /// Populates the editor with a request captured elsewhere (e.g. the Endpoint Probe dialog),
    /// retaining all headers including authorization. Safe to call on an already-open editor.
    /// </summary>
    public void LoadCapturedRequest(string method, string url, IReadOnlyDictionary<string, string>? headers, string? body)
    {
        _suppressTabSync = true;
        try
        {
            _savedRequestsCombo.SelectedIndex = 0;
            _urlBox.Text = url;
            SetMethodCombo(method);
            _headersBox.Text = headers != null && headers.Count > 0 ? FormatHeaders(headers) : "";
            _bodyBox.Text = body ?? "";
            _tabs.SelectedIndex = ComposeTabIndex;
            _lastTabIndex = ComposeTabIndex;
            _responseSection.Visibility = Visibility.Collapsed;
            _urlBox.Focus();
        }
        finally
        {
            _suppressTabSync = false;
        }
    }

    private SavedHttpRequest BuildCurrentRequest(string name)
    {
        if (_tabs.SelectedIndex == RawTabIndex)
        {
            return RequestEditorMapping.FromRaw(
                name,
                _rawTargetUrl.Text,
                _rawRequestLine.Text,
                _rawHeadersBox.Text,
                _rawBodyBox.Text);
        }

        return RequestEditorMapping.FromCompose(
            name,
            _urlBox.Text,
            _methodCombo.Text ?? "GET",
            ParseHeaders(_headersBox.Text),
            _bodyBox.Text);
    }

    private void SaveRequest_Click(object sender, RoutedEventArgs e)
    {
        var selected = _savedRequestsCombo.SelectedItem as ComboBoxItem;
        var existingName = selected?.Tag as string;

        if (existingName != null)
        {
            var idx = _savedRequests.FindIndex(r => r.Name == existingName);
            if (idx >= 0)
            {
                _savedRequests[idx] = BuildCurrentRequest(existingName);
                RequestSettings.Save(_savedRequests);
                RefreshSavedRequestsCombo();
                SelectSavedRequest(existingName);
                return;
            }
        }

        SaveRequestAs_Click(sender, e);
    }

    private void SaveRequestAs_Click(object sender, RoutedEventArgs e)
    {
        var nameDialog = new Window
        {
            Title = "Save Request As",
            Width = 400,
            Height = 170,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            Background = BgMedium,
            ShowInTaskbar = false,
            ResizeMode = ResizeMode.NoResize
        };

        var stack = new StackPanel { Margin = new Thickness(16) };
        stack.Children.Add(new TextBlock { Text = "Request name:", Foreground = FgText, FontSize = 12, Margin = new Thickness(0, 0, 0, 6) });

        var nameBox = CreateInputBox(BuildDefaultName());
        stack.Children.Add(nameBox);

        var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var okBtn = CreateSmallButton("Save", AccentGreen);
        okBtn.Width = 70;
        okBtn.Click += (_, _) =>
        {
            var name = nameBox.Text.Trim();
            if (string.IsNullOrEmpty(name)) return;

            var existing = _savedRequests.FindIndex(r => r.Name == name);
            if (existing >= 0)
            {
                var result = MessageBox.Show(
                    $"A request named \"{name}\" already exists.\nOverwrite it?",
                    "Overwrite?", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result != MessageBoxResult.Yes) return;
                _savedRequests[existing] = BuildCurrentRequest(name);
            }
            else
            {
                _savedRequests.Add(BuildCurrentRequest(name));
            }

            RequestSettings.Save(_savedRequests);
            RefreshSavedRequestsCombo();
            SelectSavedRequest(name);
            nameDialog.Close();
        };
        btnRow.Children.Add(okBtn);

        var cancelBtn = CreateSmallButton("Cancel", Bc("#3F3F46"));
        cancelBtn.Margin = new Thickness(6, 0, 0, 0);
        cancelBtn.Width = 70;
        cancelBtn.Click += (_, _) => nameDialog.Close();
        btnRow.Children.Add(cancelBtn);

        stack.Children.Add(btnRow);
        nameDialog.Content = stack;
        nameBox.Focus();
        nameBox.SelectAll();
        nameDialog.ShowDialog();
    }

    private void DeleteRequest_Click(object sender, RoutedEventArgs e)
    {
        var selected = _savedRequestsCombo.SelectedItem as ComboBoxItem;
        var name = selected?.Tag as string;
        if (name == null)
        {
            MessageBox.Show("Select a saved request to delete.", "Delete", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = MessageBox.Show(
            $"Delete \"{name}\"?", "Delete Request",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes) return;

        _savedRequests.RemoveAll(r => r.Name == name);
        RequestSettings.Save(_savedRequests);
        RefreshSavedRequestsCombo();
    }

    private void SelectSavedRequest(string name)
    {
        for (int i = 0; i < _savedRequestsCombo.Items.Count; i++)
        {
            if (_savedRequestsCombo.Items[i] is ComboBoxItem ci && ci.Tag as string == name)
            {
                _savedRequestsCombo.SelectedIndex = i;
                return;
            }
        }
    }

    private string BuildDefaultName()
    {
        if (_tabs.SelectedIndex == RawTabIndex)
            return RequestEditorMapping.DefaultName(
                MethodFromRequestLine(_rawRequestLine.Text),
                _rawTargetUrl.Text,
                _rawRequestLine.Text);

        var method = (_methodCombo.Text ?? "GET").Trim().ToUpperInvariant();
        return RequestEditorMapping.DefaultName(method, _urlBox.Text, requestLine: null);
    }

    // ─────────────────── Import cURL ───────────────────

    private void ImportCurl_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Window
        {
            Title = "Import cURL (bash)",
            Width = 640,
            Height = 360,
            MinWidth = 480,
            MinHeight = 280,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            Background = BgMedium,
            ShowInTaskbar = false,
            ResizeMode = ResizeMode.CanResizeWithGrip
        };

        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var hint = new TextBlock
        {
            Text = "Paste a bash curl command (Copy as cURL from Chrome, or cURL to clipboard from this editor). Line continuations (\\) are accepted.",
            Foreground = FgDim,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(16, 16, 16, 8)
        };
        Grid.SetRow(hint, 0);
        grid.Children.Add(hint);

        var pasteBox = CreateMultilineBox("", 8);
        pasteBox.Margin = new Thickness(16, 0, 16, 0);
        pasteBox.FontFamily = new FontFamily("Consolas, Cascadia Mono, Courier New");
        pasteBox.AcceptsReturn = true;
        pasteBox.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
        Grid.SetRow(pasteBox, 1);
        grid.Children.Add(pasteBox);

        var btnRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(16, 12, 16, 16)
        };
        var okBtn = CreateSmallButton("OK", AccentGreen);
        okBtn.Width = 80;
        okBtn.IsDefault = true;
        okBtn.Click += (_, _) =>
        {
            try
            {
                var parsed = CurlCommandParser.Parse(pasteBox.Text);
                ApplyImportedCurl(parsed);
                dlg.DialogResult = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(dlg, ex.Message, "Import cURL", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        btnRow.Children.Add(okBtn);

        var cancelBtn = CreateSmallButton("Cancel", Bc("#3F3F46"));
        cancelBtn.Margin = new Thickness(8, 0, 0, 0);
        cancelBtn.Width = 80;
        cancelBtn.IsCancel = true;
        cancelBtn.Click += (_, _) => dlg.DialogResult = false;
        btnRow.Children.Add(cancelBtn);

        Grid.SetRow(btnRow, 2);
        grid.Children.Add(btnRow);

        dlg.Content = grid;
        dlg.Loaded += (_, _) => pasteBox.Focus();
        dlg.ShowDialog();
    }

    private void ApplyImportedCurl(CurlCommandParser.ParsedRequest parsed)
    {
        _suppressTabSync = true;
        try
        {
            _savedRequestsCombo.SelectedIndex = 0;
            _urlBox.Text = parsed.Url;
            SetMethodCombo(parsed.Method);
            _headersBox.Text = parsed.Headers.Count > 0 ? FormatHeaders(parsed.Headers) : "";
            _bodyBox.Text = parsed.Body ?? "";
            _followRedirectsCheck.IsChecked = parsed.FollowRedirects;
            _tabs.SelectedIndex = ComposeTabIndex;
            _lastTabIndex = ComposeTabIndex;
            _responseSection.Visibility = Visibility.Collapsed;
            _urlBox.Focus();
        }
        finally
        {
            _suppressTabSync = false;
        }
    }

    // ─────────────────── Import / Export ───────────────────

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_savedRequests.Count == 0)
            {
                MessageBox.Show("No saved requests to export.", "Export", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var json = RequestSettings.ExportToJson(_savedRequests);
            var dialog = new SaveFileDialog
            {
                Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                DefaultExt = ".json",
                FileName = "trowser-requests.json",
                Title = "Export Saved Requests"
            };
            if (dialog.ShowDialog() == true)
            {
                File.WriteAllText(dialog.FileName, json);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "Export Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new OpenFileDialog
            {
                Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                DefaultExt = ".json",
                Title = "Import Saved Requests"
            };
            if (dialog.ShowDialog() != true) return;

            var json = File.ReadAllText(dialog.FileName);
            var imported = RequestSettings.ImportFromJson(json);

            bool clearExisting = false;
            if (_savedRequests.Count > 0)
            {
                var result = MessageBox.Show(
                    $"You have {_savedRequests.Count} saved request(s).\n\n" +
                    "Replace all with imported requests?\n\n" +
                    "Yes = Replace  |  No = Merge (add to existing)",
                    "Import Requests",
                    MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

                if (result == MessageBoxResult.Cancel) return;
                clearExisting = result == MessageBoxResult.Yes;
            }

            if (clearExisting)
            {
                _savedRequests = imported;
            }
            else
            {
                foreach (var req in imported)
                {
                    var existing = _savedRequests.FindIndex(r => r.Name == req.Name);
                    if (existing >= 0)
                        _savedRequests[existing] = req;
                    else
                        _savedRequests.Add(req);
                }
            }

            RequestSettings.Save(_savedRequests);
            RefreshSavedRequestsCombo();

            MessageBox.Show(
                $"Imported {imported.Count} request(s).",
                "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Import failed: {ex.Message}", "Import Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ─────────────────── Helpers ───────────────────

    private void SetMethodCombo(string method)
    {
        var upper = method.Trim().ToUpperInvariant();
        for (int i = 0; i < _methodCombo.Items.Count; i++)
        {
            if (_methodCombo.Items[i] as string == upper)
            {
                _methodCombo.SelectedIndex = i;
                return;
            }
        }
        _methodCombo.Text = upper;
    }

    private static string FormatHeaders(IReadOnlyDictionary<string, string> headers)
    {
        var sb = new StringBuilder();
        foreach (var kv in headers)
            sb.AppendLine($"{kv.Key}: {kv.Value}");
        return sb.ToString().TrimEnd();
    }

    private static Dictionary<string, string> ParseHeaders(string text)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(text)) return dict;
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.TrimEnd('\r');
            var colon = trimmed.IndexOf(':');
            if (colon > 0)
                dict[trimmed[..colon].Trim()] = trimmed[(colon + 1)..].Trim();
        }
        return dict;
    }

    private static string TryFormatJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return text;
        try
        {
            var trimmed = text.TrimStart();
            if (trimmed.Length > 0 && (trimmed[0] == '{' || trimmed[0] == '['))
            {
                var doc = JsonDocument.Parse(text);
                return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
            }
        }
        catch { /* not JSON, return as-is */ }
        return text;
    }

    // ─────────────────── UI factory ───────────────────

    private static TabControl CreateDarkTabControl()
    {
        return new TabControl
        {
            Background = BgMedium,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(0, 8, 0, 0)
        };
    }

    private static TabItem CreateTabItem(string header, UIElement content)
    {
        return new TabItem
        {
            Header = header,
            Content = content,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            Padding = new Thickness(12, 4, 12, 4)
        };
    }

    private static void AddSectionHeader(StackPanel parent, string text, double topMargin = 0)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = AccentBlue,
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 4)
        });
    }

    private static void AddHint(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 0, 0, 2),
            TextWrapping = TextWrapping.Wrap
        });
    }

    private static void AddFieldLabel(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 8, 0, 2)
        });
    }

    private static void AddMicroLabel(Grid grid, string text, int col, Thickness? margin = null)
    {
        var tb = new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 9,
            Margin = margin ?? new Thickness(0)
        };
        Grid.SetColumn(tb, col);
        grid.Children.Add(tb);
    }

    private static TextBox CreateRepeatCountBox()
    {
        var box = new TextBox
        {
            Text = "1",
            Width = 36,
            Height = 26,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4, 0, 4, 0),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            TextAlignment = TextAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            VerticalContentAlignment = VerticalAlignment.Center,
            ToolTip = "How many times Send (Direct) or Send Raw fires this request at once (1\u201350). The summary lists every result; the full response is the last request."
        };
        CenterTextVertically(box);
        return box;
    }

    private static void AddRepeatCount(Panel row, TextBox box, Thickness margin)
    {
        row.Children.Add(new TextBlock
        {
            Text = "\u2502",
            Foreground = FgDim,
            FontSize = 16,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(margin.Left, margin.Top, 4, margin.Bottom)
        });
        row.Children.Add(new TextBlock
        {
            Text = "\u00D7",
            Foreground = FgText,
            FontSize = 12,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, margin.Top, 2, margin.Bottom)
        });
        box.Margin = new Thickness(0, margin.Top, margin.Right, margin.Bottom);
        row.Children.Add(box);
    }

    /// <summary>
    /// The text host sits at the top of a fixed-height box. Center it so the digits
    /// are vertically centered, not only horizontally.
    /// </summary>
    private static void CenterTextVertically(TextBox box)
    {
        box.VerticalContentAlignment = VerticalAlignment.Center;
        box.Loaded += (_, _) =>
        {
            box.ApplyTemplate();
            if (box.Template?.FindName("PART_ContentHost", box) is FrameworkElement host)
                host.VerticalAlignment = VerticalAlignment.Center;
        };
    }

    private static TextBox CreateInputBox(string value, double width = double.NaN)
    {
        var tb = new TextBox
        {
            Text = value,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 3, 6, 3),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            Height = 26
        };
        if (!double.IsNaN(width))
        {
            tb.Width = width;
            tb.HorizontalAlignment = HorizontalAlignment.Left;
        }
        return tb;
    }

    private static TextBox CreateMultilineBox(string value, int minLines)
    {
        return new TextBox
        {
            Text = value,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MinLines = minLines,
            MaxLines = 40
        };
    }

    private static ComboBox CreateStyledComboBox(bool isEditable)
    {
        var combo = new ComboBox
        {
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Height = 26,
            FontSize = 12,
            FontFamily = new FontFamily("Consolas"),
            IsEditable = isEditable
        };

        // Style the dropdown popup items with dark background
        var itemStyle = new Style(typeof(ComboBoxItem));
        itemStyle.Setters.Add(new Setter(Control.BackgroundProperty, BgDark));
        itemStyle.Setters.Add(new Setter(Control.ForegroundProperty, FgText));
        itemStyle.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        itemStyle.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
        itemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(6, 3, 6, 3)));

        var hoverTrigger = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true };
        hoverTrigger.Setters.Add(new Setter(Control.BackgroundProperty, BgItem));
        hoverTrigger.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
        itemStyle.Triggers.Add(hoverTrigger);

        combo.Resources.Add(typeof(ComboBoxItem), itemStyle);

        if (isEditable)
            DarkComboBoxHelper.ApplyDarkEditableStyle(combo);
        else
            DarkComboBoxHelper.ApplyDarkStyle(combo);

        return combo;
    }

    private static Button CreateSmallButton(string text, SolidColorBrush bg)
    {
        return new Button
        {
            Content = text,
            Height = 24,
            Padding = new Thickness(10, 0, 10, 0),
            Background = bg,
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand
        };
    }

    private static Button CreateActionButton(string text, SolidColorBrush bg, string tooltip)
    {
        return new Button
        {
            Content = text,
            Height = 28,
            Padding = new Thickness(14, 0, 14, 0),
            Background = bg,
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            ToolTip = tooltip
        };
    }

    private static Button CreateStyledButton(string text)
    {
        return new Button
        {
            Content = text,
            Width = 90,
            Height = 28,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand
        };
    }

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
