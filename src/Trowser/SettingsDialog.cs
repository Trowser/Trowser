using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Settings dialog for navigation scope, API port, proxy, and security options.
/// Dark-themed to match the Trowser UI.
/// </summary>
public class SettingsDialog : Window
{
    private readonly TextBox _scopeTextBox;
    private readonly TextBox _portTextBox;
    private readonly CheckBox _proxyCheckBox;
    private readonly TextBox _proxyUrlTextBox;
    private readonly CheckBox _apiKeyRequiredCheckBox;
    private readonly CheckBox _keepApiKeyForNextSessionCheckBox;
    private readonly TextBox _restApiKeyTextBox;
    private readonly CheckBox _safeModeCheckBox;

    private bool? _shadowEnabledOverride;
    private bool? _shadowNotifyOverride;
    private string? _shadowScopeOverride;
    private HashSet<string>? _shadowAuditsOverride;
    private bool? _powerModeEnabledOverride;
    private bool? _powerOverlaysOverride;
    private bool? _whisperEnabledOverride;
    private bool? _whisperNotifyOverride;
    private bool? _shadowLawsEnabledOverride;
    private bool? _shadowLawsMiningOverride;
    private bool? _shadowRunHeavyAfterScriptOverride;
    private bool? _shadowSerendipityOverride;
    private readonly Security.ShadowConfig? _shadowConfig;
    private readonly Security.PowerModeConfig? _powerModeConfig;
    private readonly Security.WhisperConfig? _whisperConfig;
    private readonly SslManager? _sslManager;
    private readonly Action? _onVpxExport;
    private readonly Action? _onVpxImport;

    public string ScopeValue => _scopeTextBox.Text.Trim();
    public int PortValue => int.TryParse(_portTextBox.Text.Trim(), out var p) && p > 0 && p < 65536 ? p : 6923;
    public bool ProxyEnabled => _proxyCheckBox.IsChecked == true;
    public string ProxyUrl => _proxyUrlTextBox.Text.Trim();
    public bool ApiKeyRequired => _apiKeyRequiredCheckBox.IsChecked == true;
    public bool KeepApiKeyForNextSession => _keepApiKeyForNextSessionCheckBox.IsChecked == true;
    public string RestApiKey => _restApiKeyTextBox.Text;
    public bool SafeModeValue => _safeModeCheckBox.IsChecked == true;

    public bool ShadowEnabled => _shadowEnabledOverride ?? _shadowConfig?.Enabled ?? false;
    public bool ShadowNotifyGui => _shadowNotifyOverride ?? _shadowConfig?.NotifyGui ?? true;
    public string ShadowScope => _shadowScopeOverride ?? _shadowConfig?.Scope ?? "same-origin";

    public HashSet<string> ShadowAudits =>
        _shadowAuditsOverride ?? _shadowConfig?.Audits ?? ShadowConfig.CreateDefaultAudits();

    public bool ShadowLawsEnabled => _shadowLawsEnabledOverride ?? _shadowConfig?.LawsEnabled ?? true;
    public bool ShadowLawsMining => _shadowLawsMiningOverride ?? _shadowConfig?.LawsMiningEnabled ?? false;
    public bool ShadowRunHeavyAfterQuicktest => _shadowRunHeavyAfterScriptOverride ?? _shadowConfig?.RunHeavyAfterQuicktest ?? false;
    public bool ShadowSerendipityTimer => _shadowSerendipityOverride ?? _shadowConfig?.SerendipityTimerEnabled ?? false;

    public bool PowerModeEnabled => _powerModeEnabledOverride ?? _powerModeConfig?.Enabled ?? false;
    public bool PowerModeShowOverlays => _powerOverlaysOverride ?? _powerModeConfig?.ShowOverlays ?? true;
    public bool WhisperEnabled => _whisperEnabledOverride ?? _whisperConfig?.Enabled ?? false;
    public bool WhisperNotifyGui => _whisperNotifyOverride ?? _whisperConfig?.NotifyGui ?? true;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public SettingsDialog(Window owner, string currentScope, int currentPort,
        bool proxyEnabled = false, string proxyUrl = "http://localhost:8080",
        bool safeMode = false, string? apiKey = null, bool apiKeyRequired = true, bool keepApiKeyForNextSession = false,
        Security.ShadowConfig? shadowConfig = null,
        Security.PowerModeConfig? powerModeConfig = null,
        Security.WhisperConfig? whisperConfig = null,
        SslManager? sslManager = null,
        Action? onVpxExport = null,
        Action? onVpxImport = null)
    {
        Owner = owner;
        Title = "Trowser Settings";
        Width = 560;
        Height = 580;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;
        _onVpxExport = onVpxExport;
        _onVpxImport = onVpxImport;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(0)
        };

        var rootStack = new StackPanel { Margin = new Thickness(24, 20, 24, 12) };

        // Store configs for ExperimentalDialog
        _shadowConfig = shadowConfig;
        _powerModeConfig = powerModeConfig;
        _whisperConfig = whisperConfig;
        _sslManager = sslManager;

        // ─── Section: Browser ───
        AddSectionHeader(rootStack, "Browser");

        AddLabel(rootStack, "Navigation Scope (comma-separated patterns, *.* = no restrictions)");
        _scopeTextBox = CreateTextBox(currentScope);
        rootStack.Children.Add(_scopeTextBox);
        AddHint(rootStack, "Examples: https://*.myapp.com  |  https://staging.app.com, https://api.app.com  |  *.*");

        AddLabel(rootStack, "REST API Port");
        var portRow = new StackPanel { Orientation = Orientation.Horizontal };
        _portTextBox = CreateTextBox(currentPort.ToString(), 100);
        _portTextBox.PreviewTextInput += (_, e) => { e.Handled = !char.IsDigit(e.Text[0]); };
        portRow.Children.Add(_portTextBox);
        AddInlineHint(portRow, "Use different ports to run multiple Trowser instances");
        rootStack.Children.Add(portRow);

        _proxyCheckBox = new CheckBox
        {
            Content = "Route traffic through proxy",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 4),
            IsChecked = proxyEnabled
        };
        rootStack.Children.Add(_proxyCheckBox);

        AddLabel(rootStack, "Proxy URL");
        _proxyUrlTextBox = CreateTextBox(proxyUrl);
        _proxyUrlTextBox.IsEnabled = proxyEnabled;
        rootStack.Children.Add(_proxyUrlTextBox);
        AddHint(rootStack, "e.g. http://localhost:8080 for OWASP ZAP, Burp Suite, Fiddler. Requires restart to take effect.");

        _proxyCheckBox.Checked += (_, _) => _proxyUrlTextBox.IsEnabled = true;
        _proxyCheckBox.Unchecked += (_, _) => _proxyUrlTextBox.IsEnabled = false;

        // ─── Section: Security ───
        AddSectionHeader(rootStack, "Security", topMargin: 20);

        _apiKeyRequiredCheckBox = new CheckBox
        {
            Content = "API Key (required for all API requests)",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 6, 0, 4),
            IsChecked = apiKeyRequired
        };
        rootStack.Children.Add(_apiKeyRequiredCheckBox);

        _keepApiKeyForNextSessionCheckBox = new CheckBox
        {
            Content = "Keep API key for next session",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 2, 0, 4),
            IsChecked = keepApiKeyForNextSession
        };
        rootStack.Children.Add(_keepApiKeyForNextSessionCheckBox);

        var displayKey = apiKey ?? "";
        var keyRowGrid = new Grid();
        keyRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        keyRowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _restApiKeyTextBox = CreateTextBox(displayKey);
        _restApiKeyTextBox.IsReadOnly = true;
        _restApiKeyTextBox.Foreground = FgDim;
        _restApiKeyTextBox.IsEnabled = apiKeyRequired;
        _restApiKeyTextBox.HorizontalAlignment = HorizontalAlignment.Stretch;
        Grid.SetColumn(_restApiKeyTextBox, 0);
        var copyBtn = new Button
        {
            Content = "Copy",
            Width = 50,
            Height = 30,
            Margin = new Thickness(6, 0, 0, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand,
            IsEnabled = apiKeyRequired
        };
        copyBtn.Click += (_, _) =>
        {
            Clipboard.SetText(_restApiKeyTextBox.Text);
            copyBtn.Content = "Copied";
        };
        var newKeyBtn = new Button
        {
            Content = "New",
            Width = 50,
            Height = 30,
            Margin = new Thickness(6, 0, 0, 0),
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand,
            IsEnabled = apiKeyRequired
        };
        newKeyBtn.Click += (_, _) =>
        {
            _restApiKeyTextBox.Text = TrowserApiKey.Generate();
            newKeyBtn.Content = "New";
            copyBtn.Content = "Copy";
        };
        var keyBtnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(6, 0, 0, 0) };
        keyBtnRow.Children.Add(copyBtn);
        keyBtnRow.Children.Add(newKeyBtn);
        Grid.SetColumn(keyBtnRow, 1);
        keyRowGrid.Children.Add(_restApiKeyTextBox);
        keyRowGrid.Children.Add(keyBtnRow);
        rootStack.Children.Add(keyRowGrid);

        void SetKeyRowEnabled(bool on)
        {
            _restApiKeyTextBox.IsEnabled = on;
            copyBtn.IsEnabled = on;
            newKeyBtn.IsEnabled = on;
        }

        _apiKeyRequiredCheckBox.Checked += (_, _) => SetKeyRowEnabled(true);
        _apiKeyRequiredCheckBox.Unchecked += (_, _) => SetKeyRowEnabled(false);

        AddHint(rootStack, "Recommendation is to generate a new API key for each session, but this is user responsibility. For MCP agents, consider enabling Keep API key.");

        _safeModeCheckBox = new CheckBox
        {
            Content = "Safe mode \u2014 block JS execution, C# scripting, network mocking, cookie manipulation",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 8, 0, 2),
            IsChecked = safeMode
        };
        rootStack.Children.Add(_safeModeCheckBox);
        AddHint(rootStack, "Enable when browsing untrusted sites to prevent the API from executing code or intercepting requests.");

        // SSL Manager button
        var sslManagerBtn = new Button
        {
            Content = "SSL Manager\u2026",
            Width = 120,
            Height = 28,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            Margin = new Thickness(0, 10, 0, 0)
        };
        sslManagerBtn.Click += (_, _) =>
        {
            if (_sslManager != null)
                new SslManagerDialog(this, _sslManager).ShowDialog();
        };
        rootStack.Children.Add(sslManagerBtn);
        AddHint(rootStack, "Manage client certificates (.pfx / .p12) for mutual TLS.");

        // ─── Section: Experimental ───
        AddSectionHeader(rootStack, "Experimental", topMargin: 20);

        var experimentalBtn = new Button
        {
            Content = "Experimental\u2026",
            Width = 120,
            Height = 28,
            HorizontalAlignment = HorizontalAlignment.Left,
            Background = Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 12,
            Cursor = Cursors.Hand,
            Margin = new Thickness(0, 0, 0, 4)
        };
        experimentalBtn.Click += (_, _) =>
        {
            var currentShadow = new Security.ShadowConfig
            {
                Enabled = ShadowEnabled,
                Audits = new HashSet<string>(ShadowAudits),
                Scope = ShadowScope,
                NotifyGui = ShadowNotifyGui,
                Suggestions = _shadowConfig?.Suggestions ?? true,
                Deduplication = _shadowConfig?.Deduplication ?? true,
                MaxFindings = _shadowConfig?.MaxFindings ?? 500,
                LawsEnabled = ShadowLawsEnabled,
                LawsMiningEnabled = ShadowLawsMining,
                RunHeavyAfterQuicktest = ShadowRunHeavyAfterQuicktest,
                SerendipityTimerEnabled = ShadowSerendipityTimer
            };
            var currentPower = new Security.PowerModeConfig
            {
                Enabled = PowerModeEnabled,
                ShowOverlays = PowerModeShowOverlays
            };
            var currentWhisper = new Security.WhisperConfig
            {
                Enabled = WhisperEnabled,
                NotifyGui = WhisperNotifyGui
            };
            var expDialog = new ExperimentalDialog(
                this, currentShadow, currentPower, currentWhisper,
                onVpxExport: _onVpxExport, onVpxImport: _onVpxImport);
            if (expDialog.ShowDialog() == true)
            {
                _shadowEnabledOverride = expDialog.ShadowEnabled;
                _shadowNotifyOverride = expDialog.ShadowNotifyGui;
                _shadowScopeOverride = expDialog.ShadowScope;
                _shadowAuditsOverride = new HashSet<string>(expDialog.ShadowAudits);
                _powerModeEnabledOverride = expDialog.PowerModeEnabled;
                _powerOverlaysOverride = expDialog.PowerModeShowOverlays;
                _whisperEnabledOverride = expDialog.WhisperEnabled;
                _whisperNotifyOverride = expDialog.WhisperNotifyGui;
                _shadowLawsEnabledOverride = expDialog.ShadowLawsEnabled;
                _shadowLawsMiningOverride = expDialog.ShadowLawsMining;
                _shadowRunHeavyAfterScriptOverride = expDialog.ShadowRunHeavyAfterQuicktest;
                _shadowSerendipityOverride = expDialog.ShadowSerendipityTimer;
            }
        };
        rootStack.Children.Add(experimentalBtn);
        AddHint(rootStack, "Shadow, Power Mode, Red Team Whisper, VPX export/import.");

        scrollViewer.Content = rootStack;
        Grid.SetRow(scrollViewer, 0);
        rootGrid.Children.Add(scrollViewer);

        // Buttons
        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(24, 12, 24, 16)
        };

        var okButton = CreateButton("OK", true);
        okButton.Click += (_, _) => { DialogResult = true; };

        var cancelButton = CreateButton("Cancel", false);
        cancelButton.Click += (_, _) => { DialogResult = false; };
        cancelButton.Margin = new Thickness(8, 0, 0, 0);

        buttonPanel.Children.Add(okButton);
        buttonPanel.Children.Add(cancelButton);
        Grid.SetRow(buttonPanel, 1);
        rootGrid.Children.Add(buttonPanel);

        Content = rootGrid;

        Loaded += (_, _) =>
        {
            _scopeTextBox.Focus();
            _scopeTextBox.CaretIndex = _scopeTextBox.Text.Length;
            scrollViewer.ScrollToHome();
        };
    }

    // Back-compat: old callers without extra options
    public SettingsDialog(Window owner, string currentScope, int currentPort)
        : this(owner, currentScope, currentPort, false, "http://localhost:8080")
    {
    }

    #region UI Helpers

    private static void AddSectionHeader(StackPanel parent, string text, double topMargin = 0)
    {
        var header = new TextBlock
        {
            Text = text,
            Foreground = Bc("#569CD6"),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 10)
        };
        parent.Children.Add(header);
    }

    private static void AddLabel(Panel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = Brushes.White,
            FontSize = 12,
            Margin = new Thickness(0, 6, 0, 4)
        });
    }

    private static void AddHint(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextWrapping = TextWrapping.Wrap
        });
    }

    private static void AddInlineHint(StackPanel parent, string text)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 0, 0)
        });
    }

    private static TextBox CreateTextBox(string value, double width = double.NaN)
    {
        var tb = new TextBox
        {
            Text = value,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            FontSize = 13,
            FontFamily = new FontFamily("Segoe UI"),
            Height = 30
        };
        if (!double.IsNaN(width))
        {
            tb.Width = width;
            tb.HorizontalAlignment = HorizontalAlignment.Left;
        }
        return tb;
    }

    private static Button CreateButton(string text, bool isDefault)
    {
        return new Button
        {
            Content = text,
            Width = 90,
            Height = 28,
            IsDefault = isDefault,
            IsCancel = !isDefault,
            Background = isDefault ? Bc("#0E639C") : Bc("#3F3F46"),
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

    #endregion
}
