using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Dialog for experimental features (Shadow, Power Mode, Red Team Whisper) and VPX session I/O.
/// Opened from Settings → Experimental… or from Shadow — Findings → Settings...
/// </summary>
public class ExperimentalDialog : Window
{
    private readonly CheckBox _shadowEnabledCheckBox;
    private readonly CheckBox _shadowNotifyCheckBox;
    private readonly CheckBox _shadowHeadersCheckBox;
    private readonly CheckBox _shadowCookiesCheckBox;
    private readonly CheckBox _shadowXssCheckBox;
    private readonly CheckBox _shadowMixedContentCheckBox;
    private readonly CheckBox _shadowSourceMapsCheckBox;
    private readonly CheckBox _shadowStorageCheckBox;
    private readonly CheckBox _shadowRetireJsCheckBox;
    private readonly CheckBox _shadowWcagCheckBox;
    private readonly CheckBox _shadowNetworkCheckBox;
    private readonly CheckBox _shadowConsoleCheckBox;
    private readonly CheckBox _shadowLawsCheckBox;
    private readonly CheckBox _shadowLawsMiningCheckBox;
    private readonly CheckBox _shadowRunHeavyAfterScriptCheckBox;
    private readonly CheckBox _shadowSerendipityCheckBox;
    private readonly ComboBox _shadowScopeCombo;
    private readonly CheckBox _powerModeCheckBox;
    private readonly CheckBox _powerOverlaysCheckBox;
    private readonly CheckBox _whisperCheckBox;
    private readonly CheckBox _whisperNotifyCheckBox;

    public bool ShadowEnabled => _shadowEnabledCheckBox.IsChecked == true;
    public bool ShadowNotifyGui => _shadowNotifyCheckBox.IsChecked == true;
    public string ShadowScope => _shadowScopeCombo.SelectedIndex switch
    {
        1 => "all",
        _ => "same-origin"
    };

    public HashSet<string> ShadowAudits
    {
        get
        {
            // "all" is the named original pack (includes Retire.js). WCAG, Network, and Console are never implied by "all".
            var originalPack = new[] { _shadowHeadersCheckBox, _shadowCookiesCheckBox, _shadowXssCheckBox,
                              _shadowMixedContentCheckBox, _shadowSourceMapsCheckBox, _shadowStorageCheckBox,
                              _shadowRetireJsCheckBox };
            var audits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (originalPack.All(c => c.IsChecked == true))
                audits.Add("all");
            else
            {
                if (_shadowHeadersCheckBox.IsChecked == true) audits.Add("security-headers");
                if (_shadowCookiesCheckBox.IsChecked == true) audits.Add("cookies");
                if (_shadowXssCheckBox.IsChecked == true) audits.Add("xss");
                if (_shadowMixedContentCheckBox.IsChecked == true) audits.Add("mixed-content");
                if (_shadowSourceMapsCheckBox.IsChecked == true) audits.Add("source-maps");
                if (_shadowStorageCheckBox.IsChecked == true) audits.Add("storage");
                if (_shadowRetireJsCheckBox.IsChecked == true) audits.Add("retire-js");
            }
            if (_shadowWcagCheckBox.IsChecked == true) audits.Add("wcag");
            if (_shadowNetworkCheckBox.IsChecked == true) audits.Add("network");
            if (_shadowConsoleCheckBox.IsChecked == true) audits.Add("console");
            return audits.Count > 0 ? audits : ShadowConfig.CreateDefaultAudits();
        }
    }

    public bool PowerModeEnabled => _powerModeCheckBox.IsChecked == true;
    public bool PowerModeShowOverlays => _powerOverlaysCheckBox.IsChecked == true;
    public bool WhisperEnabled => _whisperCheckBox.IsChecked == true;
    public bool WhisperNotifyGui => _whisperNotifyCheckBox.IsChecked == true;

    public bool ShadowLawsEnabled => _shadowLawsCheckBox.IsChecked == true;
    public bool ShadowLawsMining => _shadowLawsMiningCheckBox.IsChecked == true;
    public bool ShadowRunHeavyAfterQuicktest => _shadowRunHeavyAfterScriptCheckBox.IsChecked == true;
    public bool ShadowSerendipityTimer => _shadowSerendipityCheckBox.IsChecked == true;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public ExperimentalDialog(Window owner, ShadowConfig? shadowConfig = null,
        PowerModeConfig? powerModeConfig = null, WhisperConfig? whisperConfig = null,
        Action? onVpxExport = null, Action? onVpxImport = null)
    {
        Owner = owner;
        Title = "Experimental";
        Width = 520;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = BgMedium;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var rootStack = new StackPanel { Margin = new Thickness(24, 20, 24, 12) };

        // ─── Section: Shadows ───
        AddSectionHeader(rootStack, "Shadows");

        var sc = shadowConfig ?? new ShadowConfig();
        var allAudits = sc.Audits.Contains("all");

        _shadowEnabledCheckBox = new CheckBox
        {
            Content = "Shadow \u2014 ambient analysis on every navigation",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 2),
            IsChecked = sc.Enabled
        };
        rootStack.Children.Add(_shadowEnabledCheckBox);
        AddHint(rootStack, "Off by default. When on, factory audits: XSS, Retire.js, Headers, Network, Console (errors only). Optional (off): WCAG, Cookies, Mixed content, Source maps, Storage.");

        var shadowAuditPanel = new WrapPanel { Margin = new Thickness(16, 4, 0, 0) };
        CheckBox MakeAuditCb(string label, bool on)
        {
            var cb = new CheckBox
            {
                Content = label,
                Foreground = FgText,
                FontSize = 11,
                Margin = new Thickness(0, 2, 14, 2),
                IsChecked = on,
                IsEnabled = sc.Enabled
            };
            shadowAuditPanel.Children.Add(cb);
            return cb;
        }
        _shadowHeadersCheckBox = MakeAuditCb("Headers", allAudits || sc.Audits.Contains("security-headers"));
        _shadowCookiesCheckBox = MakeAuditCb("Cookies", allAudits || sc.Audits.Contains("cookies"));
        _shadowXssCheckBox = MakeAuditCb("XSS", allAudits || sc.Audits.Contains("xss"));
        _shadowMixedContentCheckBox = MakeAuditCb("Mixed content", allAudits || sc.Audits.Contains("mixed-content"));
        _shadowSourceMapsCheckBox = MakeAuditCb("Source maps", allAudits || sc.Audits.Contains("source-maps"));
        _shadowStorageCheckBox = MakeAuditCb("Storage", allAudits || sc.Audits.Contains("storage"));
        _shadowRetireJsCheckBox = MakeAuditCb("Retire.js", allAudits || sc.Audits.Contains("retire-js"));
        _shadowWcagCheckBox = MakeAuditCb("WCAG", sc.Audits.Contains("wcag"));
        _shadowNetworkCheckBox = MakeAuditCb("Network", sc.Audits.Contains("network"));
        _shadowConsoleCheckBox = MakeAuditCb("Console", sc.Audits.Contains("console"));
        rootStack.Children.Add(shadowAuditPanel);

        var shadowOptionsRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(16, 4, 0, 0) };

        var scopeLabel = new TextBlock
        {
            Text = "Scope:",
            Foreground = FgText,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        };
        shadowOptionsRow.Children.Add(scopeLabel);

        _shadowScopeCombo = new ComboBox
        {
            Width = 130,
            Height = 24,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 11,
            IsEnabled = sc.Enabled
        };
        DarkComboBoxHelper.ApplyDarkStyle(_shadowScopeCombo);
        _shadowScopeCombo.Items.Add(DarkComboBoxHelper.CreateItem("Same origin"));
        _shadowScopeCombo.Items.Add(DarkComboBoxHelper.CreateItem("All pages"));
        _shadowScopeCombo.SelectedIndex = sc.Scope == "all" ? 1 : 0;
        shadowOptionsRow.Children.Add(_shadowScopeCombo);

        _shadowNotifyCheckBox = new CheckBox
        {
            Content = "GUI notifications",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(18, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            IsChecked = sc.NotifyGui,
            IsEnabled = sc.Enabled
        };
        shadowOptionsRow.Children.Add(_shadowNotifyCheckBox);
        rootStack.Children.Add(shadowOptionsRow);

        var lawsPanel = new StackPanel { Margin = new Thickness(16, 6, 0, 0) };
        _shadowLawsCheckBox = new CheckBox
        {
            Content = "Laws — invariant checks (embedded + your Laws folder)",
            Foreground = FgText,
            FontSize = 11,
            IsChecked = sc.LawsEnabled,
            IsEnabled = sc.Enabled
        };
        lawsPanel.Children.Add(_shadowLawsCheckBox);
        _shadowLawsMiningCheckBox = new CheckBox
        {
            Content = "Law mining — propose Laws from JSON API shapes (Proposals tab)",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 0),
            IsChecked = sc.LawsMiningEnabled,
            IsEnabled = sc.Enabled
        };
        lawsPanel.Children.Add(_shadowLawsMiningCheckBox);
        _shadowRunHeavyAfterScriptCheckBox = new CheckBox
        {
            Content = "Run Shadow Heavy after each Script Console run (needs Shadow + Laws on; logs to console)",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 0),
            IsChecked = sc.RunHeavyAfterQuicktest,
            IsEnabled = sc.Enabled
        };
        lawsPanel.Children.Add(_shadowRunHeavyAfterScriptCheckBox);
        _shadowSerendipityCheckBox = new CheckBox
        {
            Content = "Serendipity timer — Shadow Heavy now, then on an interval while Trowser runs (needs Laws on)",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 0),
            IsChecked = sc.SerendipityTimerEnabled,
            IsEnabled = sc.Enabled
        };
        lawsPanel.Children.Add(_shadowSerendipityCheckBox);
        AddHint(lawsPanel, "Check now (Shadow dialog) runs Heavy immediately. Serendipity runs Heavy once when enabled, then every interval (default 5 min). Failures appear under Findings; passes show in the status bar. Heavy quicktests run only when listed in heavyQuicktests (REST/MCP).");
        AddHint(lawsPanel, "Light quicktests in Shadow run only when you add their names to lightQuicktests (REST/MCP). @shadow light on a quicktest is a hint, not auto-run.");
        rootStack.Children.Add(lawsPanel);

        void SetLawControlsEnabled(bool on)
        {
            _shadowLawsCheckBox.IsEnabled = on;
            _shadowLawsMiningCheckBox.IsEnabled = on;
            _shadowRunHeavyAfterScriptCheckBox.IsEnabled = on;
            _shadowSerendipityCheckBox.IsEnabled = on;
        }

        _shadowEnabledCheckBox.Checked += (_, _) =>
        {
            foreach (CheckBox cb in shadowAuditPanel.Children) cb.IsEnabled = true;
            _shadowScopeCombo.IsEnabled = true;
            _shadowNotifyCheckBox.IsEnabled = true;
            SetLawControlsEnabled(true);
        };
        _shadowEnabledCheckBox.Unchecked += (_, _) =>
        {
            foreach (CheckBox cb in shadowAuditPanel.Children) cb.IsEnabled = false;
            _shadowScopeCombo.IsEnabled = false;
            _shadowNotifyCheckBox.IsEnabled = false;
            SetLawControlsEnabled(false);
        };

        // ─── Section: Power Mode ───
        AddSectionHeader(rootStack, "Power Mode", topMargin: 16);

        var pm = powerModeConfig ?? new PowerModeConfig();

        _powerModeCheckBox = new CheckBox
        {
            Content = "Enable Power mode \u2014 reveal hidden, aria-hidden, display:none, and disabled controls",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 4, 0, 2),
            IsChecked = pm.Enabled
        };
        rootStack.Children.Add(_powerModeCheckBox);
        _powerOverlaysCheckBox = new CheckBox
        {
            Content = "Overlay labels \u2014 outlines + floating tags (hidden / disabled / hidden inputs)",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(16, 0, 0, 4),
            IsChecked = pm.ShowOverlays,
            IsEnabled = pm.Enabled
        };
        rootStack.Children.Add(_powerOverlaysCheckBox);
        AddHint(rootStack, "May disrupt layout. Hidden inputs are labeled without changing input type (forms still submit).");
        _powerModeCheckBox.Checked += (_, _) => _powerOverlaysCheckBox.IsEnabled = true;
        _powerModeCheckBox.Unchecked += (_, _) => _powerOverlaysCheckBox.IsEnabled = false;

        // ─── Section: Red Team Whisper ───
        AddSectionHeader(rootStack, "Red Team Whisper", topMargin: 16);

        var wh = whisperConfig ?? new WhisperConfig();

        _whisperCheckBox = new CheckBox
        {
            Content = "Enable clues (DOM + network heuristics after navigation; stack/cache once per new domain)",
            Foreground = FgText,
            FontSize = 12,
            Margin = new Thickness(0, 4, 0, 2),
            IsChecked = wh.Enabled
        };
        rootStack.Children.Add(_whisperCheckBox);
        _whisperNotifyCheckBox = new CheckBox
        {
            Content = "GUI notifications when new clues appear",
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(16, 0, 0, 4),
            IsChecked = wh.NotifyGui,
            IsEnabled = wh.Enabled
        };
        rootStack.Children.Add(_whisperNotifyCheckBox);
        AddHint(rootStack, "Clues are hypotheses for you and the AI — not findings. Copy a toast for details. Shadow already covers CSP, cookies, XSS, mixed content, source maps, storage, and Retire.js.");
        _whisperCheckBox.Checked += (_, _) => _whisperNotifyCheckBox.IsEnabled = true;
        _whisperCheckBox.Unchecked += (_, _) => _whisperNotifyCheckBox.IsEnabled = false;

        rootGrid.Children.Add(rootStack);
        Grid.SetRow(rootStack, 0);

        // Footer: VPX I/O on the left, OK/Cancel on the right
        var footer = new DockPanel { Margin = new Thickness(24, 12, 24, 16) };

        var okCancelPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        DockPanel.SetDock(okCancelPanel, Dock.Right);

        var okButton = CreateButton("OK", isDefault: true);
        okButton.Click += (_, _) => { DialogResult = true; };

        var cancelButton = CreateButton("Cancel", isCancel: true);
        cancelButton.Click += (_, _) => { DialogResult = false; };
        cancelButton.Margin = new Thickness(8, 0, 0, 0);

        okCancelPanel.Children.Add(okButton);
        okCancelPanel.Children.Add(cancelButton);
        footer.Children.Add(okCancelPanel);

        var vpxPanel = new StackPanel { Orientation = Orientation.Horizontal };
        var exportBtn = CreateButton("VPX Export…", width: 110);
        exportBtn.IsEnabled = onVpxExport != null;
        exportBtn.ToolTip = "Save merged session findings as a VPX 1.1 document";
        exportBtn.Click += (_, _) => onVpxExport?.Invoke();
        var importBtn = CreateButton("VPX Import…", width: 110);
        importBtn.IsEnabled = onVpxImport != null;
        importBtn.Margin = new Thickness(8, 0, 0, 0);
        importBtn.ToolTip = "Merge a VPX document into this session (for continued dedup)";
        importBtn.Click += (_, _) => onVpxImport?.Invoke();
        vpxPanel.Children.Add(exportBtn);
        vpxPanel.Children.Add(importBtn);
        footer.Children.Add(vpxPanel);

        Grid.SetRow(footer, 1);
        rootGrid.Children.Add(footer);

        Content = rootGrid;
    }

    #region UI Helpers

    private static void AddSectionHeader(StackPanel parent, string text, double topMargin = 0)
    {
        parent.Children.Add(new TextBlock
        {
            Text = text,
            Foreground = Bc("#569CD6"),
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, topMargin, 0, 10)
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

    private static Button CreateButton(string text, bool isDefault = false, bool isCancel = false, double width = 90)
    {
        return new Button
        {
            Content = text,
            Width = width,
            Height = 28,
            IsDefault = isDefault,
            IsCancel = isCancel,
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
