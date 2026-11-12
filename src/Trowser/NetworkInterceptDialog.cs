using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Trowser.Automation;

namespace Trowser;

/// <summary>
/// Modeless dialog for managing network mock rules, breakpoint rules, and pending intercepted requests.
/// Stays open so the user can interact with the browser while managing interception.
/// </summary>
public class NetworkInterceptDialog : Window
{
    private readonly AutomationContext _context;
    private readonly Window _mainWindow;
    private readonly DispatcherTimer _refreshTimer;

    // Mock rule inputs
    private readonly TextBox _mockUrlPattern;
    private readonly TextBox _mockStatus;
    private readonly TextBox _mockBody;
    private readonly TextBox _mockDelay;
    private readonly StackPanel _mockRulesList;

    // Breakpoint inputs
    private readonly TextBox _bpUrlPattern;
    private readonly TextBox _bpMethod;
    private readonly StackPanel _bpRulesList;

    // Pending requests
    private readonly StackPanel _pendingSection;
    private readonly StackPanel _pendingList;

    public event Action? InterceptStateChanged;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentYellow = Bc("#CCA700");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");

    public NetworkInterceptDialog(AutomationContext context, Window owner)
    {
        _context = context;
        _mainWindow = owner;
        Owner = owner;
        Title = "Network Interception";
        Width = 620;
        Height = 680;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var scrollViewer = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(0)
        };

        var rootStack = new StackPanel { Margin = new Thickness(20, 16, 20, 8) };

        // ─── Section: Mock Rules ───
        AddSectionHeader(rootStack, "Mock Rules");
        AddHint(rootStack, "Intercept matching requests and return fake responses (error codes, delays, custom bodies).");

        _mockRulesList = new StackPanel { Margin = new Thickness(0, 6, 0, 6) };
        rootStack.Children.Add(_mockRulesList);

        var mockInputGrid = new Grid { Margin = new Thickness(0, 4, 0, 0) };
        mockInputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        mockInputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });
        mockInputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        mockInputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });

        _mockUrlPattern = CreateTextBox("/api/users");
        _mockUrlPattern.ToolTip = "URL pattern (glob with * or substring)";
        Grid.SetColumn(_mockUrlPattern, 0);
        mockInputGrid.Children.Add(_mockUrlPattern);

        _mockStatus = CreateTextBox("500", 54);
        _mockStatus.ToolTip = "Status code";
        _mockStatus.Margin = new Thickness(4, 0, 0, 0);
        Grid.SetColumn(_mockStatus, 1);
        mockInputGrid.Children.Add(_mockStatus);

        _mockBody = CreateTextBox("{\"error\": \"Server Error\"}");
        _mockBody.ToolTip = "Response body";
        _mockBody.Margin = new Thickness(4, 0, 0, 0);
        Grid.SetColumn(_mockBody, 2);
        mockInputGrid.Children.Add(_mockBody);

        _mockDelay = CreateTextBox("0", 54);
        _mockDelay.ToolTip = "Delay (ms)";
        _mockDelay.Margin = new Thickness(4, 0, 0, 0);
        Grid.SetColumn(_mockDelay, 3);
        mockInputGrid.Children.Add(_mockDelay);

        rootStack.Children.Add(mockInputGrid);

        var mockLabelRow = new Grid { Margin = new Thickness(0, 1, 0, 0) };
        mockLabelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        mockLabelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });
        mockLabelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        mockLabelRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(60) });
        AddMicroLabel(mockLabelRow, "URL Pattern", 0);
        AddMicroLabel(mockLabelRow, "Status", 1, new Thickness(4, 0, 0, 0));
        AddMicroLabel(mockLabelRow, "Body", 2, new Thickness(4, 0, 0, 0));
        AddMicroLabel(mockLabelRow, "Delay ms", 3, new Thickness(4, 0, 0, 0));
        rootStack.Children.Add(mockLabelRow);

        var mockButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
        var addMockBtn = CreateSmallButton("Add Mock", AccentGreen);
        addMockBtn.Click += AddMock_Click;
        mockButtons.Children.Add(addMockBtn);
        var clearMocksBtn = CreateSmallButton("Clear All", Bc("#3F3F46"));
        clearMocksBtn.Margin = new Thickness(6, 0, 0, 0);
        clearMocksBtn.Click += (_, _) => { _context.ClearMocks(); RefreshAll(); };
        mockButtons.Children.Add(clearMocksBtn);
        rootStack.Children.Add(mockButtons);

        // ─── Section: Breakpoints ───
        AddSectionHeader(rootStack, "Breakpoints", 18);
        AddHint(rootStack, "Pause requests matching a URL regex. Decide per-request: continue, fulfill, or abort.");

        _bpRulesList = new StackPanel { Margin = new Thickness(0, 6, 0, 6) };
        rootStack.Children.Add(_bpRulesList);

        var bpInputRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
        _bpUrlPattern = CreateTextBox("/api/users");
        _bpUrlPattern.Width = 340;
        _bpUrlPattern.ToolTip = "URL regex pattern";
        bpInputRow.Children.Add(_bpUrlPattern);

        _bpMethod = CreateTextBox("", 80);
        _bpMethod.ToolTip = "Method filter (optional)";
        _bpMethod.Margin = new Thickness(4, 0, 0, 0);
        bpInputRow.Children.Add(_bpMethod);
        rootStack.Children.Add(bpInputRow);

        var bpLabelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 1, 0, 0) };
        bpLabelRow.Children.Add(new TextBlock { Text = "URL Regex", Foreground = FgDim, FontSize = 9, Width = 340 });
        bpLabelRow.Children.Add(new TextBlock { Text = "Method", Foreground = FgDim, FontSize = 9, Margin = new Thickness(4, 0, 0, 0) });
        rootStack.Children.Add(bpLabelRow);

        var bpButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
        var addBpBtn = CreateSmallButton("Add Breakpoint", AccentBlue);
        addBpBtn.Click += AddBreakpoint_Click;
        bpButtons.Children.Add(addBpBtn);
        var clearBpBtn = CreateSmallButton("Clear All", Bc("#3F3F46"));
        clearBpBtn.Margin = new Thickness(6, 0, 0, 0);
        clearBpBtn.Click += (_, _) => { _context.ClearInterceptRules(); RefreshAll(); };
        bpButtons.Children.Add(clearBpBtn);
        rootStack.Children.Add(bpButtons);

        // ─── Section: Pending Requests ───
        _pendingSection = new StackPanel();
        AddSectionHeader(_pendingSection, "Pending Requests", 18);
        AddHint(_pendingSection, "Requests held at breakpoints. Choose an action for each, or they auto-continue after 120s.");

        _pendingList = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
        _pendingSection.Children.Add(_pendingList);

        rootStack.Children.Add(_pendingSection);

        scrollViewer.Content = rootStack;
        Grid.SetRow(scrollViewer, 0);
        rootGrid.Children.Add(scrollViewer);

        // Bottom bar: Import / Export on left, Close on right
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

        DockPanel.SetDock(ioPanel, Dock.Left);
        bottomBar.Children.Add(ioPanel);

        Grid.SetRow(bottomBar, 1);
        rootGrid.Children.Add(bottomBar);

        Content = rootGrid;

        // Auto-refresh for pending requests
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _refreshTimer.Tick += (_, _) => RefreshPending();
        _refreshTimer.Start();

        Closed += (_, _) => _refreshTimer.Stop();

        RefreshAll();
    }

    private void AddMock_Click(object sender, RoutedEventArgs e)
    {
        var urlPattern = _mockUrlPattern.Text.Trim();
        if (string.IsNullOrEmpty(urlPattern)) return;

        int.TryParse(_mockStatus.Text.Trim(), out var status);
        if (status <= 0) status = 200;
        int.TryParse(_mockDelay.Text.Trim(), out var delay);

        var body = _mockBody.Text.Trim();
        _context.MockResponse(urlPattern, status, string.IsNullOrEmpty(body) ? null : body, delayMs: delay);
        RefreshAll();
    }

    private void AddBreakpoint_Click(object sender, RoutedEventArgs e)
    {
        var urlPattern = _bpUrlPattern.Text.Trim();
        if (string.IsNullOrEmpty(urlPattern)) return;

        var method = _bpMethod.Text.Trim();
        _context.AddInterceptRule(urlPattern, string.IsNullOrEmpty(method) ? null : method, silent: false);
        RefreshAll();
    }

    private void RefreshAll()
    {
        RefreshMockRules();
        RefreshBreakpointRules();
        RefreshPending();
        InterceptStateChanged?.Invoke();
    }

    private void RefreshMockRules()
    {
        _mockRulesList.Children.Clear();
        var rules = _context.GetMockRules();

        if (rules.Count == 0)
        {
            _mockRulesList.Children.Add(new TextBlock
            {
                Text = "No mock rules active.",
                Foreground = FgDim,
                FontSize = 11,
                FontStyle = FontStyles.Italic
            });
            return;
        }

        foreach (var r in rules)
        {
            var row = new Border
            {
                Background = r.Enabled ? BgItem : BgDark,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(6, 4, 4, 4),
                Margin = new Thickness(0, 0, 0, 3)
            };

            var dock = new DockPanel();

            var removeBtn = CreateTinyButton("\u2715");
            var pattern = r.UrlPattern;
            var method = r.Method;
            removeBtn.Click += (_, _) => { _context.RemoveMock(pattern); RefreshAll(); };
            DockPanel.SetDock(removeBtn, Dock.Right);
            dock.Children.Add(removeBtn);

            var copyBtn = CreateTinyButton("\uD83D\uDCCB");
            copyBtn.ToolTip = "Copy as JSON";
            var mockRule = r;
            copyBtn.Click += (_, _) => CopyMockToClipboard(mockRule);
            DockPanel.SetDock(copyBtn, Dock.Right);
            dock.Children.Add(copyBtn);

            var check = new CheckBox
            {
                IsChecked = r.Enabled,
                Foreground = FgText,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = r.Enabled ? "Disable this mock" : "Enable this mock"
            };
            check.Checked += (_, _) => { _context.SetMockRuleEnabled(pattern, method, true); RefreshAll(); };
            check.Unchecked += (_, _) => { _context.SetMockRuleEnabled(pattern, method, false); RefreshAll(); };
            DockPanel.SetDock(check, Dock.Left);
            dock.Children.Add(check);

            var methodStr = r.Method ?? "ANY";
            var info = $"[{r.StatusCode}] {methodStr} {r.UrlPattern}";
            if (r.DelayMs > 0) info += $" (+{r.DelayMs}ms)";
            var textBlock = new TextBlock
            {
                Text = info,
                Foreground = r.Enabled ? FgText : FgDim,
                FontSize = 11,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            dock.Children.Add(textBlock);

            row.Child = dock;
            _mockRulesList.Children.Add(row);
        }
    }

    private void RefreshBreakpointRules()
    {
        _bpRulesList.Children.Clear();
        var rules = _context.GetInterceptRules();

        if (rules.Count == 0)
        {
            _bpRulesList.Children.Add(new TextBlock
            {
                Text = "No breakpoints active.",
                Foreground = FgDim,
                FontSize = 11,
                FontStyle = FontStyles.Italic
            });
            return;
        }

        foreach (var r in rules)
        {
            var row = new Border
            {
                Background = r.Enabled ? BgItem : BgDark,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(6, 4, 4, 4),
                Margin = new Thickness(0, 0, 0, 3)
            };

            var dock = new DockPanel();

            var removeBtn = CreateTinyButton("\u2715");
            var pattern = r.UrlPattern;
            var method = r.Method;
            removeBtn.Click += (_, _) => { _context.RemoveInterceptRule(pattern); RefreshAll(); };
            DockPanel.SetDock(removeBtn, Dock.Right);
            dock.Children.Add(removeBtn);

            var copyBtn = CreateTinyButton("\uD83D\uDCCB");
            copyBtn.ToolTip = "Copy URL pattern";
            var urlPattern = r.UrlPattern;
            copyBtn.Click += (_, _) => CopyToClipboard(urlPattern);
            DockPanel.SetDock(copyBtn, Dock.Right);
            dock.Children.Add(copyBtn);

            var check = new CheckBox
            {
                IsChecked = r.Enabled,
                Foreground = FgText,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0),
                ToolTip = r.Enabled ? "Disable this breakpoint" : "Enable this breakpoint"
            };
            check.Checked += (_, _) => { _context.SetInterceptRuleEnabled(pattern, method, true); RefreshAll(); };
            check.Unchecked += (_, _) => { _context.SetInterceptRuleEnabled(pattern, method, false); RefreshAll(); };
            DockPanel.SetDock(check, Dock.Left);
            dock.Children.Add(check);

            var info = $"/{r.UrlPattern}/";
            if (r.Method != null) info += $"  method={r.Method}";
            var textBlock = new TextBlock
            {
                Text = info,
                Foreground = r.Enabled ? AccentBlue : FgDim,
                FontSize = 11,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            dock.Children.Add(textBlock);

            row.Child = dock;
            _bpRulesList.Children.Add(row);
        }
    }

    private void RefreshPending()
    {
        var pending = _context.GetPendingRequests();
        _pendingSection.Visibility = pending.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        _pendingList.Children.Clear();

        foreach (var p in pending)
        {
            var row = new Border
            {
                Background = BgItem,
                BorderBrush = AccentYellow,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(8, 6, 8, 6),
                Margin = new Thickness(0, 0, 0, 4)
            };

            var stack = new StackPanel();

            stack.Children.Add(new TextBlock
            {
                Text = $"#{p.Id}  {p.Method}  {p.Url}",
                Foreground = AccentYellow,
                FontSize = 11,
                FontFamily = new FontFamily("Consolas"),
                TextTrimming = TextTrimming.CharacterEllipsis
            });

            stack.Children.Add(new TextBlock
            {
                Text = $"Matched: /{p.MatchedPattern}/   Type: {p.ResourceType}   {p.Timestamp:HH:mm:ss}",
                Foreground = FgDim,
                FontSize = 9,
                Margin = new Thickness(0, 2, 0, 4)
            });

            var buttons = new StackPanel { Orientation = Orientation.Horizontal };
            var reqId = p.Id;
            var pendingRef = p;

            var inspectBtn = CreateSmallButton("Inspect \u25B6", AccentBlue);
            inspectBtn.Click += (_, _) =>
            {
                if (_mainWindow is MainWindow mw)
                    mw.InspectPendingRequest(pendingRef);
            };
            buttons.Children.Add(inspectBtn);

            var continueBtn = CreateSmallButton("Continue", AccentGreen);
            continueBtn.Margin = new Thickness(4, 0, 0, 0);
            continueBtn.Click += (_, _) =>
            {
                _context.ResolvePendingRequest(reqId, new InterceptDecision { Action = InterceptAction.Continue });
                RefreshAll();
            };
            buttons.Children.Add(continueBtn);

            var abortBtn = CreateSmallButton("Abort", AccentRed);
            abortBtn.Margin = new Thickness(4, 0, 0, 0);
            abortBtn.Click += (_, _) =>
            {
                _context.ResolvePendingRequest(reqId, new InterceptDecision { Action = InterceptAction.Abort });
                RefreshAll();
            };
            buttons.Children.Add(abortBtn);

            stack.Children.Add(buttons);

            row.Child = stack;
            _pendingList.Children.Add(row);
        }
    }

    #region Import / Export

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var json = InterceptSettings.ExportToJson(_context);
            var dialog = new SaveFileDialog
            {
                Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                DefaultExt = ".json",
                FileName = "intercept-rules.json",
                Title = "Export Intercept Rules"
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
                Title = "Import Intercept Rules"
            };
            if (dialog.ShowDialog() != true) return;

            var json = File.ReadAllText(dialog.FileName);

            var existingMocks = _context.GetMockRules().Count;
            var existingBps = _context.GetInterceptRules().Count;
            bool clearExisting = true;

            if (existingMocks > 0 || existingBps > 0)
            {
                var result = MessageBox.Show(
                    $"You have {existingMocks} mock(s) and {existingBps} breakpoint(s).\n\n" +
                    "Replace all existing rules with the imported ones?\n\n" +
                    "Yes = Replace  |  No = Merge (add to existing)",
                    "Import Rules",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question);

                if (result == MessageBoxResult.Cancel) return;
                clearExisting = result == MessageBoxResult.Yes;
            }

            var (mocks, breakpoints) = InterceptSettings.ImportFromJson(_context, json, clearExisting);
            RefreshAll();

            MessageBox.Show(
                $"Imported {mocks} mock(s) and {breakpoints} breakpoint(s).",
                "Import Complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Import failed: {ex.Message}", "Import Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    #endregion

    #region Copy

    private static void CopyToClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch { }
    }

    private void CopyMockToClipboard(Automation.MockRule rule)
    {
        try
        {
            var json = InterceptSettings.ExportSingleMockToJson(rule);
            Clipboard.SetText(json);
        }
        catch { }
    }

    #endregion

    #region UI Helpers

    private static void AddSectionHeader(Panel parent, string text, double topMargin = 0)
    {
        if (parent is StackPanel sp)
        {
            sp.Children.Add(new TextBlock
            {
                Text = text,
                Foreground = AccentBlue,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, topMargin, 0, 4)
            });
        }
    }

    private static void AddHint(Panel parent, string text)
    {
        if (parent is StackPanel sp)
        {
            sp.Children.Add(new TextBlock
            {
                Text = text,
                Foreground = FgDim,
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 2),
                TextWrapping = TextWrapping.Wrap
            });
        }
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

    private static Button CreateTinyButton(string text)
    {
        return new Button
        {
            Content = text,
            Width = 22,
            Height = 22,
            Background = Brushes.Transparent,
            Foreground = FgDim,
            BorderThickness = new Thickness(0),
            FontSize = 10,
            Cursor = Cursors.Hand,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(4, 0, 0, 0)
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

    #endregion
}
