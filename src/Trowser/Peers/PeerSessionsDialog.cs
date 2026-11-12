using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Trowser.Peers;

/// <summary>
/// Standalone manager for peer Trowser sessions (launch, health, BOLA test trigger).
/// </summary>
public class PeerSessionsDialog : Window
{
    private readonly PeerSessionManager _manager;
    private readonly StackPanel _peerList;
    private readonly TextBlock _helpText;
    private readonly TextBlock _bolaSummaryText;
    private readonly TextBlock _mirrorBannerText;
    private readonly Button _testBolaBtn;
    private readonly Button _launchAllBtn;
    private readonly Button _refreshBtn;
    private readonly Button _mirrorBtn;

    private readonly List<PeerRowUi> _rows = [];
    private bool _busy;
    private bool _mirrorActive;

    public int? BolaEndpointCount { get; set; }
    public bool UseCapturedHeadersBody { get; set; } = true;

    public Func<Task>? TestBolaRequested { get; set; }

    /// <summary>
    /// Called with <c>true</c> to enable Mirror Mode, <c>false</c> to disable.
    /// Returns whether the requested state was applied.
    /// </summary>
    public Func<bool, Task<bool>>? MirrorToggleRequested { get; set; }

    /// <summary>Optional status supplier for the mirror banner (peers, errors).</summary>
    public Func<(IReadOnlyList<string> peers, string? warning, IReadOnlyDictionary<string, string> errors)>? MirrorStatusProvider { get; set; }

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");

    public PeerSessionsDialog(PeerSessionManager manager, Window owner)
    {
        _manager = manager;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Peer Sessions";
        Width = 820;
        Height = 620;
        MinWidth = 640;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        var root = new Grid { Margin = new Thickness(12) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        _helpText = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            Foreground = FgDim,
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 8)
        };
        Grid.SetRow(_helpText, 0);
        root.Children.Add(_helpText);

        var scroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _peerList = new StackPanel();
        scroll.Content = _peerList;
        Grid.SetRow(scroll, 1);
        root.Children.Add(scroll);

        _bolaSummaryText = new TextBlock
        {
            Foreground = AccentBlue,
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 4),
            Visibility = Visibility.Collapsed
        };
        Grid.SetRow(_bolaSummaryText, 2);
        root.Children.Add(_bolaSummaryText);

        _mirrorBannerText = new TextBlock
        {
            Foreground = AccentGreen,
            FontSize = 12,
            Margin = new Thickness(0, 6, 0, 4),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed
        };
        Grid.SetRow(_mirrorBannerText, 3);
        root.Children.Add(_mirrorBannerText);

        var bottom = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        Grid.SetRow(bottom, 4);

        var leftButtons = new StackPanel { Orientation = Orientation.Horizontal };
        DockPanel.SetDock(leftButtons, Dock.Left);

        var addBtn = CreateButton("+ Add peer", AccentBlue);
        addBtn.Click += (_, _) => AddPeerRow();
        leftButtons.Children.Add(addBtn);

        _launchAllBtn = CreateButton("Launch all", AccentGreen);
        _launchAllBtn.Margin = new Thickness(8, 0, 0, 0);
        _launchAllBtn.Click += async (_, _) => await LaunchAllAsync();
        leftButtons.Children.Add(_launchAllBtn);

        _refreshBtn = CreateButton("Refresh", FgText);
        _refreshBtn.Margin = new Thickness(8, 0, 0, 0);
        _refreshBtn.Click += async (_, _) => await RefreshAsync();
        leftButtons.Children.Add(_refreshBtn);

        _mirrorBtn = CreateButton("Mirror Mode", FgText);
        _mirrorBtn.Margin = new Thickness(8, 0, 0, 0);
        _mirrorBtn.FontWeight = FontWeights.SemiBold;
        ToolTipService.SetShowOnDisabled(_mirrorBtn, true);
        // async void: an escaping exception would reach Dispatcher.UnhandledException and kill the process.
        _mirrorBtn.Click += async (_, _) =>
        {
            try
            {
                await OnMirrorToggleClickAsync();
            }
            catch (Exception ex)
            {
                TrowserLog.Error("Mirror Mode toggle failed", ex);
                SetBusy(false);
                MessageBox.Show($"Mirror Mode failed: {ex.Message}", "Mirror Mode",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        leftButtons.Children.Add(_mirrorBtn);

        bottom.Children.Add(leftButtons);

        var rightButtons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        DockPanel.SetDock(rightButtons, Dock.Right);

        var closeBtn = CreateButton("Close", FgText);
        closeBtn.Click += (_, _) => Close();
        rightButtons.Children.Add(closeBtn);

        _testBolaBtn = CreateButton("Test BOLA", AccentRed);
        _testBolaBtn.Margin = new Thickness(0, 0, 8, 0);
        _testBolaBtn.FontWeight = FontWeights.SemiBold;
        _testBolaBtn.Click += async (_, _) => await OnTestBolaClickAsync();
        _testBolaBtn.Visibility = Visibility.Collapsed;
        rightButtons.Children.Add(_testBolaBtn);

        bottom.Children.Add(rightButtons);
        root.Children.Add(bottom);
        Content = root;

        Closing += (_, _) => SyncAllRows();

        Loaded += async (_, _) =>
        {
            RebuildPeerList();
            UpdateHelpText();
            await RefreshAsync();
            RefreshMirrorUi();
        };
    }

    /// <summary>Sync dialog chrome with the controller's current mirror state.</summary>
    public void SetMirrorActive(bool active)
    {
        _mirrorActive = active;
        RefreshMirrorUi();
    }

    public void SetBolaContext(int endpointCount, bool useCapturedHeadersBody)
    {
        BolaEndpointCount = endpointCount;
        UseCapturedHeadersBody = useCapturedHeadersBody;
        _testBolaBtn.Visibility = endpointCount > 0 ? Visibility.Visible : Visibility.Collapsed;
        UpdateBolaSummary();
        UpdateHelpText();
    }

    private void UpdateHelpText()
    {
        if (BolaEndpointCount is > 0)
        {
            _helpText.Text =
                "Peer sessions let you test the same API as different users. Launch each peer, log in as a " +
                "different user in that Trowser window, then return here and click Test BOLA. " +
                "The test replays your checked Endpoint Probe requests in this session (driver) and each peer, " +
                "then flags identical responses as BOLA_SUSPECTED.";
        }
        else
        {
            _helpText.Text =
                "Manage additional Trowser instances for cross-user testing. Launch peers, log in as different " +
                "users, then use Live Authz Shadow to compare authorization while using the site. " +
                "Mirror Mode replays GUI actions from this window to all alive peers (cookies and URLs stay independent).";
        }
    }

    private void UpdateBolaSummary()
    {
        if (BolaEndpointCount is not > 0)
        {
            _bolaSummaryText.Visibility = Visibility.Collapsed;
            return;
        }

        var testPeers = _manager.Sessions.Count(s => s.Config.UseForTests);
        _bolaSummaryText.Visibility = Visibility.Visible;
        _bolaSummaryText.Text =
            $"Ready to test {BolaEndpointCount} endpoint(s) × {testPeers} peer(s) marked for tests.";
    }

    private void RebuildPeerList()
    {
        _peerList.Children.Clear();
        _rows.Clear();

        foreach (var state in _manager.Sessions)
            AddPeerRowUi(state);

        if (_manager.Sessions.Count == 0)
            AddPeerRow();
    }

    private void AddPeerRow()
    {
        var state = _manager.AddPeer();
        AddPeerRowUi(state);
        UpdateBolaSummary();
    }

    private void AddPeerRowUi(PeerSessionState state)
    {
        var border = new Border
        {
            Background = BgItem,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(8),
            Margin = new Thickness(0, 0, 0, 4)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var nameBox = CreateTextBox(state.Config.Name);
        var portBox = CreateTextBox(state.Config.Port.ToString());
        var sessionBox = CreateTextBox(state.Config.SessionName);
        var apiKeyBox = CreateTextBox(state.Config.ApiKey);
        apiKeyBox.FontFamily = new FontFamily("Consolas");

        var useForTests = new CheckBox
        {
            Content = "Use for tests",
            IsChecked = state.Config.UseForTests,
            Foreground = FgText,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 4, 0, 0),
            ToolTip = "When checked, BOLA and Live Authz Shadow replay this peer once it is running."
        };
        useForTests.Checked += (_, _) => SetUseForTests(state, true);
        useForTests.Unchecked += (_, _) => SetUseForTests(state, false);

        var statusDot = new Ellipse
        {
            Width = 10,
            Height = 10,
            Fill = state.Alive ? AccentGreen : FgDim,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 6, 0)
        };
        var statusText = new TextBlock
        {
            Text = state.Alive
                ? $"alive ({state.RemoteSessionName ?? state.Config.SessionName})"
                : (state.LastError ?? "not running"),
            Foreground = state.Alive ? AccentGreen : FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        var mirrorBadge = new TextBlock
        {
            Text = "mirroring",
            Foreground = AccentGreen,
            FontSize = 10,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0),
            Visibility = Visibility.Collapsed
        };
        var statusPanel = new StackPanel { Orientation = Orientation.Horizontal };
        statusPanel.Children.Add(statusDot);
        statusPanel.Children.Add(statusText);
        statusPanel.Children.Add(mirrorBadge);

        var launchBtn = CreateButton("Launch", AccentGreen);
        launchBtn.Margin = new Thickness(4, 0, 0, 0);
        launchBtn.Click += async (_, _) =>
        {
            SyncRowToConfig(state, nameBox, portBox, sessionBox, apiKeyBox, useForTests);
            await LaunchOneAsync(state, statusDot, statusText);
        };

        var stopBtn = CreateButton("Stop", AccentRed);
        stopBtn.Margin = new Thickness(4, 0, 0, 0);
        stopBtn.Click += async (_, _) =>
        {
            await _manager.StopAsync(state);
            statusDot.Fill = FgDim;
            statusText.Text = "stopped";
            statusText.Foreground = FgDim;
            RefreshMirrorUi();
        };

        var removeBtn = CreateButton("Remove", FgDim);
        removeBtn.Margin = new Thickness(4, 0, 0, 0);
        removeBtn.Click += async (_, _) =>
        {
            await _manager.StopAsync(state);
            _manager.RemovePeer(state.Config.Name);
            RebuildPeerList();
            UpdateBolaSummary();
        };

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        btnPanel.Children.Add(launchBtn);
        btnPanel.Children.Add(stopBtn);
        btnPanel.Children.Add(removeBtn);

        AddLabeled(grid, 0, 0, "Name", nameBox);
        AddLabeled(grid, 0, 1, "Port", portBox);
        AddLabeled(grid, 0, 2, "Session", sessionBox);
        AddLabeled(grid, 0, 3, "API key", apiKeyBox);

        Grid.SetColumn(useForTests, 0);
        Grid.SetColumnSpan(useForTests, 2);
        Grid.SetRow(useForTests, 1);
        grid.Children.Add(useForTests);

        Grid.SetColumn(statusPanel, 2);
        Grid.SetColumnSpan(statusPanel, 2);
        Grid.SetRow(statusPanel, 1);
        grid.Children.Add(statusPanel);

        Grid.SetColumn(btnPanel, 4);
        Grid.SetRow(btnPanel, 1);
        grid.Children.Add(btnPanel);

        border.Child = grid;
        _peerList.Children.Add(border);

        _rows.Add(new PeerRowUi(state, nameBox, portBox, sessionBox, apiKeyBox, useForTests, statusDot, statusText, mirrorBadge));
    }

    private static void AddLabeled(Grid grid, int row, int col, string label, Control control)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 0, 6, 4) };
        panel.Children.Add(new TextBlock
        {
            Text = label,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 0, 0, 2)
        });
        panel.Children.Add(control);
        Grid.SetRow(panel, row);
        Grid.SetColumn(panel, col);
        grid.Children.Add(panel);
    }

    private static void SyncRowToConfig(
        PeerSessionState state,
        TextBox nameBox,
        TextBox portBox,
        TextBox sessionBox,
        TextBox apiKeyBox,
        CheckBox useForTests)
    {
        state.Config.Name = nameBox.Text.Trim();
        if (int.TryParse(portBox.Text.Trim(), out var port))
            state.Config.Port = port;
        state.Config.SessionName = sessionBox.Text.Trim();
        state.Config.ApiKey = apiKeyBox.Text.Trim();
        state.Config.UseForTests = useForTests.IsChecked == true;
    }

    private void SetUseForTests(PeerSessionState state, bool value)
    {
        if (state.Config.UseForTests == value)
            return;
        state.Config.UseForTests = value;
        _manager.Persist();
        UpdateBolaSummary();
    }

    private void SyncAllRows()
    {
        foreach (var row in _rows)
            SyncRowToConfig(row.State, row.NameBox, row.PortBox, row.SessionBox, row.ApiKeyBox, row.UseForTests);
        _manager.Persist();
    }

    private async Task LaunchOneAsync(PeerSessionState state, Ellipse statusDot, TextBlock statusText)
    {
        SetBusy(true);
        try
        {
            var (ok, error) = await _manager.LaunchAsync(state);
            var row = _rows.FirstOrDefault(r => ReferenceEquals(r.State, state));
            if (row != null)
            {
                row.PortBox.Text = state.Config.Port.ToString();
                row.ApiKeyBox.Text = state.Config.ApiKey;
            }

            statusDot.Fill = ok ? AccentGreen : AccentRed;
            if (ok)
            {
                statusText.Text = !string.IsNullOrEmpty(state.LastError)
                    ? state.LastError
                    : $"alive ({state.RemoteSessionName ?? state.Config.SessionName})";
                statusText.Foreground = string.IsNullOrEmpty(state.LastError) ? AccentGreen : AccentBlue;
            }
            else
            {
                statusText.Text = error ?? "failed";
                statusText.Foreground = AccentRed;
            }
        }
        finally
        {
            SetBusy(false);
            UpdateBolaSummary();
            RefreshMirrorUi();
        }
    }

    private async Task LaunchAllAsync()
    {
        SyncAllRows();
        SetBusy(true);
        try
        {
            foreach (var row in _rows)
            {
                await _manager.LaunchAsync(row.State);
                row.StatusDot.Fill = row.State.Alive ? AccentGreen : AccentRed;
                row.StatusText.Text = row.State.Alive
                    ? $"alive ({row.State.RemoteSessionName ?? row.State.Config.SessionName})"
                    : (row.State.LastError ?? "failed");
                row.StatusText.Foreground = row.State.Alive ? AccentGreen : AccentRed;
            }
        }
        finally
        {
            SetBusy(false);
            UpdateBolaSummary();
            RefreshMirrorUi();
        }
    }

    private async Task RefreshAsync()
    {
        SyncAllRows();
        await _manager.RefreshHealthAsync();
        foreach (var row in _rows)
        {
            row.StatusDot.Fill = row.State.Alive ? AccentGreen : FgDim;
            if (row.State.Alive)
            {
                row.StatusText.Text = !string.IsNullOrEmpty(row.State.LastError)
                    ? row.State.LastError
                    : $"alive ({row.State.RemoteSessionName ?? row.State.Config.SessionName})";
                row.StatusText.Foreground = string.IsNullOrEmpty(row.State.LastError) ? AccentGreen : AccentBlue;
            }
            else
            {
                row.StatusText.Text = row.State.LastError ?? "not running";
                row.StatusText.Foreground = FgDim;
            }
        }
        UpdateBolaSummary();
        RefreshMirrorUi();
    }

    private async Task OnMirrorToggleClickAsync()
    {
        if (_busy || MirrorToggleRequested == null) return;
        SyncAllRows();

        var wantOn = !_mirrorActive;
        if (wantOn && !_manager.Sessions.Any(s => s.Alive))
        {
            MessageBox.Show(
                "Launch at least one peer before enabling Mirror Mode.",
                "Peer Sessions",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        SetBusy(true);
        try
        {
            var applied = await MirrorToggleRequested.Invoke(wantOn);
            if (applied)
                _mirrorActive = wantOn;
        }
        finally
        {
            SetBusy(false);
            RefreshMirrorUi();
        }
    }

    private void RefreshMirrorUi()
    {
        var aliveCount = _manager.Sessions.Count(s => s.Alive);
        _mirrorBtn.IsEnabled = !_busy && (_mirrorActive || aliveCount > 0);

        if (_mirrorActive)
        {
            _mirrorBtn.Content = "Mirror Mode ●";
            _mirrorBtn.Foreground = AccentGreen;
            _mirrorBtn.ToolTip = "Mirror Mode is on — click to stop. GUI actions in this window are replayed to all mirrored peers.";
        }
        else
        {
            _mirrorBtn.Content = "Mirror Mode";
            _mirrorBtn.Foreground = FgText;
            _mirrorBtn.ToolTip = aliveCount > 0
                ? "Replay GUI clicks, typing, scrolling, and address-bar navigation from this window to all alive peers. Cookies and URLs stay independent."
                : "Launch at least one peer before enabling Mirror Mode.";
        }

        HashSet<string>? mirroredNames = null;
        string? warning = null;
        IReadOnlyDictionary<string, string>? errors = null;

        if (_mirrorActive && MirrorStatusProvider != null)
        {
            var status = MirrorStatusProvider.Invoke();
            mirroredNames = new HashSet<string>(status.peers, StringComparer.OrdinalIgnoreCase);
            warning = status.warning;
            errors = status.errors;
        }

        foreach (var row in _rows)
        {
            var isMirrored = mirroredNames != null && mirroredNames.Contains(row.State.Config.Name);
            row.MirrorBadge.Visibility = isMirrored ? Visibility.Visible : Visibility.Collapsed;
        }

        if (_mirrorActive)
        {
            _mirrorBannerText.Visibility = Visibility.Visible;
            var peerList = mirroredNames is { Count: > 0 }
                ? string.Join(", ", mirroredNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
                : "(none)";
            var text = $"Mirror Mode ON — replaying to: {peerList}";
            if (!string.IsNullOrEmpty(warning))
                text += $"\n{warning}";
            if (errors is { Count: > 0 })
            {
                var errParts = errors.Select(kv => $"{kv.Key}: {kv.Value}");
                text += "\nErrors: " + string.Join(" | ", errParts);
                _mirrorBannerText.Foreground = AccentBlue;
            }
            else
            {
                _mirrorBannerText.Foreground = AccentGreen;
            }
            _mirrorBannerText.Text = text;
        }
        else
        {
            _mirrorBannerText.Visibility = Visibility.Collapsed;
            _mirrorBannerText.Text = "";
        }
    }

    private async Task OnTestBolaClickAsync()
    {
        if (_busy || TestBolaRequested == null) return;
        SyncAllRows();

        var peersForTest = _manager.GetPeersForTests();
        if (peersForTest.Count == 0)
        {
            MessageBox.Show(
                "No alive peers marked \"Use for tests\". Launch at least one peer and log in as a different user.",
                "Peer Sessions",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        SetBusy(true);
        try
        {
            await TestBolaRequested.Invoke();
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        _testBolaBtn.IsEnabled = !busy;
        _launchAllBtn.IsEnabled = !busy;
        _refreshBtn.IsEnabled = !busy;
        // Mirror enable/disable is handled in RefreshMirrorUi (needs alive count)
        if (!busy)
            RefreshMirrorUi();
        else
            _mirrorBtn.IsEnabled = false;
    }

    private static TextBox CreateTextBox(string text) => new()
    {
        Text = text,
        Background = BgDark,
        Foreground = FgText,
        BorderBrush = BorderClr,
        Padding = new Thickness(4, 2, 4, 2),
        FontSize = 12
    };

    private static Button CreateButton(string text, Brush foreground)
    {
        var btn = new Button
        {
            Content = text,
            Foreground = foreground,
            Background = BgItem,
            BorderBrush = BorderClr,
            Padding = new Thickness(10, 4, 10, 4),
            Cursor = System.Windows.Input.Cursors.Hand
        };
        return btn;
    }

    private static SolidColorBrush Bc(string hex) =>
        (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;

    private sealed class PeerRowUi(
        PeerSessionState state,
        TextBox nameBox,
        TextBox portBox,
        TextBox sessionBox,
        TextBox apiKeyBox,
        CheckBox useForTests,
        Ellipse statusDot,
        TextBlock statusText,
        TextBlock mirrorBadge)
    {
        public PeerSessionState State { get; } = state;
        public TextBox NameBox { get; } = nameBox;
        public TextBox PortBox { get; } = portBox;
        public TextBox SessionBox { get; } = sessionBox;
        public TextBox ApiKeyBox { get; } = apiKeyBox;
        public CheckBox UseForTests { get; } = useForTests;
        public Ellipse StatusDot { get; } = statusDot;
        public TextBlock StatusText { get; } = statusText;
        public TextBlock MirrorBadge { get; } = mirrorBadge;
    }
}
