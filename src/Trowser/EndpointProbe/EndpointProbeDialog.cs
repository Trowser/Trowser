using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.EndpointProbe;

internal enum EndpointSortColumn
{
    Method,
    Time,
    Risk,
    Url
}

/// <summary>
/// Modeless dialog for selecting network-log endpoints and running scoped security probes.
/// </summary>
public class EndpointProbeDialog : Window
{
    private readonly AutomationContext _context;
    private readonly PlaybookRegistry _playbookRegistry;

    private readonly StackPanel _endpointList;
    private readonly Grid _endpointHeader;
    private readonly StackPanel _probeList;
    private readonly ComboBox _safetyCombo;
    private readonly ComboBox _depthCombo;
    private readonly CheckBox _useCapturedCheck;
    private readonly CheckBox _replayOnceCheck;
    private readonly CheckBox _allHeadersCheck;
    private readonly Button _runBtn;

    private readonly List<EndpointProbeItem> _imported = [];
    private readonly List<(EndpointProbeItem Item, CheckBox Box)> _endpointRows = [];
    private readonly List<(EndpointProbeDefinition Def, CheckBox Box)> _probeRows = [];
    private readonly List<EndpointProbeItem> _cachedEndpoints = [];
    private readonly Dictionary<EndpointSortColumn, TextBlock> _sortHeaderLabels = [];

    private static EndpointSortColumn _sortColumn = EndpointSortColumn.Risk;
    private static bool _sortAscending;

    private bool _running;

    public event Action? ProbeRunStarting;
    public event Action<string>? ProbeRunFinished;

    /// <summary>Raised when the user wants to load a captured endpoint into the HTTP Request Editor.</summary>
    public event Action<EndpointProbeItem>? OpenInRequestEditorRequested;

    /// <summary>Raised when the user wants to paste a captured endpoint into the AI Assistant chat.</summary>
    public event Action<EndpointProbeItem>? SendToChatRequested;

    /// <summary>Raised when the user wants to run BOLA testing via peer sessions (checks the row first).</summary>
    public event Action? TestBolaPeerRequested;

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

    public EndpointProbeDialog(AutomationContext context, PlaybookRegistry playbookRegistry, Window owner)
    {
        _context = context;
        _playbookRegistry = playbookRegistry;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Endpoint Probe";
        Width = 880;
        Height = 820;
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

        AddSectionHeader(rootStack, "Endpoints");
        AddHint(rootStack,
            "Endpoints from the session network log, prioritized like attack surface. Select one or more targets.");

        var endpointToolbar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 6) };
        var refreshBtn = CreateSmallButton("Refresh", Bc("#3F3F46"));
        refreshBtn.Click += (_, _) => RefreshEndpointList();
        endpointToolbar.Children.Add(refreshBtn);

        var selectAllBtn = CreateSmallButton("Select All", Bc("#3F3F46"));
        selectAllBtn.Margin = new Thickness(6, 0, 0, 0);
        selectAllBtn.Click += (_, _) => SetAllEndpoints(true);
        endpointToolbar.Children.Add(selectAllBtn);

        var clearBtn = CreateSmallButton("Clear", Bc("#3F3F46"));
        clearBtn.Margin = new Thickness(6, 0, 0, 0);
        clearBtn.Click += (_, _) => SetAllEndpoints(false);
        endpointToolbar.Children.Add(clearBtn);
        rootStack.Children.Add(endpointToolbar);

        var endpointPanel = new StackPanel();
        _endpointHeader = CreateEndpointHeaderRow();
        endpointPanel.Children.Add(_endpointHeader);

        var endpointScroll = new ScrollViewer
        {
            Height = 360,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1, 0, 1, 1),
            Padding = new Thickness(4)
        };
        _endpointList = new StackPanel();
        endpointScroll.Content = _endpointList;
        endpointPanel.Children.Add(endpointScroll);

        var endpointFrame = new Border
        {
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Background = BgDark,
            Child = endpointPanel
        };
        rootStack.Children.Add(endpointFrame);

        AddSectionHeader(rootStack, "Session", 14);
        _useCapturedCheck = new CheckBox
        {
            Content = "Use captured headers/body from this request",
            IsChecked = true,
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 2)
        };
        rootStack.Children.Add(_useCapturedCheck);

        _replayOnceCheck = new CheckBox
        {
            Content = "Replay once before scan (seeds log + validates session)",
            IsChecked = false,
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 2)
        };
        rootStack.Children.Add(_replayOnceCheck);

        _allHeadersCheck = new CheckBox
        {
            Content = "Auth Control Identifier: test all headers (not only auth/token-like names)",
            IsChecked = false,
            Foreground = FgText,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 2),
            ToolTip = "When unchecked, only cookies (all) and headers/fields matching auth/token/csrf patterns are tested."
        };
        rootStack.Children.Add(_allHeadersCheck);

        AddSectionHeader(rootStack, "Probes", 14);
        AddHint(rootStack,
            "endpoint — probes the checked URL/method (captured body where supported). " +
            "site-wide — session or current page (cookies, JWT, DOM); runs per checked row but not tied to that POST template. " +
            "Full, A02, A03 are omitted here.");

        var probeScroll = new ScrollViewer
        {
            MaxHeight = 220,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4),
            Margin = new Thickness(0, 4, 0, 0)
        };
        _probeList = new StackPanel();
        probeScroll.Content = _probeList;
        rootStack.Children.Add(probeScroll);

        AddSectionHeader(rootStack, "Run options", 14);

        var safetyRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
        safetyRow.Children.Add(new TextBlock
        {
            Text = "Safety:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        });
        _safetyCombo = CreateStyledComboBox();
        _safetyCombo.Width = 140;
        foreach (var mode in new[] { "Safe", "Active", "Aggressive" })
            _safetyCombo.Items.Add(mode);
        _safetyCombo.SelectedItem = "Active";
        _safetyCombo.ToolTip = "Safe: read-only probes. Active: state-changing tests (default). Aggressive: stress/load.";
        safetyRow.Children.Add(_safetyCombo);

        safetyRow.Children.Add(new TextBlock
        {
            Text = "Depth:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(16, 0, 8, 0)
        });
        _depthCombo = CreateStyledComboBox();
        _depthCombo.Width = 140;
        foreach (var depth in new[] { "Quick", "Standard", "Full" })
            _depthCombo.Items.Add(depth);
        _depthCombo.SelectedItem = "Standard";
        _depthCombo.ToolTip = "Quick: fast smoke checks. Standard: balanced coverage (default). Full: thorough endpoint scan.";
        safetyRow.Children.Add(_depthCombo);
        rootStack.Children.Add(safetyRow);

        scrollViewer.Content = rootStack;
        Grid.SetRow(scrollViewer, 0);
        rootGrid.Children.Add(scrollViewer);

        var bottomBar = new DockPanel { Margin = new Thickness(20, 8, 20, 12) };

        _runBtn = CreateStyledButton("Run");
        _runBtn.Background = Bc("#0E639C");
        _runBtn.Click += Run_Click;
        DockPanel.SetDock(_runBtn, Dock.Right);
        bottomBar.Children.Add(_runBtn);

        var closeBtn = CreateStyledButton("Close");
        closeBtn.Margin = new Thickness(8, 0, 0, 0);
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

        BuildProbeList();
        RefreshEndpointList();
    }

    private void BuildProbeList()
    {
        _probeList.Children.Clear();
        _probeRows.Clear();

        string? currentGroup = null;
        foreach (var def in EndpointProbeCatalog.Build(_playbookRegistry))
        {
            if (def.Group != currentGroup)
            {
                currentGroup = def.Group;
                _probeList.Children.Add(new TextBlock
                {
                    Text = currentGroup,
                    Foreground = AccentBlue,
                    FontSize = 10,
                    FontWeight = FontWeights.SemiBold,
                    Margin = new Thickness(2, 6, 0, 2)
                });
            }

            var cb = new CheckBox
            {
                Content = CreateProbeRowContent(def),
                Tag = def.Id,
                Foreground = FgText,
                FontSize = 11,
                Margin = new Thickness(4, 1, 0, 1),
                ToolTip = def.RunScope == EndpointProbeRunScope.Endpoint
                    ? "Pinned to each checked endpoint (URL, method, and captured headers/body where the probe supports it)."
                    : "Session- or page-oriented checks. Still runs once per checked endpoint row, but scanners use the whole session or visible page—not only that request's template."
            };
            _probeList.Children.Add(cb);
            _probeRows.Add((def, cb));
        }
    }

    private UIElement CreateProbeRowContent(EndpointProbeDefinition def)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal };
        row.Children.Add(new TextBlock
        {
            Text = def.Title,
            Foreground = FgText,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center
        });

        var isEndpoint = def.RunScope == EndpointProbeRunScope.Endpoint;
        row.Children.Add(new Border
        {
            Background = isEndpoint ? Bc("#1a3d32") : Bc("#3d351a"),
            BorderBrush = isEndpoint ? AccentGreen : AccentYellow,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(2),
            Padding = new Thickness(5, 1, 5, 1),
            Margin = new Thickness(8, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = isEndpoint
                ? "Endpoint-pinned probe"
                : "Site-wide / session probe",
            Child = new TextBlock
            {
                Text = isEndpoint ? "endpoint" : "site-wide",
                FontFamily = new FontFamily("Consolas"),
                FontSize = 9,
                Foreground = isEndpoint ? AccentGreen : AccentYellow
            }
        });

        return row;
    }

    private void RefreshEndpointList()
    {
        var selectedKeys = _endpointRows
            .Where(r => r.Box.IsChecked == true)
            .Select(r => r.Item.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var discovered = EndpointProbeDiscovery.FromNetworkLog(_context.Network.Entries);
        _cachedEndpoints.Clear();
        _cachedEndpoints.AddRange(EndpointProbeDiscovery.Merge(discovered, _imported));

        RenderEndpointList(selectedKeys);
    }

    private void RenderEndpointList(HashSet<string>? selectedKeys = null)
    {
        selectedKeys ??= _endpointRows
            .Where(r => r.Box.IsChecked == true)
            .Select(r => r.Item.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _endpointList.Children.Clear();
        _endpointRows.Clear();
        UpdateSortHeaderLabels();

        if (_cachedEndpoints.Count == 0)
        {
            _endpointHeader.Visibility = Visibility.Collapsed;
            _endpointList.Children.Add(new TextBlock
            {
                Text = "No endpoints in network log. Browse the application first, or Import endpoints.",
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(4, 8, 4, 4)
            });
            return;
        }

        _endpointHeader.Visibility = Visibility.Visible;

        foreach (var item in SortEndpoints(_cachedEndpoints))
        {
            var row = CreateEndpointRow(item, selectedKeys.Contains(item.Key));
            _endpointList.Children.Add(row.Border);
            _endpointRows.Add((item, row.CheckBox));
        }
    }

    private List<EndpointProbeItem> SortEndpoints(IEnumerable<EndpointProbeItem> items)
    {
        IEnumerable<EndpointProbeItem> ordered = _sortColumn switch
        {
            EndpointSortColumn.Method => _sortAscending
                ? items.OrderBy(i => i.Method, StringComparer.OrdinalIgnoreCase)
                : items.OrderByDescending(i => i.Method, StringComparer.OrdinalIgnoreCase),
            EndpointSortColumn.Time => _sortAscending
                ? items.OrderBy(i => i.Timestamp ?? DateTime.MinValue)
                : items.OrderByDescending(i => i.Timestamp ?? DateTime.MinValue),
            EndpointSortColumn.Risk => _sortAscending
                ? items.OrderBy(i => EndpointProbeDiscovery.PriorityRank(i.Priority))
                : items.OrderByDescending(i => EndpointProbeDiscovery.PriorityRank(i.Priority)),
            EndpointSortColumn.Url => _sortAscending
                ? items.OrderBy(i => i.Url, StringComparer.OrdinalIgnoreCase)
                : items.OrderByDescending(i => i.Url, StringComparer.OrdinalIgnoreCase),
            _ => items
        };

        return ordered.ToList();
    }

    private void OnSortColumnClicked(EndpointSortColumn column)
    {
        if (_sortColumn == column)
            _sortAscending = !_sortAscending;
        else
        {
            _sortColumn = column;
            _sortAscending = column switch
            {
                EndpointSortColumn.Method => true,
                EndpointSortColumn.Time => false,
                EndpointSortColumn.Risk => false,
                EndpointSortColumn.Url => true,
                _ => true
            };
        }

        RenderEndpointList();
    }

    private Grid CreateEndpointHeaderRow()
    {
        var grid = CreateEndpointRowGrid();
        grid.Background = Bc("#333337");
        grid.Margin = new Thickness(0);

        var actionSpacer = CreateHeaderActionSpacer();
        var checkSpacer = new CheckBox
        {
            IsEnabled = false,
            IsHitTestVisible = false,
            Margin = new Thickness(0, 2, 6, 0),
            Opacity = 0
        };
        Grid.SetColumn(actionSpacer, 0);
        Grid.SetColumn(checkSpacer, 1);
        grid.Children.Add(actionSpacer);
        grid.Children.Add(checkSpacer);

        AddSortHeader(grid, 2, "Method", EndpointSortColumn.Method);
        AddSortHeader(grid, 3, "Time", EndpointSortColumn.Time);
        AddSortHeader(grid, 4, "Risk", EndpointSortColumn.Risk);
        AddSortHeader(grid, 5, "URL", EndpointSortColumn.Url);

        return grid;
    }

    private static StackPanel CreateHeaderActionSpacer()
    {
        var panel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
            IsHitTestVisible = false
        };

        for (var i = 0; i < 3; i++)
        {
            panel.Children.Add(new Border
            {
                Width = 64,
                Height = 20,
                Margin = i > 0 ? new Thickness(4, 0, 0, 0) : new Thickness(0),
                Background = Brushes.Transparent
            });
        }

        return panel;
    }

    private void AddSortHeader(Grid grid, int column, string label, EndpointSortColumn sortColumn)
    {
        var header = new TextBlock
        {
            Text = label,
            Foreground = AccentBlue,
            FontSize = 10,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            Cursor = Cursors.Hand,
            Padding = new Thickness(2, 4, 4, 4)
        };
        header.MouseLeftButtonDown += (_, e) =>
        {
            OnSortColumnClicked(sortColumn);
            e.Handled = true;
        };
        Grid.SetColumn(header, column);
        grid.Children.Add(header);
        _sortHeaderLabels[sortColumn] = header;
    }

    private void UpdateSortHeaderLabels()
    {
        foreach (var (column, header) in _sortHeaderLabels)
        {
            var label = column switch
            {
                EndpointSortColumn.Method => "Method",
                EndpointSortColumn.Time => "Time",
                EndpointSortColumn.Risk => "Risk",
                EndpointSortColumn.Url => "URL",
                _ => ""
            };
            var arrow = _sortColumn == column ? (_sortAscending ? " \u25B2" : " \u25BC") : "";
            header.Text = label + arrow;
            header.Foreground = _sortColumn == column ? FgText : AccentBlue;
        }
    }

    private static Grid CreateEndpointRowGrid()
    {
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(72) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(64) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(72) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        return grid;
    }

    private (Border Border, CheckBox CheckBox) CreateEndpointRow(EndpointProbeItem item, bool isChecked)
    {
        var cb = new CheckBox
        {
            IsChecked = isChecked,
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 2, 6, 0)
        };

        var priorityBrush = item.Priority.ToLowerInvariant() switch
        {
            "critical" => AccentRed,
            "high" => AccentYellow,
            "medium" => AccentBlue,
            _ => FgDim
        };

        var methodBlock = new TextBlock
        {
            Text = item.Method,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Foreground = AccentGreen,
            VerticalAlignment = VerticalAlignment.Top,
            Padding = new Thickness(0, 2, 4, 0)
        };

        var timeBlock = new TextBlock
        {
            Text = item.Timestamp?.ToString("HH:mm:ss") ?? "\u2014",
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Foreground = item.Timestamp.HasValue ? FgDim : Bc("#555555"),
            VerticalAlignment = VerticalAlignment.Top,
            Padding = new Thickness(0, 2, 4, 0),
            ToolTip = item.Timestamp?.ToString("yyyy-MM-dd HH:mm:ss")
        };

        var riskBlock = new TextBlock
        {
            Text = item.Priority.ToUpperInvariant(),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Foreground = priorityBrush,
            VerticalAlignment = VerticalAlignment.Top,
            Padding = new Thickness(0, 2, 4, 0)
        };

        var displayUrl = TruncateUrl(item.Url);
        var urlBlock = new TextBlock
        {
            Text = displayUrl,
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 11,
            Foreground = FgText,
            VerticalAlignment = VerticalAlignment.Top,
            Padding = new Thickness(0, 2, 0, 0),
            ToolTip = displayUrl.Length < item.Url.Length ? item.Url : null
        };

        var urlPanel = new StackPanel();
        urlPanel.Children.Add(urlBlock);
        if (item.IsImported)
        {
            urlPanel.Children.Add(new TextBlock
            {
                Text = "imported",
                Foreground = FgDim,
                FontSize = 9,
                Margin = new Thickness(0, 1, 0, 0)
            });
        }

        var actionPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        };

        var editorBtn = CreateRowActionButton("\u2192 Editor",
            "Load this request (URL, method, headers, body) into the HTTP Request Editor");
        editorBtn.Click += (_, _) => OpenInRequestEditorRequested?.Invoke(item);
        actionPanel.Children.Add(editorBtn);

        var chatBtn = CreateRowActionButton("\u2192 Chat",
            "Paste this request into the AI Assistant chat, keeping its headers");
        chatBtn.Margin = new Thickness(4, 0, 0, 0);
        chatBtn.Click += (_, _) => SendToChatRequested?.Invoke(item);
        actionPanel.Children.Add(chatBtn);

        var peerBtn = CreateRowActionButton("Peer \u2192",
            "Check this endpoint and open Peer Sessions to compare responses across users (BOLA)");
        peerBtn.Margin = new Thickness(4, 0, 0, 0);
        peerBtn.Click += (_, _) =>
        {
            foreach (var (_, box) in _endpointRows)
                box.IsChecked = false;
            cb.IsChecked = true;
            TestBolaPeerRequested?.Invoke();
        };
        actionPanel.Children.Add(peerBtn);

        var grid = CreateEndpointRowGrid();
        Grid.SetColumn(actionPanel, 0);
        Grid.SetColumn(cb, 1);
        Grid.SetColumn(methodBlock, 2);
        Grid.SetColumn(timeBlock, 3);
        Grid.SetColumn(riskBlock, 4);
        Grid.SetColumn(urlPanel, 5);
        grid.Children.Add(actionPanel);
        grid.Children.Add(cb);
        grid.Children.Add(methodBlock);
        grid.Children.Add(timeBlock);
        grid.Children.Add(riskBlock);
        grid.Children.Add(urlPanel);

        var border = new Border
        {
            Background = BgItem,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(4, 4, 4, 4),
            Child = grid
        };

        return (border, cb);
    }

    private void SetAllEndpoints(bool selected)
    {
        foreach (var (_, box) in _endpointRows)
            box.IsChecked = selected;
    }

    public List<EndpointProbeItem> GetSelectedEndpoints() =>
        _endpointRows.Where(r => r.Box.IsChecked == true).Select(r => r.Item).ToList();

    public bool UseCapturedHeadersBody => _useCapturedCheck.IsChecked == true;

    private List<string> GetSelectedProbeIds() =>
        _probeRows.Where(r => r.Box.IsChecked == true).Select(r => r.Def.Id).ToList();

    private SafetyMode GetSelectedSafetyMode() =>
        SafetyModeExtensions.Parse(_safetyCombo.SelectedItem as string);

    private static string GetSelectedDepthLabel(string? selected) =>
        selected?.Trim().ToLowerInvariant() switch
        {
            "quick" => "quick",
            "full" => "full",
            _ => "standard"
        };

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (_running) return;

        var endpoints = GetSelectedEndpoints();
        if (endpoints.Count == 0)
        {
            MessageBox.Show("Select at least one endpoint.", "Endpoint Probe",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var probes = GetSelectedProbeIds();
        if (probes.Count == 0)
        {
            MessageBox.Show("Select at least one probe.", "Endpoint Probe",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _running = true;
        _runBtn.IsEnabled = false;

        try
        {
            ProbeRunStarting?.Invoke();

            _context.Log("Endpoint Probe run started", "#4EC9B0");
            var depth = GetSelectedDepthLabel(_depthCombo.SelectedItem as string);
            _context.Log($"  Endpoints: {endpoints.Count}  Probes: {probes.Count}  Safety: {GetSelectedSafetyMode().ToLabel()}  Depth: {depth}",
                "#888888");
            _context.Log("", "#CCCCCC");

            var options = new EndpointProbeRunner.RunOptions
            {
                Endpoints = endpoints,
                ProbeIds = probes,
                SafetyMode = GetSelectedSafetyMode(),
                Depth = depth,
                UseCapturedHeadersBody = _useCapturedCheck.IsChecked == true,
                ReplayOnceBeforeScan = _replayOnceCheck.IsChecked == true,
                AuthControlAllHeaders = _allHeadersCheck.IsChecked == true
            };

            var runResult = await EndpointProbeRunner.RunAsync(_context, options);

            _context.Log("", "#CCCCCC");
            _context.Log("Endpoint Probe run finished", "#4EC9B0");
            ProbeRunFinished?.Invoke("Endpoint probe run finished");

            if (runResult.AuthControl is { Rows.Count: > 0 } authResult)
                ShowAuthControlResults(authResult);
        }
        catch (Exception ex)
        {
            _context.Log($"Endpoint Probe error: {ex.Message}", "#F44747");
            ProbeRunFinished?.Invoke($"Endpoint probe failed: {ex.Message}");
        }
        finally
        {
            _running = false;
            _runBtn.IsEnabled = true;
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var selected = GetSelectedEndpoints();
        if (selected.Count == 0)
        {
            MessageBox.Show("Select at least one endpoint to export.", "Export",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var json = EndpointProbeStore.Export(selected);
            var dialog = new SaveFileDialog
            {
                Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                DefaultExt = ".json",
                FileName = "endpoint-probe-endpoints.json",
                Title = "Export Endpoints"
            };
            if (dialog.ShowDialog() == true)
                File.WriteAllText(dialog.FileName, json);
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
                Title = "Import Endpoints"
            };
            if (dialog.ShowDialog() != true) return;

            var imported = EndpointProbeStore.Import(File.ReadAllText(dialog.FileName));
            var existingKeys = _imported.Select(i => i.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var added = 0;
            foreach (var item in imported)
            {
                if (existingKeys.Add(item.Key))
                {
                    _imported.Add(item);
                    added++;
                }
            }

            RefreshEndpointList();
            MessageBox.Show($"Added {added} endpoint(s) to the list.", "Import Complete",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Import failed: {ex.Message}", "Import Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ShowAuthControlResults(Security.AuthControlIdentifier.ScanResult result)
    {
        var dlg = new AuthControlResultsDialog(Owner ?? this, result);
        dlg.OpenInRequestEditorRequested += item => OpenInRequestEditorRequested?.Invoke(item);
        dlg.Show();
    }

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

    private static ComboBox CreateStyledComboBox()
    {
        var combo = new ComboBox
        {
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 2, 6, 2),
            FontSize = 11,
            Height = 26
        };

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
            Cursor = System.Windows.Input.Cursors.Hand
        };
    }

    private static Button CreateRowActionButton(string text, string tooltip)
    {
        return new Button
        {
            Content = text,
            Width = 64,
            Height = 20,
            Padding = new Thickness(0),
            Background = Bc("#37373D"),
            Foreground = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 10,
            Cursor = System.Windows.Input.Cursors.Hand,
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
            Cursor = System.Windows.Input.Cursors.Hand
        };
    }

    private static SolidColorBrush Bc(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex));

    private static string TruncateUrl(string url, int maxLength = 200) =>
        url.Length <= maxLength ? url : url[..maxLength] + "\u2026";

    #endregion
}
