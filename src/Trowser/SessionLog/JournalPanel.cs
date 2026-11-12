using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace Trowser.SessionLog;

/// <summary>
/// Left-docked live Journal panel. Renders the in-memory journal using
/// <see cref="JournalReportGenerator"/> inside an embedded WebView2, shows a compact
/// coverage summary line, and offers a bottom add-note box (with kind picker) plus a
/// button to open the full Session Log settings dialog.
///
/// The panel refreshes itself whenever <see cref="SessionLogger.JournalChanged"/> fires
/// (debounced) so it stays live as the tester wanders and quicktests run.
/// </summary>
public class JournalPanel : Border
{
    private readonly WebView2 _webView;
    private readonly ComboBox _kindPicker;
    private readonly TextBox _noteInput;
    private readonly TextBlock _coverageSummary;
    private readonly Border _coverageBar;
    private readonly Border _memoryBar;
    private readonly TextBlock _memorySummary;
    private readonly Button _recordBtn;
    private readonly StackPanel _structuredPanel;
    private readonly TextBox _stepsBox;
    private readonly TextBox _actualBox;
    private readonly TextBox _expectedBox;
    private ComboBox? _typeFilter;
    private ComboBox? _sourceFilter;
    private TextBox? _tagFilter;

    private SessionLogger? _logger;
    private SessionMemory? _memory;
    private Func<string?>? _getCurrentUrl;
    private bool _coreReady;
    private readonly DispatcherTimer _refreshDebounce;
    private bool _refreshQueued;
    private bool _refreshDirty;

    /// <summary>Raised when the user clicks the "Session Log…" button.</summary>
    public event Action? SessionLogRequested;

    /// <summary>Raised when the user clicks the panel's close button.</summary>
    public event Action? CloseRequested;

    /// <summary>Raised when the user toggles Record to file in the header.</summary>
    public event Action? RecordToggleRequested;

    /// <summary>Raised when the user clicks "Open report" to view the full report in a browser tab.</summary>
    public event Action? ReportRequested;

    /// <summary>
    /// Raised when the user clicks a clickable journal item (a recording or the API-actions card).
    /// The argument is the pseudo-URL, e.g. <c>trowser://recording/12</c> or <c>trowser://apiactions</c>.
    /// </summary>
    public event Action<string>? DetailRequested;

    private static readonly Brush BgDark = Bc("#1E1E1E");
    private static readonly Brush BgPanel = Bc("#2D2D30");
    private static readonly Brush BgInput = Bc("#252526");
    private static readonly Brush BorderClr = Bc("#3F3F46");
    private static readonly Brush FgNormal = Bc("#CCCCCC");
    private static readonly Brush FgDim = Bc("#888888");
    private static readonly Brush FgGreen = Bc("#4EC9B0");

    public JournalPanel()
    {
        Background = BgDark;
        BorderBrush = BorderClr;
        BorderThickness = new Thickness(0, 0, 1, 0);

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(36) });       // header
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });          // coverage line
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });          // session memory
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });          // filters
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // journal html
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });          // add-note box

        // --- Header ---
        var header = new Border
        {
            Background = BgPanel,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1)
        };
        var headerPanel = new DockPanel { Margin = new Thickness(10, 0, 6, 0) };
        headerPanel.Children.Add(new TextBlock
        {
            Text = "Journal",
            Foreground = FgNormal,
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        });

        var headerRight = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        DockPanel.SetDock(headerRight, Dock.Right);

        var reportBtn = HeaderButton("Report", "Open the full session report in a new browser tab");
        reportBtn.Click += (_, _) => ReportRequested?.Invoke();
        headerRight.Children.Add(reportBtn);

        _recordBtn = HeaderButton("Record: Off", "Start or stop writing the journal to a session log file");
        _recordBtn.Click += (_, _) => RecordToggleRequested?.Invoke();
        headerRight.Children.Add(_recordBtn);

        var moreBtn = HeaderButton("\u22EF", "Open, Save, Log Settings");
        moreBtn.Width = 28;
        moreBtn.Padding = new Thickness(0);
        moreBtn.Click += (_, _) =>
        {
            var menu = CreateDarkContextMenu();
            AddHeaderMenuItems(menu);
            menu.PlacementTarget = moreBtn;
            menu.Placement = PlacementMode.Bottom;
            menu.IsOpen = true;
        };
        headerRight.Children.Add(moreBtn);

        var closeBtn = HeaderButton("\u2715", "Close Journal panel (Ctrl+J)");
        closeBtn.Width = 26;
        closeBtn.Click += (_, _) => CloseRequested?.Invoke();
        headerRight.Children.Add(closeBtn);

        headerPanel.Children.Add(headerRight);
        header.Child = headerPanel;
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        // --- Coverage summary line (Pillar 2) ---
        _coverageBar = new Border
        {
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(10, 4, 10, 4)
        };
        _coverageSummary = new TextBlock
        {
            Text = "Coverage: —",
            Foreground = FgDim,
            FontSize = 11,
            TextTrimming = TextTrimming.CharacterEllipsis,
            VerticalAlignment = VerticalAlignment.Center
        };
        _coverageBar.Child = _coverageSummary;
        Grid.SetRow(_coverageBar, 1);
        root.Children.Add(_coverageBar);

        _memoryBar = new Border
        {
            Background = BgPanel,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(10, 6, 10, 6),
            Visibility = Visibility.Collapsed
        };
        _memorySummary = new TextBlock
        {
            Text = "",
            Foreground = FgNormal,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        };
        _memoryBar.Child = _memorySummary;
        Grid.SetRow(_memoryBar, 2);
        root.Children.Add(_memoryBar);

        var filterBar = BuildFilterBar();
        Grid.SetRow(filterBar, 3);
        root.Children.Add(filterBar);

        // --- Journal HTML (WebView2) ---
        _webView = new WebView2
        {
            DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 30, 30, 30)
        };
        Grid.SetRow(_webView, 4);
        root.Children.Add(_webView);

        // --- Add-note box ---
        var addBar = new Border
        {
            Background = BgPanel,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(8)
        };
        var addGrid = new Grid();
        addGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        addGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var pickerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6), LastChildFill = false };
        _kindPicker = new ComboBox
        {
            Width = 130,
            Height = 24,
            FontSize = 11,
            VerticalContentAlignment = VerticalAlignment.Center,
            Background = BgDark,
            Foreground = FgNormal,
            BorderBrush = BorderClr
        };
        DarkComboBoxHelper.ApplyDarkStyle(_kindPicker);
        foreach (var kind in NoteKinds.All)
        {
            var item = DarkComboBoxHelper.CreateItem(NoteKinds.DisplayLabel(kind));
            item.Tag = kind;
            _kindPicker.Items.Add(item);
        }
        _kindPicker.SelectedIndex = 0;
        _kindPicker.SelectionChanged += (_, _) => UpdateStructuredVisibility();
        DockPanel.SetDock(_kindPicker, Dock.Left);
        pickerRow.Children.Add(_kindPicker);

        var addBtn = HeaderButton("Add", "Add this note to the journal (Ctrl+Enter)");
        addBtn.Width = 60;
        addBtn.Foreground = Brushes.White;
        addBtn.Background = Bc("#16825B");
        DockPanel.SetDock(addBtn, Dock.Right);
        addBtn.Click += (_, _) => SubmitNote();
        pickerRow.Children.Add(addBtn);
        Grid.SetRow(pickerRow, 0);
        addGrid.Children.Add(pickerRow);

        _noteInput = new TextBox
        {
            Background = BgInput,
            Foreground = FgNormal,
            CaretBrush = FgNormal,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinLines = 2,
            MaxLines = 5,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            ToolTip = "Markdown supported. First line is the title; the rest is the body. Ctrl+Enter to add."
        };
        _noteInput.PreviewKeyDown += NoteInput_PreviewKeyDown;
        Grid.SetRow(_noteInput, 1);
        addGrid.Children.Add(_noteInput);

        addGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _structuredPanel = new StackPanel { Visibility = Visibility.Collapsed, Margin = new Thickness(0, 6, 0, 0) };
        _stepsBox = CompactField("Steps", _structuredPanel);
        _actualBox = CompactField("Actual", _structuredPanel);
        _expectedBox = CompactField("Expected", _structuredPanel);
        Grid.SetRow(_structuredPanel, 2);
        addGrid.Children.Add(_structuredPanel);

        addGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var hint = new TextBlock
        {
            Text = "Markdown: **bold**, lists, `code`  •  Ctrl+Enter to add",
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 4, 0, 0)
        };
        Grid.SetRow(hint, 3);
        addGrid.Children.Add(hint);

        addBar.Child = addGrid;
        Grid.SetRow(addBar, 5);
        root.Children.Add(addBar);

        Child = root;

        _refreshDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(350) };
        _refreshDebounce.Tick += (_, _) => { _refreshDebounce.Stop(); Refresh(); };
    }

    /// <summary>Wire the panel to the session logger and a current-URL provider. Call once.</summary>
    public void Initialize(SessionLogger logger, Func<string?>? getCurrentUrl, SessionMemory? memory = null)
    {
        _logger = logger;
        _memory = memory;
        _getCurrentUrl = getCurrentUrl;
        logger.JournalChanged += OnJournalChanged;
        if (_memory != null)
        {
            _memory.Changed += () => Dispatcher.InvokeAsync(UpdateMemorySummary);
            UpdateMemorySummary();
        }
        UpdateRecordingState();
    }

    public void UpdateRecordingState()
    {
        if (_logger == null) return;
        _recordBtn.Content = _logger.IsLogging ? "Record: On" : "Record: Off";
        _recordBtn.Foreground = _logger.IsLogging ? FgGreen : FgDim;
    }

    private void UpdateMemorySummary()
    {
        if (_memory == null)
        {
            _memoryBar.Visibility = Visibility.Collapsed;
            return;
        }

        var sb = new System.Text.StringBuilder();
        if (!string.IsNullOrEmpty(_memory.Mission))
            sb.AppendLine($"Mission: {_memory.Mission}");
        if (!string.IsNullOrEmpty(_memory.Focus))
            sb.AppendLine($"Focus: {_memory.Focus}");
        var openTasks = _memory.Tasks.Where(t => t.Status is SessionTaskStatus.Open or SessionTaskStatus.Doing).Take(5).ToList();
        if (openTasks.Count > 0)
            sb.AppendLine("Tasks: " + string.Join(" · ", openTasks.Select(t => t.Text)));
        if (_memory.Handoff != null)
            sb.AppendLine($"Last compact: {_memory.Handoff.Timestamp:HH:mm:ss}");

        if (sb.Length == 0)
        {
            _memoryBar.Visibility = Visibility.Collapsed;
            return;
        }

        _memoryBar.Visibility = Visibility.Visible;
        _memorySummary.Text = sb.ToString().TrimEnd();
    }

    /// <summary>
    /// Create the embedded WebView2 (idempotent) using the shared environment and render the
    /// current journal. Call when the panel first becomes visible.
    /// </summary>
    public async Task EnsureWebViewAsync(CoreWebView2Environment environment)
    {
        if (_coreReady) return;
        try
        {
            await _webView.EnsureCoreWebView2Async(environment);
            _webView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            _webView.CoreWebView2.Settings.IsStatusBarEnabled = false;
            _webView.CoreWebView2.WebMessageReceived += OnJournalWebMessage;
            // Keep the panel showing the report: external link clicks shouldn't navigate it away.
            // Clickable journal items use trowser:// pseudo-URLs — cancel the navigation and surface
            // them as a DetailRequested event so the host can open the detail in a new browser tab.
            _webView.CoreWebView2.NavigationStarting += (_, args) =>
            {
                var uri = args.Uri ?? "";
                if (uri.StartsWith("trowser://", StringComparison.OrdinalIgnoreCase)
                    || uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    || uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    args.Cancel = true;
                    var captured = uri;
                    Dispatcher.InvokeAsync(() => DetailRequested?.Invoke(captured));
                    return;
                }
                if (!(uri.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
                      || uri.StartsWith("about:", StringComparison.OrdinalIgnoreCase)))
                {
                    args.Cancel = true;
                }
            };
            _coreReady = true;
            Refresh();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Journal panel WebView2 init failed: {ex.Message}");
        }
    }

    /// <summary>Re-render the journal HTML from the current in-memory entries.</summary>
    public void Refresh()
    {
        if (!_coreReady || _logger == null || _webView.CoreWebView2 == null) return;
        if (_refreshQueued)
        {
            _refreshDirty = true;
            return;
        }
        _refreshQueued = true;
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            do
            {
                _refreshDirty = false;
                JournalPanelViewState? state = null;
                try
                {
                    var raw = await _webView.CoreWebView2!.ExecuteScriptAsync(
                        "(function(){ try { return { scroll: window.scrollY, open: [...document.querySelectorAll('details.sec')].filter(function(d){return d.open;}).map(function(d){return d.id;}) }; } catch(e) { return null; } })()");
                    state = ParseViewState(raw);
                }
                catch { /* first paint or webview not ready */ }

                var entries = _logger!.GetJournal(type: FilterValue(_typeFilter), source: FilterValue(_sourceFilter), q: SearchQuery());
                var html = JournalReportGenerator.GenerateHtml(entries, _logger.FilePath, _getCurrentUrl?.Invoke(), compact: true, viewState: state);
                if (html.Length > 1_800_000)
                {
                    var trimmed = _logger.GetJournal(last: 200, type: FilterValue(_typeFilter), source: FilterValue(_sourceFilter), q: SearchQuery());
                    html = JournalReportGenerator.GenerateHtml(trimmed, _logger.FilePath, _getCurrentUrl?.Invoke(), compact: true, viewState: state);
                }
                _webView.CoreWebView2.NavigateToString(html);
            } while (_refreshDirty);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Journal panel refresh failed: {ex.Message}");
        }
        finally
        {
            _refreshQueued = false;
            if (_refreshDirty)
                Refresh();
        }
    }

    private static JournalPanelViewState? ParseViewState(string? json)
    {
        if (string.IsNullOrWhiteSpace(json) || json == "null") return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var state = new JournalPanelViewState();
            if (root.TryGetProperty("scroll", out var s) && s.ValueKind == JsonValueKind.Number)
                state.ScrollY = s.GetDouble();
            if (root.TryGetProperty("open", out var o) && o.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in o.EnumerateArray())
                {
                    var id = el.GetString();
                    if (!string.IsNullOrEmpty(id)) state.OpenSections.Add(id);
                }
            }
            return state;
        }
        catch { return null; }
    }

    /// <summary>Update the compact coverage line (Pillar 2). <paramref name="tooltip"/> shows detail on hover.</summary>
    public void SetCoverageSummary(string summary, string? tooltip = null)
    {
        _coverageSummary.Text = summary;
        _coverageBar.ToolTip = string.IsNullOrEmpty(tooltip) ? null : tooltip;
    }

    private void OnJournalChanged()
    {
        // Marshal to UI thread and debounce bursts (e.g. a quicktest logging many actions).
        Dispatcher.InvokeAsync(() =>
        {
            _refreshDebounce.Stop();
            _refreshDebounce.Start();
        }, DispatcherPriority.Background);
    }

    private void NoteInput_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control)
        {
            SubmitNote();
            e.Handled = true;
        }
    }

    private void SubmitNote()
    {
        if (_logger == null) return;
        var raw = _noteInput.Text;
        NoteKinds.SplitTitleBody(raw, out var text, out var details);
        if (string.IsNullOrEmpty(text) && string.IsNullOrEmpty(details)) return;

        var kind = (_kindPicker.SelectedItem as ComboBoxItem)?.Tag as string ?? NoteKinds.Note;
        Dictionary<string, string>? fields = null;
        if (Array.IndexOf(NoteKinds.StructuredKinds, kind) >= 0)
        {
            fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(_stepsBox.Text)) fields["steps"] = _stepsBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(_actualBox.Text)) fields["actual"] = _actualBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(_expectedBox.Text)) fields["expected"] = _expectedBox.Text.Trim();
            if (fields.Count == 0) fields = null;
        }

        if (string.IsNullOrEmpty(text))
            text = details ?? $"(untitled {kind})";

        try
        {
            _logger.LogTesterNote(kind, text, fields: fields, url: _getCurrentUrl?.Invoke(), details: details);
            _noteInput.Clear();
            _stepsBox.Clear();
            _actualBox.Clear();
            _expectedBox.Clear();
            _noteInput.Focus();
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Journal panel add-note failed: {ex.Message}");
        }
    }

    private void UpdateStructuredVisibility()
    {
        var kind = (_kindPicker.SelectedItem as ComboBoxItem)?.Tag as string ?? NoteKinds.Note;
        _structuredPanel.Visibility = Array.IndexOf(NoteKinds.StructuredKinds, kind) >= 0
            ? Visibility.Visible : Visibility.Collapsed;
    }

    private TextBox CompactField(string label, StackPanel parent)
    {
        parent.Children.Add(new TextBlock
        {
            Text = label,
            Foreground = FgDim,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 1)
        });
        var tb = new TextBox
        {
            Background = BgInput,
            Foreground = FgNormal,
            CaretBrush = FgNormal,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4, 2, 4, 2),
            FontSize = 11,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinLines = 1,
            MaxLines = 3,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        tb.PreviewKeyDown += NoteInput_PreviewKeyDown;
        parent.Children.Add(tb);
        return tb;
    }

    private Border BuildFilterBar()
    {
        var bar = new Border
        {
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(8, 4, 8, 4)
        };
        var row = new DockPanel { LastChildFill = true };

        _typeFilter = CompactFilterCombo(
            ("All types", ""),
            ("Bugs", "bug"),
            ("Enhancements", "enhancement"),
            ("Pointers", "pointer"),
            ("Decisions", "decision"),
            ("Actions", "action"),
            ("Notes", "note"),
            ("Observations", "observation"),
            ("Recordings", "recording"),
            ("Screenshots", "screenshot"));
        _typeFilter.SelectionChanged += (_, _) => Refresh();
        DockPanel.SetDock(_typeFilter, Dock.Left);
        row.Children.Add(_typeFilter);

        _sourceFilter = CompactFilterCombo(
            ("All sources", ""),
            ("User", "gui"),
            ("Agent", "api"),
            ("Auto", "system"));
        _sourceFilter.Margin = new Thickness(6, 0, 0, 0);
        _sourceFilter.SelectionChanged += (_, _) => Refresh();
        DockPanel.SetDock(_sourceFilter, Dock.Left);
        row.Children.Add(_sourceFilter);

        var searchHost = new Grid { Margin = new Thickness(6, 0, 0, 0) };
        _tagFilter = new TextBox
        {
            Background = BgInput,
            Foreground = FgNormal,
            CaretBrush = FgNormal,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4, 2, 4, 2),
            FontSize = 11,
            Height = 22,
            ToolTip = "Search title, details, URL, tags, and fields"
        };
        var searchHint = new TextBlock
        {
            Text = "Search…",
            Foreground = FgDim,
            FontSize = 11,
            Margin = new Thickness(6, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false
        };
        _tagFilter.TextChanged += (_, _) =>
        {
            searchHint.Visibility = string.IsNullOrEmpty(_tagFilter.Text)
                ? Visibility.Visible : Visibility.Collapsed;
            _refreshDebounce.Stop();
            _refreshDebounce.Start();
        };
        searchHost.Children.Add(_tagFilter);
        searchHost.Children.Add(searchHint);
        row.Children.Add(searchHost);

        bar.Child = row;
        return bar;
    }

    private ComboBox CompactFilterCombo(params (string label, string value)[] items)
    {
        var combo = new ComboBox
        {
            Width = 110,
            Height = 22,
            FontSize = 11,
            VerticalContentAlignment = VerticalAlignment.Center,
            Background = BgDark,
            Foreground = FgNormal,
            BorderBrush = BorderClr
        };
        DarkComboBoxHelper.ApplyDarkStyle(combo);
        foreach (var (label, value) in items)
        {
            var item = DarkComboBoxHelper.CreateItem(label);
            item.Tag = value;
            combo.Items.Add(item);
        }
        combo.SelectedIndex = 0;
        return combo;
    }

    private static string? FilterValue(ComboBox? combo)
    {
        var raw = (combo?.SelectedItem as ComboBoxItem)?.Tag as string;
        return string.IsNullOrWhiteSpace(raw) ? null : raw;
    }

    private string? SearchQuery()
    {
        var q = _tagFilter?.Text?.Trim();
        return string.IsNullOrEmpty(q) ? null : q;
    }

    private void OnJournalWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            var raw = e.WebMessageAsJson;
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.String)
            {
                var innerJson = root.GetString();
                if (string.IsNullOrWhiteSpace(innerJson)) return;
                using var inner = JsonDocument.Parse(innerJson);
                TryShowJournalContextFromMessage(inner.RootElement);
                return;
            }

            TryShowJournalContextFromMessage(root);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Journal context message failed: {ex.Message}");
        }
    }

    private void TryShowJournalContextFromMessage(JsonElement root)
    {
        var type = root.TryGetProperty("type", out var t) ? t.GetString() : null;
        if (!string.Equals(type, "journal-ctx", StringComparison.OrdinalIgnoreCase))
            return;

        int? index = null;
        if (root.TryGetProperty("index", out var i) && i.ValueKind == JsonValueKind.Number
            && i.TryGetInt32(out var parsed))
            index = parsed;

        Dispatcher.InvokeAsync(() => ShowJournalContextMenu(index));
    }

    private void ShowJournalContextMenu(int? index)
    {
        var menu = CreateDarkContextMenu();
        if (index.HasValue)
        {
            var entry = _logger?.GetEntry(index.Value);
            var canShow = entry != null && JournalReportGenerator.CanShowMe(entry);
            AddMenuItem(menu, "Show me", () => DetailRequested?.Invoke($"trowser://show/{index.Value}"), canShow);
            AddMenuItem(menu, "Copy", () => DetailRequested?.Invoke($"trowser://copy/{index.Value}"));
            AddMenuItem(menu, "Edit", () => DetailRequested?.Invoke($"trowser://edit/{index.Value}"));
            AddMenuItem(menu, "Delete", () => DetailRequested?.Invoke($"trowser://delete/{index.Value}"));
        }
        else
        {
            AddHeaderMenuItems(menu);
        }

        menu.Placement = PlacementMode.MousePoint;
        menu.IsOpen = true;
    }

    private void AddHeaderMenuItems(ContextMenu menu)
    {
        AddMenuItem(menu, "Open", () => DetailRequested?.Invoke("trowser://open"));
        AddMenuItem(menu, "Save", () => DetailRequested?.Invoke("trowser://save"));
        AddMenuItem(menu, "Log Settings…", () => SessionLogRequested?.Invoke());
    }

    private static ContextMenu CreateDarkContextMenu() => new()
    {
        Background = BgPanel,
        Foreground = FgNormal,
        BorderBrush = BorderClr,
        BorderThickness = new Thickness(1)
    };

    private static void AddMenuItem(ContextMenu menu, string header, Action action, bool enabled = true)
    {
        var item = new MenuItem
        {
            Header = header,
            IsEnabled = enabled,
            Foreground = enabled ? FgNormal : FgDim,
            Background = BgPanel
        };
        if (enabled)
            item.Click += (_, _) => action();
        menu.Items.Add(item);
    }

    private static Button HeaderButton(string content, string tooltip)
    {
        var btn = new Button
        {
            Content = content,
            Height = 24,
            MinWidth = 32,
            Margin = new Thickness(4, 0, 0, 0),
            Padding = new Thickness(8, 0, 8, 0),
            FontSize = 11,
            Background = Bc("#3E3E42"),
            Foreground = FgNormal,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            ToolTip = tooltip,
            VerticalAlignment = VerticalAlignment.Center
        };
        return btn;
    }

    private static Brush Bc(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        b.Freeze();
        return b;
    }
}
