using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security;
using Trowser.Security.RaceLab;

namespace Trowser.RaceLab;

public sealed class RaceLabDialog : Window
{
    private readonly AutomationContext _ctx;
    private readonly PeerRegistry? _peers;
    private readonly ComboBox _profileCombo;
    private readonly DataGrid _requestGrid;
    private DataGridComboBoxColumn? _sessionComboColumn;
    private readonly TextBox _progressLog;
    private readonly StackPanel _findingsPanel;
    private TextBox _requestsPerBatch = null!;
    private TextBox _delayPerRequest = null!;
    private TextBox _delayBetweenBatches = null!;
    private TextBox _totalBatches = null!;
    private TextBox _jitterMs = null!;
    private CheckBox _randomizeOrder = null!;
    private readonly Button _runBtn;
    private readonly Button _abortBtn;
    private readonly Button _deletePresetBtn;

    private CancellationTokenSource? _runCts;
    private bool _busy;
    private bool _suppressUiEvents;
    private RaceLabProfile _workingProfile = new() { Name = "Hammer", Parameters = RaceLabParameters.ForMode(RaceLabMode.Hammer) };
    private string _selectedPresetName = "Hammer";

    public Action? ManagePeersRequested { get; set; }
    public Action<string>? AskAiRequested { get; set; }

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");
    private static readonly SolidColorBrush AccentRed = Bc("#F44747");
    private static readonly SolidColorBrush AccentAmber = Bc("#CCA700");
    private static readonly SolidColorBrush GridHeaderBg = Bc("#E8E8EC");
    private static readonly SolidColorBrush GridHeaderFg = Bc("#1A1A1A");
    private static readonly SolidColorBrush GridCellBg = Bc("#252526");
    private static readonly SolidColorBrush GridRowAltBg = Bc("#2A2A2D");
    private static readonly SolidColorBrush GridSelectionBg = Bc("#264F78");

    private static readonly string[] HttpMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

    public RaceLabDialog(AutomationContext ctx, PeerRegistry? peers, Window owner)
    {
        _ctx = ctx;
        _peers = peers;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Race Lab";
        Width = 980;
        Height = 760;
        MinWidth = 760;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BgMedium;
        ShowInTaskbar = false;

        var root = new Grid { Margin = new Thickness(12) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        var header = new TextBlock
        {
            Text = "Multi-session race / TOCTOU testing with latency-compensated bursts.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = FgDim,
            Margin = new Thickness(0, 0, 0, 8)
        };
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        var presetRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        presetRow.Children.Add(new TextBlock { Text = "Preset:", Foreground = FgText, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
        _profileCombo = new ComboBox { Width = 180, Margin = new Thickness(0, 0, 8, 0) };
        _profileCombo.SelectionChanged += (_, _) => ApplySelectedPreset();
        presetRow.Children.Add(_profileCombo);
        presetRow.Children.Add(MkBtn("Save as…", SavePresetAs));
        _deletePresetBtn = MkBtn("Delete preset", DeletePreset);
        presetRow.Children.Add(_deletePresetBtn);
        presetRow.Children.Add(MkBtn("Export…", ExportProfile));
        presetRow.Children.Add(MkBtn("Import…", ImportProfile));
        presetRow.Children.Add(MkBtn("Manage peers…", () =>
        {
            ManagePeersRequested?.Invoke();
            RefreshSessionComboItems();
        }));
        Grid.SetRow(presetRow, 1);
        root.Children.Add(presetRow);

        _requestsPerBatch = MkNumBox("15");
        _delayPerRequest = MkNumBox("0");
        _delayBetweenBatches = MkNumBox("0");
        _totalBatches = MkNumBox("3");
        _jitterMs = MkNumBox("0");
        _randomizeOrder = new CheckBox { Content = "Random order", Foreground = FgText, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        foreach (var tb in new[] { _requestsPerBatch, _delayPerRequest, _delayBetweenBatches, _totalBatches, _jitterMs })
            tb.TextChanged += (_, _) => { if (!_suppressUiEvents) SaveGuiState(); };
        _randomizeOrder.Checked += (_, _) => { if (!_suppressUiEvents) SaveGuiState(); };
        _randomizeOrder.Unchecked += (_, _) => { if (!_suppressUiEvents) SaveGuiState(); };

        var paramGrid = new Grid();
        for (var c = 0; c < 6; c++)
            paramGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        AddParam(paramGrid, 0, "Req/batch", _requestsPerBatch);
        AddParam(paramGrid, 1, "Delay/req ms", _delayPerRequest);
        AddParam(paramGrid, 2, "Delay/batch ms", _delayBetweenBatches);
        AddParam(paramGrid, 3, "Batches", _totalBatches);
        AddParam(paramGrid, 4, "Jitter ms", _jitterMs);
        Grid.SetColumn(_randomizeOrder, 5);
        paramGrid.Children.Add(_randomizeOrder);
        Grid.SetRow(paramGrid, 2);
        root.Children.Add(paramGrid);

        var reqButtons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 4) };
        reqButtons.Children.Add(MkBtn("From network log…", AddFromNetworkLog));
        reqButtons.Children.Add(MkBtn("Add manually…", AddRequest));
        reqButtons.Children.Add(MkBtn("Edit…", EditRequest));
        reqButtons.Children.Add(MkBtn("Remove", RemoveRequest));
        Grid.SetRow(reqButtons, 3);
        root.Children.Add(reqButtons);

        _requestGrid = new DataGrid
        {
            AutoGenerateColumns = false,
            CanUserAddRows = false,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            Background = BgDark,
            Foreground = FgText,
            BorderBrush = BorderClr,
            GridLinesVisibility = DataGridGridLinesVisibility.All
        };
        ConfigureRequestGridColumns();
        Grid.SetRow(_requestGrid, 4);
        root.Children.Add(_requestGrid);

        var runRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 8) };
        _runBtn = MkBtn("Run (sync → baseline → burst)", RunClicked);
        _runBtn.Background = AccentBlue;
        _abortBtn = MkBtn("Abort", AbortClicked);
        _abortBtn.IsEnabled = false;
        runRow.Children.Add(_runBtn);
        runRow.Children.Add(_abortBtn);
        Grid.SetRow(runRow, 5);
        root.Children.Add(runRow);

        _progressLog = new TextBox
        {
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            Foreground = FgDim,
            BorderBrush = BorderClr,
            FontFamily = new FontFamily("Consolas"),
            MaxHeight = 100
        };

        var findingsScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(0, 8, 0, 0) };
        _findingsPanel = new StackPanel();
        findingsScroll.Content = _findingsPanel;

        var resultsPanel = new Grid();
        resultsPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        resultsPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        resultsPanel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        resultsPanel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var progressLabel = new TextBlock { Text = "Progress", Foreground = FgText, Margin = new Thickness(0, 0, 0, 4) };
        Grid.SetRow(progressLabel, 0);
        resultsPanel.Children.Add(progressLabel);
        Grid.SetRow(_progressLog, 1);
        resultsPanel.Children.Add(_progressLog);
        var findingsLabel = new TextBlock { Text = "Findings", Foreground = FgText, Margin = new Thickness(0, 8, 0, 4) };
        Grid.SetRow(findingsLabel, 2);
        resultsPanel.Children.Add(findingsLabel);
        Grid.SetRow(findingsScroll, 3);
        resultsPanel.Children.Add(findingsScroll);
        Grid.SetRow(resultsPanel, 6);
        root.Children.Add(resultsPanel);

        Content = root;
        Closed += (_, _) =>
        {
            ReadParametersFromUi();
            SaveGuiState();
        };

        _suppressUiEvents = true;
        try
        {
            LoadGuiState();
            ReloadPresets();
            BindWorkingProfile();
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    private IEnumerable<string> PeerNames() =>
        _peers?.GetAll().Select(p => p.Name) ?? [];

    private void LoadGuiState()
    {
        var gui = RaceLabGuiState.Load();
        _selectedPresetName = string.IsNullOrWhiteSpace(gui.SelectedPreset) ? "Hammer" : gui.SelectedPreset.Trim();
        _workingProfile = new RaceLabProfile
        {
            Name = _selectedPresetName,
            Requests = gui.Requests.Select(r => r.Clone()).ToList(),
            Parameters = gui.Parameters.Clone()
        };
    }

    private void SaveGuiState()
    {
        RaceLabGuiState.Save(new RaceLabGuiState.State
        {
            SelectedPreset = _selectedPresetName,
            Requests = _workingProfile.Requests.Select(r => r.Clone()).ToList(),
            Parameters = _workingProfile.Parameters.Clone()
        });
    }

    private static void AddParam(Grid grid, int col, string label, Control control)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 12, 0) };
        sp.Children.Add(new TextBlock { Text = label, Foreground = FgText, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) });
        sp.Children.Add(control);
        Grid.SetColumn(sp, col);
        grid.Children.Add(sp);
    }

    private static TextBox MkNumBox(string text) =>
        new() { Text = text, Width = 56, Background = Bc("#252526"), Foreground = Bc("#D4D4D4"), BorderBrush = Bc("#3F3F46") };

    private static Button MkBtn(string text, Action onClick)
    {
        var b = new Button
        {
            Content = text,
            Margin = new Thickness(0, 0, 8, 0),
            Padding = new Thickness(10, 4, 10, 4),
            Background = Bc("#3E3E42"),
            Foreground = Bc("#CCCCCC"),
            BorderBrush = Bc("#3F3F46")
        };
        b.Click += (_, _) => onClick();
        return b;
    }

    private void ReloadPresets()
    {
        _profileCombo.Items.Clear();
        foreach (var p in RaceLabSettings.Load())
            _profileCombo.Items.Add(p.Name);
        _profileCombo.SelectedItem = _selectedPresetName;
        _deletePresetBtn.IsEnabled = !RaceLabSettings.IsBuiltInName(_selectedPresetName);
    }

    private void ApplySelectedPreset()
    {
        if (_suppressUiEvents) return;
        if (_profileCombo.SelectedItem is not string name) return;
        var profile = RaceLabSettings.Load().FirstOrDefault(p =>
            string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (profile == null) return;

        var savedRequests = _workingProfile.Requests.Select(r => r.Clone()).ToList();
        _selectedPresetName = name;
        _workingProfile.Name = name;
        _workingProfile.Requests = savedRequests;
        _workingProfile.Parameters = ParametersForPreset(name, profile, savedRequests.Count);
        BindWorkingProfile();
        _deletePresetBtn.IsEnabled = !profile.IsBuiltIn;
        SaveGuiState();
    }

    private static RaceLabParameters ParametersForPreset(string name, RaceLabProfile stored, int requestCount)
    {
        if (RaceLabSettings.IsBuiltInName(name)
            && Enum.TryParse<RaceLabMode>(name, ignoreCase: true, out var builtInMode))
            return RaceLabParameters.ForMode(builtInMode, Math.Max(1, requestCount));

        return stored.Parameters.Clone();
    }

    private void BindWorkingProfile()
    {
        NormalizeRequestFields();
        RefreshSessionComboItems();
        _requestGrid.ItemsSource = null;
        _requestGrid.ItemsSource = _workingProfile.Requests;
        var p = _workingProfile.Parameters;
        _requestsPerBatch.Text = p.RequestsPerBatch.ToString();
        _delayPerRequest.Text = p.DelayPerRequestMs.ToString();
        _delayBetweenBatches.Text = p.DelayBetweenBatchesMs.ToString();
        _totalBatches.Text = p.TotalBatches.ToString();
        _jitterMs.Text = p.JitterMs.ToString();
        _randomizeOrder.IsChecked = p.RandomizeOrder;
    }

    private void ReadParametersFromUi()
    {
        _workingProfile.Parameters.RequestsPerBatch = ParseInt(_requestsPerBatch.Text, 15);
        _workingProfile.Parameters.DelayPerRequestMs = ParseInt(_delayPerRequest.Text, 0);
        _workingProfile.Parameters.DelayBetweenBatchesMs = ParseInt(_delayBetweenBatches.Text, 0);
        _workingProfile.Parameters.TotalBatches = ParseInt(_totalBatches.Text, 3);
        _workingProfile.Parameters.JitterMs = ParseInt(_jitterMs.Text, 0);
        _workingProfile.Parameters.RandomizeOrder = _randomizeOrder.IsChecked == true;
    }

    private static int ParseInt(string? s, int def) =>
        int.TryParse(s, out var v) ? v : def;

    private void AppendLog(string line)
    {
        _progressLog.AppendText(line + Environment.NewLine);
        _progressLog.ScrollToEnd();
    }

    private async void RunClicked()
    {
        if (_busy) return;
        ReadParametersFromUi();
        if (_workingProfile.Requests.Count == 0)
        {
            MessageBox.Show(this, "Add at least one request.", "Race Lab", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        _busy = true;
        _runBtn.IsEnabled = false;
        _abortBtn.IsEnabled = true;
        _progressLog.Clear();
        _findingsPanel.Children.Clear();
        _runCts = new CancellationTokenSource();

        try
        {
            var logBridge = new Action<string, string>((msg, _) => Dispatcher.Invoke(() => AppendLog(msg)));
            var engine = new RaceLabEngine(_ctx, _peers, logBridge);
            var result = await engine.RunFullAsync(_workingProfile, new RaceLabRunOptions(), ct: _runCts.Token);
            RenderFindings(result);
            AppendLog(result.Message);
        }
        catch (OperationCanceledException)
        {
            AppendLog("Run aborted.");
        }
        catch (Exception ex)
        {
            AppendLog("Error: " + ex.Message);
        }
        finally
        {
            _busy = false;
            _runBtn.IsEnabled = true;
            _abortBtn.IsEnabled = false;
            _runCts?.Dispose();
            _runCts = null;
        }
    }

    private void AbortClicked() => _runCts?.Cancel();

    private void RenderFindings(RaceLabRunResult result)
    {
        _findingsPanel.Children.Clear();
        if (result.Findings.Count == 0)
        {
            _findingsPanel.Children.Add(new TextBlock { Text = "No findings.", Foreground = AccentGreen });
            return;
        }

        foreach (var f in result.Findings)
        {
            var row = new Border
            {
                Background = Bc("#252526"),
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1),
                Margin = new Thickness(0, 0, 0, 6),
                Padding = new Thickness(8)
            };
            var sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = $"[{f.Confidence}] {f.Category}: {f.Title}",
                Foreground = ConfidenceBrush(f.Confidence),
                FontWeight = FontWeights.SemiBold
            });
            sp.Children.Add(new TextBlock { Text = f.Evidence ?? "", Foreground = FgDim, TextWrapping = TextWrapping.Wrap });
            if (AskAiRequested != null)
            {
                var ask = MkBtn("Ask AI", () => AskAiRequested(BuildAskAiPrompt(f)));
                ask.Margin = new Thickness(0, 6, 0, 0);
                sp.Children.Add(ask);
            }
            row.Child = sp;
            _findingsPanel.Children.Add(row);
        }
    }

    private static SolidColorBrush ConfidenceBrush(string confidence) =>
        confidence switch
        {
            SecurityConfidence.Confirmed => AccentRed,
            SecurityConfidence.Likely => AccentAmber,
            _ => FgDim
        };

    private static string BuildAskAiPrompt(UnifiedSecurityFinding f) =>
        $"Race Lab finding ({f.Confidence}): {f.Title}\nCategory: {f.Category}\nEndpoint: {f.Method} {f.Endpoint}\nEvidence: {f.Evidence}";

    private void SavePresetAs()
    {
        ReadParametersFromUi();
        if (!RaceLabInputDialog.TryPrompt(this, "Save Race Lab preset", "Preset name:", _workingProfile.Name + " custom", out var name))
            return;
        if (RaceLabSettings.IsBuiltInName(name))
        {
            MessageBox.Show(this, "Choose a name other than built-in presets.", "Race Lab", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var profile = _workingProfile.Clone();
        profile.Name = name.Trim();
        var user = RaceLabSettings.Load().Where(p => !p.IsBuiltIn).ToList();
        user.RemoveAll(p => string.Equals(p.Name, profile.Name, StringComparison.OrdinalIgnoreCase));
        user.Add(profile);
        RaceLabSettings.Save(user);
        _selectedPresetName = profile.Name;
        _workingProfile = profile;
        ReloadPresets();
        _profileCombo.SelectedItem = profile.Name;
        SaveGuiState();
    }

    private void DeletePreset()
    {
        if (RaceLabSettings.IsBuiltInName(_workingProfile.Name))
        {
            MessageBox.Show(this, "Built-in presets cannot be deleted.", "Race Lab", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var user = RaceLabSettings.Load().Where(p => !p.IsBuiltIn).ToList();
        user.RemoveAll(p => string.Equals(p.Name, _workingProfile.Name, StringComparison.OrdinalIgnoreCase));
        RaceLabSettings.Save(user);
        var requests = _workingProfile.Requests.Select(r => r.Clone()).ToList();
        var first = RaceLabSettings.Load().First();
        _selectedPresetName = first.Name;
        _workingProfile = new RaceLabProfile
        {
            Name = first.Name,
            Requests = requests,
            Parameters = ParametersForPreset(first.Name, first, requests.Count)
        };
        ReloadPresets();
        BindWorkingProfile();
        SaveGuiState();
    }

    private void ExportProfile()
    {
        ReadParametersFromUi();
        var dlg = new SaveFileDialog
        {
            Filter = "Race Lab JSON (*.json)|*.json",
            FileName = _workingProfile.Name + ".race-lab.json"
        };
        if (dlg.ShowDialog(this) != true) return;
        File.WriteAllText(dlg.FileName, RaceLabSettings.ExportToJson([_workingProfile.Clone()]));
    }

    private void ImportProfile()
    {
        var dlg = new OpenFileDialog { Filter = "Race Lab JSON (*.json)|*.json" };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var imported = RaceLabSettings.ImportFromJson(File.ReadAllText(dlg.FileName));
            if (imported.Count == 0) return;
            var imp = imported[0].Clone();
            _selectedPresetName = imp.Name;
            _workingProfile = imp;
            BindWorkingProfile();
            ReloadPresets();
            SaveGuiState();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void AddFromNetworkLog()
    {
        var picker = new RaceLabRequestPickerDialog(_ctx, this);
        if (picker.ShowDialog() != true)
            return;

        foreach (var r in picker.GetSelectedRequests())
            _workingProfile.Requests.Add(r);
        _requestGrid.Items.Refresh();
        SaveGuiState();
    }

    private void AddRequest()
    {
        var editor = new RaceLabRequestEditorDialog(this, new RaceLabRequest(), PeerNames());
        if (editor.ShowDialog() != true)
            return;

        _workingProfile.Requests.Add(editor.Result);
        _requestGrid.Items.Refresh();
        SaveGuiState();
    }

    private void EditRequest()
    {
        if (_requestGrid.SelectedItem is not RaceLabRequest req)
            return;

        var index = _workingProfile.Requests.IndexOf(req);
        if (index < 0)
            return;

        var editor = new RaceLabRequestEditorDialog(this, req, PeerNames());
        if (editor.ShowDialog() != true)
            return;

        _workingProfile.Requests[index] = editor.Result;
        _requestGrid.Items.Refresh();
        SaveGuiState();
    }

    private void RemoveRequest()
    {
        if (_requestGrid.SelectedItem is RaceLabRequest req)
        {
            _workingProfile.Requests.Remove(req);
            _requestGrid.Items.Refresh();
            SaveGuiState();
        }
    }

    private void ConfigureRequestGridColumns()
    {
        _requestGrid.RowBackground = GridCellBg;
        _requestGrid.AlternatingRowBackground = GridRowAltBg;
        _requestGrid.HorizontalGridLinesBrush = BorderClr;
        _requestGrid.VerticalGridLinesBrush = BorderClr;
        _requestGrid.ColumnHeaderStyle = CreateGridHeaderStyle();
        _requestGrid.CellStyle = CreateGridCellStyle();
        _requestGrid.Resources[SystemColors.HighlightBrushKey] = GridSelectionBg;
        _requestGrid.Resources[SystemColors.HighlightTextBrushKey] = FgText;
        _requestGrid.Resources[SystemColors.InactiveSelectionHighlightBrushKey] = Bc("#3F3F46");
        _requestGrid.Resources[SystemColors.InactiveSelectionHighlightTextBrushKey] = FgText;

        var textCellStyle = CreateGridCellStyle();
        var textEditStyle = CreateGridTextEditStyle();
        var comboDisplayStyle = CreateGridComboStyle();
        var comboEditStyle = CreateGridComboStyle();

        _requestGrid.Columns.Add(new DataGridTextColumn
        {
            Header = "Name",
            Binding = new Binding(nameof(RaceLabRequest.Name)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            Width = 120,
            CellStyle = textCellStyle,
            EditingElementStyle = textEditStyle
        });

        _requestGrid.Columns.Add(new DataGridComboBoxColumn
        {
            Header = "Method",
            SelectedItemBinding = new Binding(nameof(RaceLabRequest.Method)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            ItemsSource = HttpMethods,
            Width = 72,
            ElementStyle = comboDisplayStyle,
            EditingElementStyle = comboEditStyle
        });

        _requestGrid.Columns.Add(new DataGridTextColumn
        {
            Header = "URL",
            Binding = new Binding(nameof(RaceLabRequest.Url)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            Width = new DataGridLength(1, DataGridLengthUnitType.Star),
            CellStyle = textCellStyle,
            EditingElementStyle = textEditStyle
        });

        _sessionComboColumn = new DataGridComboBoxColumn
        {
            Header = "Session",
            SelectedItemBinding = new Binding(nameof(RaceLabRequest.Session)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            Width = 100,
            ElementStyle = comboDisplayStyle,
            EditingElementStyle = comboEditStyle
        };
        _requestGrid.Columns.Add(_sessionComboColumn);

        _requestGrid.Columns.Add(new DataGridComboBoxColumn
        {
            Header = "Role",
            SelectedItemBinding = new Binding(nameof(RaceLabRequest.Role)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            ItemsSource = RaceLabRoles.All.ToList(),
            Width = 80,
            ElementStyle = comboDisplayStyle,
            EditingElementStyle = comboEditStyle
        });

        _requestGrid.Columns.Add(new DataGridTextColumn
        {
            Header = "Regexp",
            Binding = new Binding(nameof(RaceLabRequest.ResponsePattern)) { UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged },
            Width = 140,
            CellStyle = textCellStyle,
            EditingElementStyle = textEditStyle
        });

        _requestGrid.CellEditEnding += RequestGridCellEditEnding;
        RefreshSessionComboItems();
    }

    private void RefreshSessionComboItems()
    {
        if (_sessionComboColumn == null)
            return;

        var items = new List<string>(RaceLabSessions.BuiltInOptions);
        foreach (var peer in PeerNames())
        {
            if (!items.Contains(peer, StringComparer.OrdinalIgnoreCase))
                items.Add(peer);
        }

        foreach (var req in _workingProfile.Requests)
        {
            var session = req.Session?.Trim();
            if (!string.IsNullOrWhiteSpace(session)
                && !items.Contains(session, StringComparer.OrdinalIgnoreCase))
                items.Add(session);
        }

        _sessionComboColumn.ItemsSource = items;
    }

    private void NormalizeRequestFields()
    {
        foreach (var req in _workingProfile.Requests)
        {
            if (!string.IsNullOrWhiteSpace(req.Method))
                req.Method = req.Method.Trim().ToUpperInvariant();
            req.Session = RaceLabSessions.Normalize(req.Session);
            req.Role = RaceLabRoles.Normalize(req.Role);
            req.ResponsePattern = string.IsNullOrWhiteSpace(req.ResponsePattern) ? null : req.ResponsePattern.Trim();
        }
    }

    private void RequestGridCellEditEnding(object? sender, DataGridCellEditEndingEventArgs e)
    {
        if (_suppressUiEvents)
            return;

        if (e.Row.Item is RaceLabRequest req)
        {
            if (!string.IsNullOrWhiteSpace(req.Method))
                req.Method = req.Method.Trim().ToUpperInvariant();
            req.Session = RaceLabSessions.Normalize(req.Session);
            req.Role = RaceLabRoles.Normalize(req.Role);
            req.ResponsePattern = string.IsNullOrWhiteSpace(req.ResponsePattern) ? null : req.ResponsePattern.Trim();
        }

        SaveGuiState();
    }

    private static Style CreateGridHeaderStyle()
    {
        var style = new Style(typeof(DataGridColumnHeader));
        style.Setters.Add(new Setter(Control.BackgroundProperty, GridHeaderBg));
        style.Setters.Add(new Setter(Control.ForegroundProperty, GridHeaderFg));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 1, 1)));
        style.Setters.Add(new Setter(Control.FontWeightProperty, FontWeights.SemiBold));
        style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(8, 6, 8, 6)));
        style.Setters.Add(new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Left));
        return style;
    }

    private static Style CreateGridCellStyle()
    {
        var style = new Style(typeof(DataGridCell));
        style.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.Transparent));
        style.Setters.Add(new Setter(Control.ForegroundProperty, FgText));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        style.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 1, 0)));
        style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(4, 2, 4, 2)));

        var selected = new Trigger { Property = DataGridCell.IsSelectedProperty, Value = true };
        selected.Setters.Add(new Setter(Control.BackgroundProperty, GridSelectionBg));
        selected.Setters.Add(new Setter(Control.ForegroundProperty, FgText));
        style.Triggers.Add(selected);

        return style;
    }

    private static Style CreateGridTextEditStyle()
    {
        var style = new Style(typeof(TextBox));
        style.Setters.Add(new Setter(Control.BackgroundProperty, BgDark));
        style.Setters.Add(new Setter(Control.ForegroundProperty, FgText));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        style.Setters.Add(new Setter(TextBox.CaretBrushProperty, FgText));
        return style;
    }

    private static Style CreateGridComboStyle()
    {
        var style = new Style(typeof(ComboBox));
        style.Setters.Add(new Setter(Control.BackgroundProperty, BgDark));
        style.Setters.Add(new Setter(Control.ForegroundProperty, FgText));
        style.Setters.Add(new Setter(Control.BorderBrushProperty, BorderClr));
        return style;
    }

    private static SolidColorBrush Bc(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex));
}

internal static class RaceLabInputDialog
{
    public static bool TryPrompt(Window owner, string title, string label, string defaultValue, out string value)
    {
        value = "";
        var dlg = new Window
        {
            Title = title,
            Width = 420,
            Height = 140,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = owner,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2D2D30"))
        };
        var tb = new TextBox { Text = defaultValue, Margin = new Thickness(12, 8, 12, 8) };
        var ok = false;
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = label, Foreground = Brushes.Gainsboro, Margin = new Thickness(12, 12, 12, 0) });
        panel.Children.Add(tb);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(12) };
        var okBtn = new Button { Content = "OK", Width = 72, Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        var cancelBtn = new Button { Content = "Cancel", Width = 72, IsCancel = true };
        okBtn.Click += (_, _) => { ok = true; dlg.Close(); };
        cancelBtn.Click += (_, _) => dlg.Close();
        buttons.Children.Add(okBtn);
        buttons.Children.Add(cancelBtn);
        panel.Children.Add(buttons);
        dlg.Content = panel;
        dlg.ShowDialog();
        if (!ok || string.IsNullOrWhiteSpace(tb.Text)) return false;
        value = tb.Text.Trim();
        return true;
    }
}
