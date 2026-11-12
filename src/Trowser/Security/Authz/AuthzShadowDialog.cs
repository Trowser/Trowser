using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Trowser.Automation;
using Trowser.Security.Orchestration;
using Trowser.Security.WebSocket;

namespace Trowser.Security.Authz;

/// <summary>
/// GUI for the Live Authz Shadow: enable/disable + safetyMode, a live color-coded verdict
/// stream, and classification for resources that do not yet have a human or AI answer.
/// Classification stays in this dialog. It does not open the AI Assistant.
/// </summary>
public sealed class AuthzShadowDialog : Window
{
    private readonly LiveAuthzShadow _shadow;
    private readonly AutomationContext? _browser;
    private readonly StackPanel _socketList;
    private readonly StackPanel _resultList;
    private readonly StackPanel _classificationList;
    private readonly TextBlock _statusText;
    private readonly CheckBox _enabledCheck;
    private readonly ComboBox _safetyModeCombo;
    private readonly DispatcherTimer _pollTimer;
    private int _lastRenderedResultId;
    private string _classificationFingerprint = "";
    private readonly Dictionary<string, int> _pendingChoices = new(StringComparer.OrdinalIgnoreCase);

    private static readonly (string Label, AccessSensitivity Sensitivity, AccessOwnership Ownership)[] ClassificationChoices =
    [
        ("Public / shared", AccessSensitivity.Public, AccessOwnership.Shared),
        ("Sensitive / per-user", AccessSensitivity.Sensitive, AccessOwnership.PerUser),
        ("Sensitive / per-tenant", AccessSensitivity.Sensitive, AccessOwnership.PerTenant),
        ("Role-gated", AccessSensitivity.Internal, AccessOwnership.RoleGated)
    ];

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");
    private static readonly SolidColorBrush AccentBlue = Bc("#569CD6");
    private static readonly SolidColorBrush AccentGreen = Bc("#4EC9B0");

    public AuthzShadowDialog(LiveAuthzShadow shadow, Window owner, AutomationContext? browser = null)
    {
        _shadow = shadow;
        _browser = browser;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Live Authz Shadow";
        Width = 780;
        Height = 640;
        MinWidth = 560;
        MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        var root = new Grid { Margin = new Thickness(12) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // help
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // controls
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // status
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(2, GridUnitType.Star) }); // results
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // classification header
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // classification list

        var help = new TextBlock
        {
            Text = "Watches normal browsing and read-only replays authz-relevant HTTP requests through registered peers. " +
                "Open WebSockets are listed below and are not HTTP-replayed. Test socket authz sends one captured frame on a peer's already-open socket. " +
                "Off by default. State-changing methods, and socket frames that are not subscribe/query/ping, only run once safetyMode is active or above. " +
                "Export saves this result log and the access models; Import resumes them later.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = FgDim,
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 8)
        };
        Grid.SetRow(help, 0);
        root.Children.Add(help);

        var controls = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        _enabledCheck = new CheckBox
        {
            Content = "Enabled",
            Foreground = FgText,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 16, 0)
        };
        _enabledCheck.Checked += (_, _) => Apply();
        _enabledCheck.Unchecked += (_, _) => Apply();

        var safetyLabel = new TextBlock { Text = "safetyMode:", Foreground = FgDim, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) };
        _safetyModeCombo = new ComboBox { Width = 110, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 16, 0) };
        foreach (var mode in new[] { "passive", "safe", "active", "aggressive" })
            _safetyModeCombo.Items.Add(mode);
        _safetyModeCombo.SelectedItem = _shadow.Config.SafetyMode;
        _safetyModeCombo.SelectionChanged += (_, _) => Apply();

        var clearBtn = new Button { Content = "Clear results", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        clearBtn.Click += (_, _) =>
        {
            _shadow.Configure(false);
            _shadow.ClearResults();
            _pendingChoices.Clear();
            _lastRenderedResultId = -1;
            _classificationFingerprint = "\0";
            RenderAll();
        };

        var refreshBtn = new Button { Content = "Refresh", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        refreshBtn.Click += (_, _) =>
        {
            _classificationFingerprint = "\0";
            _lastRenderedResultId = -1;
            RenderAll();
        };

        var classificationsBtn = new Button { Content = "Classifications", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        classificationsBtn.Click += (_, _) => ShowClassifications();

        var exportBtn = new Button { Content = "Export", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        exportBtn.Click += (_, _) => ExportBundle();

        var importBtn = new Button { Content = "Import", Padding = new Thickness(10, 4, 10, 4) };
        importBtn.Click += (_, _) => ImportBundle();

        controls.Children.Add(_enabledCheck);
        controls.Children.Add(safetyLabel);
        controls.Children.Add(_safetyModeCombo);
        controls.Children.Add(clearBtn);
        controls.Children.Add(refreshBtn);
        controls.Children.Add(classificationsBtn);
        controls.Children.Add(exportBtn);
        controls.Children.Add(importBtn);
        Grid.SetRow(controls, 1);
        root.Children.Add(controls);

        var statusPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 8) };
        _statusText = new TextBlock { Foreground = AccentBlue, FontSize = 12, TextWrapping = TextWrapping.Wrap };
        statusPanel.Children.Add(_statusText);
        statusPanel.Children.Add(new TextBlock
        {
            Text = "Open sockets",
            Foreground = FgText,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 8, 0, 4)
        });
        _socketList = new StackPanel();
        statusPanel.Children.Add(_socketList);
        Grid.SetRow(statusPanel, 2);
        root.Children.Add(statusPanel);

        var resultsScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _resultList = new StackPanel();
        resultsScroll.Content = _resultList;
        Grid.SetRow(resultsScroll, 3);
        root.Children.Add(resultsScroll);

        var classifyHeader = new StackPanel { Margin = new Thickness(0, 10, 0, 4) };
        classifyHeader.Children.Add(new TextBlock
        {
            Text = "Needs classification",
            Foreground = FgText,
            FontWeight = FontWeights.Bold
        });
        classifyHeader.Children.Add(new TextBlock
        {
            Text = "One row per endpoint. Replays through several peers are classified together.",
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        });
        Grid.SetRow(classifyHeader, 4);
        root.Children.Add(classifyHeader);

        var classifyScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _classificationList = new StackPanel();
        classifyScroll.Content = _classificationList;
        Grid.SetRow(classifyScroll, 5);
        root.Children.Add(classifyScroll);

        Content = root;

        _shadow.DismissClassificationPrompts();
        RenderAll();

        _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _pollTimer.Tick += (_, _) => RenderAll();
        _pollTimer.Start();
        Closed += (_, _) => _pollTimer.Stop();
    }

    private void ExportBundle()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export Live Authz Shadow",
            Filter = "Live Authz Shadow (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json",
            FileName = $"authz-shadow-{DateTime.Now:yyyyMMdd-HHmm}.json"
        };
        if (dialog.ShowDialog(this) != true) return;

        try
        {
            var bundle = _shadow.ExportBundle();
            File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(bundle, AuthzShadowBundle.JsonOptions));
            MessageBox.Show(this,
                $"Saved {bundle.Results.Count} result(s) and {bundle.Models.Count} access model(s) to\n{dialog.FileName}",
                "Export", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ImportBundle()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Import Live Authz Shadow",
            Filter = "Live Authz Shadow (*.json)|*.json|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;

        var replace = false;
        if (_shadow.GetResults().Count > 0)
        {
            var choice = MessageBox.Show(this,
                "Replace the current result list with this file?\n\n" +
                "Yes replaces the list. No adds results that are not already here.\n" +
                "Classifications you already saved are kept.",
                "Import Live Authz Shadow",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel) return;
            replace = choice == MessageBoxResult.Yes;
        }

        try
        {
            var json = File.ReadAllText(dialog.FileName);
            var bundle = JsonSerializer.Deserialize<AuthzShadowBundle>(json, AuthzShadowBundle.JsonOptions)
                ?? throw new InvalidDataException("The file did not contain an authz shadow bundle.");
            dynamic imported = _shadow.ImportBundle(bundle, replace);
            _lastRenderedResultId = -1;
            RenderAll();
            MessageBox.Show(this,
                $"Imported {imported.resultsImported} result(s) " +
                $"({imported.resultsSkipped} already present).\n" +
                $"{imported.modelsMerged} access model(s) merged.",
                "Import", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Apply()
    {
        var safetyMode = _safetyModeCombo.SelectedItem as string ?? "safe";
        _shadow.Configure(_enabledCheck.IsChecked == true, safetyMode);
        RenderAll();
    }

    private void RenderAll()
    {
        if (_enabledCheck.IsChecked != _shadow.Config.Enabled)
            _enabledCheck.IsChecked = _shadow.Config.Enabled;
        if (_safetyModeCombo.SelectedItem as string != _shadow.Config.SafetyMode)
            _safetyModeCombo.SelectedItem = _shadow.Config.SafetyMode;

        var results = _shadow.GetResults();
        RenderStatus(results);
        RenderSockets();
        RenderResults(results);
        RenderClassificationQueue(results);
    }

    private void RenderStatus(List<LiveAuthzShadowResult> results)
    {
        var counts = results.GroupBy(r => r.Verdict).ToDictionary(g => g.Key, g => g.Count());
        var summary = string.Join("  ", counts.OrderByDescending(kv => kv.Value)
            .Select(kv => $"{kv.Key}: {kv.Value}"));
        var gaps = _shadow.WebSocketGapCount;
        _statusText.Text = $"{(_shadow.Config.Enabled ? "Running" : "Stopped")} — {results.Count} result(s)" +
            (summary.Length > 0 ? $"  ·  {summary}" : "") +
            (gaps > 0 ? $"  ·  {gaps} WebSocket(s) seen, not replayed" : "");
    }

    private void RenderSockets()
    {
        _socketList.Children.Clear();
        var sockets = _browser?.ActiveTab?.WebSocket.GetConnections()
            .Where(c => c.State is "open" or "connecting")
            .ToList() ?? [];

        if (sockets.Count == 0)
        {
            _socketList.Children.Add(new TextBlock
            {
                Text = "No open WebSocket on this tab.",
                Foreground = FgDim,
                FontSize = 11,
                Margin = new Thickness(0, 0, 0, 4)
            });
            return;
        }

        foreach (var conn in sockets)
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
            var button = new Button
            {
                Content = "Test socket authz",
                Padding = new Thickness(8, 2, 8, 2),
                Margin = new Thickness(8, 0, 0, 0)
            };
            DockPanel.SetDock(button, Dock.Right);
            var captured = conn;
            button.Click += async (_, _) => await TestSocketAsync(captured);
            row.Children.Add(button);
            row.Children.Add(new TextBlock
            {
                Text = conn.Url,
                Foreground = FgText,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = conn.Url
            });
            _socketList.Children.Add(row);
        }
    }

    private async Task TestSocketAsync(WebSocketConnection conn)
    {
        if (_browser?.PeerRegistry == null)
        {
            MessageBox.Show(this, "Peer sessions are not available.", "Test socket authz", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var peerNames = _shadow.ResolveReplayPeers();
        if (peerNames.Count == 0)
        {
            MessageBox.Show(this,
                "No alive peers marked \"Use for tests\". Launch a peer and check Use for tests.",
                "Test socket authz",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var mode = SafetyModeExtensions.Parse(_shadow.Config.SafetyMode);
        var report = await new WebSocketAuthzTester(_browser, _browser.PeerRegistry).RunAsync(new WebSocketAuthzRequest
        {
            ConnectionId = conn.ConnectionId,
            SafetyMode = mode,
            Peers = peerNames
        });

        if (!report.Ok)
        {
            MessageBox.Show(this, report.Error ?? "Socket authz check failed.", "Test socket authz",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        WebSocketAuthzRecorder.Record(_browser, report);
        _lastRenderedResultId = -1;
        RenderAll();
    }

    private void RenderResults(List<LiveAuthzShadowResult> results)
    {
        // Cheap incremental check: only rebuild the visible list when new results arrived.
        var latestId = results.Count > 0 ? results[^1].Id : 0;
        if (latestId == _lastRenderedResultId && _resultList.Children.Count > 0)
            return;
        _lastRenderedResultId = latestId;

        _resultList.Children.Clear();
        foreach (var r in results.OrderByDescending(r => r.Timestamp).Take(200))
            _resultList.Children.Add(BuildResultRow(r));

        if (results.Count == 0)
        {
            _resultList.Children.Add(new TextBlock
            {
                Text = "No results yet. Enable the shadow, register a peer, and browse normally.",
                Foreground = FgDim,
                Margin = new Thickness(8)
            });
        }
    }

    private UIElement BuildResultRow(LiveAuthzShadowResult r)
    {
        var panel = new StackPanel { Margin = new Thickness(8, 4, 8, 4) };
        var line1 = new StackPanel { Orientation = Orientation.Horizontal };
        line1.Children.Add(new TextBlock
        {
            Text = $"[{r.Verdict}]",
            Foreground = VerdictColor(r.Verdict),
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 6, 0)
        });
        line1.Children.Add(new TextBlock { Text = $"{r.Method} {r.UrlTemplate}", Foreground = FgText });
        panel.Children.Add(line1);

        panel.Children.Add(new TextBlock
        {
            Text = $"  via peer \"{r.Peer}\" ({r.Confidence} confidence) — {r.Reason}",
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap
        });

        if (r.DuplicateHtmlShell && LiveAuthzShadow.IsClassificationVerdict(r.Verdict))
        {
            panel.Children.Add(new TextBlock
            {
                Text = "  Not listed below: this is the same HTML document as another route, so it is not a second endpoint to classify.",
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            });
        }
        else if (LiveAuthzShadow.IsClassificationVerdict(r.Verdict) && AlreadyClassified(r))
        {
            panel.Children.Add(new TextBlock
            {
                Text = "  Already classified. Use Classifications to review or change it.",
                Foreground = FgDim,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            });
        }

        var border = new Border
        {
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Background = BgItem,
            Child = panel
        };
        var classified = AlreadyClassified(r);
        TextCopyMenu.Attach(border, () => ResultCopyText(r, classified));
        return border;
    }

    private static string ResultCopyText(LiveAuthzShadowResult r, bool alreadyClassified)
    {
        var lines = new List<string>
        {
            $"[{r.Verdict}] {r.Method} {r.UrlTemplate}",
            $"via peer \"{r.Peer}\" ({r.Confidence} confidence) — {r.Reason}"
        };
        if (r.DuplicateHtmlShell && LiveAuthzShadow.IsClassificationVerdict(r.Verdict))
            lines.Add("Not listed below: this is the same HTML document as another route, so it is not a second endpoint to classify.");
        else if (LiveAuthzShadow.IsClassificationVerdict(r.Verdict) && alreadyClassified)
            lines.Add("Already classified. Use Classifications to review or change it.");
        return string.Join(Environment.NewLine, lines);
    }

    private bool AlreadyClassified(LiveAuthzShadowResult result)
    {
        try
        {
            return _shadow.FindSessionClassification(result.Host, result.Method, result.UrlTemplate) != null;
        }
        catch
        {
            return false;
        }
    }

    private void RenderClassificationQueue(List<LiveAuthzShadowResult> results)
    {
        if (ClassificationDropdownOpen()) return;

        var pending = PendingGroups(results);
        var fingerprint = ClassificationFingerprint(pending);
        if (fingerprint == _classificationFingerprint && _classificationList.Children.Count > 0)
            return;
        _classificationFingerprint = fingerprint;

        _classificationList.Children.Clear();

        if (pending.Count == 0)
        {
            _classificationList.Children.Add(new TextBlock
            {
                Text = "Nothing pending — every tested resource is classified.",
                Foreground = FgDim,
                Margin = new Thickness(8)
            });
            return;
        }

        var bulkBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4) };
        var bulkBtn = new Button { Content = $"Classify all {pending.Count} as Sensitive / per-user", Padding = new Thickness(8, 3, 8, 3) };
        bulkBtn.Click += (_, _) =>
        {
            foreach (var group in pending)
            {
                var r = group[0];
                _shadow.ClassifyResource(r.Host, r.Method, r.UrlTemplate, AccessSensitivity.Sensitive, AccessOwnership.PerUser);
            }
            _classificationFingerprint = "\0";
            RenderAll();
        };
        bulkBar.Children.Add(bulkBtn);
        _classificationList.Children.Add(bulkBar);

        foreach (var group in pending)
            _classificationList.Children.Add(BuildClassificationRow(group));
    }

    private static string ClassificationFingerprint(List<List<LiveAuthzShadowResult>> pending) =>
        string.Join("\n", pending.Select(g =>
        {
            var latest = g[0];
            return $"{latest.Host}|{latest.Method}|{latest.UrlTemplate}|{g.Count}|{latest.Verdict}|{latest.Reason}";
        }));

    private static string EndpointKey(LiveAuthzShadowResult result) =>
        $"{result.Host}|{result.Method}|{result.UrlTemplate}";

    private List<List<LiveAuthzShadowResult>> PendingGroups(List<LiveAuthzShadowResult> results)
    {
        bool Pending(LiveAuthzShadowResult r)
        {
            if (r.DuplicateHtmlShell) return false;
            if (_shadow.FindSessionClassification(r.Host, r.Method, r.UrlTemplate) != null) return false;
            return r.NeedsClassification || LiveAuthzShadow.IsClassificationVerdict(r.Verdict);
        }

        return results
            .Where(Pending)
            .GroupBy(r => $"{r.Host}|{r.Method}|{r.UrlTemplate}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(r => r.Timestamp).ToList())
            .OrderByDescending(g => g[0].Verdict == AuthzVerdictKind.ConfirmedLeak)
            .ThenByDescending(g => g[0].Verdict == AuthzVerdictKind.BolaSuspected)
            .ThenByDescending(g => g[0].Verdict == AuthzVerdictKind.ReplayedWrite)
            .ToList();
    }

    private bool ClassificationDropdownOpen()
    {
        foreach (var child in _classificationList.Children)
        {
            if (ContainsOpenCombo(child)) return true;
        }
        return false;
    }

    private static bool ContainsOpenCombo(object? node)
    {
        switch (node)
        {
            case ComboBox { IsDropDownOpen: true }:
                return true;
            case Panel panel:
                foreach (var child in panel.Children)
                    if (ContainsOpenCombo(child)) return true;
                return false;
            case Decorator { Child: { } child }:
                return ContainsOpenCombo(child);
            case ContentControl { Content: { } content }:
                return ContainsOpenCombo(content);
            default:
                return false;
        }
    }

    private UIElement BuildClassificationRow(List<LiveAuthzShadowResult> group)
    {
        var r = group[0];
        var peers = string.Join(", ", group.Select(x => x.Peer).Distinct(StringComparer.OrdinalIgnoreCase));
        var row = new StackPanel { Margin = new Thickness(8, 6, 8, 6) };

        row.Children.Add(new TextBlock
        {
            Text = $"[{r.Verdict}] {r.Method} {r.UrlTemplate}",
            Foreground = VerdictColor(r.Verdict),
            TextWrapping = TextWrapping.Wrap
        });
        row.Children.Add(new TextBlock
        {
            Text = group.Count == 1
                ? $"peer \"{peers}\" — {r.Reason}"
                : $"{group.Count} replays (peers: {peers}) — {r.Reason}",
            Foreground = FgDim,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 2, 0, 4)
        });

        var actions = new StackPanel { Orientation = Orientation.Horizontal };
        var endpointKey = EndpointKey(r);
        var combo = NewClassificationCombo();
        var selected = _pendingChoices.TryGetValue(endpointKey, out var kept)
            ? kept
            : RecommendedChoiceIndex(r);
        combo.SelectionChanged += (_, _) =>
        {
            if (combo.SelectedIndex >= 0)
                _pendingChoices[endpointKey] = combo.SelectedIndex;
        };
        combo.SelectedIndex = selected;

        var applyBtn = new Button { Content = "Apply", Padding = new Thickness(8, 2, 8, 2) };
        applyBtn.Click += (_, e) =>
        {
            e.Handled = true;
            if (combo.SelectedIndex < 0 || combo.SelectedIndex >= ClassificationChoices.Length) return;
            var choice = ClassificationChoices[combo.SelectedIndex];
            var host = r.Host;
            var method = r.Method;
            var template = r.UrlTemplate;
            // Let the click finish before the row disappears, so it cannot land on the next dropdown.
            Dispatcher.BeginInvoke(() =>
            {
                _pendingChoices.Remove(endpointKey);
                combo.SelectedIndex = -1;
                _shadow.ClassifyResource(host, method, template, choice.Sensitivity, choice.Ownership);
                RemoveClassificationRow(endpointKey);
            });
        };

        actions.Children.Add(combo);
        actions.Children.Add(applyBtn);
        row.Children.Add(actions);

        var border = new Border
        {
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(0, 0, 0, 1),
            Background = BgItem,
            Tag = endpointKey,
            Child = row
        };
        var copyHeader = $"[{r.Verdict}] {r.Method} {r.UrlTemplate}";
        var copyDetail = group.Count == 1
            ? $"peer \"{peers}\" — {r.Reason}"
            : $"{group.Count} replays (peers: {peers}) — {r.Reason}";
        TextCopyMenu.Attach(border, () => copyHeader + Environment.NewLine + copyDetail);
        return border;
    }

    private static ComboBox NewClassificationCombo()
    {
        var combo = new ComboBox
        {
            Width = 180,
            Margin = new Thickness(0, 0, 8, 0),
            IsSynchronizedWithCurrentItem = false,
            ItemsSource = ClassificationChoices.Select(choice => choice.Label).ToList()
        };
        return combo;
    }

    private void RemoveClassificationRow(string endpointKey)
    {
        UIElement? match = null;
        foreach (var child in _classificationList.Children)
        {
            if (child is FrameworkElement element && Equals(element.Tag, endpointKey))
                match = element;
        }
        if (match != null)
            _classificationList.Children.Remove(match);

        var pending = PendingGroups(_shadow.GetResults());
        if (pending.Count == 0)
        {
            _classificationList.Children.Clear();
            _classificationList.Children.Add(new TextBlock
            {
                Text = "Nothing pending — every tested resource is classified.",
                Foreground = FgDim,
                Margin = new Thickness(8)
            });
        }
        else
        {
            foreach (var child in _classificationList.Children)
            {
                if (child is StackPanel bar && bar.Children.Count > 0 && bar.Children[0] is Button bulk)
                {
                    bulk.Content = $"Classify all {pending.Count} as Sensitive / per-user";
                    break;
                }
            }
        }

        _classificationFingerprint = ClassificationFingerprint(pending);
    }

    private static int RecommendedChoiceIndex(LiveAuthzShadowResult r)
    {
        var identicalPublic = r.Verdict == AuthzVerdictKind.BolaSuspected
            && !r.DuplicateHtmlShell
            && !LiveAuthzShadow.TemplateHasIdentity(r.UrlTemplate);
        var key = LiveAuthzShadow.RecommendClassification(r.Verdict, r.UrlTemplate, identicalPublic, r.Method);
        return key switch
        {
            "A" => 0,
            "C" => 2,
            "D" => 3,
            _ => 1
        };
    }

    private void ShowClassifications()
    {
        var dialog = new ClassificationsWindow(_shadow) { Owner = this };
        dialog.ShowDialog();
        _classificationFingerprint = "\0";
        RenderAll();
    }

    private static Brush VerdictColor(AuthzVerdictKind verdict) => verdict switch
    {
        AuthzVerdictKind.ConfirmedLeak => Bc("#F44747"),
        AuthzVerdictKind.BolaSuspected => Bc("#F44747"),
        AuthzVerdictKind.SameShapeDifferentData => Bc("#CCA700"),
        AuthzVerdictKind.ReplayedWrite => Bc("#CCA700"),
        AuthzVerdictKind.NeedsReview => Bc("#CCA700"),
        AuthzVerdictKind.FilteredResponse => AccentGreen,
        AuthzVerdictKind.ProperlyDenied => AccentGreen,
        _ => FgDim
    };

    private static SolidColorBrush Bc(string hex) => new((Color)ColorConverter.ConvertFromString(hex));

    private sealed class ClassificationsWindow : Window
    {
        public ClassificationsWindow(LiveAuthzShadow shadow)
        {
            Title = "Authz classifications";
            Width = 720;
            Height = 480;
            MinWidth = 520;
            MinHeight = 280;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ResizeMode = ResizeMode.CanResizeWithGrip;
            Background = BgMedium;
            ShowInTaskbar = false;

            var root = new DockPanel { Margin = new Thickness(12) };
            var help = new TextBlock
            {
                Text = "Classifications for this run. Clear results drops them. Export and Import keep a copy for later. " +
                    "Pick a different answer and click Apply to change one.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = FgDim,
                Margin = new Thickness(0, 0, 0, 8)
            };
            DockPanel.SetDock(help, Dock.Top);
            root.Children.Add(help);

            var scroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = BgDark,
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(1)
            };
            var list = new StackPanel();
            scroll.Content = list;
            root.Children.Add(scroll);

            var saved = shadow.ListSessionClassifications();

            if (saved.Count == 0)
            {
                list.Children.Add(new TextBlock
                {
                    Text = "No classifications this run. Apply one under Needs classification and it will show up here.",
                    Foreground = FgDim,
                    Margin = new Thickness(8),
                    TextWrapping = TextWrapping.Wrap
                });
            }
            else
            {
                foreach (var (host, resource) in saved)
                    list.Children.Add(BuildRow(shadow, host, resource));
            }

            Content = root;
        }

        private static UIElement BuildRow(LiveAuthzShadow shadow, string host, AccessModelResource resource)
        {
            var row = new StackPanel { Margin = new Thickness(8, 6, 8, 6) };
            row.Children.Add(new TextBlock
            {
                Text = $"{resource.Method} {resource.UrlTemplate}",
                Foreground = FgText,
                TextWrapping = TextWrapping.Wrap
            });
            row.Children.Add(new TextBlock
            {
                Text = $"{host} · {resource.Source}",
                Foreground = FgDim,
                FontSize = 11,
                Margin = new Thickness(0, 2, 0, 4)
            });

            var actions = new StackPanel { Orientation = Orientation.Horizontal };
            var combo = NewClassificationCombo();
            combo.SelectedIndex = IndexFor(resource);

            var saved = new TextBlock
            {
                Text = "",
                Foreground = AccentGreen,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0)
            };
            var applyBtn = new Button { Content = "Apply", Padding = new Thickness(8, 2, 8, 2) };
            applyBtn.Click += (_, _) =>
            {
                if (combo.SelectedIndex < 0 || combo.SelectedIndex >= ClassificationChoices.Length) return;
                var choice = ClassificationChoices[combo.SelectedIndex];
                shadow.ClassifyResource(host, resource.Method, resource.UrlTemplate, choice.Sensitivity, choice.Ownership);
                saved.Text = "Saved";
            };

            actions.Children.Add(combo);
            actions.Children.Add(applyBtn);
            actions.Children.Add(saved);
            row.Children.Add(actions);

            var border = new Border
            {
                BorderBrush = BorderClr,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Background = BgItem,
                Child = row
            };
            TextCopyMenu.Attach(border, () =>
                $"{resource.Method} {resource.UrlTemplate}{Environment.NewLine}{host} · {resource.Source}");
            return border;
        }

        private static int IndexFor(AccessModelResource resource)
        {
            for (var i = 0; i < ClassificationChoices.Length; i++)
            {
                if (ClassificationChoices[i].Sensitivity == resource.Sensitivity
                    && ClassificationChoices[i].Ownership == resource.Ownership)
                    return i;
            }
            return 1;
        }
    }
}
