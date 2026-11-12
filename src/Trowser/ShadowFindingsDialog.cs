using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Trowser.Security;

namespace Trowser;

/// <summary>
/// Modeless dialog for browsing Shadow findings.
/// Stays open while the user browses — auto-refreshes when new findings arrive.
/// </summary>
public partial class ShadowFindingsDialog : Window
{
    private readonly SecurityShadowManager _shadow;
    private readonly Laws.LawService? _laws;
    private readonly StackPanel _findingsList;
    private readonly StackPanel _suggestionsPanel;
    private readonly TextBlock _summaryText;
    private readonly TextBlock _detailTitle;
    private readonly TextBlock _detailSeverity;
    private readonly TextBlock _detailUrl;
    private readonly TextBlock _detailDomains;
    private readonly TextBlock _detailDescription;
    private readonly TextBlock _detailRecommendation;
    private readonly TextBlock _detailMeta;
    private readonly Button _askAiButton;
    private readonly Button _toggleBtn;
    private readonly ComboBox _severityFilter;
    private readonly ComboBox _categoryFilter;
    private readonly TextBox _searchBox;
    private readonly Border _detailPanel;
    private readonly Border _suggestionsSection;

    private ShadowFinding? _selectedFinding;

    /// <summary>Raised when the tester wants the AI Assistant to look at the selected finding.</summary>
    public event Action<ShadowFinding>? AskAiRequested;

    /// <summary>Raised when the tester wants to open the Experimental settings dialog.</summary>
    public event Action<Window>? SettingsRequested;

    private static readonly SolidColorBrush BgDark = Bc("#1E1E1E");
    private static readonly SolidColorBrush BgMedium = Bc("#2D2D30");
    private static readonly SolidColorBrush BgItem = Bc("#252526");
    private static readonly SolidColorBrush BgSelected = Bc("#094771");
    private static readonly SolidColorBrush FgText = Bc("#D4D4D4");
    private static readonly SolidColorBrush FgDim = Bc("#888888");
    private static readonly SolidColorBrush BorderClr = Bc("#3F3F46");

    public ShadowFindingsDialog(Window owner, SecurityShadowManager shadow, Laws.LawService? laws = null)
    {
        _shadow = shadow;
        _laws = laws;
        Owner = owner;
        ModelessDialogFocus.WireOwnerFocusRestore(this);
        Title = "Shadow — checks & findings";
        Width = 720;
        Height = 640;
        MinWidth = 500;
        MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = BgMedium;
        ShowInTaskbar = false;

        var rootGrid = new Grid();
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // summary
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // tabs
        rootGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // suggestions

        // ─── Summary row ───
        var summaryRow = new DockPanel { Margin = new Thickness(16, 12, 16, 4) };

        _summaryText = new TextBlock
        {
            Foreground = FgText,
            FontSize = 13,
            VerticalAlignment = VerticalAlignment.Center
        };
        DockPanel.SetDock(_summaryText, Dock.Left);
        summaryRow.Children.Add(_summaryText);

        var clearBtn = CreateButton("Clear All", false);
        clearBtn.Width = 70;
        clearBtn.Height = 24;
        clearBtn.FontSize = 11;
        clearBtn.Click += (_, _) =>
        {
            _shadow.ClearFindings();
            _selectedFinding = null;
            RefreshFindings();
        };
        DockPanel.SetDock(clearBtn, Dock.Right);
        summaryRow.Children.Add(clearBtn);

        // toggle enable/disable
        _toggleBtn = CreateButton(_shadow.Enabled ? "Disable" : "Enable", _shadow.Enabled);
        _toggleBtn.Width = 70;
        _toggleBtn.Height = 24;
        _toggleBtn.FontSize = 11;
        _toggleBtn.Margin = new Thickness(0, 0, 8, 0);
        _toggleBtn.Click += (_, _) =>
        {
            _shadow.Configure(!_shadow.Enabled);
            RefreshToggleButton();
            RefreshFindings();
        };
        DockPanel.SetDock(_toggleBtn, Dock.Right);
        summaryRow.Children.Add(_toggleBtn);

        var settingsBtn = CreateButton("Settings...", false);
        settingsBtn.Width = 84;
        settingsBtn.Height = 24;
        settingsBtn.FontSize = 11;
        settingsBtn.Margin = new Thickness(0, 0, 8, 0);
        settingsBtn.Click += (_, _) => SettingsRequested?.Invoke(this);
        DockPanel.SetDock(settingsBtn, Dock.Right);
        summaryRow.Children.Add(settingsBtn);

        if (_laws != null)
        {
            var checkNowBtn = CreateButton("Check now", false);
            checkNowBtn.Width = 84;
            checkNowBtn.Height = 24;
            checkNowBtn.FontSize = 11;
            checkNowBtn.Margin = new Thickness(0, 0, 8, 0);
            checkNowBtn.Click += async (_, _) =>
            {
                checkNowBtn.IsEnabled = false;
                try
                {
                    await _laws.RunShadowHeavyAsync();
                    RefreshFindings();
                    RefreshLawsTab();
                }
                finally { checkNowBtn.IsEnabled = true; }
            };
            DockPanel.SetDock(checkNowBtn, Dock.Right);
            summaryRow.Children.Add(checkNowBtn);
        }

        Grid.SetRow(summaryRow, 0);
        rootGrid.Children.Add(summaryRow);

        // ─── Filter row ───
        var filterRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(16, 4, 16, 8)
        };

        filterRow.Children.Add(new TextBlock
        {
            Text = "Severity:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 4, 0)
        });
        _severityFilter = CreateFilterCombo(["All", "Info", "Low", "Medium", "High", "Critical"]);
        _severityFilter.SelectionChanged += (_, _) => RefreshFindings();
        filterRow.Children.Add(_severityFilter);

        filterRow.Children.Add(new TextBlock
        {
            Text = "Category:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 4, 0)
        });
        _categoryFilter = CreateFilterCombo(["All", "security-headers", "cookies", "xss",
            "mixed-content", "source-maps", "storage", "retire-js", "wcag", "network", "console", "laws", "custom"]);
        _categoryFilter.SelectionChanged += (_, _) => RefreshFindings();
        filterRow.Children.Add(_categoryFilter);

        filterRow.Children.Add(new TextBlock
        {
            Text = "Search:",
            Foreground = FgDim,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 4, 0)
        });
        _searchBox = new TextBox
        {
            Width = 140,
            Height = 22,
            Background = BgDark,
            Foreground = FgText,
            CaretBrush = FgText,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(4, 1, 4, 1),
            FontSize = 11,
            VerticalContentAlignment = VerticalAlignment.Center
        };
        _searchBox.TextChanged += (_, _) => RefreshFindings();
        filterRow.Children.Add(_searchBox);

        var findingsTabGrid = new Grid();
        findingsTabGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        findingsTabGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        Grid.SetRow(filterRow, 0);
        findingsTabGrid.Children.Add(filterRow);

        // ─── Main content: findings list (top) + detail panel (bottom) ───
        var contentGrid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        contentGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        contentGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // splitter hint
        contentGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(180) });

        var findingsScroll = new ScrollViewer
        {
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1)
        };
        _findingsList = new StackPanel();
        findingsScroll.Content = _findingsList;
        Grid.SetRow(findingsScroll, 0);
        contentGrid.Children.Add(findingsScroll);

        var splitter = new GridSplitter
        {
            Height = 4,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Background = BorderClr,
            Margin = new Thickness(0, 2, 0, 2)
        };
        Grid.SetRow(splitter, 1);
        contentGrid.Children.Add(splitter);

        _detailPanel = new Border
        {
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(12, 8, 12, 8)
        };
        var detailScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        var detailStack = new StackPanel();

        _detailTitle = new TextBlock
        {
            Foreground = FgText,
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 4)
        };
        detailStack.Children.Add(_detailTitle);

        _detailSeverity = new TextBlock { FontSize = 11, Margin = new Thickness(0, 0, 0, 2) };
        detailStack.Children.Add(_detailSeverity);

        _detailUrl = new TextBlock
        {
            Foreground = Bc("#569CD6"),
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6)
        };
        detailStack.Children.Add(_detailUrl);

        _detailDomains = new TextBlock
        {
            Foreground = FgText,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6),
            Visibility = Visibility.Collapsed
        };
        detailStack.Children.Add(_detailDomains);

        _detailDescription = new TextBlock
        {
            Foreground = FgText,
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 6)
        };
        detailStack.Children.Add(_detailDescription);

        _detailRecommendation = new TextBlock
        {
            Foreground = Bc("#4EC9B0"),
            FontSize = 11,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 4)
        };
        detailStack.Children.Add(_detailRecommendation);

        _detailMeta = new TextBlock
        {
            Foreground = FgDim,
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap
        };
        detailStack.Children.Add(_detailMeta);

        _askAiButton = CreateButton("Ask AI", true);
        _askAiButton.Width = 80;
        _askAiButton.Height = 24;
        _askAiButton.FontSize = 11;
        _askAiButton.Margin = new Thickness(0, 8, 0, 0);
        _askAiButton.HorizontalAlignment = HorizontalAlignment.Left;
        _askAiButton.IsEnabled = false;
        ToolTipService.SetShowOnDisabled(_askAiButton, true);
        _askAiButton.ToolTip = "Select a finding first to send it to the AI Assistant";
        _askAiButton.Click += (_, _) =>
        {
            if (_selectedFinding != null)
                AskAiRequested?.Invoke(_selectedFinding);
        };
        detailStack.Children.Add(_askAiButton);

        detailScroll.Content = detailStack;
        _detailPanel.Child = detailScroll;
        TextCopyMenu.Attach(_detailPanel, DetailCopyText);
        Grid.SetRow(_detailPanel, 2);
        contentGrid.Children.Add(_detailPanel);

        Grid.SetRow(contentGrid, 1);
        findingsTabGrid.Children.Add(contentGrid);

        var tabControl = new TabControl
        {
            Margin = new Thickness(16, 4, 16, 8),
            Background = BgMedium
        };
        var findingsTab = new TabItem { Header = "Findings", Content = findingsTabGrid };
        tabControl.Items.Add(findingsTab);
        if (_laws != null)
            BuildLawsAndProposalsTabs(tabControl);

        Grid.SetRow(tabControl, 1);
        rootGrid.Children.Add(tabControl);

        // ─── Suggestions section (collapsible) ───
        _suggestionsSection = new Border
        {
            Margin = new Thickness(16, 0, 16, 12),
            Background = BgDark,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10, 6, 10, 6),
            Visibility = Visibility.Collapsed
        };
        var suggestionsStack = new StackPanel();
        suggestionsStack.Children.Add(new TextBlock
        {
            Text = "Suggestions",
            Foreground = Bc("#569CD6"),
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        });
        _suggestionsPanel = new StackPanel();
        suggestionsStack.Children.Add(_suggestionsPanel);
        _suggestionsSection.Child = suggestionsStack;
        Grid.SetRow(_suggestionsSection, 2);
        rootGrid.Children.Add(_suggestionsSection);

        Content = rootGrid;

        // Subscribe to live updates
        _shadow.FindingsAdded += OnFindingsAdded;
        _shadow.ConfigChanged += OnConfigChanged;
        Closed += (_, _) =>
        {
            _shadow.FindingsAdded -= OnFindingsAdded;
            _shadow.ConfigChanged -= OnConfigChanged;
        };

        RefreshFindings();
    }

    private void OnFindingsAdded(int count, Severity severity)
    {
        Dispatcher.InvokeAsync(RefreshFindings);
    }

    private void OnConfigChanged()
    {
        Dispatcher.InvokeAsync(() =>
        {
            RefreshToggleButton();
            RefreshFindings();
        });
    }

    private void RefreshToggleButton()
    {
        _toggleBtn.Content = _shadow.Enabled ? "Disable" : "Enable";
        _toggleBtn.Background = _shadow.Enabled ? Bc("#0E639C") : Bc("#3F3F46");
    }

    private void RefreshFindings()
    {
        var severityText = (_severityFilter.SelectedItem as ComboBoxItem)?.Content?.ToString();
        var categoryText = (_categoryFilter.SelectedItem as ComboBoxItem)?.Content?.ToString();
        var searchText = _searchBox.Text.Trim();

        Severity? minSev = severityText switch
        {
            "Info" => Severity.Info,
            "Low" => Severity.Low,
            "Medium" => Severity.Medium,
            "High" => Severity.High,
            "Critical" => Severity.Critical,
            _ => null
        };
        string? cat = categoryText is null or "All" ? null : categoryText;

        var findings = _shadow.GetFindings(minSeverity: minSev, category: cat);

        if (!string.IsNullOrEmpty(searchText))
            findings = findings.Where(f =>
                f.Title.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                f.Url.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                f.Description.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                f.SeenOnDomains.Any(d => d.Contains(searchText, StringComparison.OrdinalIgnoreCase))
            ).ToList();

        var total = _shadow.FindingsCount;
        var highCount = _shadow.GetFindings(minSeverity: Severity.High).Count;
        var enabledText = _shadow.Enabled ? "active" : "off";
        _summaryText.Text = $"Shadow: {enabledText}  |  {_shadow.PagesAudited} pages  |  {total} findings ({highCount} high/critical)";

        _findingsList.Children.Clear();

        if (findings.Count == 0)
        {
            _findingsList.Children.Add(new TextBlock
            {
                Text = _shadow.Enabled
                    ? "No findings yet. Browse pages — built-in checks and Laws run automatically."
                    : "Shadow is off. Enable it above or via Settings to run checks and Laws while you browse.",
                Foreground = FgDim,
                FontSize = 11,
                Margin = new Thickness(10, 10, 10, 10),
                FontStyle = FontStyles.Italic
            });
        }
        else
        {
            foreach (var finding in findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Timestamp))
                _findingsList.Children.Add(CreateFindingRow(finding));
        }

        UpdateDetail();
        RefreshSuggestions();
    }

    private Border CreateFindingRow(ShadowFinding finding)
    {
        var isSelected = _selectedFinding?.Id == finding.Id;
        var row = new Border
        {
            Background = isSelected ? BgSelected : Brushes.Transparent,
            Padding = new Thickness(8, 5, 8, 5),
            Cursor = Cursors.Hand,
            Tag = finding
        };

        var dock = new DockPanel();

        // Severity badge
        var badge = new Border
        {
            Background = SeverityBrush(finding.Severity),
            CornerRadius = new CornerRadius(3),
            Padding = new Thickness(5, 1, 5, 1),
            Margin = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        badge.Child = new TextBlock
        {
            Text = finding.Severity.ToString().ToUpperInvariant()[..3],
            Foreground = Brushes.White,
            FontSize = 9,
            FontWeight = FontWeights.Bold
        };
        DockPanel.SetDock(badge, Dock.Left);
        dock.Children.Add(badge);

        // Occurrences count (right side)
        if (finding.Occurrences > 1)
        {
            var occ = new TextBlock
            {
                Text = $"\u00d7{finding.Occurrences}",
                Foreground = FgDim,
                FontSize = 10,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0)
            };
            DockPanel.SetDock(occ, Dock.Right);
            dock.Children.Add(occ);
        }

        // Category tag (right side)
        var catTag = new TextBlock
        {
            Text = finding.Audit,
            Foreground = FgDim,
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(8, 0, 0, 0)
        };
        DockPanel.SetDock(catTag, Dock.Right);
        dock.Children.Add(catTag);

        // Title (fills remaining space)
        var title = new TextBlock
        {
            Text = finding.Title,
            Foreground = FgText,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis
        };
        dock.Children.Add(title);

        row.Child = dock;

        row.MouseLeftButtonDown += (_, _) =>
        {
            _selectedFinding = finding;
            RefreshFindings();
        };

        row.MouseEnter += (_, _) =>
        {
            if (_selectedFinding?.Id != finding.Id)
                row.Background = Bc("#2A2D2E");
        };
        row.MouseLeave += (_, _) =>
        {
            row.Background = _selectedFinding?.Id == finding.Id ? BgSelected : Brushes.Transparent;
        };

        return row;
    }

    private void UpdateDetail()
    {
        if (_selectedFinding == null)
        {
            _detailTitle.Text = "Select a finding to see details";
            _detailSeverity.Text = "";
            _detailUrl.Text = "";
            _detailDomains.Text = "";
            _detailDomains.Visibility = Visibility.Collapsed;
            _detailDescription.Text = "";
            _detailRecommendation.Text = "";
            _detailMeta.Text = "";
            _askAiButton.IsEnabled = false;
            _askAiButton.ToolTip = "Select a finding first to send it to the AI Assistant";
            return;
        }

        var f = _selectedFinding;
        _detailTitle.Text = f.Title;
        _detailSeverity.Text = $"Severity: {f.Severity}";
        _detailSeverity.Foreground = SeverityBrush(f.Severity);
        _detailUrl.Text = string.IsNullOrEmpty(f.Url) ? "" : f.Url;
        if (f.Occurrences > 1 && f.FormatSeenOnDomains() is { } domains)
        {
            _detailDomains.Text = $"Domains: {domains}";
            _detailDomains.Visibility = Visibility.Visible;
        }
        else
        {
            _detailDomains.Text = "";
            _detailDomains.Visibility = Visibility.Collapsed;
        }
        _detailDescription.Text = f.Description;
        _detailRecommendation.Text = string.IsNullOrEmpty(f.Recommendation) ? "" : $"Recommendation: {f.Recommendation}";
        _detailMeta.Text = $"Audit: {f.Audit}  |  First seen: {f.FirstSeen:HH:mm:ss}  |  Last: {f.Timestamp:HH:mm:ss}  |  Occurrences: {f.Occurrences}";
        _askAiButton.IsEnabled = true;
        _askAiButton.ToolTip = "Send this finding to the AI Assistant";
    }

    private string? DetailCopyText()
    {
        var f = _selectedFinding;
        if (f == null) return null;

        var lines = new List<string> { f.Title, $"Severity: {f.Severity}" };
        if (!string.IsNullOrEmpty(f.Url))
            lines.Add(f.Url);
        if (f.Occurrences > 1 && f.FormatSeenOnDomains() is { } domains)
            lines.Add($"Domains: {domains}");
        if (!string.IsNullOrEmpty(f.Description))
            lines.Add(f.Description);
        if (!string.IsNullOrEmpty(f.Recommendation))
            lines.Add($"Recommendation: {f.Recommendation}");
        lines.Add($"Audit: {f.Audit}  |  First seen: {f.FirstSeen:HH:mm:ss}  |  Last: {f.Timestamp:HH:mm:ss}  |  Occurrences: {f.Occurrences}");
        return string.Join(Environment.NewLine, lines);
    }

    private void RefreshSuggestions()
    {
        var suggestions = _shadow.GetSuggestions();
        _suggestionsPanel.Children.Clear();

        if (suggestions.Count == 0)
        {
            _suggestionsSection.Visibility = Visibility.Collapsed;
            return;
        }

        _suggestionsSection.Visibility = Visibility.Visible;

        foreach (var s in suggestions)
        {
            var row = new StackPanel { Margin = new Thickness(0, 2, 0, 4) };

            row.Children.Add(new TextBlock
            {
                Text = $"\u2192 {s.Suggestion}",
                Foreground = FgText,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            });

            var followUp = s.McpTool ?? (s.ApiUrl != null ? $"{s.ApiMethod} {s.ApiUrl}" : null);
            if (followUp != null)
            {
                var apiRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(12, 2, 0, 0) };
                apiRow.Children.Add(new TextBlock
                {
                    Text = followUp,
                    Foreground = FgDim,
                    FontSize = 10,
                    VerticalAlignment = VerticalAlignment.Center
                });

                var copyBtn = new Button
                {
                    Content = "Copy",
                    Width = 40,
                    Height = 18,
                    FontSize = 9,
                    Margin = new Thickness(8, 0, 0, 0),
                    Background = Bc("#3F3F46"),
                    Foreground = Brushes.White,
                    BorderBrush = BorderClr,
                    BorderThickness = new Thickness(1),
                    Cursor = Cursors.Hand,
                    ToolTip = "Copy the MCP tool name for the AI Assistant"
                };
                copyBtn.Click += (_, _) =>
                {
                    Clipboard.SetText(followUp);
                    copyBtn.Content = "\u2713";
                };
                apiRow.Children.Add(copyBtn);
                row.Children.Add(apiRow);
            }

            row.Children.Add(new TextBlock
            {
                Text = $"Triggered by: {s.Trigger}",
                Foreground = FgDim,
                FontSize = 9,
                Margin = new Thickness(12, 1, 0, 0)
            });

            _suggestionsPanel.Children.Add(row);
        }
    }

    #region UI Helpers

    private static ComboBox CreateFilterCombo(string[] items)
    {
        var combo = new ComboBox
        {
            Width = 110,
            Height = 22,
            Background = Bc("#1E1E1E"),
            Foreground = FgText,
            BorderBrush = BorderClr,
            FontSize = 11,
            SelectedIndex = 0
        };
        DarkComboBoxHelper.ApplyDarkStyle(combo);
        foreach (var item in items)
        {
            combo.Items.Add(DarkComboBoxHelper.CreateItem(item));
        }
        return combo;
    }

    private static Button CreateButton(string text, bool isPrimary)
    {
        return new Button
        {
            Content = text,
            Width = 80,
            Height = 26,
            Background = isPrimary ? Bc("#0E639C") : Bc("#3F3F46"),
            Foreground = Brushes.White,
            BorderBrush = BorderClr,
            BorderThickness = new Thickness(1),
            FontSize = 11,
            Cursor = Cursors.Hand
        };
    }

    private static SolidColorBrush SeverityBrush(Severity severity) => severity switch
    {
        Severity.Critical => Bc("#F44747"),
        Severity.High => Bc("#CCA700"),
        Severity.Medium => Bc("#EF9552"),
        _ => Bc("#888888")
    };

    private static SolidColorBrush Bc(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }

    #endregion
}
